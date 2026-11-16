package io.bitbytelab.raijin.turbo

import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * Opens an HTTP/3 run's QUIC connections, numbers the ones that open, and counts the attempts that
 * fail, apart from requests failing on a connection that did open. Connects to [engine]'s target,
 * numbers from its connection count, and records failures as its last error.
 */
internal class Http3ConnectionOpener(
    private val engine: RequestEngine,
    private val factory: H3ConnectionFactory,
    private val verifyCertificates: Boolean,
    private val adaptive: Boolean,
) {
    /** Handshakes under way. An adaptive run does not measure its capacity while there are any. */
    val setupsInFlight = AtomicInteger()

    /**
     * How many attempts to open a QUIC connection have failed, as distinct from a request failing
     * on one that did open.
     *
     * <p>[RequestEngine.permaFails] cannot stand in for this. With retries on, and ScriptEnvironment
     * defaults to three, one request has to lose four handshakes before it is counted, and the pool
     * hands its slots to whichever request is waiting rather than to the one part way through its
     * retries. Measured against a host with no HTTP/3 on the default settings, Fails was still 0
     * fifty seconds into the run while Retries climbed, so a status line waiting on permaFails
     * stayed blank until the user halted the run, which failed every parked request at once.
     */
    val openFailures = AtomicInteger()

    fun open(): H3Session {
        setupsInFlight.incrementAndGet()
        return try {
            factory.open(engine.target, verifyCertificates)
        } finally {
            setupsInFlight.decrementAndGet()
        }
    }

    /** Counts a newly opened connection into the run's connections; its place there is its ID. */
    fun nextConnectionId(): String = engine.connections.incrementAndGet().toString()

    fun recordOpenFailure(exception: Throwable) {
        engine.lastError = exception.toString()
        openFailures.incrementAndGet()
    }

    /** A failed open, which an adaptive run also counts as a transport failure. */
    fun recordOpenAndTransportFailure(exception: Throwable) {
        recordOpenFailure(exception)
        if (adaptive) engine.recordTransportFailure(exception)
    }
}

/**
 * An HTTP/3 run's ordinary connections: opened up front, on demand and as an adaptive run grows,
 * leased to requests without a lock, retired as they fail, run out or the pool shrinks, lent whole
 * to a gate, and closed with the run.
 *
 * <p>Every connection the run holds, pooled or held by a gate, owns one of [slots]. Whatever opens
 * a connection reserves its slot first, and exactly one party hands it back: the pool when it
 * retires the connection, or the gate a connection was lent to.
 */
internal class Http3ConnectionPool(
    private val runState: AtomicInteger,
    private val retiredConnections: AtomicInteger,
    private val adaptive: Boolean,
    private val requestsPerConnection: Int,
    private val maxConcurrentStreams: Int,
    private val slots: Http3SlotLimit,
    private val opener: Http3ConnectionOpener,
    /** The engine's resize lock: a shrink plans against the limit a concurrent resize leaves. */
    private val resizeLock: Any,
    private val taskStarter: Http3AdaptiveTaskStarter,
) {
    /**
     * Never guards ordinary request leases. It is the rendezvous a request parks on when the pool
     * has no lease to give, and serializes every publication into the pool with the dispatcher's
     * final pool snapshot so a session cannot appear after teardown has passed it.
     */
    private val poolLock = Object()

    /**
     * Set under [poolLock] when the dispatcher takes the pool snapshot it closes, and checked under
     * it by everything that publishes a connection. runState alone cannot say this: a run that
     * completes rather than being cancelled is still in state 2 when that snapshot is taken, so a
     * connection still opening at that moment would be pooled after the pool's last sweep and
     * never closed.
     */
    private var ordinaryPoolClosed = false

    /**
     * Copy-on-write so a request can walk the pool without taking anything. Writes are connections
     * opening and retiring, which happen concurrentConnections times in a run rather than once per
     * request.
     */
    private val ordinaryConnections = CopyOnWriteArrayList<OrdinaryConnection>()
    private val waitingGates = AtomicInteger()
    private val retirementDrainScheduled = AtomicBoolean()

    /**
     * Where the next request starts looking for a lease. Requests would otherwise all walk the
     * pool from the front and pile onto the same connection's counter, turning one connection's
     * compare-and-set into the contention the monitor used to be.
     */
    private val leaseCursor = AtomicInteger()

    /**
     * Request threads parked in [acquireOrdinaryConnection], the only place that waits on
     * [poolLock]. Measured rather than assumed: at full rate threads park constantly, because the
     * pool hands out more leases than the transport can carry streams for, so wake-ups here are
     * on the critical path and must not be skipped. Read before every wake-up so that a run whose
     * pool always has room never touches the monitor at all.
     */
    private val poolWaiters = AtomicInteger()

    /** Gates waiting for a connection of their own. Ordinary leasing stops while there are any. */
    val gatesWaiting: Int get() = waitingGates.get()

    /** Requests parked for a lease, which only a saturated pool has. */
    val parkedRequests: Int get() = poolWaiters.get()

    fun ordinaryConnectionSnapshot(): List<OrdinaryConnection> = ordinaryConnections.toList()

    /**
     * Opens the run's connections up front, the way the other engines do, rather than letting the
     * dispatcher open them on demand. Two reasons. A QUIC handshake can be slow — on a path where a
     * middlebox drops Initial packets it takes seconds — and opening one inside the dispatcher
     * stalls every other request behind it. And a gate that inherits a connection the run has
     * already used starts with a warm congestion window, where a freshly opened one does not.
     */
    fun openInitialConnections(desiredConnections: Int, timeout: Int) {
        val ready = CountDownLatch(desiredConnections)
        repeat(desiredConnections) { index ->
            // A QUIC handshake blocks inside Kwik just as a response read does, so it needs the
            // same thread choice: on a JDK that still pins, a pool larger than the carrier count
            // would open in batches instead of at once.
            kwikBlockingThread("http3-connect-$index").start {
                var reservedSlot = false
                try {
                    if (runState.get() < 3 && slots.tryAcquire()) {
                        reservedSlot = true
                        val session = opener.open()
                        // Checked and published under poolLock, which the dispatcher's final pool
                        // snapshot also takes: either this connection is in that snapshot and is
                        // closed with the pool, or the pool has closed and it is closed here.
                        if (publishOpened(session)) {
                            reservedSlot = false
                            retireExcessOrdinaryConnections()
                            wakeAllPoolWaiters()
                        } else {
                            runCatching { session.close() }
                        }
                    }
                } catch (exception: Throwable) {
                    // A connection that will not open is not fatal on its own: the dispatcher can
                    // still open one on demand. It is still reportable straight away, which is why
                    // it is counted rather than only remembered.
                    opener.recordOpenAndTransportFailure(exception)
                } finally {
                    if (reservedSlot) {
                        slots.release()
                    }
                    ready.countDown()
                }
            }
        }
        // ScriptEnvironment starts the engine with a 5 second timeout, which is shorter than a
        // QUIC handshake on any path that drops Initial packets. Giving up before the transport
        // itself would guarantees an empty pool at the moment the dispatcher starts, which is the
        // opposite of establishing connections up front.
        val waitSeconds = maxOf(timeout.toLong(), HTTP3RequestEngine.HANDSHAKE_WAIT_SECONDS)
        if (!ready.await(waitSeconds, TimeUnit.SECONDS)) {
            Utils.out(
                "HTTP/3: only ${desiredConnections - ready.count.toInt()} of $desiredConnections connections opened " +
                    "within ${waitSeconds}s; the rest will be opened on demand"
            )
        }
    }

    /**
     * Fills a live adaptive pool independently of request dispatch. This runs while [resizeLock]
     * is held, so every worker owns a slot before another resize can plan the same capacity.
     */
    fun replenishAdaptiveConnections() {
        val connectionLimit = requireNotNull(slots.snapshot())
        val startBudget = (connectionLimit.limit - connectionLimit.acquired).coerceAtLeast(0)
        repeat(startBudget) {
            if (!tryAcquireAdaptiveTaskSlot(
                isRunning = { runState.get() in 1..2 },
                acquire = { slots.tryAcquire() },
                release = { slots.release() },
            )) return
            try {
                taskStarter.start("http3-connect-live", ::openReservedAdaptiveConnection)
            } catch (exception: Throwable) {
                slots.release()
                opener.recordOpenAndTransportFailure(exception)
                wakeAllPoolWaiters()
                return
            }
        }
    }

    /** Opens one ordinary connection against a slot reserved by [replenishAdaptiveConnections]. */
    private fun openReservedAdaptiveConnection() {
        var session: H3Session? = null
        var handedOffSlot = false
        try {
            if (runState.get() >= 3) return
            session = opener.open()
            handedOffSlot = publishOpened(session)
            if (handedOffSlot) {
                retireExcessOrdinaryConnections()
            }
        } catch (exception: Throwable) {
            opener.recordOpenAndTransportFailure(exception)
        } finally {
            if (!handedOffSlot) {
                session?.let { opened -> runCatching { opened.close() } }
                slots.release()
            }
            wakeAllPoolWaiters()
        }
    }

    /**
     * Whether a connection may still join the pool. Asked, and acted on, only under [poolLock],
     * which is what makes the answer hold until the connection is in.
     */
    private fun poolOpenForPublication(): Boolean = runState.get() < 3 && !ordinaryPoolClosed

    /**
     * Pools a connection that has just opened under a fresh ID; false once the pool has closed, when
     * the caller closes it instead.
     */
    private fun publishOpened(session: H3Session): Boolean = synchronized(poolLock) {
        if (poolOpenForPublication()) {
            val id = opener.nextConnectionId()
            ordinaryConnections.add(OrdinaryConnection(session, id))
            true
        } else {
            false
        }
    }

    /**
     * Walks the pool for a connection with room, taking nothing. Each request starts one place
     * further along than the last, so requests spread across the pool instead of queueing on
     * whichever connection happens to be first.
     */
    private fun leaseFromPool(): OrdinaryConnection? {
        if (waitingGates.get() != 0) {
            return null
        }
        val pool = ordinaryConnections
        val size = pool.size
        if (size == 0) {
            return null
        }
        val from = Math.floorMod(leaseCursor.getAndIncrement(), size)
        for (offset in 0 until size) {
            // The pool can shrink underneath this walk, and a copy-on-write list throws rather
            // than returning null for an index that was valid when the size was read.
            val connection = pool.getOrNull((from + offset) % size) ?: continue
            if (connection.tryLease(requestsPerConnection, maxConcurrentStreams)) {
                // A pooled connection can reach its idle timeout while it waits for a request,
                // exactly as it can while it waits for a gate. A retry covers this wherever the
                // run allows one, but it costs a round trip to learn what the connection could
                // have been asked, and a run with retries turned off fails the request instead.
                if (!isStillConnected(connection)) {
                    releaseOrdinaryConnection(connection, failed = true)
                    continue
                }
                return connection
            }
        }
        return null
    }

    fun acquireOrdinaryConnection(): OrdinaryConnection {
        while (runState.get() < 3) {
            leaseFromPool()?.let { return it }

            var reservedSlot = false
            synchronized(poolLock) {
                if (waitingGates.get() == 0) {
                    // Between the lock-free walk above and this monitor a request may well have
                    // finished, so look once more before deciding the pool is full and either
                    // opening a connection or parking.
                    leaseFromPool()?.let { return it }
                    reservedSlot = slots.tryAcquire()
                }
                if (!reservedSlot) {
                    poolWaiters.incrementAndGet()
                    try {
                        poolLock.wait(POOL_WAIT_MILLIS)
                    } finally {
                        poolWaiters.decrementAndGet()
                    }
                }
            }

            if (reservedSlot) {
                val connection = try {
                    val session = try {
                        opener.open()
                    } catch (exception: Throwable) {
                        opener.recordOpenFailure(exception)
                        throw exception
                    }
                    val opened = OrdinaryConnection(session, opener.nextConnectionId())
                    opened.tryLease(requestsPerConnection, maxConcurrentStreams)
                    // Checked and published under poolLock like every other publication, so a
                    // connection opened while the pool closes is closed here rather than missed
                    // by the final sweep.
                    val published = synchronized(poolLock) {
                        poolOpenForPublication().also { open ->
                            if (open) ordinaryConnections.add(opened)
                        }
                    }
                    if (!published) {
                        runCatching { session.close() }
                        throw IllegalStateException("HTTP/3 run was cancelled while opening a connection")
                    }
                    opened
                } catch (exception: Throwable) {
                    slots.release()
                    wakeAllPoolWaiters()
                    throw exception
                }
                // The pool owns the slot from here, so nothing below may hand it back.
                retireExcessOrdinaryConnections()
                wakeAllPoolWaiters()
                return connection
            }
        }
        throw IllegalStateException("HTTP/3 run is no longer accepting requests")
    }

    fun releaseOrdinaryConnection(connection: OrdinaryConnection, failed: Boolean) {
        val alive = isStillConnected(connection)
        val cancelled = runState.get() >= 3
        // A failed request retires the connection. That looks wasteful - a stream error says
        // nothing about the other streams, and the pool pays a handshake to replace something
        // isConnected() still calls up - but it was measured both ways and retiring wins by a
        // wide margin: keeping the connection gave 26,175 and 47,784 rps on 500,000 requests
        // where retiring gave 78,320-85,260. isConnected() is a poor health signal, and a
        // connection that just lost a request is usually about to lose more, so retiring is
        // really load shedding away from a sick connection.
        //
        // What is not justified is closing it under the requests already on it, which took up
        // to maxConcurrentStreams - 1 live requests down per failure. Those close on the drain
        // in retireOrdinaryConnection instead, when the last lease comes back.
        val drop = failed || !alive || cancelled
        val shouldRetire = connection.releaseLease(retiring = drop)
        wakePoolWaiter()
        if (shouldRetire) {
            retireOrdinaryConnection(connection, forceClose = cancelled || !alive)
        }
    }

    /**
     * Wakes a request parked for a lease, and only then takes the monitor. A run whose pool has
     * room never parks anything, so the common case is one volatile read rather than a monitor
     * every request has to queue for.
     */
    fun wakePoolWaiter() {
        if (poolWaiters.get() == 0) {
            return
        }
        synchronized(poolLock) {
            poolLock.notifyAll()
        }
    }

    fun wakeAllPoolWaiters() {
        synchronized(poolLock) {
            poolLock.notifyAll()
        }
    }

    /** Whether the session is usable, without allocating a Result on a path taken per request. */
    private fun isStillConnected(connection: OrdinaryConnection): Boolean =
        try {
            connection.session.isConnected()
        } catch (ignored: Throwable) {
            false
        }

    private fun retireOrdinaryConnection(connection: OrdinaryConnection, forceClose: Boolean) {
        // A delayed shrink runnable can arrive after a gate has claimed this object. It no longer
        // owns either the session or its slot and therefore has nothing it is allowed to close.
        if (!connection.retire()) return
        var closeSession = forceClose && connection.claimClose()
        var releaseSlot = false
        // A connection still carrying requests stays in the pool until the last of them gives its
        // lease back; whichever release takes it to zero is the one that takes it out.
        if (connection.inFlight == 0) {
            ordinaryConnections.remove(connection)
            closeSession = closeSession || connection.claimClose()
            releaseSlot = connection.claimSlot()
        }
        wakePoolWaiter()

        if (closeSession) {
            runCatching { connection.session.close() }
        }
        if (releaseSlot) {
            slots.release()
            if (adaptive) retiredConnections.incrementAndGet()
            wakePoolWaiter()
        }
    }

    fun retireExcessOrdinaryConnections() {
        if (!adaptive) return
        synchronized(resizeLock) {
            if (waitingGates.get() != 0) return
            val desired = requireNotNull(slots.snapshot()).limit
            var remaining = (
                ordinaryConnections.count { !it.retired } - desired
            ).coerceAtLeast(0)
            if (remaining == 0) return

            var hasIdleRetirement = false
            // Retire idle capacity first so shrink convergence does not wait for live requests. The
            // copy-on-write iterator already owns a stable backing array; no filter/sort copies are
            // needed, and one bulk drain removes every idle retiree with one pool-array rewrite.
            for (connection in ordinaryConnections) {
                if (remaining == 0) break
                if (connection.inFlight != 0 || !connection.markRetiring()) continue
                remaining -= 1
                hasIdleRetirement = true
            }
            if (remaining > 0) {
                for (connection in ordinaryConnections) {
                    if (remaining == 0) break
                    if (!connection.markRetiring()) continue
                    remaining -= 1
                    if (connection.inFlight == 0) hasIdleRetirement = true
                }
            }
            if (hasIdleRetirement) scheduleRetirementDrain()
        }
    }

    private fun scheduleRetirementDrain() {
        if (!retirementDrainScheduled.compareAndSet(false, true)) return
        try {
            taskStarter.start("http3-retire-drain", ::drainRetiredOrdinaryConnections)
        } catch (failure: Throwable) {
            // Retirement is already irreversible. If the JVM cannot schedule the bounded drain,
            // finish it here so no retired session or connection slot is stranded.
            retirementDrainScheduled.set(false)
            drainRetiredOrdinaryConnectionsSynchronously()
            if (!isRecoverableAdaptiveCapacityFailure(failure)) throw failure
        }
    }

    private fun drainRetiredOrdinaryConnections() {
        var completed = false
        try {
            val removed = ArrayList<OrdinaryConnection>()
            ordinaryConnections.removeIf { connection ->
                (connection.retired && connection.inFlight == 0).also { ready ->
                    if (ready) removed += connection
                }
            }
            removed.forEach(::finishRemovedOrdinaryConnection)
            completed = true
        } catch (failure: Throwable) {
            drainRetiredOrdinaryConnectionsSynchronously()
            throw failure
        } finally {
            retirementDrainScheduled.set(false)
            if (completed && ordinaryConnections.any { it.retired && it.inFlight == 0 }) {
                scheduleRetirementDrain()
            }
        }
    }

    private fun drainRetiredOrdinaryConnectionsSynchronously() {
        while (true) {
            val connection = ordinaryConnections.firstOrNull {
                it.retired && it.inFlight == 0
            } ?: return
            retireOrdinaryConnection(connection, forceClose = false)
        }
    }

    private fun finishRemovedOrdinaryConnection(connection: OrdinaryConnection) {
        if (connection.claimClose()) runCatching { connection.session.close() }
        if (connection.claimSlot()) {
            slots.release()
            retiredConnections.incrementAndGet()
        }
        wakePoolWaiter()
    }

    /**
     * Closes the pool to publication and retires everything in it, closing each session; the
     * dispatcher's teardown. Every publication into the pool is checked and made under the same
     * monitor. Either it wins and appears in this snapshot, or it sees the pool closed and closes
     * its own session. Closing the pool rather than relying on runState covers a run that
     * completes as well as one that is cancelled: a completed run is still in state 2 here.
     */
    fun close() {
        val pooledAtCancellation = synchronized(poolLock) {
            ordinaryPoolClosed = true
            ordinaryConnectionSnapshot()
        }
        pooledAtCancellation.forEach { connection ->
            retireOrdinaryConnection(connection, forceClose = true)
        }
    }

    /**
     * A connection for a gate's exclusive use: an idle pooled one where there is one, otherwise one
     * opened against a slot that retiring the pool frees. Ordinary leasing stops while it waits.
     */
    fun acquireGateConnection(): GateLease {
        waitingGates.incrementAndGet()
        try {
            claimPooledConnection()?.let { return it }
            ordinaryConnectionSnapshot().forEach { connection ->
                retireOrdinaryConnection(connection, forceClose = false)
            }
            // A connection can arrive either as a freed slot or as a gate handing one back to the
            // pool. Waiting on the semaphore alone misses the second and deadlocks against a gate
            // that returned its connection instead of closing it.
            while (runState.get() < 3) {
                claimPooledConnection()?.let { return it }
                if (slots.tryAcquire(50, TimeUnit.MILLISECONDS)) {
                    return openGateConnection()
                }
            }
            throw IllegalStateException("HTTP/3 run was cancelled while opening a gate connection")
        } finally {
            waitingGates.decrementAndGet()
            retireExcessOrdinaryConnections()
            wakeAllPoolWaiters()
        }
    }

    /**
     * Takes an idle connection out of the pool for a gate's exclusive use. The gate inherits the
     * connection's slot, so the connection is marked as having released it already and the gate's
     * settlement becomes the one place that hands it back.
     */
    private fun claimPooledConnection(): GateLease? {
        while (true) {
            // Claiming exclusive gate ownership is one compare-and-set, so a request cannot be
            // handed a lease on it between the two: either the gate wins and the request looks
            // elsewhere, or the request wins and this connection is not idle for the gate to take.
            val claimed = ordinaryConnections.firstOrNull { it.tryClaimIdle() } ?: return null
            ordinaryConnections.remove(claimed)
            // Asked on the way out as well as on the way in. Nothing keeps a pooled connection
            // alive and the idle timeout is the smaller of what the two ends asked for, so a
            // connection can reach it while it waits to be claimed. Staging is the first thing a
            // gate does with the connection it takes, and a gate has no retry behind it: where an
            // ordinary request survives a dead connection by asking for another one, a gate loses
            // its whole batch to it.
            if (!isStillConnected(claimed)) {
                discardGateClaim(claimed)
                continue
            }
            // The gate inherits the connection's slot, so nothing else may hand it back.
            check(claimed.claimSlot()) { "gate claimed a connection whose slot was already released" }
            synchronized(poolLock) {
                poolLock.notifyAll()
            }
            // The gate inherits the connection's ID as well as its slot, so a connection that
            // passes through a gate and back into the pool keeps tabling under the ID it started
            // with.
            return GateLease(claimed.session, claimed.id, claimed.requestsCarried)
        }
    }

    /** Closes a dead connection after this gate, rather than a pool retiree, won ownership. */
    private fun discardGateClaim(connection: OrdinaryConnection) {
        if (connection.claimClose()) runCatching { connection.session.close() }
        if (connection.claimSlot()) {
            slots.release()
            if (adaptive) retiredConnections.incrementAndGet()
        }
        wakeAllPoolWaiters()
    }

    /** Opens a connection against a slot the caller has already acquired. */
    private fun openGateConnection(): GateLease {
        var reservedSlot = true
        try {
            if (runState.get() >= 3) {
                throw IllegalStateException("HTTP/3 run was cancelled while opening a gate connection")
            }
            val session = try {
                opener.open()
            } catch (exception: Throwable) {
                opener.recordOpenAndTransportFailure(exception)
                throw exception
            }
            val id = opener.nextConnectionId()
            reservedSlot = false
            return GateLease(session, id, 0)
        } finally {
            if (reservedSlot) {
                slots.release()
            }
        }
    }

    /**
     * Takes back a connection a gate claimed but never got to stage on: into the pool if it can
     * still carry requests, closed otherwise.
     */
    fun returnGateLeaseAfterSetupFailure(lease: GateLease) {
        val connected = lease.requestsCarried < requestsPerConnection &&
            runCatching { lease.session.isConnected() }.getOrDefault(false)
        val reusable = connected && returnGateConnection(lease.session, lease.id, lease.requestsCarried)
        if (reusable) {
            retireExcessOrdinaryConnections()
        } else {
            retireGateSession(lease.session)
        }
        wakeAllPoolWaiters()
    }

    /**
     * Pools a gate's connection again under the ID it already tables under, with the requests it
     * has carried. False once the pool has closed, when the caller retires it instead.
     */
    fun returnGateConnection(session: H3Session, id: String, requestsCarried: Int): Boolean =
        synchronized(poolLock) {
            if (poolOpenForPublication()) {
                ordinaryConnections.add(OrdinaryConnection(session, id, requestsCarried))
                true
            } else {
                false
            }
        }

    /** Closes a session a gate held, and hands back the connection slot that went with it. */
    fun retireGateSession(session: H3Session?) {
        session?.let { held -> runCatching { held.close() } }
        slots.release()
        if (adaptive) retiredConnections.incrementAndGet()
    }

    /**
     * A gate's exclusive connection, and how many requests it had already carried when the gate
     * took it. Carried rather than looked up later: the pooled connection object is retired the
     * moment the gate claims it, and the count has to survive that or requestsPerConnection stops
     * applying the first time a connection passes through a gate.
     */
    class GateLease(val session: H3Session, val id: String, val requestsCarried: Int)

    /**
     * A pooled connection whose whole lease state - how many requests it has carried, how many are
     * on it now, and whether it is retired - lives in one long so that taking and giving back a
     * lease is a single compare-and-set. It used to be three fields under the engine's pool
     * monitor, which put every request through one monitor twice; measured in Burp against a live
     * target, that left 4,094 of 5,226 threads blocked entering it and 455 requests on the wire out
     * of the 4,800 the run had asked for.
     */
    class OrdinaryConnection(
        val session: H3Session,
        val id: String,
        requestsCarried: Int = 0,
    ) {
        private val state = AtomicLong(pack(requestsCarried, 0, false))
        private val closing = AtomicBoolean(false)
        private val slotHandedBack = AtomicBoolean(false)

        val inFlight: Int get() = inFlightOf(state.get())
        val retired: Boolean get() = isOwned(state.get())
        val requestsCarried: Int get() = assignedOf(state.get())

        /** Whether this caller is the one that gets to close the session. */
        fun claimClose(): Boolean = closing.compareAndSet(false, true)

        /** Whether this caller is the one that gets to hand the connection's pool slot back. */
        fun claimSlot(): Boolean = slotHandedBack.compareAndSet(false, true)

        fun tryLease(requestLimit: Int, streamLimit: Int): Boolean {
            // Up to streamLimit requests in flight at once, matching HTTP2RequestEngine: a QUIC
            // connection multiplexes, so requestsPerConnection counts the requests a connection
            // carries over its lifetime and concurrentConnections bounds the pool, exactly as they
            // do for HTTP/2. Kwik's own stream credit is the backstop when the server grants less.
            while (true) {
                val current = state.get()
                if (isOwned(current)) {
                    return false
                }
                val assigned = assignedOf(current)
                val inFlight = inFlightOf(current)
                if (inFlight >= streamLimit || assigned >= requestLimit) {
                    return false
                }
                val next = pack(assigned + 1, inFlight + 1, assigned + 1 >= requestLimit)
                if (state.compareAndSet(current, next)) {
                    return true
                }
            }
        }

        /** Gives a lease back, and reports whether the connection is now retired. */
        fun releaseLease(retiring: Boolean): Boolean {
            while (true) {
                val current = state.get()
                val inFlight = inFlightOf(current)
                check(inFlight > 0) { "HTTP/3 connection lease was released twice" }
                val next = pack(assignedOf(current), inFlight - 1, retiring || isOwned(current))
                if (state.compareAndSet(current, next)) {
                    return isOwned(next)
                }
            }
        }

        /**
         * Claims retirement, whether or not requests remain. False means a gate already owns the
         * session and slot, so a delayed pool task must not touch either one.
         */
        fun retire(): Boolean {
            while (true) {
                val current = state.get()
                when (ownerOf(current)) {
                    GATE_OWNED -> return false
                    RETIRING -> return true
                }
                if (state.compareAndSet(current, current or RETIRING)) {
                    return true
                }
            }
        }

        /** Claims a new pool retirement; false if a gate or another shrink already owns it. */
        fun markRetiring(): Boolean {
            while (true) {
                val current = state.get()
                if (isOwned(current)) return false
                if (state.compareAndSet(current, current or RETIRING)) return true
            }
        }

        /** Takes exclusive gate ownership only while idle, atomically against ordinary leasing. */
        fun tryClaimIdle(): Boolean {
            while (true) {
                val current = state.get()
                if (isOwned(current) || inFlightOf(current) != 0) {
                    return false
                }
                if (state.compareAndSet(current, current or GATE_OWNED)) {
                    return true
                }
            }
        }

        private companion object {
            // 31 bits each for requests carried and requests in flight, which is every value
            // either can take: leasing stops at requestsPerConnection, itself an Int.
            const val COUNTER_BITS = 31
            const val COUNTER_MASK = (1L shl COUNTER_BITS) - 1
            const val RETIRING = 1L shl 62
            const val GATE_OWNED = 1L shl 63
            const val OWNER_MASK = RETIRING or GATE_OWNED

            fun inFlightOf(state: Long): Int = (state and COUNTER_MASK).toInt()

            fun assignedOf(state: Long): Int = ((state ushr COUNTER_BITS) and COUNTER_MASK).toInt()

            fun ownerOf(state: Long): Long = state and OWNER_MASK

            fun isOwned(state: Long): Boolean = ownerOf(state) != 0L

            fun pack(assigned: Int, inFlight: Int, retired: Boolean): Long =
                (assigned.toLong() shl COUNTER_BITS) or
                    inFlight.toLong() or
                    (if (retired) RETIRING else 0L)
        }
    }

    private companion object {
        /**
         * How long a request thread parks when the pool has no free lease. Short because the
         * wake-up that would end the wait early is skipped when no thread appears to be parked,
         * and this timeout is what bounds that race.
         */
        const val POOL_WAIT_MILLIS = 5L
    }
}
