package io.bitbytelab.raijin.turbo

import io.bitbytelab.raijin.turbo.hp3.quic.ControlledKwikQuicTransport
import io.bitbytelab.raijin.turbo.hp3.quic.KwikThreads
import io.bitbytelab.raijin.turbo.hp3.quic.QuicConfig
import io.bitbytelab.raijin.turbo.http3.FirstByteTimingInputStream
import io.bitbytelab.raijin.turbo.http3.GateMode
import io.bitbytelab.raijin.turbo.http3.SdaBatch
import io.bitbytelab.raijin.turbo.http3.SdaOptions
import io.bitbytelab.raijin.turbo.http3.StageDrain
import io.bitbytelab.raijin.turbo.http3.TurboHttp3RequestTranslator
import java.io.IOException
import java.net.URI
import java.net.URL
import java.time.Duration
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * Engine.HTTP3. Runs the dispatcher, ordinary requests, gate releases, adaptive resizing and the
 * run's lifecycle and metrics. The ordinary connections and their leases belong to
 * [Http3ConnectionPool]; the connection each gate holds belongs to [Http3GateConnections].
 */
open class HTTP3RequestEngine @JvmOverloads constructor(
    url: String,
    private val threads: Int,
    maxQueueSize: Int,
    val requestsPerConnection: Int,
    override val maxRetriesPerRequest: Int,
    override var idleTimeout: Long = 0,
    override val callback: (Request, Boolean) -> Boolean,
    override var readCallback: ((String) -> Boolean)?,
    verifyCertificates: Boolean = false,
    connectionFactory: H3ConnectionFactory = defaultConnectionFactory(idleTimeout),
    private val maxConcurrentStreams: Int = DEFAULT_MAX_CONCURRENT_STREAMS,
    gateMode: GateMode = GateMode.AUTO,
    private val adaptive: Boolean = false,
) : RequestEngine(requiresBurpProfessional = true), AdaptiveTransport {
    private val options = SdaOptions()
    private val connectionSlots: Http3SlotLimit
    private val dispatchSlots: Http3SlotLimit
    private val opener: Http3ConnectionOpener
    private val pool: Http3ConnectionPool
    private val gateConnections: Http3GateConnections
    private val batches = ConcurrentHashMap<String, SdaBatch>()
    private val activeJobs = AtomicInteger()
    private val gateCollectors = ConcurrentHashMap<String, GateCollector>()
    private val gateCallbackAdmissions = GateCallbackAdmissions()
    private val gateLifecycleAdmissions = GateCallbackAdmissions()
    private val deferredTerminalFinalizer = AtomicReference<(() -> Unit)?>(null)
    private val terminalActionsLock = Object()
    private val cleanupRequested = AtomicBoolean()
    private val cleanupCompleted = AtomicBoolean()
    private val started = AtomicBoolean(false)

    /** Held through a live resize, and by the pool while it shrinks to the resized limit. */
    private val resizeLock = Object()

    /** Requests the configuration asks to have in flight: one per stream on every connection. */
    private val targetConcurrency =
        (threads.toLong() * maxConcurrentStreams).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()

    /**
     * Requests actually allowed in flight, which is [targetConcurrency] capped at
     * [maxRequestsInFlight]. On a JDK that still pins, each in-flight request holds an OS thread, so an unbounded
     * product would ask the OS for more threads than it will give: concurrentConnections defaults
     * to 50 in the Python API and multiplies by 100 streams, so raising it to 800 asks for 80,000.
     */
    private val useVirtualThreads = prefersVirtualThreads(Runtime.version().feature())

    private val initialRequestsInFlightLimit = dispatchCapacity(threads)

    val requestsInFlightLimit: Int
        get() = dispatchSlots.snapshot()?.limit ?: initialRequestsInFlightLimit

    /**
     * Gates that were answered before they were released, and so raced nothing.
     *
     * A gate holds only while the server still needs what was withheld from it. One that answers
     * without reading the withheld bytes — a redirect, a static handler, a 405 — replies to the
     * whole batch before the release, and the run then reports a race as absent when it was never
     * tested. Measured across 100 hosts, the single-datagram gate did this on 21 of 94; the QPACK
     * gate, which withholds the header decode that no HTTP/3 server can skip, on none of 93.
     *
     * Counted as well as logged so a caller can act on it rather than having to read output.
     */
    val gatesThatDidNotHold = AtomicInteger()

    /**
     * The longest any one gate took from firing its release to that release returning.
     *
     * The client's own contribution to how spread the batch landed, and so the part of the result
     * that is this engine's to improve. A transport that queues a release for a thread of its own
     * can hold it for hundreds of microseconds, which would otherwise look like a perfect
     * release.
     */
    val gateReleaseSendSpanNanos = AtomicLong()

    /** Carries the ungated requests, one thread per request in flight; see [newHttp3RequestExecutor]. */
    private lateinit var requestExecutor: ExecutorService

    /** Carries the gate collectors, apart from the ordinary requests; see [newHttp3GateExecutor]. */
    private lateinit var gateExecutor: ExecutorService

    @JvmOverloads
    constructor(
        url: String,
        threads: Int,
        maxQueueSize: Int,
        requestsPerConnection: Int,
        maxRetriesPerRequest: Int,
        idleTimeout: Long,
        callback: (Request, Boolean) -> Boolean,
        readCallback: ((String) -> Boolean)?,
        verifyCertificates: Boolean,
        gateMode: String,
        adaptive: Boolean = false,
    ) : this(
        url,
        threads,
        maxQueueSize,
        requestsPerConnection,
        maxRetriesPerRequest,
        idleTimeout,
        callback,
        readCallback,
        verifyCertificates,
        defaultConnectionFactory(idleTimeout),
        DEFAULT_MAX_CONCURRENT_STREAMS,
        GateMode.fromScriptName(gateMode),
        adaptive,
    )

    init {
        try {
            require(threads > 0) { "concurrentConnections must be positive" }
            require(requestsPerConnection > 0) { "requestsPerConnection must be positive" }
            require(maxRetriesPerRequest >= 0) { "maxRetriesPerRequest must be non-negative" }
            require(maxConcurrentStreams > 0) { "maxConcurrentStreams must be positive" }
            require(readCallback == null) { "readCallback is not supported by Engine.HTTP3" }
            target = URI(url).toURL()
            require(target.protocol.equals("https", ignoreCase = true)) {
                "Engine.HTTP3 requires an https endpoint"
            }
            requestQueue = if (maxQueueSize > 0) LinkedBlockingQueue(maxQueueSize) else LinkedBlockingQueue()
            completedLatch = CountDownLatch(1)
            if (adaptive) {
                val cancelled = { runState.get() >= 3 }
                connectionSlots = Http3SlotLimit.resizable(threads, cancelled)
                dispatchSlots = Http3SlotLimit.resizable(initialRequestsInFlightLimit, cancelled)
            } else {
                connectionSlots = Http3SlotLimit.fixed(threads)
                dispatchSlots = Http3SlotLimit.fixed(initialRequestsInFlightLimit)
            }
            opener = Http3ConnectionOpener(this, connectionFactory, verifyCertificates, adaptive)
            pool = Http3ConnectionPool(
                runState,
                retiredConnections,
                adaptive,
                requestsPerConnection,
                maxConcurrentStreams,
                connectionSlots,
                opener,
                resizeLock,
                Http3AdaptiveTaskStarterConstructionContext.current()
                    ?: Http3AdaptiveTaskStarter { name, task -> kwikBlockingThread(name).start(task) },
            )
            gateConnections = Http3GateConnections(
                pool,
                runState,
                activeJobs,
                requestsPerConnection,
                gateMode,
                options,
            )
            // Adaptive execution is sized once for its immutable safety ceiling. Live work is
            // controlled by the adaptive dispatch slots rather than replacing this executor.
            requestExecutor = newHttp3RequestExecutor(
                useVirtualThreads,
                if (adaptive) maxRequestsInFlight(useVirtualThreads) else initialRequestsInFlightLimit,
            )
            gateExecutor = newHttp3GateExecutor()
            // Started here rather than in start() so that a run cancelled before it ever started
            // still has something to count the completion latch down.
            Thread.ofPlatform().daemon().name("http3-dispatcher").start(::dispatchForever)
        } catch (failure: Throwable) {
            if (::gateExecutor.isInitialized) gateExecutor.shutdownNow()
            if (::requestExecutor.isInitialized) requestExecutor.shutdownNow()
            Utils.unregisterEngine(this)
            throw failure
        }
    }

    override fun start(timeout: Int) {
        if (started.compareAndSet(false, true)) {
            pool.openInitialConnections(connectionSlots.snapshot()?.limit ?: threads, timeout)
            if (runState.get() >= 3) {
                return
            }
            // Engine.HTTP2 offers only "h2" over ALPN and lets the failed TLS handshake out of the
            // engine constructor, so a target that does not speak the protocol stops the script
            // right there. Engine.HTTP3 promises no fallback, so a run where not one QUIC
            // handshake completed has nothing left to try and stops the same way, rather than
            // working through the whole queue at one failed handshake per connection slot. The
            // tolerance in openInitialConnections is still worth keeping for a target that refuses
            // part of the opening burst, which is why this asks whether any connection opened
            // rather than whether any failed.
            if (connections.get() == 0 && opener.openFailures.get() > 0) {
                // Leaves the dispatcher no run to wait for. It is parked on runState being 0.
                finish(3)
                throw Exception(failureSummary())
            }
            if (requestsInFlightLimit < targetConcurrency) {
                Utils.out(
                    "HTTP/3: $threads connections x $maxConcurrentStreams streams would put " +
                        "$targetConcurrency requests in flight, and each one holds a thread. " +
                        "Capping at $requestsInFlightLimit."
                )
            }
            // Stamped after the handshakes, the way ThreadedRequestEngine stamps it after its
            // connected latch. A QUIC handshake can take seconds, and charging it to the run
            // offsets every request's arrival and understates the reported RPS. The dispatcher is
            // parked until the run goes live, so nothing is sent over a pool that is still being
            // filled. goLive() stamps and goes live under the lock a stop ends the run under, so a
            // stop that lands after the check above stands rather than being put back to live.
            if (!goLive()) return
            startIdleTimeoutWatchdog()
            startResponseDeadlineWatchdog()
        }
    }

    override val autoProtocol = AutoProtocol.HTTP3
    override val supportsKettledRequests = true

    override fun onTerminalStateEntering(state: Int) {
        gateCallbackAdmissions.close()
        gateLifecycleAdmissions.close()
    }

    override fun defaultAdaptiveLimits() = AdaptiveLimits(DEFAULT_ADAPTIVE_CONNECTIONS, null)

    override fun currentAdaptiveLimits() = AdaptiveLimits(
        connectionSlots.snapshot()?.limit ?: threads,
        null,
    )

    override fun adaptiveMetrics(): AdaptiveMetrics {
        val limits = currentAdaptiveLimits()
        val saturated = requestQueue.isNotEmpty() ||
            pool.parkedRequests > 0 ||
            activeRequests.get() >= requestsInFlightLimit
        return baseAdaptiveMetrics(limits, saturated).copy(
            safeToMeasure = adaptiveCapacityConverged(limits.concurrency, saturated),
        )
    }

    private fun adaptiveCapacityConverged(desiredConnections: Int, saturated: Boolean): Boolean {
        if (!adaptive) return true
        if (opener.setupsInFlight.get() != 0 || pool.gatesWaiting != 0) return false
        val connectionLimit = requireNotNull(connectionSlots.snapshot())
        val dispatchLimit = requireNotNull(dispatchSlots.snapshot())
        if (connectionLimit.limit != desiredConnections || connectionLimit.acquired > connectionLimit.limit) return false
        if (dispatchLimit.limit != dispatchCapacity(desiredConnections) || dispatchLimit.acquired > dispatchLimit.limit) return false
        val connections = pool.ordinaryConnectionSnapshot()
        if (connections.any { it.retired }) return false
        if (connections.size > desiredConnections) return false
        return !saturated || connections.size >= desiredConnections
    }

    override fun resizeConcurrency(newLimit: Int) {
        require(adaptive) { "Live resize is available only to adaptive HTTP3 engines" }
        require(newLimit > 0) { "Adaptive concurrentConnections must be positive" }
        synchronized(resizeLock) {
            val previous = requireNotNull(connectionSlots.snapshot()).limit
            connectionSlots.resize(newLimit)
            dispatchSlots.resize(dispatchCapacity(newLimit))
            if (newLimit > previous) {
                pool.replenishAdaptiveConnections()
            } else if (newLimit < previous) {
                pool.retireExcessOrdinaryConnections()
            }
        }
        pool.wakeAllPoolWaiters()
    }

    override fun resizeRequestsPerConnection(newLimit: Int): Boolean {
        require(adaptive) { "Live request lifetime is available only to adaptive HTTP3 engines" }
        return false
    }

    private fun dispatchCapacity(connections: Int): Int =
        (connections.toLong() * maxConcurrentStreams)
            .coerceAtMost(maxRequestsInFlight(useVirtualThreads).toLong())
            .toInt()

    /**
     * Cancels a run whose responses have stopped arriving. This cannot live on the dispatcher
     * thread: shouldAbandonRun() cancels by blocking on the completion latch, and the dispatcher
     * is the thread that counts it down.
     */
    private fun startIdleTimeoutWatchdog() {
        if (idleTimeout <= 0) {
            return
        }
        Thread.ofVirtual().name("http3-idle-watchdog").start {
            while (runState.get() in 1..2) {
                if (shouldAbandonRun()) {
                    return@start
                }
                Thread.sleep(IDLE_POLL_MILLIS)
            }
        }
    }

    /**
     * Fails response reads that have waited past their deadline, across ordinary connections and
     * connections held exclusively by an active gate.
     *
     * <p>A response that never arrives leaves its reader parked inside Kwik, whose own per-read
     * bound is Long.MAX_VALUE with no setter to lower it. The engine counts that reader as work in
     * progress, so the run never completes, and because its clock goes on running against a
     * request count that has stopped, the rate it reports decays for as long as it is left open.
     *
     * <p>One sweeper for the whole pool rather than a timer per request: this is the path every
     * request takes, and at full rate arming and cancelling a scheduled task each would put all of
     * them through the single lock inside a scheduler's delay queue.
     */
    private fun startResponseDeadlineWatchdog() {
        // A platform thread, for the same reason the dispatcher is one. Measured against a live
        // target: as a virtual thread this slept once and was never scheduled again, because a
        // saturated run has 12,288 request threads competing for the carriers of an eight-core
        // box. A supervisor starved by the work it supervises never fails the reads it exists to
        // fail, and the run wedges exactly as it did without it.
        Thread.ofPlatform().daemon().name("http3-response-watchdog").start {
            while (runState.get() in 1..2) {
                val now = System.nanoTime()
                val ordinarySessions = pool.ordinaryConnectionSnapshot().map { it.session }
                val gateSessions = batches.values.mapNotNull { it.connection?.session }
                (ordinarySessions + gateSessions).distinct().forEach { session ->
                    // A connection torn down between the snapshot and this is not a reason to
                    // stop sweeping the rest of the pool.
                    runCatching { session.failOverdueReads(now) }
                }
                Thread.sleep(RESPONSE_SWEEP_MILLIS)
            }
        }
    }

    /**
     * What the run looks like right now, including the gate integrity counters that report a gate
     * which did not hold. Declared here rather than on [RequestEngine] because no other engine
     * reports anything like it, and the shared class should not carry a hook with one caller.
     */
    fun runtimeMetrics(): Map<String, Any?> = linkedMapOf(
        "run_state" to runState.get(),
        "queue_size" to requestQueue.size,
        "successful_requests" to successfulRequests.get(),
        "failed_requests" to permaFails.get(),
        "connections" to connections.get(),
        "retries" to retries.get(),
        "gates_that_did_not_hold" to gatesThatDidNotHold.get(),
        "gate_release_send_span_ns" to gateReleaseSendSpanNanos.get(),
    )

    override fun buildRequest(
        template: String,
        payloads: List<String?>,
        learnBoring: Int?,
        label: String,
    ): Request = Request(template, payloads, learnBoring ?: 0, label)

    override fun openGate(gateName: String) {
        check(gateLifecycleAdmissions.tryEnter()) { "HTTP/3 run is no longer accepting gate releases" }
        var admissionTransferred = false
        try {
            if (!openGateOnce(gateName)) return
            val batch = batches[gateName]
                ?: throw IllegalStateException("No HTTP/3 batch exists for gate $gateName")
            try {
                batch.throwIfFailed()
                batch.awaitStagedRequestsSent(
                    StageDrain(options.stageWaitCapMillis, options.stageFallbackMillis),
                )
                batch.markReleased()
                val exchanges = batch.stagedExchanges()
                val releasedBy = batch.mode.name.lowercase()
                val release = batch.release(options)
                    ?: throw IllegalStateException("Gate $gateName has no QUIC connection to release")
                // The instant the batch actually left, not the instant it entered Kwik's sender
                // queue. Pacing can hold a queued packet while a server answers the staged prefix;
                // timing from that enqueue would hide the response that proved this gate did not hold.
                val releaseCallStarted = System.nanoTime()
                val releaseStarted = adaptiveTransportAttempt { release.send() }
                gateReleaseSendSpanNanos.updateAndGet { widest ->
                    maxOf(widest, System.nanoTime() - releaseCallStarted)
                }
                exchanges.forEach { staged ->
                    staged.request.sent = releaseStarted
                    staged.request.gateMode = releasedBy
                    staged.exchange.startResponseDeadline(releaseStarted)
                }
                // Blocks in Kwik like the readers it collects from, so it takes the same thread kind.
                // Counted as an active job so the dispatcher's drain waits out the batch's callbacks
                // instead of letting the collector outlive the run it reports to.
                val collector = GateCollector(gateName, batch) {
                    // Recorded first, called back second. req.order is the rank of a response by
                    // arrival — 0 is the request the server answered first, which is the race
                    // outcome — and this loop reaches the exchanges in the order they were staged,
                    // which says nothing about the order they came back in. So the whole batch has
                    // to be in hand before a rank can be given to any of it, which also means a
                    // gate's callbacks fire together at the end rather than one at a time. That is
                    // what BurpRequestEngine already does with a gated batch, and a race cannot be
                    // acted on before it has resolved anyway.
                    val answered = ArrayList<Pair<Request, Boolean>>(exchanges.size)
                    exchanges.forEach { staged ->
                        val exchange = try {
                            staged.exchange.awaitResponse()
                        } catch (exception: Throwable) {
                            if (adaptive) recordTransportFailure(exception)
                            recordPermanentFailure(exception)
                            if (adaptive) activeRequests.decrementAndGet()
                            return@forEach
                        }
                        val interesting = try {
                            recordResponse(
                                staged.request,
                                exchange,
                                releaseStarted,
                                staged.connection.connectionId,
                            )
                        } catch (exception: Throwable) {
                            recordResponseProcessingFailure(exception)
                            if (adaptive) activeRequests.decrementAndGet()
                            return@forEach
                        }
                        answered.add(staged.request to interesting)
                    }
                    if (runState.get() >= 3 || Thread.currentThread().isInterrupted) {
                        if (adaptive) activeRequests.addAndGet(-answered.size)
                        return@GateCollector
                    }
                    answered.sortBy { it.first.ttfb }
                    reportIfGateDidNotHold(gateName, answered.map { it.first })
                    answered.forEachIndexed { rank, (request, interesting) ->
                        if (
                            runState.get() >= 3 ||
                            Thread.currentThread().isInterrupted ||
                            !gateCallbackAdmissions.tryEnter()
                        ) {
                            if (adaptive) activeRequests.addAndGet(-(answered.size - rank))
                            return@GateCollector
                        }
                        try {
                            request.order = rank
                            invokeCallback(request, interesting)
                        } finally {
                            gateCallbackAdmissions.exit()
                            if (adaptive) activeRequests.decrementAndGet()
                        }
                    }
                }
                activeJobs.incrementAndGet()
                if (gateCollectors.putIfAbsent(gateName, collector) != null) {
                    activeJobs.decrementAndGet()
                    throw IllegalStateException("Gate $gateName already has a response collector")
                }
                admissionTransferred = true
                try {
                    gateExecutor.execute(collector)
                } catch (startFailure: Throwable) {
                    collector.cancelBeforeStart()
                    throw startFailure
                }
            } catch (exception: Throwable) {
                batch.fail(exception)
                abandonStagedExchanges(batch, exception)
                if (adaptive) activeRequests.addAndGet(-batch.stagedExchanges().size)
                finishBatch(gateName, batch)
                throw exception
            }
        } finally {
            if (!admissionTransferred) {
                gateLifecycleAdmissions.exit()
                finishDeferredTerminalActions()
            }
        }
    }

    /**
     * Says so when a batch was answered before it was released, because the alternative is a run
     * that looks like a clean negative and tested nothing.
     *
     * A negative ttfb is unambiguous: it is measured from the release, so below zero means the
     * response was already on its way back. Exactly zero is left alone — that is a same-microsecond
     * arrival, which is suspicious but not evidence.
     */
    private fun reportIfGateDidNotHold(gateName: String, requests: List<Request>) {
        val early = requests.count { it.ttfb < 0 }
        if (early == 0) {
            return
        }
        gatesThatDidNotHold.incrementAndGet()
        Utils.out(
            "HTTP/3 gate $gateName did not hold: $early of ${requests.size} responses arrived " +
                "before the release, so the batch was never synchronised and a negative result " +
                "proves nothing. This server answers without reading the withheld bytes; try " +
                "gateMode='qpack', or a request with no body so the gate withholds header bytes " +
                "instead."
        )
    }

    /**
     * Counts every request that was staged but will never be released. Without this the requests
     * simply disappear: their responses are never awaited, so neither successfulRequests nor
     * permaFails ever accounts for them.
     */
    private fun abandonStagedExchanges(batch: SdaBatch, cause: Throwable) {
        batch.stagedExchanges().forEach { _ -> recordPermanentFailure(cause) }
    }

    private fun dispatchForever() {
        try {
            while (runState.get() == 0) {
                Thread.sleep(RUN_START_POLL_MILLIS)
            }
            while (runState.get() < 3) {
                val request = pollNextRequest()
                if (request != null) {
                    if (request.gate == null) {
                        dispatchOrdinary(request)
                    } else {
                        stageGated(request)
                    }
                    continue
                }
                if (runState.get() == 2 && activeJobs.get() == 0 && requestQueue.isEmpty()) {
                    return
                }
            }
        } finally {
            // Close admission before interrupting collectors. A collector already inside a
            // callback retains ownership of its batch until that callback exits; teardown only
            // fails its pending reads and leaves final settlement to the collector.
            gateCallbackAdmissions.close()
            gateExecutor.shutdownNow()
            batches.entries.toList().forEach { (gateName, batch) ->
                val cancellation = IOException("gate $gateName closed before its response arrived")
                batch.fail(cancellation)
                failStagedResponses(batch, cancellation)
            }
            gateCollectors.values.toList().forEach { collector ->
                collector.cancelBeforeStart()
            }
            batches.entries.toList().forEach { (gateName, batch) ->
                if (!gateCollectors.containsKey(gateName)) finishBatch(gateName, batch)
            }
            // Closed under the monitor every publication into the pool checks, so a connection
            // still opening is either in the pool's final sweep or closes its own session.
            pool.close()
            awaitRequestsInFlight()
            gateConnections.forceCloseUnsettledGateConnections()
            // Safe after the drain above: dispatchSlots caps submissions at the pool size, so
            // every task that was handed to the executor already has a thread and none are sitting
            // in its queue waiting for one that shutdown would take away. Anything the drain gave
            // up on is interrupted here, which is what finally releases a parked reader.
            requestExecutor.shutdownNow()
            completedLatch.countDown()
        }
    }

    /**
     * Waits for the requests still in flight to finish, and gives up on them rather than waiting
     * for ever.
     *
     * <p>A response that never arrives leaves its reader parked inside Kwik, and closing the
     * connection does not reliably release it. The deadline watchdog cannot help either: it stops
     * the moment the run leaves state 1..2, which a cancelled run does before this drain begins.
     * So an unbounded wait here spins for the life of the JVM on a thread that is a GC root for
     * the whole engine - its queue, its connection pool, and every request those still reach.
     * Measured in Burp, seven of these accumulated over one session and runs that began at 11.5s
     * were taking 22-40s by the end of it.
     *
     * <p>Whatever is still running when the deadline passes is left to [requestExecutor]'s
     * shutdownNow(), which interrupts it.
     */
    private fun awaitRequestsInFlight() {
        val deadline = System.nanoTime() + DRAIN_WAIT_NANOS
        while (activeJobs.get() > 0 && System.nanoTime() - deadline < 0) {
            Thread.sleep(DRAIN_POLL_MILLIS)
        }
    }

    private fun pollNextRequest(): Request? {
        // Only walk the queue looking for a gated request when one may be in it.
        // LinkedBlockingQueue's iterator takes both queue locks once per element, so an
        // unconditional scan costs O(queue depth) per dispatch, and a non-streaming run gets an
        // unbounded queue. Measured on a 50k-deep queue that is 273us per request, which caps the
        // engine at under 4k rps before a single packet is sent.
        if (gatesInUse()) {
            val gated = requestQueue.firstOrNull { it.gate != null }
            if (gated != null && requestQueue.remove(gated)) {
                return gated
            }
        }
        // Untimed poll first. The dispatcher runs this once per request, and a timed poll arms a
        // timeout even when the queue already has work, which at full rate is pure overhead on the
        // one thread every request passes through.
        return requestQueue.poll() ?: requestQueue.poll(QUEUE_POLL_MILLIS, TimeUnit.MILLISECONDS)
    }

    /**
     * Whether a gated request may still be waiting in the queue; see [gatedRequestMayBeQueued].
     * Asking whether any gate had ever been registered kept the walk running for the rest of the
     * run after the first gate, because [floodgates] is only cleared at teardown.
     *
     * <p>Read without the floodgates monitor on purpose: openGate() holds that monitor while it
     * waits for this very thread to finish staging.
     */
    private fun gatesInUse(): Boolean = gatedRequestMayBeQueued(
        activeGateLifecycleCount(),
        batches.keys,
    ) { gateName -> floodgates[gateName]?.remaining?.get() ?: 0 }

    private fun dispatchOrdinary(request: Request) {
        // Taken on the dispatcher thread, before the request gets a thread of its own, so that a
        // backlog waits in the bounded queue rather than as an unbounded pile of request threads
        // all polling poolLock for the same connection. Without this, concurrentConnections capped
        // the pool but not the dispatch rate: every queued request got a thread immediately, and
        // once the pool was saturated their 50ms poll loops spent the run contending on one
        // monitor instead of sending. ThreadedRequestEngine bounds the same way, by owning exactly
        // `threads` workers and having them pull from the queue themselves.
        if (!acquireDispatchSlot()) {
            return
        }
        activeJobs.incrementAndGet()
        if (adaptive) activeRequests.incrementAndGet()
        requestExecutor.execute {
            try {
                validateRequestOptions(request)
                val translated = translate(request)
                var attempt = 0
                while (runState.get() < 3) {
                    var connection: Http3ConnectionPool.OrdinaryConnection? = null
                    try {
                        connection = pool.acquireOrdinaryConnection()
                        // Stamped once the connection is in hand. A connection carries one request
                        // at a time, so a request can wait for a free one, and charging that wait
                        // to the response would overstate every latency the run reports.
                        val startedAt = System.nanoTime()
                        request.sent = startedAt
                        val response = connection.session.send(translated)
                        val connectionId = connection.id
                        pool.releaseOrdinaryConnection(connection, failed = false)
                        connection = null
                        try {
                            completeResponse(request, response, startedAt, connectionId)
                        } catch (exception: Throwable) {
                            recordResponseProcessingFailure(exception)
                        }
                        return@execute
                    } catch (exception: Throwable) {
                        connection?.let { pool.releaseOrdinaryConnection(it, failed = true) }
                        if (adaptive && runState.get() < 3) recordTransportFailure(exception)
                        if (runState.get() < 3 && attempt < maxRetriesPerRequest) {
                            attempt += 1
                            retries.incrementAndGet()
                            continue
                        }
                        recordPermanentFailure(exception)
                        return@execute
                    }
                }
            } catch (exception: Throwable) {
                recordPermanentFailure(exception)
            } finally {
                if (adaptive) activeRequests.decrementAndGet()
                activeJobs.decrementAndGet()
                dispatchSlots.release()
                pool.wakePoolWaiter()
            }
        }
    }

    /**
     * Waits for a dispatch slot, giving up if the run is cancelled while waiting. Polled rather
     * than blocked on outright so that a cancelled run does not leave the dispatcher parked on a
     * semaphore nothing will ever release.
     */
    private fun acquireDispatchSlot(): Boolean {
        // Same reasoning as the queue poll: when the pool has capacity, which is the common case
        // while a run is ramping, the untimed acquire avoids arming a timer per request.
        if (dispatchSlots.tryAcquire()) {
            return true
        }
        while (runState.get() < 3) {
            if (dispatchSlots.tryAcquire(DISPATCH_POLL_MILLIS, TimeUnit.MILLISECONDS)) {
                return true
            }
        }
        return false
    }

    private fun stageGated(request: Request) {
        val gate = request.gate ?: return
        var batch: SdaBatch? = null
        if (adaptive) activeRequests.incrementAndGet()
        try {
            // Opened outside any lock on batches; see Http3GateConnections.openBatch.
            batch = batches[gate.name] ?: gateConnections.openBatch(gate.name).also { batches[gate.name] = it }
            batch.throwIfFailed()
            validateRequestOptions(request)
            // The connection this gate claimed. Every bound a stage is charged against belongs
            // to it, so the batch is bounded by that one connection and nothing else.
            val connection = batch.requireConnection()
            val session = connection.session!!
            val translated = translate(request)
            val exchange = if (batch.mode == GateMode.QPACK) {
                // Reserved before the request is written, not counted after: by then the stream
                // exists and the peer's blocked-stream allowance has already been overrun.
                connection.reserveBlockedStream()
                adaptiveTransportAttempt { session.stageBlocked(translated) }
            } else {
                // Reserved after the stage rather than before it, because what a request costs the
                // release is its stream frame, and the stream ID and offset that size it are only
                // settled once the stream exists. Charging it here still stops the rest of the
                // batch reaching a target that will never see a release.
                adaptiveTransportAttempt { session.stage(translated, options.finalBytes) }
                    .also { connection.reserveReleaseBytes(it.fragment) }
            }
            batch.add(request, exchange)
        } catch (exception: Throwable) {
            batch?.fail(exception)
            lastError = exception.toString()
            permaFails.incrementAndGet()
            if (adaptive) activeRequests.decrementAndGet()
        } finally {
            gate.reportReadyWithoutWaiting()
        }
    }

    private fun validateRequestOptions(request: Request) {
        request.endpointOverride?.let {
            throw IllegalArgumentException("endpoint override is not supported by Engine.HTTP3")
        }
        request.connectionId?.let {
            throw IllegalArgumentException("connectionId is not supported by Engine.HTTP3")
        }
    }

    private fun translate(request: Request) = TurboHttp3RequestTranslator.translate(
        request.getRequest(),
        "https",
        authority(target),
        request.kettled,
    )

    private fun completeResponse(
        request: Request,
        exchange: H3Exchange,
        startedAt: Long,
        connectionId: String?,
    ) {
        invokeCallback(request, recordResponse(request, exchange, startedAt, connectionId))
    }

    /**
     * Fills in everything a finished response tells us and returns whether it is interesting,
     * without invoking the callback. Split out so a gate can rank its whole batch by arrival
     * before any callback runs.
     */
    private fun recordResponse(
        request: Request,
        exchange: H3Exchange,
        startedAt: Long,
        connectionId: String?,
    ): Boolean {
        // Stamped when the response was actually read, not when this loop reached it: a gate
        // drains its staged exchanges in order, so reading the clock here would charge a slow
        // response to every response queued behind it.
        val lastByteAt = exchange.lastByteNanos
        // A response with no bytes at all never stamps an arrival, so fall back to the completion.
        val firstByteAt = exchange.firstByteNanos
            .takeIf { it != FirstByteTimingInputStream.UNREAD } ?: lastByteAt
        val elapsedMicros = (lastByteAt - startedAt) / 1_000
        request.ttfb = (firstByteAt - startedAt) / 1_000
        request.ttlb = elapsedMicros
        request.time = elapsedMicros
        request.arrival = (lastByteAt - start) / 1_000
        request.connectionId = connectionId
        request.response = exchange.response.toString(Charsets.ISO_8859_1)
        successfulRequests.incrementAndGet()
        return processResponse(request, exchange.response)
    }

    private fun finishBatch(gateName: String, batch: SdaBatch) {
        if (!batches.remove(gateName, batch)) {
            return
        }
        // Cancellation reaches here while a gate collector is parked in awaitResponse(), and
        // closing the connection does not reliably release that read. Fail the unanswered reads
        // so the collector winds down inside the drain rather than outliving the run. On the
        // normal path the collector calls this after every exchange has answered, and failing an
        // already-completed read is a no-op.
        failStagedResponses(batch, IOException("gate $gateName closed before its response arrived"))
        try {
            batch.connection?.let { connection -> gateConnections.finishConnection(batch, connection) }
        } finally {
            finishGateLifecycle(gateName)
        }
    }

    private fun failStagedResponses(batch: SdaBatch, cause: Throwable) {
        batch.stagedExchanges().forEach { it.exchange.fail(cause) }
    }

    /** One managed gate response collector, with exactly one path that settles its batch. */
    private inner class GateCollector(
        private val gateName: String,
        private val batch: SdaBatch,
        private val collect: GateCollector.() -> Unit,
    ) : Runnable {
        private val state = AtomicInteger(COLLECTOR_PENDING)

        override fun run() {
            if (!state.compareAndSet(COLLECTOR_PENDING, COLLECTOR_RUNNING)) return
            try {
                collect()
            } finally {
                settle()
            }
        }

        fun cancelBeforeStart(): Boolean {
            if (!state.compareAndSet(COLLECTOR_PENDING, COLLECTOR_SETTLED)) return false
            settleResources()
            return true
        }

        private fun settle() {
            state.set(COLLECTOR_SETTLED)
            settleResources()
        }

        private fun settleResources() {
            gateCollectors.remove(gateName, this)
            try {
                finishBatch(gateName, batch)
            } finally {
                activeJobs.decrementAndGet()
                gateLifecycleAdmissions.exit()
                finishDeferredTerminalActions()
            }
        }
    }

    override fun runTerminalFinalizer(finalizer: () -> Unit) {
        if (!deferredTerminalFinalizer.compareAndSet(null, finalizer)) return
        finishDeferredTerminalActions()
    }

    override fun cleanup() {
        cleanupRequested.set(true)
        finishDeferredTerminalActions()
    }

    private fun finishDeferredTerminalActions() {
        if (gateLifecycleAdmissions.activeCount() != 0L) return
        synchronized(terminalActionsLock) {
            if (gateLifecycleAdmissions.activeCount() != 0L) return
            try {
                deferredTerminalFinalizer.getAndSet(null)?.invoke()
            } finally {
                if (cleanupRequested.get() && cleanupCompleted.compareAndSet(false, true)) super.cleanup()
            }
        }
    }

    /**
     * Names the missing HTTP/3 support when the transport never got off the ground.
     *
     * <p>This engine speaks only QUIC, so a run that finished with no connection ever opened got
     * no handshake through at all, and that is a different diagnosis from requests failing on a
     * connection that did open. [connections] is the one thing that separates them: it is
     * incremented only once [H3ConnectionFactory.open] has returned a session. Once it has moved,
     * the handshake demonstrably worked and the generic wording is the honest one.
     *
     * <p>What the handshake failed on is left to the underlying error rather than guessed at. A
     * host with no HTTP/3, a wrong port and a firewall dropping UDP all look the same from here,
     * whereas a rejected certificate says so in the error text.
     */
    override fun failureSummary(): String? {
        if (connections.get() == 0 && opener.openFailures.get() > 0) {
            return "No HTTP/3 connection to ${authority(target)} was established: every QUIC handshake " +
                "failed, and Engine.HTTP3 has no fallback to HTTP/2 or HTTP/1.1. Last error: $lastError"
        }
        return super.failureSummary()
    }

    private fun recordPermanentFailure(exception: Throwable) {
        lastError = exception.toString()
        permaFails.incrementAndGet()
    }

    /** Counts one failed external transport call before its caller evaluates the failed batch. */
    private inline fun <T> adaptiveTransportAttempt(attempt: () -> T): T = try {
        attempt()
    } catch (exception: Throwable) {
        if (adaptive) recordTransportFailure(exception)
        throw exception
    }

    companion object {
        private const val COLLECTOR_PENDING = 0
        private const val COLLECTOR_RUNNING = 1
        private const val COLLECTOR_SETTLED = 2

        /** Matches QuicConfig's handshake timeout: no point giving up before the transport does. */
        /**
         * How long a QUIC handshake is given before the transport abandons it, and so the longest
         * an opening connection can take to report either way.
         */
        internal const val HANDSHAKE_TIMEOUT_SECONDS = 10L

        /**
         * How long [Http3ConnectionPool.openInitialConnections] waits for the opening connections
         * to report.
         *
         * <p>Strictly longer than [HANDSHAKE_TIMEOUT_SECONDS], because a wait that expires at the
         * same moment as the handshakes it is waiting on learns nothing from them. Both were 10s,
         * and against a host with no HTTP/3 the wait lost the race every time: the run read zero
         * connections and zero failures and carried on as though the pool were still filling,
         * instead of stopping the way Engine.HTTP2 does.
         */
        internal const val HANDSHAKE_WAIT_SECONDS = HANDSHAKE_TIMEOUT_SECONDS + 2

        private const val RUN_START_POLL_MILLIS = 10L

        /**
         * How long the dispatcher waits for in-flight requests once the run is over. Long enough
         * that a request released by its connection closing is counted normally, short enough that
         * one that never comes back does not keep the engine reachable.
         */
        private val DRAIN_WAIT_NANOS = TimeUnit.SECONDS.toNanos(2)

        private const val DRAIN_POLL_MILLIS = 10L

        private const val IDLE_POLL_MILLIS = 100L

        /**
         * How often response reads are checked against their deadlines. The deadline itself is
         * tens of seconds, so this only has to be fine enough that a failed request is not left
         * holding its thread noticeably longer than that.
         */
        private const val RESPONSE_SWEEP_MILLIS = 250L

        private const val DISPATCH_POLL_MILLIS = 50L

        /** How long the dispatcher blocks for work once the queue has been found empty. */
        private const val QUEUE_POLL_MILLIS = 50L

        /**
         * Requests a single QUIC connection carries at once, and with `concurrentConnections` the
         * other half of what puts requests in flight.
         *
         * The peer advertises its own limit in `initial_max_streams_bidi` and Kwik blocks on that,
         * so asking for more than a server allows costs nothing but a parked thread. 100 was
         * inherited from HTTP2RequestEngine, where it is HTTP/2's protocol default rather than a
         * measured optimum. Against a real HTTP/3 server, on a 1,000,000 request fuzz: 100 streams
         * took 14s, 256 took 13s, and 512 collapsed into loss and retransmission. Raising it is
         * subject to the same cliff as raising connections, so this is the last point measured
         * stable rather than a number to keep climbing.
         */
        const val DEFAULT_MAX_CONCURRENT_STREAMS = 256

        const val DEFAULT_ADAPTIVE_CONNECTIONS = 10

        /**
         * Ceiling on requests in flight when each one holds an OS thread. Without it the configured
         * connections x streams product goes straight to the OS: an 800-connection run asks for
         * 80,000 threads, and a Burp with other work in flight died with "OutOfMemoryError: unable
         * to create native thread" before the engine could start its dispatcher.
         */
        const val MAX_REQUESTS_IN_FLIGHT_PLATFORM = 4096

        /**
         * Ceiling on requests in flight when the threads are virtual. Those cost heap rather than
         * OS threads, so the bound is only there to stop a runaway configuration exhausting memory,
         * and it can sit far higher. Measured in Burp on Java 26: the platform bound was throttling
         * the run, with 41 to 96 connections all flatlining at ~90k rps because each clamped to
         * 4096 in flight.
         */
        const val MAX_REQUESTS_IN_FLIGHT_VIRTUAL = 65536

        /** The in-flight ceiling appropriate to the kind of thread carrying each request. */
        @JvmStatic
        fun maxRequestsInFlight(virtualThreads: Boolean): Int =
            if (virtualThreads) MAX_REQUESTS_IN_FLIGHT_VIRTUAL else MAX_REQUESTS_IN_FLIGHT_PLATFORM

        /** Whether [jdkFeatureVersion] carries blocked virtual threads without pinning a carrier. */
        @JvmStatic
        fun prefersVirtualThreads(jdkFeatureVersion: Int): Boolean =
            KwikThreads.prefersVirtualThreads(jdkFeatureVersion)

        private fun authority(target: URL): String {
            val port = getEffectivePort(target)
            return if (port == 443) target.host else "${target.host}:$port"
        }

        private fun defaultConnectionFactory(idleTimeout: Long): H3ConnectionFactory =
            H3ConnectionFactory { target, verifyCertificates ->
                val config = QuicConfig(
                    Duration.ofSeconds(HANDSHAKE_TIMEOUT_SECONDS),
                    if (idleTimeout > 0) Duration.ofMillis(idleTimeout) else Duration.ofSeconds(30),
                    verifyCertificates,
                )
                H3Connection.open(
                    ControlledKwikQuicTransport.connect(
                        target.host,
                        getEffectivePort(target),
                        config,
                    ),
                )
            }
    }
}
