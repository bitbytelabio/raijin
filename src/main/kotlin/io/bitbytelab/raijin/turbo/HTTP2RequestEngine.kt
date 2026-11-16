package io.bitbytelab.raijin.turbo
import java.net.URL
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * Turbo's own HTTP/2 client. A manager thread owns [threads] connection slots: it opens and
 * replaces connections, hands what a dead connection left in flight back for retry, retires a slot
 * whose connections never get past the handshake, and counts the completion latch down exactly once,
 * when the run is cancelled or nothing is queued or in flight on any connection.
 */
open class HTTP2RequestEngine internal constructor(
    url: String,
    val threads: Int,
    maxQueueSize: Int,
    var requestsPerConnection: Int,
    override val maxRetriesPerRequest: Int,
    override var idleTimeout: Long,
    override val callback: (Request, Boolean) -> Boolean,
    override var readCallback: ((String) -> Boolean)?,
    /** Bounds every network wait on a connection: TCP connect, TLS handshake, the server's SETTINGS, and responses in flight. */
    internal val socketTimeoutMillis: Int,
) : RequestEngine() {

    constructor(url: String, threads: Int, maxQueueSize: Int, requestsPerConnection: Int, maxRetriesPerRequest: Int, idleTimeout: Long = 0, callback: (Request, Boolean) -> Boolean, readCallback: ((String) -> Boolean)?) :
        this(url, threads, maxQueueSize, requestsPerConnection, maxRetriesPerRequest, idleTimeout, callback, readCallback, DEFAULT_SOCKET_TIMEOUT_MILLIS)

    private companion object {
        const val DEFAULT_SOCKET_TIMEOUT_MILLIS = 10_000
        const val MANAGE_POLL_MILLIS = 10L
        const val IDLE_POLL_MILLIS = 50L
        /** How long teardown waits for connection threads, so callbacks finish before the latch opens. */
        const val TEARDOWN_WAIT_MILLIS = 10_000L
    }

    private val slots = arrayOfNulls<H2Connection>(threads)
    private val slotFailures = IntArray(threads)
    private val slotRetired = BooleanArray(threads)

    /** A slot whose connections fail this many times running, without ever being established, is retired. */
    private val maxConnectAttempts = maxRetriesPerRequest.coerceAtLeast(0) + 1

    /** Requests a connection handed back - never sent, or in flight when it died and due a retry. Taken before new work. */
    private val orphans = ConcurrentLinkedQueue<Request>()
    private var reportedUnreachable = false

    init {
        requestQueue = if (maxQueueSize > 0) {
            LinkedBlockingQueue(maxQueueSize)
        }
        else {
            LinkedBlockingQueue()
        }

        target = URL(url)
        completedLatch = CountDownLatch(1)

        thread(name = "turbo-h2-manager-${target.host}", isDaemon = true, priority = 1) {
            manageConnections()
        }
    }

    private fun manageConnections() {
        H2Connection.debug("Connection management thread starting")
        try {
            while (runState.get() < 3 && !Utils.unloaded) {
                for (slot in slots.indices) {
                    tend(slot)
                }
                if (slotRetired.all { it }) {
                    abandonUnsendable()
                }
                if (runFinished()) {
                    break
                }
                Thread.sleep(MANAGE_POLL_MILLIS)
            }
        } catch (e: Throwable) {
            Utils.err("HTTP/2 connection management failed: $e")
            recordTransportFailure(e)
        } finally {
            closeAll()
            completedLatch.countDown()
            H2Connection.debug("Connection management thread exiting")
        }
    }

    /**
     * Fully queued, and no connection, orphan or queue holds a request. A slot is only emptied once
     * its connection's threads have exited, after its last callback, so whatever a callback queued
     * is already visible here.
     */
    private fun runFinished(): Boolean =
        runState.get() == 2 && slots.all { it == null } && hasNoQueuedWork()

    private fun tend(slot: Int) {
        val con = slots[slot]
        if (con != null) {
            if (!con.isFinished()) {
                // A connection still waiting for SETTINGS at the end of the run has nothing to do.
                if (!con.established && runState.get() == 2 && hasNoQueuedWork()) {
                    con.close()
                }
                return
            }
            slots[slot] = null
            recover(con)
            if (con.established) {
                slotFailures[slot] = 0
            } else if (con.failure != null) {
                slotFailures[slot] += 1
            }
        }

        if (slotRetired[slot]) {
            return
        }
        if (slotFailures[slot] >= maxConnectAttempts) {
            slotRetired[slot] = true
            return
        }
        // Keep the pool warm while the script is still queueing; after that, only for work.
        if (runState.get() < 2 || !hasNoQueuedWork()) {
            connections.incrementAndGet()
            slots[slot] = H2Connection(target, requestsPerConnection, this)
        }
    }

    /** Hands back what a finished connection left in flight, each request charged one retry. */
    private fun recover(con: H2Connection) {
        val inflight = con.getInflightRequests()
        val failure = con.failure
        if (failure != null && (inflight.isNotEmpty() || !con.established)) {
            recordTransportFailure(failure)
        }
        if (inflight.isEmpty()) {
            return
        }

        var requeued = 0
        for (req in inflight) {
            if (shouldRetry(req)) {
                orphans.add(req)
                requeued++
            }
        }
        Utils.out("Connection died, re-queueing $requeued of ${inflight.size} unanswered requests.")
    }

    /**
     * Every slot is retired, so nothing can be sent: fail what is queued, and whatever is queued
     * later, rather than leave it waiting for ever and queue() blocking on a full queue.
     */
    private fun abandonUnsendable() {
        var dropped = 0
        while (true) {
            orphans.poll() ?: requestQueue.poll() ?: break
            dropped++
        }
        permaFails.addAndGet(dropped)
        if (!reportedUnreachable) {
            reportedUnreachable = true
            Utils.out("No HTTP/2 connection to $target got past the handshake in $maxConnectAttempts attempt(s) per connection, so queued requests fail: $lastError")
        }
    }

    private fun closeAll() {
        val live = slots.filterNotNull()
        live.forEach { it.close() }
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(TEARDOWN_WAIT_MILLIS)
        live.forEach { it.awaitExit(deadline) }
    }

    /**
     * The next request for a connection's writer: one handed back first, then new work. Read from
     * [requestQueue] each time rather than a reference taken at startup, because queue() replaces
     * that queue when a non-streaming run outgrows it.
     */
    internal fun nextRequest(pollMillis: Long): Request? =
        orphans.poll() ?: requestQueue.poll(pollMillis, TimeUnit.MILLISECONDS)

    internal fun hasNoQueuedWork(): Boolean = orphans.isEmpty() && requestQueue.isEmpty()

    /** Takes back a request a connection took but never sent. */
    internal fun requeue(req: Request) {
        orphans.add(req)
    }

    override fun start(timeout: Int) {
        runState.set(1)
        start = System.nanoTime()
        updateLastLife()
        startIdleTimeoutWatchdog()
    }

    /**
     * Cancels the run once nothing has happened for [idleTimeout] milliseconds. On its own thread:
     * cancel() waits for the completion latch, which the manager thread counts down.
     */
    private fun startIdleTimeoutWatchdog() {
        if (idleTimeout <= 0) {
            return
        }
        thread(name = "turbo-h2-idle-watchdog", isDaemon = true) {
            while (runState.get() in 1..2) {
                if (shouldAbandonRun()) {
                    return@thread
                }
                Thread.sleep(IDLE_POLL_MILLIS)
            }
        }
    }

    override fun buildRequest(template: String, payloads: List<String?>, learnBoring: Int?, label: String): Request {
        return Request(template, payloads, learnBoring?: 0, label)
    }

    override fun cleanup() {
        super.cleanup()
        orphans.clear()
    }
}
