package io.bitbytelab.raijin.turbo

import io.bitbytelab.raijin.turbo.hp3.quic.KwikThreads
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * A thread for work that blocks inside Kwik: a handshake, or a response read. Virtual where the JVM
 * carries a blocked virtual thread without pinning a carrier, platform daemon where it does not; see
 * [KwikThreads].
 */
internal fun kwikBlockingThread(name: String): Thread.Builder = KwikThreads.blockingThread(name)

/**
 * Carries an HTTP/3 run's ungated requests, one thread per request in flight.
 *
 * Which kind of thread depends on the JVM. Kwik reads a response inside
 * `synchronized (addMonitor)` (`tech.kwik.core.stream.StreamInputStreamImpl`). Before JDK 24 a
 * virtual thread that blocks inside a synchronized block pins its carrier without the scheduler
 * compensating, so an in-flight request cost a whole carrier anyway and the run was capped at a
 * pool size only a JVM option can raise — measured on 18 cores, a run configured for 800
 * requests in flight carried 18. There, pooled platform threads are strictly better.
 *
 * JEP 491 removed that pinning in JDK 24, and Burp ships a JRE well past it, so in the case
 * that matters most the threads can be virtual: a run holding 1200 requests costs 1200 cheap
 * virtual threads instead of 1200 OS threads for the scheduler to move around.
 *
 * The platform pool is fixed rather than one thread per request because starting an OS thread
 * costs tens of microseconds and the single dispatcher pays it per request. Either way the
 * engine's dispatch slots bound submissions to its requests-in-flight limit, so neither executor
 * queues work behind a busy thread.
 *
 * @param platformThreads the size of the fixed pool, where the threads are platform threads
 */
internal fun newHttp3RequestExecutor(virtualThreads: Boolean, platformThreads: Int): ExecutorService {
    if (virtualThreads) {
        // Unnamed on purpose. A named virtual thread factory formats a fresh name string
        // for every request on the hot path.
        return Executors.newThreadPerTaskExecutor(Thread.ofVirtual().factory())
    }
    // Names request threads in creation order, so a stack dump is readable.
    val requestThreads = AtomicInteger()
    return Executors.newFixedThreadPool(platformThreads) { runnable ->
        Thread.ofPlatform()
            .daemon()
            .name("http3-request-${requestThreads.incrementAndGet()}")
            .unstarted(runnable)
    }
}

/**
 * Carries an HTTP/3 run's gate collectors. They must not queue behind ordinary requests: on
 * platform-thread JVMs every request-pool thread can be parked waiting for a connection held by a
 * gate. A separately managed executor preserves that independent capacity while still giving
 * teardown one owner that can interrupt and account for every collector.
 */
internal fun newHttp3GateExecutor(): ExecutorService {
    // Names managed gate collectors and keeps them independent of the ordinary request pool.
    val gateThreads = AtomicInteger()
    return Executors.newThreadPerTaskExecutor { runnable ->
        kwikBlockingThread("http3-gate-${gateThreads.incrementAndGet()}").unstarted(runnable)
    }
}

internal fun interface Http3AdaptiveTaskStarter {
    fun start(name: String, task: () -> Unit)
}

internal object Http3AdaptiveTaskStarterConstructionContext {
    private val currentStarter = ThreadLocal<Http3AdaptiveTaskStarter?>()

    fun current(): Http3AdaptiveTaskStarter? = currentStarter.get()

    fun <T> withStarter(starter: Http3AdaptiveTaskStarter?, construct: () -> T): T {
        currentStarter.set(starter)
        return try {
            construct()
        } finally {
            currentStarter.remove()
        }
    }
}

internal inline fun tryAcquireAdaptiveTaskSlot(
    isRunning: () -> Boolean,
    acquire: () -> Boolean,
    release: () -> Unit,
): Boolean {
    if (!isRunning() || !acquire()) return false
    if (isRunning()) return true
    release()
    return false
}

/**
 * Whether a gated request may still be waiting in the dispatch queue, which is the only time
 * walking the queue for one is worth O(queue depth).
 *
 * <p>RequestEngine.queue() opens a gate's lifecycle and counts the request into the gate's
 * `remaining` before the request reaches the queue, and staging counts it back out, so a queued
 * gated request is always visible here first. A gate gets its batch when its first request is
 * staged and keeps it until its lifecycle ends. So an active gate without a batch still has its
 * requests queued, and one with a batch has requests queued exactly while some are unstaged.
 * Checking only the gates in [batchedGates] keeps the cost at the number of gates in flight rather
 * than every gate the run has ever registered.
 *
 * @param activeGateLifecycles gates queued and not yet finished
 * @param batchedGates names of the gates whose batch is open
 * @param unstagedRequests the requests a gate has queued and not yet staged
 */
internal inline fun gatedRequestMayBeQueued(
    activeGateLifecycles: Int,
    batchedGates: Collection<String>,
    unstagedRequests: (String) -> Int,
): Boolean {
    if (activeGateLifecycles == 0) return false
    if (activeGateLifecycles > batchedGates.size) return true
    return batchedGates.any { gateName -> unstagedRequests(gateName) > 0 }
}

/**
 * Atomically orders callback admission against terminal teardown. A callback that owns a token
 * was admitted before close; after close, no check-then-act window can admit another one.
 */
internal class GateCallbackAdmissions {
    private val state = AtomicLong(0)

    fun tryEnter(): Boolean {
        while (true) {
            val current = state.get()
            if (current < 0) return false
            check(current < Long.MAX_VALUE) { "too many active gate callbacks" }
            if (state.compareAndSet(current, current + 1)) return true
        }
    }

    fun exit() {
        while (true) {
            val current = state.get()
            val active = current and Long.MAX_VALUE
            check(active > 0) { "gate callback admission released without an owner" }
            if (state.compareAndSet(current, current - 1)) return
        }
    }

    fun close() {
        while (true) {
            val current = state.get()
            if (current < 0 || state.compareAndSet(current, current or Long.MIN_VALUE)) return
        }
    }

    fun activeCount(): Long = state.get() and Long.MAX_VALUE
}

/**
 * A bound an HTTP/3 run takes slots from: its connections, or its requests in flight. A fixed run
 * holds an unfair [Semaphore]; an adaptive run a [ResizableLimit] its controller moves while the
 * run is live. Chosen once, when the engine is built.
 */
internal class Http3SlotLimit private constructor(
    private val fixed: Semaphore?,
    private val resizable: ResizableLimit?,
    /** Ends an adaptive timed wait early; a fixed wait just runs out its timeout. */
    private val cancelled: () -> Boolean,
) {
    /** The live limit and how much of it is held, or null for a fixed bound, which never moves. */
    fun snapshot(): LimitSnapshot? = resizable?.snapshot()

    fun tryAcquire(): Boolean = resizable?.tryAcquire() ?: requireNotNull(fixed).tryAcquire()

    fun tryAcquire(timeout: Long, unit: TimeUnit): Boolean =
        resizable?.tryAcquire(timeout, unit, cancelled) ?: requireNotNull(fixed).tryAcquire(timeout, unit)

    fun release() {
        resizable?.release() ?: requireNotNull(fixed).release()
    }

    /** Moves an adaptive bound; a fixed one has no live limit to move. */
    fun resize(newLimit: Int) {
        requireNotNull(resizable).resize(newLimit)
    }

    companion object {
        /**
         * Unfair. A fair semaphore routes every acquire through the AQS wait queue even when a
         * permit is free; neither fixed limit needs FIFO ordering to be correct.
         */
        fun fixed(permits: Int): Http3SlotLimit = Http3SlotLimit(Semaphore(permits), null) { false }

        /** A bound the adaptive controller resizes, whose timed waits give up once [cancelled]. */
        fun resizable(initialLimit: Int, cancelled: () -> Boolean): Http3SlotLimit =
            Http3SlotLimit(null, ResizableLimit(initialLimit), cancelled)
    }
}
