package io.bitbytelab.raijin.turbo

import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * The worker threads of an engine that gives every connection a blocking thread of its own,
 * [ThreadedRequestEngine] and [BurpRequestEngine]. A fixed pool keeps [initialSize] workers for the
 * whole run; an adaptive one (AUTO) keeps as many as the adaptive controller last asked for, in a
 * [DynamicWorkerRegistry].
 *
 * Every worker runs [work] with its registry handle, null in a fixed pool, and must return from it
 * once [shouldRetire] picks it to leave a shrinking pool. Its exit is what completes the run: a
 * fixed worker counts down the engine's [RequestEngine.completedLatch], an adaptive one leaves the
 * registry, and [awaitCompletion] waits on whichever of the two applies.
 */
internal class AdaptiveWorkerLifecycle(
    private val engine: RequestEngine,
    private val adaptive: Boolean,
    private val initialSize: Int,
    private val work: (DynamicWorkerRegistry.Handle?) -> Unit,
) {
    private val workerThreads = Collections.synchronizedList(ArrayList<Thread>())
    private val registry = DynamicWorkerRegistry()
    /** What a test starts in place of a worker thread, if the engine is built under one. */
    private val starter = AdaptiveWorkerStarterConstructionContext.current()
    /**
     * Holds adaptive workers until the first pool is complete, so that none works for an engine
     * whose construction then fails, and, when the engine asks, none works before all of them run.
     */
    private val released = CountDownLatch(if (adaptive) 1 else 0)
    private val startAdaptive: (DynamicWorkerRegistry.Handle) -> Unit = { handle ->
        if (starter != null) starter.start(handle) else launch(handle)
    }

    /**
     * Starts the first workers, throwing when one cannot be started: the engine's construction
     * fails, and [abortStart] undoes the rest. With [awaitRunning] an adaptive pool returns only
     * once every one of them runs, so that [liveSize] counts all of them from the start.
     */
    fun startInitial(awaitRunning: Boolean) {
        if (!adaptive) {
            repeat(initialSize) { launch(null) }
            return
        }
        registry.resizeTo(initialSize, startAdaptive)
        if (awaitRunning) registry.awaitLiveSize(initialSize)
        released.countDown()
    }

    /**
     * Undoes the start of an engine whose construction is failing. The run is cancelled before the
     * workers held for the first pool are let go, so each of them leaves at once instead of taking
     * a request, and every worker already started is interrupted.
     */
    fun abortStart() {
        engine.runState.set(3)
        registry.abort()
        released.countDown()
        val started = synchronized(workerThreads) {
            workerThreads.toList().also { workerThreads.clear() }
        }
        started.forEach(Thread::interrupt)
    }

    /** Whether the worker holding [handle] is one a shrinking pool picked to leave; never in a fixed pool. */
    fun shouldRetire(handle: DynamicWorkerRegistry.Handle?): Boolean =
        handle != null && registry.claimRetirement(handle)

    /**
     * Moves an adaptive pool to [newLimit] workers: shrinking retires the newest, growing starts
     * more. A worker that cannot be started, for want of memory for another thread say, counts as
     * a transport failure, which the controller backs off from; anything worse is thrown.
     */
    fun resize(newLimit: Int) {
        require(newLimit > 0) { "Adaptive worker count must be positive" }
        registry.resizeTo(target = newLimit, start = startAdaptive, onStartFailure = ::recordStartFailure)
    }

    /** The size the pool is heading for: what the controller last asked for, or the fixed size. */
    fun targetSize(): Int = if (adaptive) registry.desiredSize() else initialSize

    /** Workers that run and are not retiring: how many gated requests the pool can hold at once. */
    fun liveSize(): Int = if (adaptive) registry.liveSize() else initialSize

    /** Whether the pool has settled at its target size, so that throughput measured now is that size's. */
    fun converged(): Boolean = !adaptive || registry.isConverged()

    /** Waits up to [timeout] for the adaptive pool to hold [target] workers; returns how many it holds. */
    fun awaitWorkerCount(target: Int, timeout: Long, unit: TimeUnit): Int {
        require(adaptive)
        registry.awaitCount(target, timeout, unit)
        return registry.size()
    }

    /**
     * Waits up to [timeout] for every worker to exit. An adaptive pool is then sealed, so that no
     * later resize starts another.
     */
    fun awaitCompletion(timeout: Long, unit: TimeUnit): Boolean =
        if (adaptive) registry.awaitEmptyAndSeal(timeout, unit) else engine.completedLatch.await(timeout, unit)

    /** Stops an adaptive pool from growing again, as the run ends; a fixed pool never grows. */
    fun sealCompletion() {
        if (adaptive) registry.seal()
    }

    /**
     * Interrupts every worker still running, then gives them two seconds between them to stop, for
     * the engine's cleanup. All are interrupted before any is waited for, so N slow workers cost
     * one wait, not N.
     */
    fun stopAll() {
        val running = synchronized(workerThreads) { workerThreads.toList() }.filter { it.isAlive }
        running.forEach { runCatching { it.interrupt() } }
        val deadline = System.nanoTime() + STOP_WAIT_NANOS
        for (worker in running) {
            val left = (deadline - System.nanoTime()) / 1_000_000
            if (left <= 0) break
            try {
                worker.join(left)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                break
            } catch (_: Exception) {
                // Ignore exceptions during cleanup; a worker still running is left to finish.
            }
        }
        workerThreads.clear()
    }

    private fun launch(handle: DynamicWorkerRegistry.Handle?) {
        val worker = thread(start = false) {
            handle?.markStarted()
            try {
                if (handle != null) released.await()
                work(handle)
            } finally {
                if (handle == null) engine.completedLatch.countDown() else handle.close()
                workerThreads.remove(Thread.currentThread())
            }
        }
        startTrackedWorker(worker, workerThreads)
    }

    private fun recordStartFailure(failure: Throwable) {
        if (isRecoverableAdaptiveCapacityFailure(failure)) engine.recordTransportFailure(failure)
        else throw failure
    }

    private companion object {
        /** How long [stopAll] waits for all interrupted workers together. */
        const val STOP_WAIT_NANOS = 2_000_000_000L
    }
}
