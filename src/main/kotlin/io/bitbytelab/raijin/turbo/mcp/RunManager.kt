package io.bitbytelab.raijin.turbo.mcp

import io.bitbytelab.raijin.turbo.ResultStore
import io.bitbytelab.raijin.turbo.RunHandler
import io.bitbytelab.raijin.turbo.Utils

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

class RunManager(
    private val maxCompletedRuns: Int = 100,
    private val maxFullResponseRuns: Int = 50
) {
    private val runs = ConcurrentHashMap<String, ActiveRun>()
    private val evictedIds = ConcurrentHashMap.newKeySet<String>()
    private val sequenceCounter = AtomicLong(0)
    /** Serialises stripping and eviction, which the memory monitor and run creation both do. */
    private val retentionLock = Any()
    private val monitorLock = Any()
    private var monitorThread: Thread? = null // guarded by monitorLock
    /** When a collection last showed that low free memory was only uncollected garbage. */
    private var garbageOnlyAtNanos: Long? = null // memory monitor thread only

    fun startRun(): ActiveRun {
        startMemoryMonitor()
        evictCompletedRuns()
        val run = ActiveRun(sequenceCounter.getAndIncrement())
        runs[run.id] = run
        return run
    }

    /** Registers a run created elsewhere (the GUI script dialog) so it shows up beside MCP runs. */
    fun adopt(handler: RunHandler, store: ResultStore, source: String): ActiveRun {
        startMemoryMonitor()
        evictCompletedRuns()
        val run = ActiveRun(sequenceCounter.getAndIncrement(), handler, store, source)
        runs[run.id] = run
        return run
    }

    /** All known runs, newest first. */
    fun listRuns(): List<ActiveRun> = runs.values.sortedByDescending { it.sequenceNumber }

    fun getRun(runId: String): ActiveRun? {
        return runs[runId]
    }

    fun isEvicted(runId: String): Boolean {
        return runId in evictedIds
    }

    fun stopRun(runId: String): String {
        val run = runs[runId] ?: return "not_found"
        run.handler.abort()
        return "stopped"
    }

    fun deleteRun(runId: String): String {
        val run = runs.remove(runId) ?: return "not_found"
        run.handler.abort()
        return "deleted"
    }

    /**
     * Frees what finished runs hold: strips the response bodies of every finished run that still
     * has them or, once all are stripped, evicts the oldest finished run. Returns false when no
     * finished run was left to free.
     */
    fun emergencyCleanup(): Boolean = synchronized(retentionLock) {
        val completed = completedRunsNewestFirst()

        // First pass: strip any unstripped runs
        val unstripped = completed.filter { !it.responsesStripped }
        if (unstripped.isNotEmpty()) {
            unstripped.forEach(::strip)
            return@synchronized true
        }

        // Second pass: evict oldest completed run
        val oldest = completed.lastOrNull() ?: return@synchronized false
        evict(oldest)
        true
    }

    fun startMemoryMonitor() {
        synchronized(monitorLock) {
            if (monitorThread != null) return
            monitorThread = Thread(::monitorMemory, "turbo-memory-monitor").apply {
                isDaemon = true
                start()
            }
        }
    }

    fun stopMemoryMonitor() {
        val thread = synchronized(monitorLock) {
            monitorThread.also { monitorThread = null }
        }
        thread?.interrupt()
    }

    private fun monitorMemory() {
        val runtime = Runtime.getRuntime()
        while (!Thread.currentThread().isInterrupted) {
            try {
                Thread.sleep(MONITOR_INTERVAL_MILLIS)
                relieveMemoryPressure(
                    maxHeap = runtime.maxMemory(),
                    usedHeap = { runtime.totalMemory() - runtime.freeMemory() },
                    collectGarbage = System::gc,
                    nowNanos = System.nanoTime(),
                )
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
            } catch (failure: RuntimeException) {
                Utils.err("Turbo memory monitor: $failure")
            }
        }
    }

    /**
     * One memory-monitor tick. The retention caps apply first, so finished runs age out even while
     * no new run starts. Then, only when free heap is low for the size of the heap and finished runs
     * have something to give back: one collection to rule out garbage that merely has not been
     * collected yet (retried at most once a minute when that is all it was), and one cleanup step
     * followed by a collection. Returns true when it released something.
     */
    internal fun relieveMemoryPressure(
        maxHeap: Long,
        usedHeap: () -> Long,
        collectGarbage: () -> Unit,
        nowNanos: Long,
    ): Boolean {
        evictCompletedRuns()
        if (!isLowOnMemory(maxHeap, usedHeap())) return false
        // Nothing of ours to free: a collection would cost a pause and change nothing.
        if (runs.values.none { it.handler.status() != "running" }) return false
        val garbageOnlyAt = garbageOnlyAtNanos
        if (garbageOnlyAt != null && nowNanos - garbageOnlyAt < GARBAGE_RECHECK_NANOS) return false

        collectGarbage()
        if (!isLowOnMemory(maxHeap, usedHeap())) {
            garbageOnlyAtNanos = nowNanos
            return false
        }
        if (!emergencyCleanup()) return false
        collectGarbage()
        return true
    }

    private fun evictCompletedRuns() = synchronized(retentionLock) {
        val completed = completedRunsNewestFirst()

        // Strip response bodies from runs beyond the full-response threshold
        completed.drop(maxFullResponseRuns).forEach { run ->
            if (!run.responsesStripped) strip(run)
        }

        // Evict runs beyond the total retention limit
        val excess = completed.size - maxCompletedRuns
        if (excess > 0) {
            completed.takeLast(excess).forEach(::evict)
        }
    }

    private fun completedRunsNewestFirst(): List<ActiveRun> = runs.values
        .filter { it.handler.status() != "running" }
        .sortedByDescending { it.sequenceNumber }

    private fun strip(run: ActiveRun) {
        run.store.stripResponseBodies()
        run.responsesStripped = true
    }

    private fun evict(run: ActiveRun) {
        runs.remove(run.id)
        evictedIds.add(run.id)
    }

    internal companion object {
        private const val MONITOR_INTERVAL_MILLIS = 5_000L
        private const val GARBAGE_RECHECK_NANOS = 60_000_000_000L
        private const val MAX_LOW_MEMORY_HEADROOM = 1_000_000_000L

        /**
         * Free heap below this is low: 15% of the maximum heap, capped at the 1 GB that used to
         * apply to every heap. A flat 1 GB is always short on a 1-2 GB Burp, which then stripped
         * and evicted every finished run and forced a full GC every five seconds while idle.
         */
        fun lowMemoryHeadroom(maxHeap: Long): Long = minOf(MAX_LOW_MEMORY_HEADROOM, maxHeap / 100 * 15)

        fun isLowOnMemory(maxHeap: Long, usedHeap: Long): Boolean =
            maxHeap - usedHeap < lowMemoryHeadroom(maxHeap)
    }
}
