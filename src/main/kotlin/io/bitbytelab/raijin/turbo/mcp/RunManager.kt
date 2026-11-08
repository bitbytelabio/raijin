package io.bitbytelab.raijin.turbo.mcp

import io.bitbytelab.raijin.turbo.ResultStore
import io.bitbytelab.raijin.turbo.RunHandler

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

class RunManager(
    private val maxCompletedRuns: Int = 100,
    private val maxFullResponseRuns: Int = 50
) {
    private val runs = ConcurrentHashMap<String, ActiveRun>()
    private val evictedIds = ConcurrentHashMap.newKeySet<String>()
    private val sequenceCounter = AtomicLong(0)
    @Volatile
    private var monitorThread: Thread? = null

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

    fun emergencyCleanup() {
        val completed = runs.values
            .filter { it.handler.status() != "running" }
            .sortedByDescending { it.sequenceNumber }

        // First pass: strip any unstripped runs
        val unstripped = completed.filter { !it.responsesStripped }
        if (unstripped.isNotEmpty()) {
            unstripped.forEach { run ->
                run.store.stripResponseBodies()
                run.responsesStripped = true
            }
            return
        }

        // Second pass: evict oldest completed run
        if (completed.isNotEmpty()) {
            val oldest = completed.last()
            runs.remove(oldest.id)
            evictedIds.add(oldest.id)
        }
    }

    fun startMemoryMonitor() {
        if (monitorThread != null) return
        monitorThread = Thread({
            while (!Thread.currentThread().isInterrupted) {
                try {
                    Thread.sleep(5000)
                    val runtime = Runtime.getRuntime()
                    val available = runtime.maxMemory() - runtime.totalMemory() + runtime.freeMemory()
                    if (available < 1_000_000_000L) {
                        emergencyCleanup()
                        System.gc()
                    }
                } catch (e: InterruptedException) {
                    Thread.currentThread().interrupt()
                    break
                }
            }
        }, "turbo-memory-monitor").apply {
            isDaemon = true
            start()
        }
    }

    fun stopMemoryMonitor() {
        monitorThread?.interrupt()
        monitorThread = null
    }

    private fun evictCompletedRuns() {
        val completed = runs.values
            .filter { it.handler.status() != "running" }
            .sortedByDescending { it.sequenceNumber }

        // Strip response bodies from runs beyond the full-response threshold
        completed.drop(maxFullResponseRuns).forEach { run ->
            if (!run.responsesStripped) {
                run.store.stripResponseBodies()
                run.responsesStripped = true
            }
        }

        // Evict runs beyond the total retention limit
        val excess = completed.size - maxCompletedRuns
        if (excess > 0) {
            completed.takeLast(excess).forEach { run ->
                runs.remove(run.id)
                evictedIds.add(run.id)
            }
        }
    }
}
