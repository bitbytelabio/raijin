package io.bitbytelab.raijin.bridge

import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock

/**
 * Process-lifetime registry letting [HttpPipelineBridge] reuse one TCP connection across SEPARATE
 * `http_send_pipeline` MCP calls (`keep_open` / `connection_id`). This is deliberately independent
 * of Montoya's own `connection_id` parameter on [HttpBridge.sendRequest] and of Turbo's
 * RequestEngine connectionId handling — neither of those survives past one MCP tool call, and this
 * tool's whole point is to let an agent send stage1+stage2 in one call and a later request on the
 * same socket in a separate call.
 */
object HttpPipelineConnectionRegistry {

    class Entry(
        val socket: Socket,
        val host: String,
        val port: Int,
        val useTls: Boolean,
    ) {
        @Volatile
        var lastUsedAtMs: Long = System.currentTimeMillis()
        val lock: ReentrantLock = ReentrantLock()
    }

    private const val IDLE_EVICTION_MS = 120_000L
    private const val SWEEP_INTERVAL_SECONDS = 30L

    private val entries = ConcurrentHashMap<String, Entry>()
    private val janitor = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "raijin-pipeline-janitor").apply { isDaemon = true }
    }

    init {
        janitor.scheduleWithFixedDelay({ sweep() }, SWEEP_INTERVAL_SECONDS, SWEEP_INTERVAL_SECONDS, TimeUnit.SECONDS)
    }

    private fun sweep() {
        val now = System.currentTimeMillis()
        entries.entries.removeAll { (_, entry) ->
            val idle = now - entry.lastUsedAtMs
            if (idle > IDLE_EVICTION_MS) {
                runCatching { entry.socket.close() }
                true
            } else {
                false
            }
        }
    }

    /** Replaces and closes any prior entry under [id]. */
    fun put(id: String, entry: Entry) {
        entries.put(id, entry)?.let { previous ->
            if (previous !== entry) runCatching { previous.socket.close() }
        }
    }

    fun get(id: String): Entry? = entries[id]

    fun remove(id: String) {
        entries.remove(id)?.let { runCatching { it.socket.close() } }
    }

    /** Called from the extension's unload handler so no socket or thread outlives the extension. */
    fun shutdownAll() {
        janitor.shutdownNow()
        entries.keys.toList().forEach { remove(it) }
    }
}
