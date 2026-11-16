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
 *
 * A call holds an entry's [Entry.lock] for as long as it uses the socket, and such an entry is
 * busy. Idle eviction and [close] leave a busy entry alone; [close] with `force` closes it anyway,
 * which ends the call using it with a read or write error ([shutdownAll] always does).
 */
object HttpPipelineConnectionRegistry {

    /**
     * @param sni the `sni` the connection was opened with (null: the default); a call reuses it
     *   only for the same [host], [port], TLS and sni.
     */
    class Entry(
        val socket: Socket,
        val host: String,
        val port: Int,
        val useTls: Boolean,
        val sni: String? = null,
        val openedAtMs: Long = System.currentTimeMillis(),
    ) {
        @Volatile
        var lastUsedAtMs: Long = System.currentTimeMillis()
        val lock: ReentrantLock = ReentrantLock()

        /**
         * Bytes already read off [socket] past the last response a call returned, read at
         * [pendingReadAtNanos] ([System.nanoTime]); the next call reads them first. Guarded by [lock].
         */
        var pending: String = ""
        var pendingReadAtNanos: Long = 0L
    }

    /** A kept connection as [snapshot] saw it; [busy] while a call is using it. */
    class Info(
        val id: String,
        val host: String,
        val port: Int,
        val useTls: Boolean,
        val sni: String?,
        val openedAtMs: Long,
        val lastUsedAtMs: Long,
        val busy: Boolean,
    )

    enum class CloseResult { CLOSED, UNKNOWN, BUSY }

    /** A connection no call has used for this long is closed by the next sweep. */
    const val IDLE_EVICTION_MS = 120_000L

    /** How often idle connections are looked for. */
    const val SWEEP_INTERVAL_MS = 30_000L

    private val entries = ConcurrentHashMap<String, Entry>()
    private val janitor = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "raijin-pipeline-janitor").apply { isDaemon = true }
    }

    init {
        janitor.scheduleWithFixedDelay({ sweep() }, SWEEP_INTERVAL_MS, SWEEP_INTERVAL_MS, TimeUnit.MILLISECONDS)
    }

    private fun sweep() {
        val now = System.currentTimeMillis()
        entries.entries.forEach { (id, entry) ->
            if (now - entry.lastUsedAtMs <= IDLE_EVICTION_MS) return@forEach
            if (!entry.lock.tryLock()) return@forEach
            try {
                if (now - entry.lastUsedAtMs > IDLE_EVICTION_MS && entries.remove(id, entry)) {
                    runCatching { entry.socket.close() }
                }
            } finally {
                entry.lock.unlock()
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

    /**
     * Removes [id] only while it still maps to [entry] and closes [entry]'s socket either way, so a
     * caller retiring the connection it holds the lock of never evicts one registered since.
     */
    fun remove(id: String, entry: Entry) {
        entries.remove(id, entry)
        runCatching { entry.socket.close() }
    }

    /** The kept connections, oldest first. */
    fun snapshot(): List<Info> = entries.entries
        .map { (id, e) -> Info(id, e.host, e.port, e.useTls, e.sni, e.openedAtMs, e.lastUsedAtMs, e.lock.isLocked) }
        .sortedBy { it.openedAtMs }

    /**
     * Closes the connection kept under [id]: [CloseResult.BUSY] (and left open) while a call uses
     * it, unless [force], which closes it under that call.
     */
    fun close(id: String, force: Boolean = false): CloseResult {
        val entry = entries[id] ?: return CloseResult.UNKNOWN
        if (!entry.lock.tryLock()) {
            if (!force) return CloseResult.BUSY
            remove(id, entry)
            return CloseResult.CLOSED
        }
        try {
            if (!entries.remove(id, entry)) return CloseResult.UNKNOWN
            runCatching { entry.socket.close() }
            return CloseResult.CLOSED
        } finally {
            entry.lock.unlock()
        }
    }

    /** [close] for every kept connection. */
    fun closeAll(force: Boolean = false): Map<String, CloseResult> =
        entries.keys.toList().associateWith { close(it, force) }

    /** Called from the extension's unload handler so no socket or thread outlives the extension. */
    fun shutdownAll() {
        janitor.shutdownNow()
        entries.keys.toList().forEach { remove(it) }
    }
}
