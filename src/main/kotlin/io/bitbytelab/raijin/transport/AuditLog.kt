package io.bitbytelab.raijin.transport

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.File
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * File-backed JSONL audit log with thread-safe locking, automatic line-cap rotation, and
 * atomic compaction. Extracted so unit tests can verify concurrency and rotation on temp files.
 */
class AuditFileStore(
    private val file: File,
    private val maxLines: Int = DEFAULT_MAX_LINES,
    private val retainLines: Int = (maxLines * 3) / 4
) {
    private val lock = ReentrantLock()
    private var linesSinceCheck = 0

    @Volatile
    var lastError: String? = null
        private set

    fun path(): String = file.absolutePath

    fun record(
        toolName: String,
        timestampIso: String,
        durationMs: Long,
        isError: Boolean,
        args: Map<String, JsonElement>?,
        url: String,
        host: String,
        method: String,
        statusCode: Int
    ) {
        val line = AuditLog.buildEntry(toolName, timestampIso, durationMs, isError, args, url, host, method, statusCode)
        lock.withLock {
            try {
                JsonlStoreSupport.appendLine(file, line)
                linesSinceCheck++
                if (linesSinceCheck >= COMPACT_CHECK_INTERVAL) {
                    linesSinceCheck = 0
                    compactIfNeededLocked()
                }
                lastError = null
            } catch (e: Exception) {
                lastError = e.message ?: e::class.simpleName
                System.err.println("Raijin: AuditLog.record failed (${file.absolutePath}): $lastError")
            }
        }
    }

    internal fun compactIfNeeded() {
        lock.withLock {
            try {
                compactIfNeededLocked()
                lastError = null
            } catch (e: Exception) {
                lastError = e.message ?: e::class.simpleName
                System.err.println("Raijin: AuditLog.compact failed (${file.absolutePath}): $lastError")
            }
        }
    }

    private fun compactIfNeededLocked() {
        if (maxLines <= 0 || !file.exists()) return
        val lines = file.readLines()
        if (lines.size <= maxLines) return
        val kept = lines.takeLast(retainLines.coerceAtLeast(1))
        JsonlStoreSupport.atomicWriteLines(file, kept)
    }

    companion object {
        const val DEFAULT_MAX_LINES = 20_000
        private const val COMPACT_CHECK_INTERVAL = 250
    }
}

/**
 * Durable, append-only audit trail for security-relevant MCP tool calls
 * (outbound requests, destructive tools, errors, mutating actions). Unlike the dashboard/UI
 * activity log this survives a Burp restart and keeps near-full arguments, so an
 * operator can reconstruct what an agent did.
 *
 * Writes JSON Lines to `~/.raijin-audit.jsonl` with automatic line-cap rotation.
 * Write failures are recorded in [lastError] and printed to stderr.
 */
object AuditLog {
    private const val MAX_VALUE = 8000

    private val defaultStore = AuditFileStore(File(System.getProperty("user.home") ?: ".", ".raijin-audit.jsonl"))

    val lastError: String? get() = defaultStore.lastError

    fun path(): String = defaultStore.path()

    /** Builds one JSONL audit record (pure; no I/O). Optional fields are omitted when blank. */
    fun buildEntry(
        toolName: String,
        timestampIso: String,
        durationMs: Long,
        isError: Boolean,
        args: Map<String, JsonElement>?,
        url: String,
        host: String,
        method: String,
        statusCode: Int
    ): String = buildJsonObject {
        put("ts", timestampIso)
        put("tool", toolName)
        put("duration_ms", durationMs)
        put("is_error", isError)
        if (url.isNotEmpty()) put("url", url)
        if (host.isNotEmpty()) put("host", host)
        if (method.isNotEmpty()) put("method", method)
        if (statusCode != 0) put("status_code", statusCode)
        put("args", buildJsonObject {
            args?.forEach { (k, v) ->
                val s = v.toString()
                put(k, if (s.length > MAX_VALUE) s.take(MAX_VALUE) + "...[+${s.length - MAX_VALUE}]" else s)
            }
        })
    }.toString()

    /** Appends an audit record to the log file. */
    fun record(
        toolName: String,
        timestampIso: String,
        durationMs: Long,
        isError: Boolean,
        args: Map<String, JsonElement>?,
        url: String,
        host: String,
        method: String,
        statusCode: Int
    ) = defaultStore.record(toolName, timestampIso, durationMs, isError, args, url, host, method, statusCode)
}
