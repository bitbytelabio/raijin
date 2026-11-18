package io.bitbytelab.raijin.transport

import io.bitbytelab.raijin.core.BodyText
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.File
import kotlin.concurrent.withLock

/**
 * File-backed JSONL audit log with a per-file lock shared with every other writer of the file
 * ([JsonlStoreSupport.lockFor]), and rotation by atomic compaction: once the file holds more than
 * [maxLines] lines or [maxBytes] bytes, only the newest [retainLines] lines (within three quarters
 * of [maxBytes]) are kept. Extracted so unit tests can verify concurrency and rotation on temp files.
 */
class AuditFileStore(
    private val file: File,
    private val maxLines: Int = DEFAULT_MAX_LINES,
    private val retainLines: Int = (maxLines * 3) / 4,
    private val maxBytes: Long = DEFAULT_MAX_BYTES
) {
    private val lock = JsonlStoreSupport.lockFor(file)
    private var appendsSinceCheck = 0 // guarded by lock
    private var knownLines = -1 // guarded by lock; -1 until counted

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
        statusCode: Int,
        outOfScope: Boolean = false,
    ) {
        val line = AuditLog.buildEntry(toolName, timestampIso, durationMs, isError, args, url, host, method, statusCode, outOfScope)
        lock.withLock {
            try {
                JsonlStoreSupport.appendLine(file, line)
                if (knownLines >= 0) knownLines++
                if (++appendsSinceCheck >= COMPACT_CHECK_INTERVAL) {
                    appendsSinceCheck = 0
                    compactIfNeededLocked()
                }
                succeeded()
            } catch (e: Exception) {
                failed("record", e)
            }
        }
    }

    internal fun compactIfNeeded() {
        lock.withLock {
            try {
                compactIfNeededLocked()
                succeeded()
            } catch (e: Exception) {
                failed("compact", e)
            }
        }
    }

    private fun compactIfNeededLocked() {
        if (!file.exists()) {
            knownLines = 0
            return
        }
        if (knownLines < 0) knownLines = file.useLines { it.count() }
        val tooLong = maxLines > 0 && knownLines > maxLines
        val tooBig = maxBytes > 0 && file.length() > maxBytes
        if (!tooLong && !tooBig) return
        val kept = retainedTail(file.readLines())
        JsonlStoreSupport.atomicWriteLines(file, kept)
        knownLines = kept.size
    }

    /** The newest lines that fit both the line and the byte budget (always at least one line). */
    private fun retainedTail(lines: List<String>): List<String> {
        val byCount = if (maxLines > 0) lines.takeLast(retainLines.coerceAtLeast(1)) else lines
        if (maxBytes <= 0) return byCount
        val budget = maxBytes * 3 / 4
        var size = byCount.sumOf { it.toByteArray(Charsets.UTF_8).size + 1L }
        var start = 0
        while (start < byCount.size - 1 && size > budget) {
            size -= byCount[start].toByteArray(Charsets.UTF_8).size + 1L
            start++
        }
        return byCount.subList(start, byCount.size)
    }

    private fun succeeded() {
        lastError = null
        JsonlStoreSupport.recovered(file)
    }

    private fun failed(op: String, e: Exception) {
        lastError = JsonlStoreSupport.reportFailure("AuditLog", op, file, e)
    }

    companion object {
        const val DEFAULT_MAX_LINES = 20_000
        const val DEFAULT_MAX_BYTES = 16L * 1024 * 1024
        private const val COMPACT_CHECK_INTERVAL = 250
    }
}

/**
 * Durable, append-only audit trail for security-relevant MCP tool calls
 * (outbound requests, destructive tools, errors, mutating actions). Unlike the dashboard/UI
 * activity log this survives a Burp restart and keeps near-full arguments, so an
 * operator can reconstruct what an agent did.
 *
 * Writes JSON Lines to `~/.raijin-audit.jsonl`, rotated by line count and size. Write failures
 * are recorded in [lastError], printed to stderr and reported to the Burp error log.
 */
object AuditLog {
    private const val MAX_VALUE = 8000

    /** The file behind the log; tests point it at a temp file instead of the user's home. */
    @Volatile
    internal var store = AuditFileStore(File(System.getProperty("user.home") ?: ".", ".raijin-audit.jsonl"))

    val lastError: String? get() = store.lastError

    fun path(): String = store.path()

    /** The Burp project the records belong to, as the activity store names it; set at startup. */
    @Volatile
    var project: String = ""

    /**
     * Builds one JSONL audit record (pure; no I/O). Optional fields are omitted when blank. Each
     * argument keeps its JSON value: a long string is cut (never inside a surrogate pair), and an
     * oversized object or array is replaced by a note giving its size.
     */
    fun buildEntry(
        toolName: String,
        timestampIso: String,
        durationMs: Long,
        isError: Boolean,
        args: Map<String, JsonElement>?,
        url: String,
        host: String,
        method: String,
        statusCode: Int,
        outOfScope: Boolean = false,
        project: String = this.project,
    ): String = buildJsonObject {
        put("ts", timestampIso)
        put("tool", toolName)
        put("duration_ms", durationMs)
        put("is_error", isError)
        if (outOfScope) put("out_of_scope", true)
        if (project.isNotEmpty()) put("project", project)
        if (url.isNotEmpty()) put("url", url)
        if (host.isNotEmpty()) put("host", host)
        if (method.isNotEmpty()) put("method", method)
        if (statusCode != 0) put("status_code", statusCode)
        put("args", buildJsonObject {
            args?.forEach { (k, v) -> put(k, cappedArg(v)) }
        })
    }.toString()

    private fun cappedArg(value: JsonElement): JsonElement {
        if (value is JsonPrimitive) {
            // Every primitive is capped: a lenient client can send a huge unquoted literal too.
            val s = value.content
            if (s.length <= MAX_VALUE) return value
            return JsonPrimitive(BodyText.truncate(s, MAX_VALUE) + "...[+${s.length - MAX_VALUE}]")
        }
        // An oversized object or array keeps its start (requests, steps), so the call can still be reconstructed.
        val text = value.toString()
        return if (text.length <= MAX_VALUE) value
        else JsonPrimitive(BodyText.truncate(text, MAX_VALUE) + "…[json truncated: ${text.length} chars]")
    }

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
        statusCode: Int,
        outOfScope: Boolean = false,
    ) = store.record(toolName, timestampIso, durationMs, isError, args, url, host, method, statusCode, outOfScope)
}
