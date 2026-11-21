package io.bitbytelab.raijin.transport

import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.logging.Logging
import burp.api.montoya.scanner.audit.issues.AuditIssue
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.addJsonObject
import java.io.File
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Durable record of the traffic Raijin's tools send and of the scanner issues Burp reports, for the
 * `raijin` CLI's offline history (`.burp` files do not keep tool-sent exchanges in proxy history).
 *
 * Enabled only while `-Draijin.archiveDir` is set (read on every call). Writes
 * `<dir>/exchanges.jsonl` and `<dir>/issues.jsonl`, one JSON object per line with a per-file `seq`.
 * Failures are reported once to [logging] and never fail a tool.
 */
internal object ExchangeArchive {
    const val PROP_DIR = "raijin.archiveDir"
    const val EXCHANGES_FILE = "exchanges.jsonl"
    const val ISSUES_FILE = "issues.jsonl"
    const val MAX_MESSAGE_BYTES = 10 * 1024 * 1024
    private const val MAX_EVIDENCE = 3

    /** Burp's logger while the extension is loaded; set by `RaijinExtension.initialize`, cleared on unload. */
    @Volatile
    var logging: Logging? = null

    @Volatile
    private var failureReported = false

    private val seqs = ConcurrentHashMap<String, AtomicLong>()

    private fun dir(): File? = System.getProperty(PROP_DIR)?.trim()?.ifEmpty { null }?.let(::File)

    /** Whether archiving is on, so callers can skip building what they would archive. */
    fun enabled(): Boolean = dir() != null

    fun appendExchange(tool: String, rr: HttpRequestResponse) {
        val dir = dir() ?: return
        guarded {
            val request = rr.request()
            val response = if (rr.hasResponse()) rr.response() else null
            append(File(dir, EXCHANGES_FILE)) { seq ->
                exchangeLine(
                    seq, tool, request.method(), request.url(),
                    request.toByteArray().bytes, response?.toByteArray()?.bytes,
                    response?.statusCode()?.toInt(), reconstructed = false
                )
            }
        }
    }

    fun appendRaw(
        tool: String, method: String, url: String, request: ByteArray, response: ByteArray?, status: Int?, reconstructed: Boolean,
    ) {
        val dir = dir() ?: return
        guarded {
            append(File(dir, EXCHANGES_FILE)) { seq -> exchangeLine(seq, tool, method, url, request, response, status, reconstructed) }
        }
    }

    fun appendIssue(issue: AuditIssue) {
        val dir = dir() ?: return
        guarded {
            append(File(dir, ISSUES_FILE)) { seq ->
                buildJsonObject {
                    put("seq", seq)
                    put("time_epoch_ms", System.currentTimeMillis())
                    put("name", issue.name())
                    put("severity", issue.severity()?.name)
                    put("confidence", issue.confidence()?.name)
                    put("base_url", issue.baseUrl())
                    put("detail", issue.detail()?.ifEmpty { null })
                    put("remediation", issue.remediation()?.ifEmpty { null })
                    putJsonArray("evidence") {
                        issue.requestResponses().orEmpty().take(MAX_EVIDENCE).forEach { rr ->
                            addJsonObject {
                                put("request_b64", b64(cap(rr.request().toByteArray().bytes)))
                                put("response_b64", if (rr.hasResponse()) b64(cap(rr.response().toByteArray().bytes)) else null)
                            }
                        }
                    }
                }
            }
        }
    }

    private fun exchangeLine(
        seq: Long, tool: String, method: String, url: String,
        request: ByteArray, response: ByteArray?, status: Int?, reconstructed: Boolean,
    ): JsonObject = buildJsonObject {
        put("seq", seq)
        put("time_epoch_ms", System.currentTimeMillis())
        put("tool", tool)
        put("method", method)
        put("url", url)
        put("status", status)
        put("request_b64", b64(cap(request)))
        if (response == null) put("response_b64", JsonNull) else put("response_b64", b64(cap(response)))
        put("request_truncated", request.size > MAX_MESSAGE_BYTES)
        put("response_truncated", response != null && response.size > MAX_MESSAGE_BYTES)
        put("response_reconstructed", reconstructed)
    }

    /**
     * Serialised per file: the next seq (seeded from the file's line count on first use) and the
     * append happen under one lock, and the counter only moves once the line is written, so a failed
     * write leaves no gap that a restart (re-seeding from the line count) would reuse.
     */
    private fun append(file: File, line: (Long) -> JsonObject) {
        val lock = JsonlStoreSupport.lockFor(file)
        lock.lock()
        try {
            val key = file.absoluteFile.normalize().path
            val counter = seqs.computeIfAbsent(key) { AtomicLong(countLines(file)) }
            val next = counter.get() + 1
            JsonlStoreSupport.appendLine(file, line(next).toString())
            counter.set(next)
        } finally {
            lock.unlock()
        }
    }

    private fun countLines(file: File): Long =
        if (!file.isFile) 0L else file.bufferedReader(Charsets.UTF_8).use { r -> r.lineSequence().count { it.isNotBlank() }.toLong() }

    private inline fun guarded(block: () -> Unit) {
        try {
            block()
            failureReported = false
        } catch (e: Exception) {
            if (!failureReported) {
                failureReported = true
                val message = "Raijin: exchange archive write failed: ${e.message ?: e::class.simpleName}"
                logging?.logToError(message) ?: System.err.println(message)
            }
        }
    }

    private fun cap(bytes: ByteArray): ByteArray = if (bytes.size > MAX_MESSAGE_BYTES) bytes.copyOf(MAX_MESSAGE_BYTES) else bytes

    private fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)
}
