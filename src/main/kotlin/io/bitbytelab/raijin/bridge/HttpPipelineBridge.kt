package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import io.bitbytelab.raijin.bridge.HttpPipelineFraming.Outcome
import io.bitbytelab.raijin.core.BodyText
import io.bitbytelab.raijin.safety.ScopeGate
import io.bitbytelab.raijin.transport.ExchangeArchive
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import java.io.IOException
import java.io.OutputStream
import java.net.Socket
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.thread
import kotlin.concurrent.withLock

/**
 * One request of an `http_send_pipeline` call: [bytes] exactly as they go on the wire, and the
 * offsets (0..size, ascending) after which writing pauses for up to [pauseMs], ending early when
 * the server sends data (Turbo's `pauseBefore` / `pauseMarkers` / `pauseTime`).
 */
internal class PipelineRequestSpec(
    val bytes: ByteArray,
    val pauseOffsets: List<Int> = emptyList(),
    val pauseMs: Long = DEFAULT_PAUSE_MS,
) {
    init {
        require(bytes.isNotEmpty()) { "the request is empty" }
        require(pauseOffsets.all { it in 0..bytes.size } && pauseOffsets.zipWithNext().all { (a, b) -> a < b }) {
            "pause offsets must ascend within 0..${bytes.size}"
        }
        require(pauseMs >= 0) { "pause_ms must not be negative" }
    }

    companion object {
        const val DEFAULT_PAUSE_MS = 1_000L

        /**
         * Where writing [bytes] pauses, ascending and distinct. [pauseBefore] follows Turbo: n > 0
         * sends bytes [0, n-1) first, n < 0 holds back the last |n| bytes, 0 means no such pause
         * (an offset outside the request is clamped into it). Writing also pauses after every
         * occurrence of a [markers] entry, found left to right without overlapping the previous one.
         */
        fun pauseOffsets(bytes: ByteArray, pauseBefore: Int, markers: List<ByteArray>): List<Int> {
            val offsets = sortedSetOf<Int>()
            if (pauseBefore > 0) offsets += (pauseBefore - 1).coerceAtMost(bytes.size)
            if (pauseBefore < 0) offsets += (bytes.size + pauseBefore).coerceAtLeast(0)
            // The next occurrence of each marker at or after [from]: -2 not searched yet, -1 none left.
            val next = IntArray(markers.size) { -2 }
            var from = 0
            while (true) {
                var start = -1
                var end = -1
                markers.forEachIndexed { k, marker ->
                    if (next[k] == -1) return@forEachIndexed
                    if (next[k] < from) next[k] = indexOf(bytes, marker, from)
                    val at = next[k]
                    if (at >= 0 && (start < 0 || at < start || (at == start && at + marker.size < end))) {
                        start = at
                        end = at + marker.size
                    }
                }
                if (start < 0) return offsets.toList()
                offsets += end
                from = end
            }
        }

        /** First index of [needle] (non-empty) in [haystack] at or after [from], or -1. */
        fun indexOf(haystack: ByteArray, needle: ByteArray, from: Int): Int {
            outer@ for (i in from..haystack.size - needle.size) {
                for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
                return i
            }
            return -1
        }
    }
}

/**
 * Sends multiple raw HTTP/1.1 requests over ONE socket connection and reads back multiple
 * responses in order — something Montoya's `api.http().sendRequest()` structurally cannot do (it
 * is strictly one request in, one response out). Needed for HTTP desync / request-smuggling
 * research (0.CL, stage1+stage2 probes) where the agent currently has to drop out of MCP and
 * hand-write a Turbo Python script for this one primitive.
 *
 * Requests are written on their own thread while the calling thread reads responses, so a
 * response that starts before its request is fully written (during a pause, or between writes) is
 * seen when it happens and timed against the writes. Every response is reported with its exact
 * wire bytes and its first/last byte times.
 *
 * Deliberately standalone: does not touch Turbo's RequestEngine/ThreadedRequestEngine/RunManager,
 * so a bug here cannot regress a running Turbo campaign, and it never recomputes Content-Length
 * ([io.bitbytelab.raijin.safety.RequestHygiene.fixContentLength]) — a deliberately-wrong declared
 * Content-Length is the entire point of this tool. HTTP/2, HTTP/3 and kettled H2-smuggling escape
 * fields remain Turbo-only; see `tools/http/HttpPipelineTools.kt`'s `http_send_pipeline` description.
 */
class HttpPipelineBridge(private val api: MontoyaApi) {

    private val scopeGate = ScopeGate(api)

    /**
     * `decode_content`'s `br` coding is refused for now: Burp's `compressionUtils().decompress()` is
     * the only brotli decoder available here, and unlike the gzip/deflate paths (streamed through
     * [HttpContentDecoding.inflate], which stop at `maxBytes`) it builds the whole decompressed
     * output before anything can check its size. A small, deliberately crafted brotli body can
     * decompress to gigabytes and exhaust the heap before the cap is ever applied. Re-enable once a
     * streaming brotli decoder backs this, so [HttpContentDecoding.decode] reports the same clear
     * "not available" result it already gives outside Burp.
     */
    private val brotli: ((ByteArray) -> ByteArray)? = null

    /**
     * Writes [requests] on one connection and reads up to [maxResponses] responses (default: one
     * per request). See `http_send_pipeline` for every parameter and result field.
     *
     * @param sni TLS server name: null sends the default, "" none; ignored (with a note) without TLS.
     * @param rawHexMaxBytes cap on each response's `raw_response_hex`; 0 leaves raw hex out.
     */
    internal fun send(
        host: String,
        port: Int,
        useTls: Boolean,
        httpMode: String?,
        requests: List<PipelineRequestSpec>,
        writeMode: String = "concat",
        writePauseMs: Long = 0,
        maxResponses: Int? = null,
        idleTimeoutMs: Long = 2_000,
        totalTimeoutMs: Long = 15_000,
        keepOpen: Boolean = false,
        connectionId: String? = null,
        maxResponseLength: Int? = null,
        sni: String? = null,
        decodeContent: Boolean = false,
        rawHexMaxBytes: Int = DEFAULT_RAW_HEX_MAX_BYTES,
    ): JsonObject {
        if (httpMode != null && !httpMode.equals("HTTP_1", ignoreCase = true)) {
            return failure("validate", "http_send_pipeline only supports HTTP_1 in this version. HTTP/2, HTTP/3 and kettled H2 fields are Turbo-only (turbo_start_run with Engine.HTTP2 / Engine.HTTP3 / kettled=True).")
        }
        if (requests.isEmpty()) return failure("validate", "'requests' must contain at least one item")
        val notes = ArrayList<String>()
        // SNI only exists in TLS: a plain connection neither sends nor remembers one.
        val serverName = sni.takeIf { useTls }
        if (sni != null && !useTls) notes += "sni was ignored: it is only sent over TLS."
        if (!serverName.isNullOrEmpty()) {
            try {
                RawHttpConnector.serverName(serverName)
            } catch (e: IllegalArgumentException) {
                return failure("validate", e.message ?: "sni '$serverName' cannot be sent")
            }
        }

        // Every item: a later request on the socket may target a path the first one does not.
        val scope = scopeGate.checkRequests(host, port, useTls, requests.asSequence().map { String(it.bytes, Charsets.ISO_8859_1) })
        if (scope.blocked) return scope.denyJson()
        return scope.annotate(sendChecked(host, port, useTls, requests, writeMode, writePauseMs, maxResponses,
            idleTimeoutMs, totalTimeoutMs, keepOpen, connectionId, maxResponseLength, serverName, decodeContent, rawHexMaxBytes, notes))
    }

    private fun sendChecked(
        host: String,
        port: Int,
        useTls: Boolean,
        requests: List<PipelineRequestSpec>,
        writeMode: String,
        writePauseMs: Long,
        maxResponses: Int?,
        idleTimeoutMs: Long,
        totalTimeoutMs: Long,
        keepOpen: Boolean,
        connectionId: String?,
        maxResponseLength: Int?,
        serverName: String?,
        decodeContent: Boolean,
        rawHexMaxBytes: Int,
        notes: List<String>,
    ): JsonObject {
        val deadlineAtMs = System.currentTimeMillis() + totalTimeoutMs
        val target = Target(host, port, useTls, serverName)
        val link = try {
            openLink(target, connectionId, deadlineAtMs)
        } catch (e: ConnectionInUse) {
            return failure("connect", e.message ?: "connection in use")
        } catch (e: Exception) {
            return failure("connect", "connect failed: ${e.message}")
        }

        val socket = link.socket
        val control = WriteControl()
        try {
            val reader = HttpPipelineFraming.Reader(
                socket, idleTimeoutMs, deadlineAtMs,
                captureBytes = rawHexMaxBytes,
                activity = control,
                carry = link.entry?.pending.orEmpty(),
                carryReadAtNanos = link.entry?.pendingReadAtNanos ?: System.nanoTime(),
            )
            val writer = PipelineWriter(socket.getOutputStream(), requests, writeMode == "single_write", writePauseMs, control)
            val startedAtNanos = System.nanoTime()
            val writing = thread(isDaemon = true, name = "raijin-pipeline-writer") { writer.run() }

            val read = readResponses(reader, requests, maxResponses)
            if (read.closeReason == "fin" || read.closeReason == "rst") control.peerClosed()
            val writerFinished = awaitWriter(writing, control, socket, deadlineAtMs, stopNow = read.closeReason == "total_timeout")
            val progress = writer.progress()
            archive(target, requests, read.responses, progress)
            val writeError = if (writerFinished) {
                writer.error
            } else {
                "total_timeout_ms ran out with ${writer.bytesWritten} of ${writer.total} request bytes written"
            }

            // Only offer the socket for reuse when every requested response framed cleanly, every
            // request byte went out, and the server keeps the connection (no Connection: close,
            // close-delimited body or HTTP/1.0 close).
            val keepAlive = keepOpen && read.closeReason == "max_responses" && read.reusable && writeError == null && !socket.isClosed
            val leftover = if (read.failure == null) reader.leftover() else ""
            val resultConnectionId = if (keepAlive) connectionId ?: UUID.randomUUID().toString() else null
            if (keepAlive) {
                val kept = link.entry ?: HttpPipelineConnectionRegistry.Entry(socket, host, port, useTls, serverName, link.openedAtMs)
                kept.pending = leftover
                kept.pendingReadAtNanos = reader.lastDataAtNanos
                kept.lastUsedAtMs = System.currentTimeMillis()
                HttpPipelineConnectionRegistry.put(resultConnectionId!!, kept)
            } else {
                retire(socket, connectionId, link.entry)
            }

            val t0 = writer.firstWriteAtNanos ?: writer.startedAtNanos ?: startedAtNanos
            return buildJsonObject {
                put("connection_id", resultConnectionId)
                put("connection_reused", link.reused)
                if (link.targetMismatch) put("connection_id_target_mismatch", true)
                put("bytes_sent", writer.bytesWritten)
                put("bytes_received", reader.totalBytesRead)
                put("responses_received", read.responses.size)
                putJsonArray("responses") {
                    read.responses.forEachIndexed { i, ok ->
                        add(responseJson(i, ok, t0, progress.getOrNull(i)?.endNanos, maxResponseLength, decodeContent, rawHexMaxBytes))
                    }
                }
                putJsonArray("requests") {
                    progress.forEachIndexed { i, p -> add(requestJson(i, requests[i], p, t0)) }
                }
                read.failure?.received?.takeIf { it.length > 0 }?.let { partial ->
                    putJsonObject("partial_response") {
                        put("index", read.responses.size)
                        putWire(partial, t0, null, rawHexMaxBytes)
                    }
                }
                if (leftover.isNotEmpty()) {
                    putJsonObject("unparsed") {
                        put("bytes", leftover.length)
                        if (rawHexMaxBytes > 0) {
                            put("raw_hex", HttpContentDecoding.hex(leftover, rawHexMaxBytes))
                            if (leftover.length > rawHexMaxBytes) put("raw_truncated", true)
                        }
                        put("kept_for_next_call", keepAlive)
                    }
                }
                put("close_reason", read.closeReason)
                put("connection_open", keepAlive)
                writeError?.let { put("write_error", it) }
                read.error?.let { put("error", it) }
                if (notes.isNotEmpty()) putJsonArray("notes") { notes.forEach { add(it) } }
            }
        } catch (e: Exception) {
            control.stop()
            retire(socket, connectionId, link.entry)
            return buildJsonObject { put("error", "pipeline failed: ${e.message}"); put("phase", "read") }
        } finally {
            link.entry?.lock?.unlock()
        }
    }

    /**
     * Lists the connections kept by `keep_open`, after closing those in [close] (ids), or all of
     * them with [closeAll]. A connection a call is using is reported busy and left open unless
     * [force]; forcing it closes it under that call, which then ends with a read or write error.
     */
    internal fun connections(close: List<String>, closeAll: Boolean, force: Boolean): JsonObject {
        val closing = closeAll || close.isNotEmpty()
        val results = if (closeAll) {
            HttpPipelineConnectionRegistry.closeAll(force)
        } else {
            close.distinct().associateWith { HttpPipelineConnectionRegistry.close(it, force) }
        }
        val now = System.currentTimeMillis()
        return buildJsonObject {
            if (closing) {
                for ((key, result) in CLOSE_RESULT_KEYS) {
                    putJsonArray(key) { results.forEach { (id, r) -> if (r == result) add(id) } }
                }
            }
            putJsonArray("connections") {
                HttpPipelineConnectionRegistry.snapshot().forEach { c ->
                    add(buildJsonObject {
                        put("connection_id", c.id)
                        put("host", c.host)
                        put("port", c.port)
                        put("use_tls", c.useTls)
                        c.sni?.let { put("sni", it) }
                        put("age_ms", now - c.openedAtMs)
                        put("idle_ms", now - c.lastUsedAtMs)
                        put("busy", c.busy)
                        if (!c.busy) {
                            put("evicts_in_ms", (HttpPipelineConnectionRegistry.IDLE_EVICTION_MS - (now - c.lastUsedAtMs)).coerceAtLeast(0))
                        }
                    })
                }
            }
        }
    }

    private class Target(val host: String, val port: Int, val useTls: Boolean, val sni: String?)

    /** The socket a call uses: [entry] is the kept connection it came from, whose lock the call holds. */
    private class Link(
        val socket: Socket,
        val entry: HttpPipelineConnectionRegistry.Entry?,
        val reused: Boolean,
        val targetMismatch: Boolean,
        val openedAtMs: Long,
    )

    private class ConnectionInUse(message: String) : Exception(message)

    /**
     * The connection kept under [connectionId] when it is still open and was opened for the same
     * [target] (its lock is then held), else a new one. A kept connection for another target is closed.
     */
    private fun openLink(target: Target, connectionId: String?, deadlineAtMs: Long): Link {
        var targetMismatch = false
        val existing = connectionId?.let { HttpPipelineConnectionRegistry.get(it) }
        if (connectionId != null && existing != null) {
            if (!existing.lock.tryLock(LOCK_WAIT_MS, TimeUnit.MILLISECONDS)) {
                throw ConnectionInUse("connection_id '$connectionId' is in use by a concurrent call")
            }
            var held = false
            try {
                // It may have been closed (http_pipeline_connections, eviction) while this call waited.
                val live = HttpPipelineConnectionRegistry.get(connectionId) === existing && !existing.socket.isClosed
                val sameTarget = existing.host == target.host && existing.port == target.port &&
                    existing.useTls == target.useTls && existing.sni == target.sni
                if (live && sameTarget) {
                    held = true
                    return Link(existing.socket, existing, reused = true, targetMismatch = false, existing.openedAtMs)
                }
                targetMismatch = live
                HttpPipelineConnectionRegistry.remove(connectionId, existing)
            } finally {
                if (!held) existing.lock.unlock()
            }
        }
        val timeoutMs = (deadlineAtMs - System.currentTimeMillis()).coerceIn(1, MAX_CONNECT_TIMEOUT_MS).toInt()
        val openedAtMs = System.currentTimeMillis()
        val socket = RawHttpConnector.connect(target.host, target.port, target.useTls, timeoutMs, target.sni)
        return Link(socket, null, reused = false, targetMismatch = targetMismatch, openedAtMs)
    }

    /**
     * One exchange-archive line per request (a no-op unless `-Draijin.archiveDir` is set). The pipeline
     * keeps only the framed response, so the archived response is rebuilt from it (`reconstructed`).
     */
    private fun archive(
        target: Target,
        requests: List<PipelineRequestSpec>,
        responses: List<Outcome.Ok>,
        progress: List<PipelineWriter.Progress>,
    ) {
        if (!ExchangeArchive.enabled()) return
        val scheme = if (target.useTls) "https" else "http"
        val host = if (':' in target.host && !target.host.startsWith("[")) "[${target.host}]" else target.host
        requests.forEachIndexed { i, spec ->
            // A request the writer never started did not reach the wire.
            if ((progress.getOrNull(i)?.written ?: 0) == 0) return@forEachIndexed
            val firstLine = String(spec.bytes, Charsets.ISO_8859_1).substringBefore('\n').trimEnd('\r')
            val parts = firstLine.split(' ')
            val method = parts.getOrElse(0) { "" }
            val path = parts.getOrElse(1) { "" }
            val response = responses.getOrNull(i)?.response
            val rebuilt = response?.let { r ->
                buildString {
                    append(r.statusLine).append("\r\n")
                    r.headers.forEach { (name, value) -> append(name).append(": ").append(value).append("\r\n") }
                    append("\r\n").append(r.body)
                }.toByteArray(Charsets.ISO_8859_1)
            }
            ExchangeArchive.appendRaw(
                "http_send_pipeline", method, "$scheme://$host:${target.port}$path",
                spec.bytes, rebuilt, response?.statusCode, reconstructed = true
            )
        }
    }

    /** Responses read, and why reading stopped: [failure] is the outcome that ended it early. */
    private class Reading(
        val responses: List<Outcome.Ok>,
        val failure: Outcome?,
        val closeReason: String,
        val error: String?,
        val reusable: Boolean,
    )

    private fun readResponses(reader: HttpPipelineFraming.Reader, requests: List<PipelineRequestSpec>, maxResponses: Int?): Reading {
        val responses = ArrayList<Outcome.Ok>()
        var reusable = true
        repeat(maxResponses ?: requests.size) { i ->
            val isHead = requests.getOrNull(i)?.let { extractRequestMethod(it.bytes) }?.equals("HEAD", ignoreCase = true) == true
            when (val outcome = reader.next(expectNoBody = isHead)) {
                is Outcome.Ok -> {
                    responses += outcome
                    if (!outcome.response.persistent) reusable = false
                    // After 101 the connection no longer speaks HTTP/1.1, so nothing more can be framed.
                    if (outcome.response.statusCode == 101) return Reading(responses, null, "switching_protocols", null, reusable)
                }
                is Outcome.Eof -> return Reading(responses, outcome, "fin", null, reusable)
                is Outcome.TimedOut ->
                    return Reading(responses, outcome, if (outcome.kind == "total") "total_timeout" else "idle", null, reusable)
                is Outcome.Reset -> return Reading(responses, outcome, "rst", outcome.message, reusable)
                is Outcome.Malformed -> return Reading(responses, outcome, "error", outcome.reason, reusable)
            }
        }
        return Reading(responses, null, "max_responses", null, reusable)
    }

    /**
     * Lets the writer finish within the deadline. Past it, or right away with [stopNow], it is
     * stopped and [socket] closed so a blocked write returns. True when it finished on its own.
     */
    private fun awaitWriter(writing: Thread, control: WriteControl, socket: Socket, deadlineAtMs: Long, stopNow: Boolean): Boolean {
        if (!stopNow) writing.join((deadlineAtMs - System.currentTimeMillis()).coerceAtLeast(1))
        if (!writing.isAlive) return true
        control.stop()
        socket.closeAbortively()
        writing.join(WRITER_STOP_MS)
        return false
    }

    /** Closes [socket]; when it came from the registry under [connectionId], also drops that (locked) [entry]. */
    private fun retire(socket: Socket, connectionId: String?, entry: HttpPipelineConnectionRegistry.Entry?) {
        if (connectionId != null && entry != null) {
            HttpPipelineConnectionRegistry.remove(connectionId, entry)
        } else {
            socket.closeAbortively()
        }
    }

    private fun extractRequestMethod(bytes: ByteArray): String? {
        val text = String(bytes, 0, minOf(bytes.size, 32), Charsets.ISO_8859_1)
        val sp = text.indexOf(' ')
        return if (sp > 0) text.substring(0, sp) else null
    }

    private fun responseJson(
        index: Int,
        ok: Outcome.Ok,
        t0: Long,
        requestEndNanos: Long?,
        maxResponseLength: Int?,
        decodeContent: Boolean,
        rawHexMaxBytes: Int,
    ): JsonObject = buildJsonObject {
        val r = ok.response
        put("index", index)
        put("status_line", r.statusLine)
        put("status_code", r.statusCode)
        put("framing", r.framing)
        put("connection_close_header", r.connectionCloseHeader)
        put("headers", fieldsJson(r.headers))
        val wireBody = r.body.toByteArray(Charsets.ISO_8859_1)
        val decoded = if (decodeContent) contentEncoding(r.headers)?.let { HttpContentDecoding.decode(wireBody, it, brotli) } else null
        val renderedBody = BodyText.render(HttpContentDecoding.text(decoded?.body ?: wireBody), maxResponseLength)
        put("body", renderedBody.text)
        if (renderedBody.binary) put("body_binary", true)
        if (renderedBody.truncated) put("body_truncated", true)
        if (decoded != null) {
            if (decoded.applied.isNotEmpty()) putJsonArray("decoded_codings") { decoded.applied.forEach { add(it) } }
            decoded.error?.let { put("decode_error", it) }
        }
        if (r.trailers.isNotEmpty()) put("trailers", fieldsJson(r.trailers))
        if (r.warnings.isNotEmpty()) put("warnings", buildJsonArray { r.warnings.forEach { add(it) } })
        putWire(ok.received, t0, requestEndNanos, rawHexMaxBytes)
    }

    /**
     * [wire]'s bytes and arrival times (ms after [t0]); ttfb/ttlb count from [requestEndNanos],
     * when the request with the same index was completely written.
     */
    private fun JsonObjectBuilder.putWire(wire: HttpPipelineFraming.Received, t0: Long, requestEndNanos: Long?, rawHexMaxBytes: Int) {
        if (rawHexMaxBytes > 0) {
            put("raw_response_hex", HttpContentDecoding.hex(wire.bytes))
            if (wire.truncated) put("raw_response_truncated", true)
        }
        put("raw_response_bytes", wire.length)
        put("first_byte_ms", millis(wire.firstByteAtNanos - t0))
        put("last_byte_ms", millis(wire.lastByteAtNanos - t0))
        if (requestEndNanos != null) {
            put("ttfb_ms", millis(wire.firstByteAtNanos - requestEndNanos))
            put("ttlb_ms", millis(wire.lastByteAtNanos - requestEndNanos))
        }
    }

    private fun requestJson(index: Int, spec: PipelineRequestSpec, p: PipelineWriter.Progress, t0: Long): JsonObject = buildJsonObject {
        put("index", index)
        put("bytes", spec.bytes.size)
        put("bytes_written", p.written)
        p.startNanos?.let { put("write_start_ms", millis(it - t0)) }
        p.endNanos?.let { put("write_end_ms", millis(it - t0)) }
        if (p.pauses.isNotEmpty()) {
            putJsonArray("pauses") {
                p.pauses.forEach { pause ->
                    add(buildJsonObject {
                        put("offset", pause.offset)
                        put("at_ms", millis(pause.atNanos - t0))
                        put("duration_ms", millis(pause.nanos))
                        put("ended_by", pause.endedBy)
                    })
                }
            }
        }
    }

    private fun contentEncoding(headers: List<Pair<String, String>>): String? =
        headers.filter { it.first.equals("Content-Encoding", ignoreCase = true) }.joinToString(",") { it.second }.ifBlank { null }

    private fun fieldsJson(fields: List<Pair<String, String>>): JsonArray = buildJsonArray {
        fields.forEach { (name, value) -> add(buildJsonObject { put("name", name); put("value", value) }) }
    }

    private fun failure(phase: String, message: String): JsonObject = buildJsonObject {
        put("error", message)
        put("phase", phase)
    }

    companion object {
        const val DEFAULT_RAW_HEX_MAX_BYTES = 65_536

        private const val LOCK_WAIT_MS = 2_000L
        private const val MAX_CONNECT_TIMEOUT_MS = 10_000L

        /** How long a stopped writer gets to return once its socket is closed. */
        private const val WRITER_STOP_MS = 2_000L

        private val CLOSE_RESULT_KEYS = listOf(
            "closed" to HttpPipelineConnectionRegistry.CloseResult.CLOSED,
            "unknown" to HttpPipelineConnectionRegistry.CloseResult.UNKNOWN,
            "busy" to HttpPipelineConnectionRegistry.CloseResult.BUSY,
        )

        /** [nanos] as milliseconds with microsecond precision. */
        private fun millis(nanos: Long): Double = Math.round(nanos / 1_000.0) / 1_000.0
    }
}

/**
 * Between the thread writing a call's requests and the one reading its responses: the reader
 * reports data and a closed connection, the call can stop the writer, and the writer says when it
 * is done so the idle timeout starts counting only then.
 */
private class WriteControl : HttpPipelineFraming.Activity {

    /** How a wait ended, as `ended_by` reports it. */
    enum class End(val label: String) {
        ELAPSED("pause_ms"),
        DATA("data"),
        CLOSED("connection_closed"),
        STOPPED("stopped"),
    }

    private val lock = ReentrantLock()
    private val changed = lock.newCondition()
    private var arrivals = 0L
    private var peerClosed = false
    private var stopped = false

    @Volatile
    private var writesEndedAtMs: Long? = null

    override fun dataArrived() = lock.withLock {
        arrivals++
        changed.signalAll()
    }

    override fun quietSinceMs(): Long? = writesEndedAtMs

    fun writesEnded() {
        writesEndedAtMs = System.currentTimeMillis()
    }

    /** The server closed or reset the connection. */
    fun peerClosed() = lock.withLock {
        peerClosed = true
        changed.signalAll()
    }

    fun stop() = lock.withLock {
        stopped = true
        changed.signalAll()
    }

    fun stopped(): Boolean = lock.withLock { stopped }

    /** How many reads have returned data so far. */
    fun arrivals(): Long = lock.withLock { arrivals }

    /**
     * Waits up to [nanos]. With [dataSeen] (an [arrivals] count) the wait also ends as soon as more
     * data has arrived or the server has closed the connection; a stop always ends it.
     */
    fun await(nanos: Long, dataSeen: Long?): End {
        lock.lock()
        try {
            var left = nanos
            while (true) {
                if (stopped) return End.STOPPED
                if (dataSeen != null && arrivals != dataSeen) return End.DATA
                if (dataSeen != null && peerClosed) return End.CLOSED
                if (left <= 0) return End.ELAPSED
                left = changed.awaitNanos(left)
            }
        } finally {
            lock.unlock()
        }
    }
}

/**
 * Writes the requests of one call on its own thread. In concat mode every byte up to the next
 * pause goes out in one write; in single_write mode each request, or each piece of one around its
 * pauses, is its own write, with [gapMs] between requests. A pause ends after the request's
 * `pauseMs`, or as soon as data arrives that came after the write before it began.
 */
private class PipelineWriter(
    private val out: OutputStream,
    private val requests: List<PipelineRequestSpec>,
    private val singleWrite: Boolean,
    private val gapMs: Long,
    private val control: WriteControl,
) {
    class Pause(val offset: Int, val atNanos: Long, val nanos: Long, val endedBy: String)

    /** A request's bytes in completed writes, when the first of those writes began and the one with its last byte ended. */
    class Progress(val written: Int, val startNanos: Long?, val endNanos: Long?, val pauses: List<Pause>)

    private class Stopped : Exception()

    /** Offset of each request in the bytes of all requests back to back; the last entry is their total. */
    private val starts = IntArray(requests.size + 1).also { s ->
        requests.forEachIndexed { i, r -> s[i + 1] = s[i] + r.bytes.size }
    }

    val total: Int get() = starts[requests.size]

    private val combined: ByteArray? = if (singleWrite) null else ByteArray(total).also { all ->
        requests.forEachIndexed { i, r -> r.bytes.copyInto(all, starts[i]) }
    }

    // Guarded by this: read by the calling thread while (or after) the writer thread updates them.
    private val written = IntArray(requests.size)
    private val startNanos = arrayOfNulls<Long>(requests.size)
    private val endNanos = arrayOfNulls<Long>(requests.size)
    private val pauses = List(requests.size) { ArrayList<Pause>() }

    // Writer thread only: the first request not completely written, and the data count a pause compares with.
    private var current = 0
    private var dataSeen = 0L

    @Volatile
    var startedAtNanos: Long? = null
        private set

    @Volatile
    var firstWriteAtNanos: Long? = null
        private set

    @Volatile
    var bytesWritten: Long = 0
        private set

    @Volatile
    var error: String? = null
        private set

    fun run() {
        startedAtNanos = System.nanoTime()
        try {
            dataSeen = control.arrivals()
            var pending = 0
            requests.forEachIndexed { i, spec ->
                if (singleWrite && i > 0 && gapMs > 0) hold(gapMs)
                for (offset in spec.pauseOffsets) {
                    val at = starts[i] + offset
                    write(pending, at)
                    pending = at
                    pause(i, offset, spec.pauseMs)
                }
                if (singleWrite) {
                    write(pending, starts[i + 1])
                    pending = starts[i + 1]
                }
            }
            write(pending, total)
        } catch (e: IOException) {
            error = "write failed with $bytesWritten of $total request bytes written: ${e.message ?: e.javaClass.simpleName}"
        } catch (_: Stopped) {
            error = "stopped with $bytesWritten of $total request bytes written"
        } catch (_: InterruptedException) {
            error = "interrupted with $bytesWritten of $total request bytes written"
        } finally {
            control.writesEnded()
        }
    }

    /** Writes bytes [from, to) of all requests back to back in one call. */
    private fun write(from: Int, to: Int) {
        if (to <= from) return
        if (control.stopped()) throw Stopped()
        dataSeen = control.arrivals()
        val before = System.nanoTime()
        if (firstWriteAtNanos == null) firstWriteAtNanos = before
        if (combined != null) {
            out.write(combined, from, to - from)
        } else {
            out.write(requests[current].bytes, from - starts[current], to - from)
        }
        out.flush()
        val after = System.nanoTime()
        bytesWritten += to - from
        synchronized(this) {
            var i = current
            while (i < requests.size && starts[i] < to) {
                written[i] += minOf(to, starts[i + 1]) - maxOf(from, starts[i])
                if (startNanos[i] == null) startNanos[i] = before
                if (starts[i + 1] <= to) endNanos[i] = after
                i++
            }
        }
        while (current < requests.size && starts[current + 1] <= to) current++
    }

    private fun pause(request: Int, offset: Int, ms: Long) {
        if (control.stopped()) throw Stopped()
        val at = System.nanoTime()
        val end = control.await(TimeUnit.MILLISECONDS.toNanos(ms), dataSeen)
        val took = System.nanoTime() - at
        synchronized(this) { pauses[request] += Pause(offset, at, took, end.label) }
        dataSeen = control.arrivals()
        if (end == WriteControl.End.STOPPED) throw Stopped()
    }

    /** `write_pause_ms` between requests: a plain wait that only a stop cuts short. */
    private fun hold(ms: Long) {
        if (control.await(TimeUnit.MILLISECONDS.toNanos(ms), null) == WriteControl.End.STOPPED) throw Stopped()
    }

    fun progress(): List<Progress> = synchronized(this) {
        requests.indices.map { Progress(written[it], startNanos[it], endNanos[it], pauses[it].toList()) }
    }
}
