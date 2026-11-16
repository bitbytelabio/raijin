package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.core.BodyText
import io.bitbytelab.raijin.safety.RequestHygiene
import io.bitbytelab.raijin.safety.ScopeGate
import kotlinx.serialization.json.*
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.UUID
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

internal class PipelineRequestSpec(val bytes: ByteArray)

/**
 * Sends multiple raw HTTP/1.1 requests over ONE socket connection and reads back multiple
 * responses in order — something Montoya's `api.http().sendRequest()` structurally cannot do (it
 * is strictly one request in, one response out). Needed for HTTP desync / request-smuggling
 * research (0.CL, stage1+stage2 probes) where the agent currently has to drop out of MCP and
 * hand-write a Turbo Python script for this one primitive.
 *
 * Deliberately standalone: does not touch Turbo's RequestEngine/ThreadedRequestEngine/RunManager,
 * so a bug here cannot regress a running Turbo campaign, and it never recomputes Content-Length
 * ([RequestHygiene.fixContentLength]) — a deliberately-wrong declared Content-Length is the entire
 * point of this tool. HTTP/2, HTTP/3 and kettled H2-smuggling escape fields remain Turbo-only; see
 * `tools/http/HttpTools.kt`'s `http_send_pipeline` description.
 */
class HttpPipelineBridge(api: MontoyaApi) {

    private val scopeGate = ScopeGate(api)

    fun send(
        host: String,
        port: Int,
        useTls: Boolean,
        httpMode: String?,
        requests: List<JsonObject>,
        writeMode: String,
        writePauseMs: Long,
        maxResponses: Int?,
        idleTimeoutMs: Long,
        totalTimeoutMs: Long,
        keepOpen: Boolean,
        connectionId: String?,
        maxResponseLength: Int?,
    ): JsonObject {
        if (httpMode != null && !httpMode.equals("HTTP_1", ignoreCase = true)) {
            return buildJsonObject {
                put("error", "http_send_pipeline only supports HTTP_1 in this version. HTTP/2, HTTP/3 and kettled H2 fields are Turbo-only (turbo_start_run with Engine.HTTP2 / Engine.HTTP3 / kettled=True).")
                put("phase", "validate")
            }
        }
        if (requests.isEmpty()) {
            return buildJsonObject { put("error", "'requests' must contain at least one item"); put("phase", "validate") }
        }
        val specs = try {
            requests.mapIndexed(::decodeRequestSpec)
        } catch (e: Exception) {
            return buildJsonObject { put("error", e.message ?: "invalid request spec"); put("phase", "validate") }
        }

        val scheme = if (useTls) "https" else "http"
        scopeGate.deny("$scheme://$host:$port/")?.let { return it }

        // Registry entry whose socket this call uses; non-null exactly while this call holds its lock.
        var entry: HttpPipelineConnectionRegistry.Entry? = null
        var connectionReused = false
        var connectionMismatch = false

        val socket: Socket = try {
            val existing = connectionId?.let { HttpPipelineConnectionRegistry.get(it) }
            when {
                existing == null -> connect(host, port, useTls, totalTimeoutMs)
                !existing.lock.tryLock(2, TimeUnit.SECONDS) ->
                    return buildJsonObject { put("error", "connection_id '$connectionId' is in use by a concurrent call"); put("phase", "connect") }
                existing.host == host && existing.port == port && existing.useTls == useTls && !existing.socket.isClosed -> {
                    entry = existing
                    connectionReused = true
                    existing.socket
                }
                else -> {
                    connectionMismatch = true
                    try {
                        HttpPipelineConnectionRegistry.remove(connectionId, existing)
                    } finally {
                        existing.lock.unlock()
                    }
                    connect(host, port, useTls, totalTimeoutMs)
                }
            }
        } catch (e: Exception) {
            return buildJsonObject { put("error", "connect failed: ${e.message}"); put("phase", "connect") }
        }

        try {
            val bytesSent = try {
                writeRequests(socket, specs, writeMode, writePauseMs)
            } catch (e: Exception) {
                retire(socket, connectionId, entry)
                return buildJsonObject {
                    put("error", "write failed: ${e.message}")
                    put("phase", "write")
                    put("connection_reused", connectionReused)
                }
            }

            val wanted = maxResponses ?: specs.size
            val requestMethods = specs.map { extractRequestMethod(it.bytes) }
            val totalDeadline = System.currentTimeMillis() + totalTimeoutMs
            val carry = StringBuilder()
            val responses = mutableListOf<JsonObject>()
            var bytesReceived = 0L
            var closeReason = "max_responses"
            var errorMessage: String? = null
            var reusable = true

            for (i in 0 until wanted) {
                val isHead = requestMethods.getOrNull(i)?.equals("HEAD", ignoreCase = true) == true
                val outcome = HttpPipelineFraming.readOne(socket, carry, idleTimeoutMs, totalDeadline, expectNoBody = isHead)
                bytesReceived += outcome.bytesReadFromSocket
                when (outcome) {
                    is HttpPipelineFraming.Outcome.Ok -> {
                        responses += serializeResponse(i, outcome.response, maxResponseLength)
                        if (!outcome.response.persistent) reusable = false
                        // After 101 the connection no longer speaks HTTP/1.1, so nothing more can be framed.
                        if (outcome.response.statusCode == 101) { closeReason = "switching_protocols"; break }
                    }
                    is HttpPipelineFraming.Outcome.Eof -> { closeReason = "fin"; break }
                    is HttpPipelineFraming.Outcome.TimedOut -> { closeReason = if (outcome.kind == "total") "total_timeout" else "idle"; break }
                    is HttpPipelineFraming.Outcome.Reset -> { closeReason = "rst"; errorMessage = outcome.message; break }
                    is HttpPipelineFraming.Outcome.Malformed -> { closeReason = "error"; errorMessage = outcome.reason; break }
                }
            }

            // Only offer the socket for reuse when every requested response framed cleanly and the
            // server keeps the connection (no Connection: close, close-delimited body or HTTP/1.0 close).
            val keepAlive = keepOpen && closeReason == "max_responses" && reusable
            val resultConnectionId = if (keepAlive) (connectionId ?: UUID.randomUUID().toString()) else null

            if (keepAlive) {
                val kept = entry ?: HttpPipelineConnectionRegistry.Entry(socket, host, port, useTls)
                kept.lastUsedAtMs = System.currentTimeMillis()
                HttpPipelineConnectionRegistry.put(resultConnectionId!!, kept)
            } else {
                retire(socket, connectionId, entry)
            }

            return buildJsonObject {
                put("connection_id", resultConnectionId)
                put("connection_reused", connectionReused)
                if (connectionMismatch) put("connection_id_target_mismatch", true)
                put("bytes_sent", bytesSent)
                put("bytes_received", bytesReceived)
                put("responses_received", responses.size)
                put("responses", buildJsonArray { responses.forEach { add(it) } })
                put("close_reason", closeReason)
                put("connection_open", keepAlive)
                errorMessage?.let { put("error", it) }
            }
        } catch (e: Exception) {
            retire(socket, connectionId, entry)
            return buildJsonObject { put("error", "pipeline failed: ${e.message}"); put("phase", "read") }
        } finally {
            entry?.lock?.unlock()
        }
    }

    /** Closes [socket]; when it came from the registry under [connectionId], also drops that (locked) [entry]. */
    private fun retire(socket: Socket, connectionId: String?, entry: HttpPipelineConnectionRegistry.Entry?) {
        if (connectionId != null && entry != null) {
            HttpPipelineConnectionRegistry.remove(connectionId, entry)
        } else {
            runCatching { socket.close() }
        }
    }

    private fun decodeRequestSpec(index: Int, obj: JsonObject): PipelineRequestSpec {
        val hex = obj["raw_request_hex"]?.jsonPrimitive?.contentOrNull
        val str = obj["raw_request"]?.jsonPrimitive?.contentOrNull
        val bytes = try {
            when {
                hex != null -> RequestHygiene.decodeHex(hex)
                str != null -> RequestHygiene.unescapeLineEndings(str).let { it.toByteArray(RequestHygiene.wireCharset(it)) }
                else -> throw IllegalArgumentException("must have 'raw_request' or 'raw_request_hex'")
            }
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("requests[$index]: ${e.message}")
        }
        return PipelineRequestSpec(bytes)
    }

    private fun writeRequests(socket: Socket, requests: List<PipelineRequestSpec>, writeMode: String, writePauseMs: Long): Long {
        val out = socket.getOutputStream()
        var sent = 0L
        if (writeMode == "single_write") {
            requests.forEachIndexed { i, req ->
                out.write(req.bytes)
                out.flush()
                sent += req.bytes.size
                if (writePauseMs > 0 && i < requests.lastIndex) Thread.sleep(writePauseMs)
            }
        } else {
            val total = requests.sumOf { it.bytes.size }
            val combined = ByteArray(total)
            var pos = 0
            requests.forEach { req ->
                System.arraycopy(req.bytes, 0, combined, pos, req.bytes.size)
                pos += req.bytes.size
            }
            out.write(combined)
            out.flush()
            sent = total.toLong()
        }
        return sent
    }

    private fun connect(host: String, port: Int, useTls: Boolean, totalTimeoutMs: Long): Socket {
        val connectTimeoutMs = totalTimeoutMs.coerceIn(1, 10_000L).toInt()
        val plain = Socket()
        try {
            plain.connect(InetSocketAddress(host, port), connectTimeoutMs)
            if (!useTls) return plain
            val ssl = trustAllSslSocketFactory().createSocket(plain, host, port, true) as SSLSocket
            // Bounds the handshake: a server that accepts TCP but never answers the ClientHello
            // would otherwise block this call forever.
            ssl.soTimeout = connectTimeoutMs
            val params = ssl.sslParameters
            params.applicationProtocols = arrayOf("http/1.1")
            ssl.sslParameters = params
            ssl.startHandshake()
            return ssl
        } catch (e: Exception) {
            runCatching { plain.close() }
            throw e
        }
    }

    private fun extractRequestMethod(bytes: ByteArray): String? {
        val text = String(bytes, 0, minOf(bytes.size, 32), Charsets.ISO_8859_1)
        val sp = text.indexOf(' ')
        return if (sp > 0) text.substring(0, sp) else null
    }

    private fun trustAllSslSocketFactory(): SSLSocketFactory {
        val context = SSLContext.getInstance("TLS")
        context.init(
            null,
            arrayOf<TrustManager>(object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit
                override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) = Unit
                override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            }),
            SecureRandom(),
        )
        return context.socketFactory
    }

    private fun serializeResponse(index: Int, r: HttpPipelineFraming.Response, maxResponseLength: Int?): JsonObject = buildJsonObject {
        put("index", index)
        put("status_line", r.statusLine)
        put("status_code", r.statusCode)
        put("framing", r.framing)
        put("connection_close_header", r.connectionCloseHeader)
        put("headers", fieldsJson(r.headers))
        val renderedBody = BodyText.render(r.body, maxResponseLength)
        put("body", renderedBody.text)
        if (renderedBody.binary) put("body_binary", true)
        if (renderedBody.truncated) put("body_truncated", true)
        if (r.trailers.isNotEmpty()) put("trailers", fieldsJson(r.trailers))
        if (r.warnings.isNotEmpty()) put("warnings", buildJsonArray { r.warnings.forEach { add(it) } })
    }

    private fun fieldsJson(fields: List<Pair<String, String>>): JsonArray = buildJsonArray {
        fields.forEach { (name, value) -> add(buildJsonObject { put("name", name); put("value", value) }) }
    }
}
