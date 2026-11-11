package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
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
 * so a bug here cannot regress a running Turbo campaign, and it never calls [HttpBridge]'s
 * `fixContentLength` — a deliberately-wrong declared Content-Length is the entire point of this
 * tool. HTTP/2, HTTP/3 and kettled H2-smuggling escape fields remain Turbo-only; see
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
        if (httpMode != null && httpMode != "HTTP_1") {
            return buildJsonObject {
                put("error", "http_send_pipeline only supports HTTP_1 in this version. HTTP/2, HTTP/3 and kettled H2 fields are Turbo-only (turbo_start_run with Engine.HTTP2 / Engine.HTTP3 / kettled=True).")
                put("phase", "validate")
            }
        }
        if (requests.isEmpty()) {
            return buildJsonObject { put("error", "'requests' must contain at least one item"); put("phase", "validate") }
        }
        val specs = try {
            requests.map(::decodeRequestSpec)
        } catch (e: Exception) {
            return buildJsonObject { put("error", e.message ?: "invalid request spec"); put("phase", "validate") }
        }

        val scheme = if (useTls) "https" else "http"
        scopeGate.deny("$scheme://$host:$port/")?.let { return it }

        var entry: HttpPipelineConnectionRegistry.Entry? = null
        var connectionReused = false
        var connectionMismatch = false
        var lockedExistingEntry = false

        val socket: Socket = try {
            if (connectionId != null) {
                val existing = HttpPipelineConnectionRegistry.get(connectionId)
                if (existing != null) {
                    if (!existing.lock.tryLock(2, TimeUnit.SECONDS)) {
                        return buildJsonObject { put("error", "connection_id '$connectionId' is in use by a concurrent call"); put("phase", "connect") }
                    }
                    lockedExistingEntry = true
                    if (existing.host == host && existing.port == port && existing.useTls == useTls && !existing.socket.isClosed) {
                        entry = existing
                        connectionReused = true
                        existing.socket
                    } else {
                        connectionMismatch = true
                        existing.lock.unlock()
                        lockedExistingEntry = false
                        HttpPipelineConnectionRegistry.remove(connectionId)
                        connect(host, port, useTls, totalTimeoutMs)
                    }
                } else {
                    connect(host, port, useTls, totalTimeoutMs)
                }
            } else {
                connect(host, port, useTls, totalTimeoutMs)
            }
        } catch (e: Exception) {
            return buildJsonObject { put("error", "connect failed: ${e.message}"); put("phase", "connect") }
        }

        try {
            val bytesSent = try {
                writeRequests(socket, specs, writeMode, writePauseMs)
            } catch (e: Exception) {
                runCatching { socket.close() }
                connectionId?.let { HttpPipelineConnectionRegistry.remove(it) }
                return buildJsonObject {
                    put("error", "write failed: ${e.message}")
                    put("phase", "write")
                    put("connection_reused", connectionReused)
                }
            }

            val wanted = maxResponses ?: specs.size
            val totalDeadline = System.currentTimeMillis() + totalTimeoutMs
            val carry = StringBuilder()
            val responses = mutableListOf<JsonObject>()
            var bytesReceived = 0L
            var closeReason = "max_responses"
            var errorMessage: String? = null

            for (i in 0 until wanted) {
                val outcome = HttpPipelineFraming.readOne(socket, carry, idleTimeoutMs, totalDeadline)
                bytesReceived += outcome.bytesReadFromSocket
                when (outcome) {
                    is HttpPipelineFraming.Outcome.Ok -> responses += serializeResponse(i, outcome.response, maxResponseLength)
                    is HttpPipelineFraming.Outcome.Eof -> { closeReason = "fin"; break }
                    is HttpPipelineFraming.Outcome.TimedOut -> { closeReason = if (outcome.kind == "total") "total_timeout" else "idle"; break }
                    is HttpPipelineFraming.Outcome.Reset -> { closeReason = "rst"; errorMessage = outcome.message; break }
                    is HttpPipelineFraming.Outcome.Malformed -> { closeReason = "error"; errorMessage = outcome.reason; break }
                }
            }

            // Only offer connection reuse when every requested response framed cleanly — a broken
            // or ambiguous read leaves the socket's framing state indeterminate, so it is not safe
            // to hand back to a later call.
            val keepAlive = keepOpen && closeReason == "max_responses"
            val resultConnectionId = if (keepAlive) (connectionId ?: UUID.randomUUID().toString()) else null

            if (keepAlive) {
                val newEntry = entry ?: HttpPipelineConnectionRegistry.Entry(socket, host, port, useTls)
                newEntry.lastUsedAtMs = System.currentTimeMillis()
                HttpPipelineConnectionRegistry.put(resultConnectionId!!, newEntry)
            } else {
                runCatching { socket.close() }
                connectionId?.let { HttpPipelineConnectionRegistry.remove(it) }
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
            runCatching { socket.close() }
            connectionId?.let { HttpPipelineConnectionRegistry.remove(it) }
            return buildJsonObject { put("error", "pipeline failed: ${e.message}"); put("phase", "read") }
        } finally {
            if (lockedExistingEntry) entry?.lock?.unlock()
        }
    }

    private fun decodeRequestSpec(obj: JsonObject): PipelineRequestSpec {
        val hex = obj["raw_request_hex"]?.jsonPrimitive?.contentOrNull
        val str = obj["raw_request"]?.jsonPrimitive?.contentOrNull
        val bytes = hex?.chunked(2)?.map { it.toInt(16).toByte() }?.toByteArray()
            ?: str?.replace("\\r\\n", "\r\n")?.replace("\\n", "\n")?.toByteArray(Charsets.ISO_8859_1)
            ?: throw IllegalArgumentException("each item in 'requests' must have 'raw_request' or 'raw_request_hex'")
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
        plain.connect(InetSocketAddress(host, port), connectTimeoutMs)
        if (!useTls) return plain
        val ssl = trustAllSslSocketFactory().createSocket(plain, host, port, true) as SSLSocket
        val params = ssl.sslParameters
        params.applicationProtocols = arrayOf("http/1.1")
        ssl.sslParameters = params
        ssl.startHandshake()
        return ssl
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
        put("headers", buildJsonArray {
            r.headers.forEach { (name, value) -> add(buildJsonObject { put("name", name); put("value", value) }) }
        })
        val body = if (maxResponseLength != null && maxResponseLength > 0 && r.body.length > maxResponseLength) {
            r.body.take(maxResponseLength) + "... [truncated, full length: ${r.body.length}]"
        } else {
            r.body
        }
        put("body", body)
        if (r.warnings.isNotEmpty()) put("warnings", buildJsonArray { r.warnings.forEach { add(it) } })
    }
}
