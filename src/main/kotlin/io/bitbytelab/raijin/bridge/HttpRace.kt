package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import io.bitbytelab.raijin.core.BodyText
import io.bitbytelab.raijin.safety.RequestHygiene
import io.bitbytelab.raijin.safety.ScopeGate
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicIntegerArray
import java.util.concurrent.atomic.AtomicReferenceArray
import kotlin.math.max
import kotlin.math.roundToLong
import burp.api.montoya.core.ByteArray as BurpByteArray

/**
 * `http_race`: releases a batch of requests at once behind a real synchronisation barrier, then
 * clusters the responses ([HttpResponseClusters]) to show whether the race changed the outcome.
 *
 * - [Sync.SINGLE_PACKET]: the HTTP/2 single-packet attack, through Burp's synchronised parallel
 *   sender (Montoya `sendRequests` in HTTP/2 mode: what Repeater's "send group in parallel" and
 *   Turbo's gated BURP2 engine use). The final frames of every request leave in one TCP packet, so
 *   network jitter cannot separate them.
 * - [Sync.LAST_BYTE]: HTTP/1.1 last-byte synchronisation on Raijin's own connections
 *   ([LastByteSync]): every request is written except its final byte, and once every connection is
 *   primed the final bytes go out back to back. These requests bypass Burp (no session handling,
 *   not in the site map); the bytes are sent exactly as planned.
 */
internal class HttpRace(
    private val api: MontoyaApi,
    private val scopeGate: ScopeGate,
    private val timeouts: HttpTimeouts,
) {

    enum class Sync(val id: String) {
        SINGLE_PACKET("single_packet"),
        LAST_BYTE("last_byte");

        companion object {
            val ids: List<String> = entries.map { it.id }

            fun of(id: String?): Sync? = entries.firstOrNull { it.id.equals(id?.trim(), ignoreCase = true) }
        }
    }

    /**
     * @param texts the request texts (Content-Length already fixed), sent in [RequestHygiene.wireCharset].
     * @param payloads the payload of each request when the batch was built from payloads.
     * @param mode for single_packet, [HttpMode.HTTP_2_IGNORE_ALPN] forces HTTP/2 without ALPN; any
     *   other mode sends HTTP/2.
     * @param sni TLS server name for last_byte connections (null = host, "" = none).
     * @param timeoutMs hard timeout for the whole batch; null or 0 = none for single_packet, and
     *   [LAST_BYTE_MAX_MS] for last_byte, whose sockets always need a bound.
     */
    fun run(
        texts: List<String>,
        payloads: List<String>?,
        host: String,
        port: Int,
        useTls: Boolean,
        sync: Sync,
        mode: HttpMode,
        sni: String?,
        maxBodyLength: Int?,
        timeoutMs: Long?,
        similarity: Double,
    ): JsonObject {
        val scope = scopeGate.checkRequests(host, port, useTls, texts.asSequence().ifEmpty { sequenceOf("") })
        if (scope.blocked) return scope.denyJson()
        val result = try {
            when (sync) {
                Sync.SINGLE_PACKET -> singlePacket(texts, payloads, host, port, useTls, mode, maxBodyLength, timeoutMs, similarity)
                Sync.LAST_BYTE -> lastByte(texts, payloads, host, port, useTls, sni, maxBodyLength, timeoutMs, similarity)
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Race condition test failed: ${e.message}")
                put("is_timeout", e is HttpRequestTimeoutException)
            }
        }
        return scope.annotate(result)
    }

    private fun singlePacket(
        texts: List<String>,
        payloads: List<String>?,
        host: String,
        port: Int,
        useTls: Boolean,
        mode: HttpMode,
        maxBodyLength: Int?,
        timeoutMs: Long?,
        similarity: Double,
    ): JsonObject {
        val service = HttpService.httpService(host, port, useTls)
        val h2Mode = if (mode == HttpMode.HTTP_2_IGNORE_ALPN) HttpMode.HTTP_2_IGNORE_ALPN else HttpMode.HTTP_2
        // As Turbo's gated BURP2 engine does: the request line names HTTP/2, the version the batch goes out in.
        val batch = texts.map { text ->
            val h2Text = text.replaceFirst("HTTP/1.1\r\n", "HTTP/2\r\n")
            HttpRequest.httpRequest(service, BurpByteArray.byteArray(*h2Text.toByteArray(RequestHygiene.wireCharset(h2Text))))
        }
        val start = System.nanoTime()
        val exchanges: List<HttpRequestResponse?> = timeouts.run(timeoutMs) { api.http().sendRequests(batch, h2Mode) }
        val totalMs = (System.nanoTime() - start) / 1_000_000

        val clusters = HttpResponseClusters.Builder(similarity)
        val results = ArrayList<JsonObject>(texts.size)
        var http1Responses = 0
        texts.indices.forEach { index ->
            val exchange = exchanges.getOrNull(index)
            val payload = payloads?.getOrNull(index)
            val response = exchange?.takeIf { it.hasResponse() }?.response()
            if (response != null && !response.httpVersion().orEmpty().startsWith("HTTP/2")) http1Responses++
            val ttfbMs = exchange?.let { ex ->
                runCatching { ex.timingData().orElse(null)?.timeBetweenRequestSentAndStartOfResponse()?.toNanos() }.getOrNull()
            }?.let { it / 1_000_000.0 }
            clusters.add(
                HttpResponseClusters.Sample(
                    index,
                    response?.statusCode()?.toInt() ?: 0,
                    response?.body()?.length() ?: 0,
                    response?.bodyToString() ?: "",
                    ttfbMs,
                    payload,
                )
            )
            if (exchange != null) api.recordToolExchange(exchange, "[MCP] Race single_packet #$index via Raijin", "http_race")
            results += buildJsonObject {
                put("index", index)
                if (payload != null) put("payload", payload)
                if (exchange != null) {
                    HttpExchangeJson.serialize(exchange, null, maxBodyLength).forEach { (k, v) -> put(k, v) }
                } else {
                    put("has_response", false)
                    put("error", "Burp returned no exchange for this request")
                }
            }
        }
        val summary = clusters.build()
        val notes = ArrayList<String>()
        if (summary.clusterCount == 0) {
            notes += "No request was answered. single_packet needs a target that speaks HTTP/2 (http_mode HTTP_2_IGNORE_ALPN " +
                "forces it without ALPN); for an HTTP/1.1 target use sync=last_byte."
        }
        if (http1Responses > 0) {
            notes += "$http1Responses response(s) came back over HTTP/1.x, so those requests were not part of a single packet; " +
                "use sync=last_byte for an HTTP/1.1 target."
        }
        return buildJsonObject {
            put("sync", Sync.SINGLE_PACKET.id)
            put("http_mode", h2Mode.name)
            put("total_requests", texts.size)
            put("total_elapsed_ms", totalMs)
            put("analysis", HttpResponseClusters.raceAnalysis(summary, payloads == null, similarity))
            put("results", buildJsonArray { results.forEach { result -> add(withCluster(result, summary)) } })
            if (notes.isNotEmpty()) putJsonArray("notes") { notes.forEach { add(it) } }
        }
    }

    private fun lastByte(
        texts: List<String>,
        payloads: List<String>?,
        host: String,
        port: Int,
        useTls: Boolean,
        sni: String?,
        maxBodyLength: Int?,
        timeoutMs: Long?,
        similarity: Double,
    ): JsonObject {
        val notes = ArrayList<String>()
        val sent = if (texts.size > MAX_LAST_BYTE_CONNECTIONS) {
            notes += "last_byte opens one connection per request: the first $MAX_LAST_BYTE_CONNECTIONS of ${texts.size} requests were sent."
            texts.take(MAX_LAST_BYTE_CONNECTIONS)
        } else {
            texts
        }
        val budgetMs = timeoutMs?.takeIf { it > 0 } ?: LAST_BYTE_MAX_MS
        val connectTimeoutMs = budgetMs.coerceIn(1, CONNECT_TIMEOUT_MS).toInt()
        val sync = LastByteSync { RawHttpConnector.connect(host, port, useTls, connectTimeoutMs, sni) }
        val result = sync.run(
            requests = sent.map { it.toByteArray(RequestHygiene.wireCharset(it)) },
            expectNoBody = sent.map { it.startsWith("HEAD ", ignoreCase = true) },
            totalTimeoutMs = budgetMs,
        )

        val clusters = HttpResponseClusters.Builder(similarity)
        val entries = result.outcomes.map { outcome ->
            val payload = payloads?.getOrNull(outcome.index)
            val ok = outcome.response as? HttpPipelineFraming.Outcome.Ok
            val response = ok?.response
            val bodyBytes = response?.body?.length ?: 0
            // The framing reader holds bytes one char each; show them as UTF-8 text when they are UTF-8.
            val bodyText = response?.let { HttpContentDecoding.text(it.body.toByteArray(Charsets.ISO_8859_1)) }.orEmpty()
            val ttfbMs = if (ok != null && outcome.releasedAtNanos != null) millis(ok.firstByteAtNanos - outcome.releasedAtNanos) else null
            clusters.add(HttpResponseClusters.Sample(outcome.index, response?.statusCode ?: 0, bodyBytes, bodyText, ttfbMs, payload))
            buildJsonObject {
                put("index", outcome.index)
                if (payload != null) put("payload", payload)
                put("has_response", response != null)
                outcome.releasedAtNanos?.let { put("released_at_us", (it - result.releaseStartNanos) / 1000) }
                if (response != null) {
                    put("status_code", response.statusCode)
                    put("status_line", response.statusLine)
                    put("response_headers", buildJsonArray {
                        response.headers.forEach { (name, value) -> add(buildJsonObject { put("name", name); put("value", value) }) }
                    })
                    put("response_body_length", bodyBytes)
                    val rendered = BodyText.render(bodyText, maxBodyLength)
                    put("response_body", rendered.text)
                    if (rendered.binary) put("response_body_binary", true)
                    if (rendered.truncated) put("response_body_truncated", true)
                    put("framing", response.framing)
                    if (response.warnings.isNotEmpty()) putJsonArray("warnings") { response.warnings.forEach { add(it) } }
                    ttfbMs?.let { put("ttfb_ms", it) }
                    outcome.releasedAtNanos?.let { put("ttlb_ms", millis(ok.lastByteAtNanos - it)) }
                } else {
                    put("error", outcome.error ?: failure(outcome.response))
                }
            }
        }
        val summary = clusters.build()
        if (result.primed < sent.size) {
            notes += "${sent.size - result.primed} of ${sent.size} connections were not ready at the barrier and were not released."
        }
        return buildJsonObject {
            put("sync", Sync.LAST_BYTE.id)
            put("total_requests", sent.size)
            put("primed_connections", result.primed)
            put("release_spread_us", (result.releaseEndNanos - result.releaseStartNanos) / 1000)
            put("total_elapsed_ms", result.elapsedMs)
            put("analysis", HttpResponseClusters.raceAnalysis(summary, payloads == null, similarity))
            put("results", buildJsonArray { entries.forEach { add(withCluster(it, summary)) } })
            if (notes.isNotEmpty()) putJsonArray("notes") { notes.forEach { add(it) } }
        }
    }

    private fun withCluster(result: JsonObject, summary: HttpResponseClusters.Summary): JsonObject {
        val index = (result["index"] as? JsonPrimitive)?.content?.toIntOrNull() ?: return result
        val cluster = summary.clusterOf[index] ?: return result
        return JsonObject(result + ("cluster" to JsonPrimitive(cluster)))
    }

    private fun failure(outcome: HttpPipelineFraming.Outcome?): String = when (outcome) {
        null -> "not sent"
        is HttpPipelineFraming.Outcome.Ok -> "no response"
        is HttpPipelineFraming.Outcome.Eof -> "connection closed (fin) before a response"
        is HttpPipelineFraming.Outcome.TimedOut -> "timed out (${outcome.kind}) waiting for the response"
        is HttpPipelineFraming.Outcome.Reset -> "connection reset: ${outcome.message}"
        is HttpPipelineFraming.Outcome.Malformed -> "malformed response: ${outcome.reason}"
    }

    private fun millis(nanos: Long): Double = (nanos / 1000.0).roundToLong() / 1000.0

    companion object {
        /** last_byte opens one connection per request; beyond this the batch is cut (with a note). */
        const val MAX_LAST_BYTE_CONNECTIONS = 256

        /** Budget of a last_byte batch when no timeout was given. */
        const val LAST_BYTE_MAX_MS = 600_000L

        private const val CONNECT_TIMEOUT_MS = 10_000L
    }
}

/**
 * HTTP/1.1 last-byte synchronisation. Every request goes out on its own connection except for its
 * final byte; once every connection holds its request minus that byte (the barrier) the final bytes
 * are written back to back from one thread, and each connection's response is read
 * ([HttpPipelineFraming.readOne]). A connection that is not primed when the barrier closes (connect
 * or write failed, or the budget ran out) is reported and never released.
 *
 * @param connect opens the connection for request i.
 */
internal class LastByteSync(private val connect: (Int) -> Socket) {

    /**
     * @param response the response read after the release; null when the request was not released.
     * @param error why the request was not released (connect, write or release failure).
     * @param releasedAtNanos `System.nanoTime()` right after its final byte was written.
     */
    class Outcome(
        val index: Int,
        val response: HttpPipelineFraming.Outcome?,
        val error: String?,
        val releasedAtNanos: Long?,
    )

    /** @param primed connections that reached the barrier; releases ran from [releaseStartNanos] to [releaseEndNanos]. */
    class Result(
        val outcomes: List<Outcome>,
        val primed: Int,
        val releaseStartNanos: Long,
        val releaseEndNanos: Long,
        val elapsedMs: Long,
    )

    fun run(
        requests: List<ByteArray>,
        expectNoBody: List<Boolean> = List(requests.size) { false },
        totalTimeoutMs: Long,
        maxResponseBytes: Int = HttpPipelineFraming.DEFAULT_MAX_RESPONSE_BYTES,
    ): Result {
        val n = requests.size
        val started = System.nanoTime()
        val deadlineMs = System.currentTimeMillis() + totalTimeoutMs
        if (n == 0) return Result(emptyList(), 0, started, started, 0)

        val sockets = AtomicReferenceArray<Socket?>(n)
        val errors = AtomicReferenceArray<String?>(n)
        // PENDING -> PRIMED by the worker, PENDING -> ABANDONED by the barrier: whichever comes first wins.
        val state = AtomicIntegerArray(n)
        val primedLatch = CountDownLatch(n)
        val pool: ExecutorService = Executors.newFixedThreadPool(n) { runnable ->
            Thread(runnable, "raijin-race-${System.nanoTime()}").apply { isDaemon = true }
        }
        val released = arrayOfNulls<Long>(n)
        val responses = arrayOfNulls<HttpPipelineFraming.Outcome>(n)
        try {
            for (i in 0 until n) {
                pool.submit {
                    var socket: Socket? = null
                    try {
                        socket = connect(i)
                        // Registered at once, so the cleanup closes it even if priming hangs past the run.
                        sockets.set(i, socket)
                        val bytes = requests[i]
                        if (bytes.size > 1) {
                            val out = socket.getOutputStream()
                            out.write(bytes, 0, bytes.size - 1)
                            out.flush()
                        }
                        if (!state.compareAndSet(i, PENDING, PRIMED)) {
                            sockets.set(i, null)
                            runCatching { socket.close() }
                        }
                    } catch (e: Exception) {
                        errors.set(i, "connect or write failed: ${e.message ?: e.javaClass.simpleName}")
                        sockets.set(i, null)
                        runCatching { socket?.close() }
                        state.compareAndSet(i, PENDING, ABANDONED)
                    } finally {
                        primedLatch.countDown()
                    }
                }
            }

            // The barrier: every connection primed, or the budget for priming used up.
            primedLatch.await(remaining(deadlineMs), TimeUnit.MILLISECONDS)
            // A connection still pending is abandoned here (its worker closes it when it gets that far).
            val ready = (0 until n).filter { i -> !state.compareAndSet(i, PENDING, ABANDONED) && state.get(i) == PRIMED }
            for (i in 0 until n) {
                if (i !in ready && errors.get(i) == null) errors.set(i, "not connected and primed before the barrier deadline")
            }

            // The release: the withheld final bytes, back to back from this one thread.
            val releaseStart = System.nanoTime()
            for (i in ready) {
                val bytes = requests[i]
                try {
                    if (bytes.isNotEmpty()) {
                        val out = sockets.get(i)!!.getOutputStream()
                        out.write(bytes, bytes.size - 1, 1)
                        out.flush()
                    }
                    released[i] = System.nanoTime()
                } catch (e: Exception) {
                    errors.set(i, "final byte could not be written: ${e.message ?: e.javaClass.simpleName}")
                }
            }
            val releaseEnd = System.nanoTime()
            // Priming that used up the budget must not leave released requests no time to answer.
            val readDeadlineMs = max(deadlineMs, System.currentTimeMillis() + MIN_READ_MS)

            val reads = HashMap<Int, Future<HttpPipelineFraming.Outcome>>()
            for (i in ready) {
                if (released[i] == null) continue
                val socket = sockets.get(i)!!
                reads[i] = pool.submit<HttpPipelineFraming.Outcome> {
                    val idle = max(1L, readDeadlineMs - System.currentTimeMillis())
                    HttpPipelineFraming.readOne(socket, StringBuilder(), idle, readDeadlineMs, maxResponseBytes, expectNoBody.getOrElse(i) { false })
                }
            }
            for ((i, future) in reads) {
                responses[i] = try {
                    future.get(remaining(readDeadlineMs) + READ_GRACE_MS, TimeUnit.MILLISECONDS)
                } catch (e: Exception) {
                    errors.set(i, "reading the response failed: ${e.message ?: e.javaClass.simpleName}")
                    null
                }
            }
            val outcomes = (0 until n).map { i -> Outcome(i, responses[i], errors.get(i), released[i]) }
            return Result(outcomes, ready.size, releaseStart, releaseEnd, (System.nanoTime() - started) / 1_000_000)
        } finally {
            for (i in 0 until n) runCatching { sockets.get(i)?.close() }
            pool.shutdownNow()
        }
    }

    private fun remaining(deadlineMs: Long): Long = max(0L, deadlineMs - System.currentTimeMillis())

    private companion object {
        const val PENDING = 0
        const val PRIMED = 1
        const val ABANDONED = 2

        /** Reads are bounded by the deadline themselves; this only covers a reader slow to notice it. */
        const val READ_GRACE_MS = 1_000L

        /** Least time released requests get to answer, whatever priming took. */
        const val MIN_READ_MS = 5_000L
    }
}
