package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.state.WebSocketConnection
import io.bitbytelab.raijin.state.WebSocketMessage
import kotlinx.serialization.json.*
import java.util.concurrent.TimeUnit

/**
 * Arguments of a WebSocket fuzz run ([WebSocketBridge.fuzz]). Exactly one of [connectionId] (send
 * over that open connection) and [url] (open a fresh connection for every payload) is set.
 * Numbers outside their range are clamped and the result says so; they are never an error.
 *
 * @property payloads the payloads, one message each.
 * @property headers extra upgrade headers for [url], as for `websocket_create`.
 * @property subprotocol WebSocket subprotocol for [url].
 * @property template message each payload is placed in, at every occurrence of [marker]; null sends
 *   the payload itself.
 * @property marker placeholder in [template]; null or empty means [WebSocketFuzzPlan.DEFAULT_MARKER].
 * @property payloadEncoding "none", or "json" to escape each payload for a JSON string literal.
 * @property messageType "TEXT", or "BINARY" to send each message base64-decoded as a binary frame.
 * @property setupMessages text messages sent before the payloads: once on [connectionId], on every
 *   fresh connection with [url].
 * @property pattern case-insensitive regex; only server frames containing it count as responses.
 * @property startIndex index of the first payload to send (to resume a run that stopped early).
 * @property delayMs pause between two payloads.
 * @property windowMs longest wait for the responses to one payload.
 * @property idleMs once a response arrived, the window ends after this long without another.
 * @property timeoutMs time budget of the whole run, checked before each payload; 0 means the maximum.
 * @property maxFrameLength characters of each frame (and echoed payload) kept in the result; 0 keeps all.
 */
data class WebSocketFuzzRequest(
    val payloads: List<String>,
    val connectionId: String? = null,
    val url: String? = null,
    val headers: Map<String, String>? = null,
    val subprotocol: String? = null,
    val template: String? = null,
    val marker: String? = null,
    val payloadEncoding: String? = null,
    val messageType: String? = null,
    val setupMessages: List<String> = emptyList(),
    val pattern: String? = null,
    val startIndex: Long = 0,
    val delayMs: Long = 0,
    val windowMs: Long = DEFAULT_WINDOW_MS,
    val idleMs: Long = DEFAULT_IDLE_MS,
    val timeoutMs: Long = DEFAULT_TIMEOUT_MS,
    val maxFrameLength: Long = DEFAULT_MAX_FRAME_LENGTH,
) {
    companion object {
        const val DEFAULT_WINDOW_MS = 2_000L
        const val MAX_WINDOW_MS = 60_000L
        const val DEFAULT_IDLE_MS = 200L
        const val MAX_DELAY_MS = 60_000L

        /** Below the 60 s request timeout many MCP clients apply, so a long run returns a resumable partial result instead. */
        const val DEFAULT_TIMEOUT_MS = 50_000L
        const val MAX_TIMEOUT_MS = 600_000L
        const val DEFAULT_MAX_FRAME_LENGTH = 1_000L
    }
}

/** Turns the payload list of a fuzz run into the frames to send. Pure. */
internal object WebSocketFuzzPlan {

    const val DEFAULT_MARKER = "FUZZ"

    val ENCODINGS = listOf("none", "json")

    /**
     * One frame to send.
     *
     * @property payload the payload as the caller gave it.
     * @property message the frame as text: the payload, encoded and placed in the template.
     * @property bytes the bytes of a binary frame ([message] base64-decoded); null for a text frame.
     */
    class Frame(val payload: String, val message: String, val bytes: ByteArray?)

    sealed class Result {
        class Ok(val frames: List<Frame>) : Result()
        class Error(val message: String) : Result()
    }

    /**
     * @param template message with [marker] wherever the payload goes; null sends each payload as is.
     * @param marker null or empty means [DEFAULT_MARKER].
     * @param encoding one of [ENCODINGS], applied to the payload before it is placed.
     * @param binary each message is base64 of a binary frame.
     */
    fun expand(payloads: List<String>, template: String?, marker: String?, encoding: String, binary: Boolean): Result {
        val placeholder = marker?.takeIf { it.isNotEmpty() } ?: DEFAULT_MARKER
        if (template != null && !template.contains(placeholder)) {
            return Result.Error(
                "Parameter 'template' does not contain the marker '$placeholder'; put it where each payload goes, or set 'marker'"
            )
        }
        val frames = ArrayList<Frame>(payloads.size)
        val notBase64 = ArrayList<Int>()
        payloads.forEachIndexed { index, payload ->
            val encoded = if (encoding == "json") jsonEscape(payload) else payload
            val message = template?.replace(placeholder, encoded) ?: encoded
            val bytes = if (binary) WebSocketFrames.decodeBase64(message) else null
            if (binary && bytes == null) notBase64 += index
            frames += Frame(payload, message, bytes)
        }
        if (notBase64.isNotEmpty()) {
            val listed = notBase64.take(10).joinToString(", ") + if (notBase64.size > 10) ", ..." else ""
            return Result.Error(
                "message_type BINARY sends each message base64-decoded, but the message of payload index $listed is not base64"
            )
        }
        return Result.Ok(frames)
    }

    /** [text] escaped for the inside of a JSON string literal (no surrounding quotes). */
    fun jsonEscape(text: String): String = JsonPrimitive(text).toString().let { it.substring(1, it.length - 1) }
}

/** What a fuzz run needs from the bridge; tests supply an in-memory one. */
internal interface WebSocketFuzzHost {

    /** The outcome of [open]: the new connection, or why there is none. */
    class Opened(val connection: WebSocketConnection?, val error: String?)

    /** True once the extension is unloading: the run stops before its next payload. */
    val stopping: Boolean

    fun find(connectionId: String): WebSocketConnection?

    /** Why nothing can be sent on [connection], or null when it has a live socket. */
    fun unsendableReason(connection: WebSocketConnection): String?

    /** Opens a connection as `websocket_create` does. */
    fun open(url: String, headers: Map<String, String>?, subprotocol: String?): Opened

    /**
     * Records a text frame on [connection], then sends it, and returns its record. Throws when it
     * cannot be sent. Recording first gives the frame a lower index than any reply to it.
     */
    fun sendText(connection: WebSocketConnection, message: String): WebSocketMessage

    /** Binary counterpart of [sendText]. */
    fun sendBinary(connection: WebSocketConnection, bytes: ByteArray): WebSocketMessage

    fun close(connection: WebSocketConnection)
}

/**
 * A WebSocket fuzz run: sends each payload as one frame, collects the server frames it triggers,
 * and clusters the responses.
 *
 * Attribution of frames to payloads. A payload's window starts at the index of its own frame, so
 * nothing recorded before it went out counts as its response. Over one open connection, every
 * server frame recorded after a payload and before the next one went out belongs to the former,
 * so nothing is lost or counted twice; the window only decides when the next payload may go. On a
 * fresh connection per payload, what the server sends first (a greeting, replies to setup messages)
 * is let through before the payload goes out, by waiting until the connection is quiet.
 */
internal object WebSocketFuzz {

    /** Frames listed per payload; `frame_count` still gives the real number. */
    const val MAX_REPORTED_FRAMES = 20

    /** Frames kept per payload; a payload's window ends early once this many arrived. */
    const val MAX_KEPT_FRAMES = 200

    /** Failures to open a fresh connection in a row after which the run stops. */
    const val MAX_OPEN_FAILURES = 3

    private const val SAMPLE_CHARS = 300
    private const val MAX_CLUSTER_INDICES = 50

    /**
     * Validates [request], runs it on the calling thread and returns the tool result.
     *
     * @throws InterruptedException when the calling thread is interrupted; a fresh connection in use
     *   is closed first.
     */
    fun run(request: WebSocketFuzzRequest, host: WebSocketFuzzHost): JsonObject {
        val connectionId = request.connectionId?.takeIf { it.isNotBlank() }
        val url = request.url?.takeIf { it.isNotBlank() }
        if (connectionId != null && url != null) {
            return failure(
                "Provide either 'connection_id' (fuzz over that open connection) or 'url' (a fresh connection per payload), not both"
            )
        }
        if (connectionId == null && url == null) {
            return failure("Provide 'connection_id' (fuzz over that open connection) or 'url' (a fresh connection per payload)")
        }
        WebSocketFrames.messageTypeError(request.messageType)?.let { return failure(it) }
        val binary = WebSocketFrames.normalizeMessageType(request.messageType) == "BINARY"
        val encoding = request.payloadEncoding?.trim()?.lowercase()?.takeIf { it.isNotEmpty() } ?: "none"
        if (encoding !in WebSocketFuzzPlan.ENCODINGS) {
            return failure("Invalid payload_encoding: '${request.payloadEncoding}'. Must be 'none' or 'json'")
        }
        request.pattern?.let { pattern ->
            SafeRegex.validate(pattern, ignoreCase = true)?.let { return failure("Invalid pattern regex: $it") }
        }
        if (request.payloads.isEmpty()) return failure("No payloads: provide 'payloads' and/or 'payload_library'")
        val frames = when (
            val plan = WebSocketFuzzPlan.expand(request.payloads, request.template, request.marker, encoding, binary)
        ) {
            is WebSocketFuzzPlan.Result.Error -> return failure(plan.message)
            is WebSocketFuzzPlan.Result.Ok -> plan.frames
        }
        val shared = connectionId?.let { id ->
            val connection = host.find(id) ?: return failure("Connection not found: $id")
            host.unsendableReason(connection)?.let { return failure(it) }
            connection
        }

        val clamped = LinkedHashMap<String, Long>()
        fun clamp(name: String, value: Long, min: Long, max: Long): Long =
            value.coerceIn(min, max).also { if (it != value) clamped[name] = it }

        val windowMs = clamp("window_ms", request.windowMs, 0, WebSocketFuzzRequest.MAX_WINDOW_MS)
        // The idle time cannot outlast the window; that is not worth reporting as a clamp.
        val idleMs = minOf(clamp("idle_ms", request.idleMs, 0, WebSocketFuzzRequest.MAX_WINDOW_MS), windowMs)
        val delayMs = clamp("delay_ms", request.delayMs, 0, WebSocketFuzzRequest.MAX_DELAY_MS)
        val timeoutMs = if (request.timeoutMs == 0L) {
            WebSocketFuzzRequest.MAX_TIMEOUT_MS
        } else {
            clamp("timeout_ms", request.timeoutMs, 1, WebSocketFuzzRequest.MAX_TIMEOUT_MS)
        }
        val start = clamp("start_index", request.startIndex, 0, frames.size.toLong()).toInt()
        val maxFrameLength = clamp("max_frame_length", request.maxFrameLength, 0, Int.MAX_VALUE.toLong()).toInt()

        val runner = Runner(
            host = host,
            filter = WebSocketFrameFilter(direction = "server_to_client", pattern = request.pattern),
            windowNanos = TimeUnit.MILLISECONDS.toNanos(windowMs),
            idleNanos = TimeUnit.MILLISECONDS.toNanos(idleMs),
            setupMessages = request.setupMessages,
        )
        val began = System.nanoTime()
        val execution = runner.execute(
            frames = frames,
            start = start,
            shared = shared,
            open = { host.open(url.orEmpty(), request.headers, request.subprotocol) },
            delayMs = delayMs,
            budgetNanos = TimeUnit.MILLISECONDS.toNanos(timeoutMs),
        )
        val durationMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - began)

        val exchanges = execution.exchanges
        val clustering = WebSocketFuzzClusters.cluster(exchanges.map { it.toResponse() })
        val responseTimes = exchanges.filter { it.responseNanos >= 0 }
            .map { TimeUnit.NANOSECONDS.toMillis(it.responseNanos) }
            .sorted()

        return buildJsonObject {
            put("mode", if (shared != null) "connection" else "fresh_connection")
            if (shared != null) put("connection_id", shared.connectionId) else put("url", url)
            put("message_type", if (binary) "BINARY" else "TEXT")
            put("total_payloads", frames.size)
            put("start_index", start)
            put("sent", exchanges.count { it.sentIndex >= 0 })
            put("responded", exchanges.count { it.frameCount > 0 })
            put("duration_ms", durationMs)
            put("stopped_early", execution.stopReason != null)
            if (execution.stopReason != null) {
                put("stop_reason", execution.stopReason)
                if (execution.nextIndex < frames.size) put("next_index", execution.nextIndex)
            }
            if (clamped.isNotEmpty()) putJsonObject("clamped") { clamped.forEach { (name, value) -> put(name, value) } }
            if (responseTimes.isNotEmpty()) {
                putJsonObject("response_time_ms") {
                    put("min", responseTimes.first())
                    put("median", responseTimes[responseTimes.size / 2])
                    put("max", responseTimes.last())
                }
            }
            put("clustered_by", clustering.basis)
            putJsonArray("clusters") {
                clustering.clusters.forEachIndexed { id, members -> add(clusterJson(id, members, exchanges)) }
            }
            putJsonArray("results") {
                exchanges.forEachIndexed { position, exchange ->
                    add(exchangeJson(exchange, clustering.clusterOf[position], maxFrameLength, binary, perPayloadConnection = shared == null))
                }
            }
        }
    }

    private fun failure(message: String): JsonObject = buildJsonObject { put("error", message) }

    private fun clusterJson(id: Int, members: List<Int>, exchanges: List<Exchange>): JsonObject = buildJsonObject {
        val sample = exchanges[members[0]]
        put("id", id)
        put("count", members.size)
        if (sample.error != null) put("error", sample.error) else if (sample.frameCount == 0) put("no_response", true)
        if (sample.closed) put("connection_closed", true)
        put("frame_count", sample.frameCount)
        put("sample_index", sample.index)
        put("sample_payload", WebSocketFrames.clip(sample.frame.payload, SAMPLE_CHARS))
        sample.frames.firstOrNull()?.let {
            put("sample", WebSocketFrames.clip(it.payload, SAMPLE_CHARS, WebSocketFrames.isBinary(it.type)))
        }
        putJsonArray("indices") { members.take(MAX_CLUSTER_INDICES).forEach { add(exchanges[it].index) } }
        if (members.size > MAX_CLUSTER_INDICES) put("indices_truncated", true)
    }

    private fun exchangeJson(
        exchange: Exchange,
        cluster: Int,
        maxFrameLength: Int,
        binary: Boolean,
        perPayloadConnection: Boolean,
    ): JsonObject = buildJsonObject {
        val frame = exchange.frame
        put("index", exchange.index)
        putClipped("payload", frame.payload, maxFrameLength, base64 = false)
        if (frame.message != frame.payload) putClipped("message", frame.message, maxFrameLength, base64 = binary)
        if (perPayloadConnection && exchange.connectionId != null) put("connection_id", exchange.connectionId)
        if (exchange.sentIndex >= 0) put("sent_index", exchange.sentIndex)
        if (exchange.error != null) put("error", exchange.error)
        if (exchange.responseNanos >= 0) put("response_ms", TimeUnit.NANOSECONDS.toMillis(exchange.responseNanos))
        if (exchange.closed) put("connection_closed", true)
        if (exchange.missed > 0) put("missed_frames", exchange.missed)
        put("frame_count", exchange.frameCount)
        putJsonArray("frames") {
            exchange.frames.take(MAX_REPORTED_FRAMES).forEach { add(WebSocketFrames.toJson(it, maxFrameLength, brief = true)) }
        }
        if (exchange.frameCount > MAX_REPORTED_FRAMES) put("frames_truncated", true)
        put("cluster", cluster)
    }

    /** Puts [text] under [name], cut to [max] chars (0 keeps all) with a `<name>_truncated` flag when it was cut. */
    private fun JsonObjectBuilder.putClipped(name: String, text: String, max: Int, base64: Boolean) {
        val clipped = WebSocketFrames.clip(text, max, base64)
        put(name, clipped)
        if (clipped.length < text.length) put("${name}_truncated", true)
    }

    /**
     * What one payload produced.
     *
     * @property sentIndex index of the sent frame in its connection's buffer; -1 when it was not sent.
     * @property openFailed no connection could be opened, so the payload was never attempted.
     */
    private class Exchange(
        val index: Int,
        val frame: WebSocketFuzzPlan.Frame,
        val connectionId: String?,
        val sentIndex: Long,
        val error: String? = null,
        val openFailed: Boolean = false,
    ) {
        /** The response frames kept, at most [MAX_REPORTED_FRAMES] (all that is ever read back). */
        val frames = ArrayList<WebSocketMessage>()

        /** Response frames that arrived, kept or not. */
        var frameCount = 0

        /** Time from the send to the first response frame; -1 when none arrived in the window. */
        var responseNanos = -1L

        var closed = false

        /** Messages evicted from the connection's buffer before they could be examined. */
        var missed = 0L

        /** Index of the last message examined for this payload: where its late frames are looked for. */
        var cursor = sentIndex

        fun take(collected: WebSocketWait.Collected) {
            // Only MAX_REPORTED_FRAMES are ever read back (the result list and the cluster
            // signature); MAX_KEPT_FRAMES only bounds how long collect() keeps accepting frames.
            val room = MAX_REPORTED_FRAMES - frames.size
            if (room > 0) frames.addAll(collected.frames.take(room))
            frameCount += collected.frames.size
            missed += collected.missed
            if (collected.cursor > cursor) cursor = collected.cursor
            if (collected.closed) closed = true
        }

        fun toResponse() = WebSocketFuzzClusters.Response(frame.payload, frame.message, frames, frameCount, closed, error)
    }

    /** @property nextIndex index of the first payload that was not dealt with: where a resumed run starts. */
    private class Execution(val exchanges: List<Exchange>, val stopReason: String?, val nextIndex: Int)

    private class Runner(
        private val host: WebSocketFuzzHost,
        private val filter: WebSocketFrameFilter,
        private val windowNanos: Long,
        private val idleNanos: Long,
        private val setupMessages: List<String>,
    ) {
        fun execute(
            frames: List<WebSocketFuzzPlan.Frame>,
            start: Int,
            shared: WebSocketConnection?,
            open: () -> WebSocketFuzzHost.Opened,
            delayMs: Long,
            budgetNanos: Long,
        ): Execution {
            val exchanges = ArrayList<Exchange>(frames.size - start)
            val began = System.nanoTime()
            if (shared != null && start < frames.size) {
                try {
                    prepare(shared, settleFirst = false)
                } catch (e: InterruptedException) {
                    throw e
                } catch (e: Exception) {
                    return Execution(exchanges, "setup message could not be sent: ${describe(e)}", start)
                }
            }

            // Over one connection: the exchange that owns the frames recorded until the next payload goes out.
            var previous: Exchange? = null
            var index = start
            var openFailures = 0
            while (index < frames.size) {
                if (host.stopping) return Execution(exchanges, "extension is unloading", index)
                if (System.nanoTime() - began >= budgetNanos) return Execution(exchanges, "timeout_ms reached", index)
                if (Thread.interrupted()) throw InterruptedException()

                val exchange =
                    if (shared != null) exchange(index, frames[index], shared, previous) else freshExchange(index, frames[index], open)
                exchanges += exchange
                index++
                val more = index < frames.size

                if (shared != null) {
                    if (exchange.error != null) {
                        return Execution(exchanges, "payload ${exchange.index} could not be sent: ${exchange.error}", exchange.index)
                    }
                    previous = exchange
                    if (more && delayMs > 0 && !exchange.closed) Thread.sleep(delayMs)
                    // Frames that arrived after the window, during the delay, still answer this payload.
                    absorbLateFrames(exchange, shared, untilIndex = Long.MAX_VALUE)
                    if (more && exchange.closed) {
                        return Execution(
                            exchanges,
                            "connection closed after payload ${exchange.index}; pass 'url' to continue over fresh connections",
                            index,
                        )
                    }
                } else {
                    if (!exchange.openFailed) {
                        openFailures = 0
                    } else if (++openFailures >= MAX_OPEN_FAILURES) {
                        return Execution(
                            exchanges,
                            "could not open a connection $MAX_OPEN_FAILURES times in a row: ${exchange.error}",
                            index - openFailures,
                        )
                    }
                    if (more && delayMs > 0) Thread.sleep(delayMs)
                }
            }
            return Execution(exchanges, null, frames.size)
        }

        /** Opens a connection for one payload, runs the exchange on it and closes it again. */
        private fun freshExchange(index: Int, frame: WebSocketFuzzPlan.Frame, open: () -> WebSocketFuzzHost.Opened): Exchange {
            val opened = open()
            val connection = opened.connection
                ?: return failed(index, frame, null, opened.error ?: "WebSocket connection could not be opened", openFailed = true)
            try {
                try {
                    prepare(connection, settleFirst = true)
                } catch (e: InterruptedException) {
                    throw e
                } catch (e: Exception) {
                    return failed(index, frame, connection, "setup message could not be sent: ${describe(e)}")
                }
                return exchange(index, frame, connection, previous = null)
            } finally {
                try {
                    host.close(connection)
                } catch (_: Exception) {
                    // Closing is best-effort; the run goes on.
                }
            }
        }

        /**
         * Sends [frame] on [connection] and collects its response window, which starts at the sent
         * frame. Frames recorded before it went out are handed to [previous] instead.
         */
        private fun exchange(
            index: Int,
            frame: WebSocketFuzzPlan.Frame,
            connection: WebSocketConnection,
            previous: Exchange?,
        ): Exchange {
            val began = System.nanoTime()
            val sent = try {
                if (frame.bytes != null) host.sendBinary(connection, frame.bytes) else host.sendText(connection, frame.message)
            } catch (e: InterruptedException) {
                throw e
            } catch (e: Exception) {
                return failed(index, frame, connection, describe(e))
            }
            val sendNanos = System.nanoTime() - began
            if (previous != null) absorbLateFrames(previous, connection, untilIndex = sent.index)
            val window = WebSocketWait.collect(connection, sent.index, filter, windowNanos, idleNanos, maxFrames = MAX_KEPT_FRAMES)
            return Exchange(index, frame, connection.connectionId, sent.index).apply {
                if (window.firstFrameNanos >= 0) responseNanos = sendNanos + window.firstFrameNanos
                take(window)
            }
        }

        private fun failed(
            index: Int,
            frame: WebSocketFuzzPlan.Frame,
            connection: WebSocketConnection?,
            error: String,
            openFailed: Boolean = false,
        ) = Exchange(index, frame, connection?.connectionId, sentIndex = -1, error = error, openFailed = openFailed).apply {
            closed = connection?.status == "closed"
        }

        /** Adds to [exchange] the response frames recorded after its window and before [untilIndex]; never waits. */
        private fun absorbLateFrames(exchange: Exchange, connection: WebSocketConnection, untilIndex: Long) {
            exchange.take(WebSocketWait.collect(connection, exchange.cursor, filter, windowNanos = 0, untilIndex = untilIndex))
        }

        /**
         * Gets [connection] ready for a payload: optionally lets it go quiet first, then sends each
         * setup message and lets its replies pass.
         */
        private fun prepare(connection: WebSocketConnection, settleFirst: Boolean) {
            if (settleFirst) settle(connection, -1L)
            for (message in setupMessages) {
                settle(connection, host.sendText(connection, message).index)
            }
        }

        /** Waits until no response frame has arrived for the idle time, at most one window. */
        private fun settle(connection: WebSocketConnection, since: Long) {
            if (idleNanos > 0) WebSocketWait.collect(connection, since, filter, windowNanos, idleNanos, awaitFirst = false, keepFrames = 0)
        }

        private fun describe(e: Exception): String = e.message ?: e.javaClass.simpleName
    }
}
