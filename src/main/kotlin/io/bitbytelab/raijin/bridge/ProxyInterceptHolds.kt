package io.bitbytelab.raijin.bridge

import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import io.bitbytelab.raijin.bridge.InterceptHoldQueue.Reason
import io.bitbytelab.raijin.bridge.InterceptHoldQueue.Verdict
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.safety.RequestHygiene
import io.bitbytelab.raijin.safety.SafeRegex
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.nio.charset.Charset
import java.time.Instant

/** A proxied message parked in the hold queue. For a response, [request] is the request it answers. */
internal class HeldMessage(
    val isRequest: Boolean,
    val messageId: Int,
    val request: HttpRequest?,
    val response: HttpResponse?,
    val method: String?,
    val url: String?,
    val host: String?,
    val status: Int?,
) {
    val kind: String get() = if (isRequest) "request" else "response"
}

/**
 * An agent's changes to a held message before it is forwarded. [raw] replaces the whole message
 * first; the other fields then apply on top of it, in the order method, path, status code, removed
 * headers, set headers, body. Nothing is checked against the HTTP grammar.
 */
internal data class InterceptEdit(
    val raw: String? = null,
    val autoFixContentLength: Boolean = true,
    val method: String? = null,
    val path: String? = null,
    val statusCode: Int? = null,
    val setHeaders: Map<String, String> = emptyMap(),
    val removeHeaders: List<String> = emptyList(),
    val body: String? = null,
) {
    val isEmpty: Boolean
        get() = raw == null && method == null && path == null && statusCode == null &&
            setHeaders.isEmpty() && removeHeaders.isEmpty() && body == null

    /** Why this edit can never apply to a held request ([isRequest]) or response; null when it can. */
    fun errorFor(isRequest: Boolean): String? = when {
        isRequest && statusCode != null -> "'status_code' applies to a held response; this message is a request"
        !isRequest && (method != null || path != null) -> "'method' and 'path' apply to a held request; this message is a response"
        statusCode != null && statusCode !in 0..ProxyRuleEdits.MAX_STATUS ->
            "'status_code' must be between 0 and ${ProxyRuleEdits.MAX_STATUS} (got $statusCode)"
        setHeaders.keys.any { ProxyRuleEdits.headerName(it).isEmpty() } -> "'set_headers' has an entry without a header name"
        removeHeaders.any { ProxyRuleEdits.headerName(it).isEmpty() } -> "'remove_headers' has an empty header name"
        else -> null
    }
}

/**
 * A raw replacement message made ready for the wire the way `http_send_request(raw_request)` does
 * it: the header block's line endings become CRLF so Burp can delimit the message, the body stays
 * as written, and a single mismatching `Content-Length` is corrected unless the caller opted out
 * (a message framed by `Transfer-Encoding` or several `Content-Length` headers is never touched).
 */
internal class PreparedRaw(val text: String, val charset: Charset, val contentLengthFrom: Int?, val contentLengthTo: Int?) {
    val bytes: ByteArray get() = text.toByteArray(charset)

    companion object {
        fun of(raw: String, autoFixContentLength: Boolean): PreparedRaw {
            val normalized = RequestHygiene.normalizeCrlf(raw)
            val charset = RequestHygiene.wireCharset(normalized)
            if (!autoFixContentLength) return PreparedRaw(normalized, charset, null, null)
            val fix = RequestHygiene.fixContentLength(normalized, utf8Body = charset == Charsets.UTF_8)
            return PreparedRaw(fix.request, charset, fix.rewrittenFrom, fix.rewrittenTo)
        }
    }
}

/**
 * Raijin's proxy intercept queue: holds proxied requests and responses that match an agent-set
 * policy so the agent can list them, edit them, and forward or drop them. Wraps an
 * [InterceptHoldQueue] (which owns the timing and the guarantee that an unanswered hold forwards
 * by itself) with the Montoya message handling and the JSON the tools return.
 *
 * Messages are held at the last stage of the proxy ("to be sent"): after Raijin's proxy rules and
 * Burp's own Intercept tab, so what the agent sees and edits is what goes on the wire.
 */
internal class ProxyInterceptHolds(private val eventBus: EventBus) {

    private val queue = InterceptHoldQueue<HeldMessage>()

    @Volatile
    private var policy = HoldPolicy()

    /**
     * A message that was held and came back.
     *
     * @property message what to carry on with: the held message or the agent's edited one.
     * @property drop the agent dropped it.
     * @property decided an agent forwarded or dropped it (as opposed to a timeout or a release).
     */
    class Offered<M>(val message: M, val drop: Boolean, val decided: Boolean)

    // ---------------------------------------------------------------
    // Proxy handler side
    // ---------------------------------------------------------------

    /**
     * Offers a proxied request to the queue, blocking the calling proxy thread while it is held.
     * Null when it was not held, so the caller carries on exactly as it would without the queue.
     */
    fun holdRequest(messageId: Int, request: HttpRequest, inScope: () -> Boolean): Offered<HttpRequest>? {
        if (!queue.armed) return null
        return try {
            val method = safe { request.method() }
            val url = safe { request.url() }
            val host = safe { request.httpService().host() }
            if (!policy.matches(true, host, url, method, inScope)) return null
            val outcome = park(HeldMessage(true, messageId, request, null, method, url, host, null))
            if (!outcome.wasHeld) return null
            Offered(outcome.replacement?.request ?: request, outcome.verdict == Verdict.DROP, outcome.reason == Reason.DECIDED)
        } catch (_: Exception) {
            null
        }
    }

    /** [holdRequest] for a proxied response; [request] is the request it answers (null when Burp has none). */
    fun holdResponse(
        messageId: Int,
        response: HttpResponse,
        request: HttpRequest?,
        inScope: () -> Boolean,
    ): Offered<HttpResponse>? {
        if (!queue.armed) return null
        return try {
            val method = safe { request?.method() }
            val url = safe { request?.url() }
            val host = safe { request?.httpService()?.host() }
            if (!policy.matches(false, host, url, method, inScope)) return null
            val status = safe { response.statusCode().toInt() }
            val outcome = park(HeldMessage(false, messageId, request, response, method, url, host, status))
            if (!outcome.wasHeld) return null
            Offered(outcome.replacement?.response ?: response, outcome.verdict == Verdict.DROP, outcome.reason == Reason.DECIDED)
        } catch (_: Exception) {
            null
        }
    }

    private fun park(message: HeldMessage): InterceptHoldQueue.Outcome<HeldMessage> {
        var id = 0L
        val outcome = queue.hold(message) { held ->
            id = held.id
            eventBus.emit("proxy.intercept.held", buildJsonObject {
                summary(held, System.currentTimeMillis())
                put("timestamp", Instant.now().toString())
            })
        }
        if (outcome.wasHeld) {
            eventBus.emit("proxy.intercept.released", buildJsonObject {
                put("id", id)
                put("kind", message.kind)
                put("message_id", message.messageId)
                message.url?.let { put("url", it) }
                put("verdict", outcome.verdict.name.lowercase())
                put("reason", outcome.reason.name.lowercase())
                put("modified", outcome.replacement != null)
                put("timestamp", Instant.now().toString())
            })
        }
        return outcome
    }

    // ---------------------------------------------------------------
    // Tool side
    // ---------------------------------------------------------------

    /**
     * Arms the queue for messages matching the given filters. Out-of-range limits are clamped and
     * reported; a pattern that does not compile or an unknown [target] is an error.
     */
    fun arm(
        target: String?,
        matchHost: String?,
        matchUrl: String?,
        matchMethod: String?,
        inScopeOnly: Boolean,
        timeoutSeconds: Int?,
        maxHeld: Int?,
        maxMessages: Int?,
    ): JsonObject {
        val (requests, responses) = HoldPolicy.sides(target)
            ?: return err("Invalid target '$target'. Allowed: request, response, both")
        matchHost?.let { pattern -> ProxyBridge.hostPatternError(pattern)?.let { return err("match_host: $it") } }
        matchUrl?.let { pattern ->
            SafeRegex.validate(pattern, ignoreCase = true)?.let { return err("Invalid match_url regex: $it") }
        }
        if (matchMethod != null && matchMethod.isBlank()) return err("match_method must not be blank")

        val notes = mutableListOf<String>()
        val timeout = ProxyLimits.clamp(
            "timeout_seconds", timeoutSeconds ?: HoldPolicy.DEFAULT_TIMEOUT_SECONDS, 1, HoldPolicy.MAX_TIMEOUT_SECONDS, notes
        )
        val max = ProxyLimits.clamp("max_held", maxHeld ?: HoldPolicy.DEFAULT_MAX_HELD, 1, HoldPolicy.MAX_HELD, notes)
        val budget = maxMessages?.let { ProxyLimits.clamp("max_messages", it, 1, Int.MAX_VALUE, notes) }

        policy = HoldPolicy(requests, responses, matchHost, matchUrl, matchMethod?.trim(), inScopeOnly)
        if (!queue.arm(max, timeout * 1000L, budget)) return err("Raijin is unloading; nothing can be held")
        emitHoldState()
        return status(notes)
    }

    /** Disarms the queue and forwards everything it holds, unchanged. */
    fun release(): JsonObject {
        queue.disarm("released by proxy_intercept action 'release'")
        val released = queue.resolveAll(Verdict.FORWARD, Reason.RELEASED)
        emitHoldState()
        return buildJsonObject {
            put("armed", false)
            put("released", released)
        }
    }

    /** The hold configuration, what is held and the totals; [notes] are appended when given. */
    fun status(notes: List<String> = emptyList()): JsonObject {
        val state = queue.status()
        val current = policy
        return buildJsonObject {
            put("armed", state.armed)
            state.disarmReason?.let { put("disarm_reason", it) }
            if (state.timeoutMs > 0) {
                put("target", current.target)
                current.matchHost?.let { put("match_host", it) }
                current.matchUrl?.let { put("match_url", it) }
                current.matchMethod?.let { put("match_method", it) }
                put("in_scope_only", current.inScopeOnly)
                put("timeout_seconds", state.timeoutMs / 1000)
                put("max_held", state.maxHeld)
                state.remainingMessages?.let { put("remaining_messages", it) }
            }
            put("held", state.held)
            put("totals", buildJsonObject {
                put("held", state.totalHeld)
                put("decided", state.decided)
                put("timed_out", state.timedOut)
                put("passed_queue_full", state.passedQueueFull)
            })
            putNotes(notes)
        }
    }

    /**
     * The messages held right now, oldest first, after waiting up to [waitSeconds] for one to
     * arrive. [includeRaw] adds each message's text, its body cut to [maxLength] characters.
     */
    fun listHeld(waitSeconds: Int?, includeRaw: Boolean, maxLength: Int?): JsonObject {
        val notes = mutableListOf<String>()
        val wait = ProxyLimits.clamp("wait_seconds", waitSeconds ?: 0, 0, MAX_WAIT_SECONDS, notes)
        if (wait > 0) queue.awaitHeld(wait * 1000L)
        val state = queue.status()
        val held = queue.list()
        val now = System.currentTimeMillis()
        return buildJsonObject {
            put("armed", state.armed)
            state.disarmReason?.let { put("disarm_reason", it) }
            put("held", held.size)
            put("messages", buildJsonArray {
                held.forEach { entry ->
                    add(buildJsonObject {
                        summary(entry, now)
                        if (includeRaw) raw(entry.message, maxLength)
                    })
                }
            })
            val recent = queue.recentlyReleased(RECENT_SHOWN)
            if (recent.isNotEmpty()) {
                put("recently_released", buildJsonArray { recent.forEach { add(describe(it)) } })
            }
            putNotes(notes)
        }
    }

    /**
     * Forwards the held message [id] with [edit] applied, or every held message unchanged when
     * [all]. An edit that cannot be applied is an error and leaves the message held.
     */
    fun forward(id: Long?, all: Boolean, edit: InterceptEdit): JsonObject {
        if (all) {
            if (!edit.isEmpty) return err("An edit applies to one message: give its 'id' instead of all=true")
            return buildJsonObject { put("forwarded", queue.resolveAll(Verdict.FORWARD, Reason.DECIDED)) }
        }
        if (id == null) return err("Give the 'id' of a held message (proxy_intercept action 'list_held'), or all=true")
        val entry = queue.find(id) ?: return notHeld(id)
        val message = entry.message
        edit.errorFor(message.isRequest)?.let { return err(it) }

        var rewritten: PreparedRaw? = null
        val replacement = if (edit.isEmpty) {
            null
        } else {
            try {
                rewritten = edit.raw?.let { PreparedRaw.of(it, edit.autoFixContentLength) }
                if (message.isRequest) edited(message, checkNotNull(message.request), edit, rewritten)
                else edited(message, checkNotNull(message.response), edit, rewritten)
            } catch (e: Exception) {
                return err("The edit could not be applied (message $id is still held): ${e.message ?: e.javaClass.simpleName}")
            }
        }
        if (!queue.decide(id, Verdict.FORWARD, replacement)) return notHeld(id)
        return buildJsonObject {
            put("id", id)
            put("kind", message.kind)
            put("forwarded", true)
            put("modified", replacement != null)
            val fix = rewritten
            if (fix?.contentLengthFrom != null) {
                put("content_length_rewritten", buildJsonObject {
                    put("from", fix.contentLengthFrom)
                    put("to", fix.contentLengthTo)
                })
            }
        }
    }

    /** Drops the held message [id], or every held message when [all]. */
    fun drop(id: Long?, all: Boolean): JsonObject {
        if (all) return buildJsonObject { put("dropped", queue.resolveAll(Verdict.DROP, Reason.DECIDED)) }
        if (id == null) return err("Give the 'id' of a held message (proxy_intercept action 'list_held'), or all=true")
        val entry = queue.find(id) ?: return notHeld(id)
        if (!queue.decide(id, Verdict.DROP)) return notHeld(id)
        return buildJsonObject {
            put("id", id)
            put("kind", entry.message.kind)
            put("dropped", true)
        }
    }

    /** Releases everything held and stops holding for good (extension unload). */
    fun shutdown() = queue.close()

    // ---------------------------------------------------------------
    // Edits
    // ---------------------------------------------------------------

    private fun edited(message: HeldMessage, original: HttpRequest, edit: InterceptEdit, raw: PreparedRaw?): HeldMessage {
        var request = original
        if (raw != null) request = HttpRequest.httpRequest(original.httpService(), BurpByteArray.byteArray(*raw.bytes))
        edit.method?.let { request = request.withMethod(it) }
        edit.path?.let { request = request.withPath(it) }
        edit.removeHeaders.forEach { request = HeaderModifier.remove(request, ProxyRuleEdits.headerName(it)) }
        edit.setHeaders.forEach { (name, value) -> request = HeaderModifier.set(request, ProxyRuleEdits.headerName(name), value) }
        edit.body?.let { request = request.withBody(it) }
        return HeldMessage(true, message.messageId, request, null, message.method, message.url, message.host, null)
    }

    private fun edited(message: HeldMessage, original: HttpResponse, edit: InterceptEdit, raw: PreparedRaw?): HeldMessage {
        var response = original
        if (raw != null) response = HttpResponse.httpResponse(BurpByteArray.byteArray(*raw.bytes))
        edit.statusCode?.let { response = response.withStatusCode(it.toShort()) }
        edit.removeHeaders.forEach { response = HeaderModifier.remove(response, ProxyRuleEdits.headerName(it)) }
        edit.setHeaders.forEach { (name, value) -> response = HeaderModifier.set(response, ProxyRuleEdits.headerName(name), value) }
        edit.body?.let { response = response.withBody(it) }
        return HeldMessage(false, message.messageId, message.request, response, message.method, message.url, message.host, message.status)
    }

    // ---------------------------------------------------------------
    // JSON
    // ---------------------------------------------------------------

    private fun JsonObjectBuilder.summary(entry: InterceptHoldQueue.Held<HeldMessage>, nowMs: Long) {
        val message = entry.message
        val heldMs = (nowMs - entry.heldAtMs).coerceAtLeast(0)
        put("id", entry.id)
        put("kind", message.kind)
        put("message_id", message.messageId)
        message.method?.let { put("method", it) }
        message.url?.let { put("url", it) }
        message.host?.let { put("host", it) }
        message.status?.let { put("status_code", it) }
        put("held_ms", heldMs)
        put("expires_in_ms", (entry.timeoutMs - heldMs).coerceAtLeast(0))
    }

    private fun JsonObjectBuilder.raw(message: HeldMessage, maxLength: Int?) {
        val text = safe { (if (message.isRequest) message.request else message.response)?.toString() }
        if (text == null) {
            put("raw", "")
            return
        }
        val rendered = ProxyLimits.renderMessage(text, maxLength ?: DEFAULT_RAW_LENGTH, message.kind)
        put("raw", rendered.text)
        if (rendered.binary) put("raw_binary_body", true)
        if (rendered.truncated) put("raw_truncated", true)
    }

    private fun describe(released: InterceptHoldQueue.Released): JsonObject = buildJsonObject {
        put("id", released.id)
        put("verdict", released.verdict.name.lowercase())
        put("reason", released.reason.name.lowercase())
        if (released.modified) put("modified", true)
    }

    private fun notHeld(id: Long): JsonObject {
        val released = queue.released(id)
        val message = when {
            released == null -> "No held message with id $id."
            released.reason == Reason.TIMEOUT -> "Message $id is no longer held: its hold timed out and it was forwarded unchanged."
            released.reason == Reason.DECIDED ->
                "Message $id is no longer held: it was already " + (if (released.verdict == Verdict.DROP) "dropped." else "forwarded.")
            else -> "Message $id is no longer held: it was released and forwarded unchanged."
        }
        return buildJsonObject {
            put("error", message)
            put("held_ids", buildJsonArray { queue.list().forEach { add(it.id) } })
        }
    }

    private fun JsonObjectBuilder.putNotes(notes: List<String>) {
        if (notes.isNotEmpty()) put("notes", buildJsonArray { notes.forEach { add(it) } })
    }

    private fun emitHoldState() {
        val state = queue.status()
        eventBus.emit("proxy.intercept.hold", buildJsonObject {
            put("armed", state.armed)
            if (state.armed) put("target", policy.target)
            put("timestamp", Instant.now().toString())
        })
    }

    private fun err(message: String): JsonObject = buildJsonObject { put("error", message) }

    /** Runs a Montoya accessor that may throw on malformed data. */
    private inline fun <T> safe(block: () -> T): T? = try {
        block()
    } catch (_: Exception) {
        null
    }

    companion object {
        /** Longest wait of one `list_held` call. */
        const val MAX_WAIT_SECONDS = 60

        /** Default cap on the body text returned per held message. */
        const val DEFAULT_RAW_LENGTH = 20_000

        private const val RECENT_SHOWN = 10
    }
}
