package io.bitbytelab.raijin.bridge

import burp.api.montoya.core.Annotations
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.safety.RequestHygiene
import io.bitbytelab.raijin.state.TrafficRule
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.ByteArrayOutputStream
import java.time.Instant
import burp.api.montoya.core.ByteArray as BurpByteArray

/**
 * Applies the operator's [TrafficRule]s (`http_set_traffic_rule`) in the global HTTP handler:
 * matching, header edits, and the drop / spoof_response actions.
 *
 * Header edits are written exactly as stored. A canonical `Name: value` edit goes through Montoya's
 * header API (byte-identical result, and it works on HTTP/2 header lists); anything else (a line
 * without a colon, CR/LF inside it, odd spacing such as `Transfer-Encoding : chunked`) is spliced
 * into the message's header block as raw text by [RawHeaderEdit], so a rule can inject a second
 * line or a malformed header on purpose.
 */
internal class TrafficRuleApplier(private val eventBus: EventBus) {

    sealed class RequestOutcome {
        /** A drop / spoof_response rule answered for the request: it is not sent. */
        class Terminated(val action: RequestToBeSentAction) : RequestOutcome()

        /** The request to send; [modified] when a modify rule changed it. */
        class Continue(val request: HttpRequest, val modified: Boolean) : RequestOutcome()
    }

    /**
     * Applies the request rules among [rules] that match. [outgoing] is the request as it will be
     * sent so far (Raijin's internal marker already removed). The first matching drop /
     * spoof_response rule wins over every modify rule.
     */
    fun onRequest(
        rules: Collection<TrafficRule>,
        requestToBeSent: HttpRequestToBeSent,
        outgoing: HttpRequest,
        toolName: String?,
        internalProbe: Boolean,
        annotations: Annotations,
    ): RequestOutcome {
        val matching = rules.filter { rule ->
            rule.enabled && rule.direction.equals("request", ignoreCase = true) &&
                HttpBridge.trafficRuleAppliesTo(rule, toolName, internalProbe) &&
                matchesRequest(rule, outgoing)
        }
        if (matching.isEmpty()) return RequestOutcome.Continue(outgoing, modified = false)

        // Falls through to the modify pipeline when the running Burp predates Montoya 2026.7 (no
        // drop()/spoof()) or the stored spoof_response text is not an HTTP response.
        val terminating = matching.firstOrNull { it.action.equals("drop", true) || it.action.equals("spoof_response", true) }
        if (terminating != null) {
            terminate(terminating, requestToBeSent, annotations)?.let { return RequestOutcome.Terminated(it) }
        }

        val modifyRules = matching.filter { it.action.equals("modify", true) }
        var current = outgoing
        for (rule in modifyRules) {
            current = applyToRequest(rule, current)
            eventBus.emit("http.traffic_rule.applied", buildJsonObject {
                put("rule_id", rule.ruleId)
                put("direction", "request")
                put("action", "modify")
                put("url", requestToBeSent.url())
                put("timestamp", Instant.now().toString())
            })
        }
        return RequestOutcome.Continue(current, modified = modifyRules.isNotEmpty())
    }

    /** Applies the response rules among [rules] that match; null when none does. */
    fun onResponse(
        rules: Collection<TrafficRule>,
        responseReceived: HttpResponseReceived,
        toolName: String?,
        internalProbe: Boolean,
    ): HttpResponse? {
        val matching = rules.filter { rule ->
            rule.enabled && rule.direction.equals("response", ignoreCase = true) &&
                HttpBridge.trafficRuleAppliesTo(rule, toolName, internalProbe) &&
                matchesResponse(rule, responseReceived)
        }
        if (matching.isEmpty()) return null
        var current: HttpResponse = responseReceived
        for (rule in matching) {
            current = applyToResponse(rule, current)
            eventBus.emit("http.traffic_rule.applied", buildJsonObject {
                put("rule_id", rule.ruleId)
                put("direction", "response")
                try {
                    put("url", responseReceived.initiatingRequest()?.url() ?: "")
                } catch (_: Exception) {
                }
                put("timestamp", Instant.now().toString())
            })
        }
        return current
    }

    private fun matchesRequest(rule: TrafficRule, request: HttpRequest): Boolean {
        if (rule.matchUrl != null && !RuleMatcher.url(rule.matchUrl, request.url())) return false
        if (rule.matchHost != null && !RuleMatcher.host(rule.matchHost, request.httpService().host())) return false
        if (rule.matchHeader != null && !RuleMatcher.headers(rule.matchHeader, request.headers())) return false
        return true
    }

    private fun matchesResponse(rule: TrafficRule, response: HttpResponseReceived): Boolean {
        if (rule.matchUrl != null) {
            val url = try { response.initiatingRequest()?.url() } catch (_: Exception) { null }
            if (!RuleMatcher.url(rule.matchUrl, url)) return false
        }
        if (rule.matchHost != null) {
            val host = try { response.initiatingRequest()?.httpService()?.host() } catch (_: Exception) { null }
            if (!RuleMatcher.host(rule.matchHost, host)) return false
        }
        if (rule.matchHeader != null && !RuleMatcher.headers(rule.matchHeader, response.headers())) return false
        return true
    }

    private fun applyToRequest(rule: TrafficRule, request: HttpRequest): HttpRequest {
        var modified = request
        rule.modifyAddHeader?.let { line ->
            val canonical = RawHeaderEdit.canonical(line)
            modified = if (canonical != null) {
                modified.withAddedHeader(canonical.first, canonical.second)
            } else {
                rawRequest(modified) { RawHeaderEdit.addLine(it, line) }
            }
        }
        rule.modifyRemoveHeader?.let { modified = modified.withRemovedHeader(it) }
        rule.modifyReplaceHeader?.forEach { (name, value) ->
            modified = if (RawHeaderEdit.canonical("$name: $value") != null) {
                modified.withUpdatedHeader(name, value)
            } else {
                rawRequest(modified) { RawHeaderEdit.replace(it, name, value) }
            }
        }
        // Named cookie pairs merged into the Cookie header, the request's other pairs kept.
        rule.modifySetCookies?.let { modified = AuditAuthRules.withCookies(modified, it) }
        return modified
    }

    private fun applyToResponse(rule: TrafficRule, response: HttpResponse): HttpResponse {
        var modified = response
        rule.modifyAddHeader?.let { line ->
            val canonical = RawHeaderEdit.canonical(line)
            modified = if (canonical != null) {
                modified.withAddedHeader(canonical.first, canonical.second)
            } else {
                rawResponse(modified) { RawHeaderEdit.addLine(it, line) }
            }
        }
        rule.modifyRemoveHeader?.let { modified = modified.withRemovedHeader(it) }
        rule.modifyReplaceHeader?.forEach { (name, value) ->
            modified = if (RawHeaderEdit.canonical("$name: $value") != null) {
                modified.withUpdatedHeader(name, value)
            } else {
                rawResponse(modified) { RawHeaderEdit.replace(it, name, value) }
            }
        }
        return modified
    }

    private fun rawRequest(request: HttpRequest, edit: (ByteArray) -> ByteArray): HttpRequest =
        HttpRequest.httpRequest(request.httpService(), BurpByteArray.byteArray(*edit(request.toByteArray().bytes)))

    private fun rawResponse(response: HttpResponse, edit: (ByteArray) -> ByteArray): HttpResponse =
        HttpResponse.httpResponse(BurpByteArray.byteArray(*edit(response.toByteArray().bytes)))

    /**
     * The drop / spoof_response action of [rule], through Montoya's `RequestToBeSentAction.drop()` /
     * `.spoof()` (Montoya 2026.7). Null, with an `http.traffic_rule.degraded` event, when the running
     * Burp is older ([NoSuchMethodError]) or the stored spoof_response text does not parse: the
     * request is then sent.
     */
    private fun terminate(rule: TrafficRule, requestToBeSent: HttpRequestToBeSent, annotations: Annotations): RequestToBeSentAction? {
        fun degraded(reason: String) = eventBus.emit("http.traffic_rule.degraded", buildJsonObject {
            put("rule_id", rule.ruleId)
            put("action", rule.action.lowercase())
            put("url", requestToBeSent.url())
            put("reason", reason)
            put("timestamp", Instant.now().toString())
        })
        fun applied(action: String) = eventBus.emit("http.traffic_rule.applied", buildJsonObject {
            put("rule_id", rule.ruleId)
            put("direction", "request")
            put("action", action)
            put("url", requestToBeSent.url())
            put("timestamp", Instant.now().toString())
        })

        if (rule.action.equals("drop", true)) {
            return try {
                RequestToBeSentAction.drop(annotations).also { applied("drop") }
            } catch (_: NoSuchMethodError) {
                degraded("drop() needs Burp's Montoya API 2026.7 or later; this Burp is older, so the request was sent instead.")
                null
            }
        }

        val spoofText = rule.spoofResponse
        if (spoofText == null) {
            degraded("spoof_response action has no stored response text; the request was sent instead.")
            return null
        }
        val spoofed = try {
            HttpResponse.httpResponse(RequestHygiene.normalizeCrlf(spoofText))
        } catch (e: Exception) {
            degraded("spoof_response text could not be parsed as an HTTP response (${e.message}); the request was sent instead.")
            return null
        }
        return try {
            RequestToBeSentAction.spoof(spoofed, annotations).also { applied("spoof_response") }
        } catch (_: NoSuchMethodError) {
            degraded("spoof() needs Burp's Montoya API 2026.7 or later; this Burp is older, so the request was sent instead.")
            null
        }
    }
}

/**
 * Raw edits of an HTTP message's header block, on its bytes. The message is read one char per byte
 * (ISO-8859-1), so nothing outside the edit changes; an inserted line containing a character above
 * U+00FF is written as UTF-8.
 */
internal object RawHeaderEdit {

    /** RFC 9110 token characters, the only ones Montoya's header API is given. */
    private val TOKEN = Regex("[!#$%&'*+\\-.^_`|~0-9A-Za-z]+")

    /**
     * (name, value) when [line] is exactly `Name: value` as Montoya's header API would write it (a
     * token name, one space after the colon, no CR/LF); null for anything that has to be written raw.
     */
    fun canonical(line: String): Pair<String, String>? {
        val colon = line.indexOf(": ")
        if (colon <= 0) return null
        val name = line.substring(0, colon)
        val value = line.substring(colon + 2)
        if (!TOKEN.matches(name) || value.contains('\r') || value.contains('\n')) return null
        return name to value
    }

    /** [message] with [line] (and a CRLF) added as the last line of its header block. */
    fun addLine(message: ByteArray, line: String): ByteArray {
        val text = String(message, Charsets.ISO_8859_1)
        return splice(message, text, emptyList(), headerBlockEnd(text), line)
    }

    /**
     * [message] without its header lines named [name] (case-insensitive; the request or status line
     * is never touched) and with `name: value` added as the last header line.
     */
    fun replace(message: ByteArray, name: String, value: String): ByteArray {
        val text = String(message, Charsets.ISO_8859_1)
        val end = headerBlockEnd(text)
        val removed = ArrayList<IntRange>()
        var lineStart = lineEnd(text, 0, end)
        while (lineStart < end) {
            val next = lineEnd(text, lineStart, end)
            val colon = text.indexOf(':', lineStart)
            if (colon in lineStart until next && text.substring(lineStart, colon).trim().equals(name.trim(), ignoreCase = true)) {
                removed += lineStart until next
            }
            lineStart = next
        }
        return splice(message, text, removed, end, "$name: $value")
    }

    /** Offset right after the last header line's CRLF, where a new header line goes. */
    private fun headerBlockEnd(text: String): Int {
        val blank = text.indexOf("\r\n\r\n")
        return if (blank >= 0) blank + 2 else text.length
    }

    /** Offset after the line starting at [from] (its CRLF included), at most [limit]. */
    private fun lineEnd(text: String, from: Int, limit: Int): Int {
        val crlf = text.indexOf("\r\n", from)
        return if (crlf < 0 || crlf + 2 > limit) limit else crlf + 2
    }

    /** [message] without [cuts] (all before [insertAt]) and with [line] plus CRLF written at [insertAt]. */
    private fun splice(message: ByteArray, text: String, cuts: List<IntRange>, insertAt: Int, line: String): ByteArray {
        val out = ByteArrayOutputStream(message.size + line.length * 2 + 4)
        var cursor = 0
        for (cut in cuts.sortedBy { it.first }) {
            out.write(message, cursor, cut.first - cursor)
            cursor = cut.last + 1
        }
        out.write(message, cursor, insertAt - cursor)
        // A header block that does not end in a line break gets one before the new line.
        if (insertAt > 0 && !text.regionMatches(insertAt - 2, "\r\n", 0, 2)) out.write(CRLF)
        out.write(line.toByteArray(RequestHygiene.wireCharset(line)))
        out.write(CRLF)
        out.write(message, insertAt, message.size - insertAt)
        return out.toByteArray()
    }

    private val CRLF = byteArrayOf('\r'.code.toByte(), '\n'.code.toByte())
}
