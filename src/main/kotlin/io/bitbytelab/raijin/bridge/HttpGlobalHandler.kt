package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.ToolType
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.safety.BoundedHttp
import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.time.Instant
import java.util.Collections

/**
 * The [HttpHandler] Raijin registers once with Burp ([HttpBridge.createGlobalHttpHandler]): applies
 * the [StateManager]'s traffic rules ([TrafficRuleApplier]), session rules ([SessionInjection],
 * [SessionRuleEngine]) and session login macros ([SessionMacroEngine]) to every outgoing request and
 * incoming response.
 *
 * Raijin's own internal probes (auth_diff, autorize, idor_hunt, access-control sweep: sent by
 * [BoundedHttp.sendInternal], so tool EXTENSIONS plus [BoundedHttp.INTERNAL_BYPASS_HEADER]) skip
 * every session rule, every login macro and every traffic rule whose tool filter does not name
 * EXTENSIONS, on the request and on the response path. An unauthenticated probe therefore never
 * leaves with a re-injected Cookie/Authorization or a macro cookie, never triggers a re-login, and
 * its response never overwrites an extracted session value.
 *
 * Login macro traffic (tool EXTENSIONS plus [SessionMacroEngine.MARKER_HEADER]): a macro step is
 * sent as stored (traffic rules apply, session values and macro cookies do not); a retry is sent as
 * the engine built it (it went through the traffic rules once already, as the original request).
 * Session rules extract from both responses, and neither ever triggers a macro.
 *
 * Neither marker header reaches the wire. [HttpExchangeJson.REAUTHENTICATED_HEADER] on a response
 * only ever comes from a login macro: the same header sent by a server is removed.
 */
internal class HttpGlobalHandler(
    private val api: MontoyaApi,
    private val eventBus: EventBus,
    private val stateManager: StateManager,
    private val sessionMacros: SessionMacroEngine,
) : HttpHandler {

    private val trafficRules = TrafficRuleApplier(eventBus)

    /** Internal probes still waiting for their response; bounded because a dropped probe never gets one. */
    private val internalProbeMessageIds: MutableMap<Int, Boolean> = Collections.synchronizedMap(
        object : LinkedHashMap<Int, Boolean>(256, 0.75f, false) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Int, Boolean>): Boolean = size > 4096
        }
    )

    override fun handleHttpRequestToBeSent(requestToBeSent: HttpRequestToBeSent): RequestToBeSentAction {
        val toolName = try { requestToBeSent.toolSource().toolType().name } catch (_: Exception) { null }
        val fromExtension = toolName == ToolType.EXTENSIONS.name
        val marked = try { requestToBeSent.hasHeader(BoundedHttp.INTERNAL_BYPASS_HEADER) } catch (_: Exception) { false }
        val macroMarker = try { requestToBeSent.headerValue(SessionMacroEngine.MARKER_HEADER) } catch (_: Exception) { null }
        val internalProbe = marked && fromExtension
        val macroTraffic = if (fromExtension && !internalProbe) SessionMacroEngine.Traffic.of(macroMarker) else null
        val messageId = try { requestToBeSent.messageId() } catch (_: Exception) { null }
        if (messageId != null) {
            if (internalProbe) internalProbeMessageIds[messageId] = true
            if (macroTraffic != null) sessionMacros.trackMacroTraffic(messageId, macroTraffic)
        }
        var outgoing: HttpRequest = requestToBeSent
        if (marked) outgoing = outgoing.withRemovedHeader(BoundedHttp.INTERNAL_BYPASS_HEADER)
        if (macroMarker != null) outgoing = outgoing.withRemovedHeader(SessionMacroEngine.MARKER_HEADER)
        val annotations = requestToBeSent.annotations()

        // A retry already went through the traffic rules as the original request, and the macro
        // engine gave it the refreshed session values.
        if (macroTraffic == SessionMacroEngine.Traffic.RETRY) return RequestToBeSentAction.continueWith(outgoing, annotations)

        var currentRequest = when (
            val outcome = trafficRules.onRequest(stateManager.trafficRules, requestToBeSent, outgoing, toolName, internalProbe, annotations)
        ) {
            is TrafficRuleApplier.RequestOutcome.Terminated -> return outcome.action
            is TrafficRuleApplier.RequestOutcome.Continue -> outcome.request
        }

        // Session handling: macro cookies replace same-named ones, then session rules inject their
        // values. Never for internal probes, nor for macro steps, which are sent as stored.
        if (!internalProbe && macroTraffic == null) {
            val url = requestToBeSent.url()
            val suite by lazy { isInSuiteScope(url) }
            currentRequest = sessionMacros.applyCookies(currentRequest, url, toolName) { suite }
            currentRequest = SessionInjection.applyRules(stateManager.sessionRules, currentRequest, url, { suite }, eventBus)
            if (messageId != null && sessionMacros.hasActive()) sessionMacros.noteSent(messageId, url, toolName) { suite }
        }

        return if (currentRequest === requestToBeSent) {
            RequestToBeSentAction.continueWith(requestToBeSent)
        } else {
            RequestToBeSentAction.continueWith(currentRequest, annotations)
        }
    }

    override fun handleHttpResponseReceived(responseReceived: HttpResponseReceived): ResponseReceivedAction {
        val messageId = try { responseReceived.messageId() } catch (_: Exception) { null }
        val internalProbe = messageId != null && internalProbeMessageIds.remove(messageId) != null
        val macroTraffic = messageId?.let { sessionMacros.takeMacroTraffic(it) }
        val sentEpoch = messageId?.let { sessionMacros.takeSentEpoch(it) }
        val toolName = try { responseReceived.toolSource().toolType().name } catch (_: Exception) { null }

        var modified = trafficRules.onResponse(stateManager.trafficRules, responseReceived, toolName, internalProbe)
        var currentResponse = modified ?: responseReceived
        if (hasHeader(currentResponse, HttpExchangeJson.REAUTHENTICATED_HEADER)) {
            currentResponse = currentResponse.withRemovedHeader(HttpExchangeJson.REAUTHENTICATED_HEADER)
            modified = currentResponse
        }

        if (!internalProbe) extractSessionValues(responseReceived, currentResponse)

        if (!internalProbe && macroTraffic == null) {
            sessionMacros.onResponse(responseReceived, currentResponse, toolName, sentEpoch)?.let { reauthenticated ->
                return ResponseReceivedAction.continueWith(
                    reauthenticated.response,
                    noted(responseReceived.annotations(), reauthenticated.macro),
                )
            }
        }

        return if (modified == null) {
            ResponseReceivedAction.continueWith(responseReceived)
        } else {
            ResponseReceivedAction.continueWith(currentResponse, responseReceived.annotations())
        }
    }

    /** Session rules: extract token/CSRF values from [response] for later injection. */
    private fun extractSessionValues(responseReceived: HttpResponseReceived, response: HttpResponse) {
        val rules = stateManager.sessionRules
        if (rules.none { it.enabled }) return
        val url = try { responseReceived.initiatingRequest()?.url() ?: "" } catch (_: Exception) { "" }
        val suite by lazy { isInSuiteScope(url) }
        val headers: List<HttpHeader> by lazy { try { response.headers() } catch (_: Exception) { emptyList() } }
        val body by lazy { try { response.bodyToString() } catch (_: Exception) { "" } }
        for (rule in rules) {
            if (!rule.enabled) continue
            if (!SessionRuleEngine.inScope(rule.scope, rule.scopePattern, url) { suite }) continue
            val extracted = if (rule.extractFrom.equals("header", ignoreCase = true)) {
                val name = rule.extractHeaderName ?: continue
                SessionRuleEngine.extract(rule, headers.filter { it.name().equals(name, ignoreCase = true) }.map { it.value() }, "")
            } else {
                SessionRuleEngine.extract(rule, emptyList(), body)
            }
            if (extracted != null && extracted != rule.lastExtractedValue) {
                rule.lastExtractedValue = extracted
                eventBus.emit("session.rule.extracted", buildJsonObject {
                    put("rule", rule.ruleName)
                    put("url", url)
                    put("timestamp", Instant.now().toString())
                })
            }
        }
    }

    /** [annotations] with a note saying that [macro] re-established the session for this response. */
    private fun noted(annotations: Annotations, macro: String): Annotations {
        val note = "Raijin: session expired; login macro '$macro' ran and the request was sent again"
        return try {
            val existing = annotations.notes()
            annotations.withNotes(if (existing.isNullOrBlank()) note else "$existing; $note")
        } catch (_: Exception) {
            annotations
        }
    }

    private fun hasHeader(response: HttpResponse, name: String): Boolean =
        try { response.hasHeader(name) } catch (_: Exception) { false }

    private fun isInSuiteScope(url: String): Boolean =
        try { api.scope().isInScope(url) } catch (_: Exception) { false }
}
