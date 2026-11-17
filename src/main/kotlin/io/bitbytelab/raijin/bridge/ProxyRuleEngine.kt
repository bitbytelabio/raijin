package io.bitbytelab.raijin.bridge

import burp.api.montoya.core.Annotations
import burp.api.montoya.core.HighlightColor
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.http.InterceptedRequest
import burp.api.montoya.proxy.http.InterceptedResponse
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction
import io.bitbytelab.raijin.bridge.ProxyBridge.Companion.RULE_TYPES
import io.bitbytelab.raijin.bridge.ProxyBridge.Companion.safe
import io.bitbytelab.raijin.bridge.ProxyBridge.Companion.validateRule
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.state.ProxyRule
import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.*
import java.time.Instant

/**
 * The proxy rules of [ProxyBridge]: kept in [StateManager.proxyRules] once
 * [ProxyBridge.validateRule] accepts them, and applied to the traffic its proxy handlers see. A
 * matching rule drops, modifies ([ProxyRuleEdits]) or tags the message, and each rule applied is
 * emitted as a "proxy.rule.applied" event.
 */
internal class ProxyRuleEngine(
    private val eventBus: EventBus,
    private val stateManager: StateManager,
) {
    /** Serialises rule writes so concurrent sets of one id cannot both append. */
    private val ruleLock = Any()

    /** Validates [rule] and stores it, replacing (in place) any rule with the same id. */
    fun setRule(rule: ProxyRule): JsonObject {
        validateRule(rule)?.let { return buildJsonObject { put("error", it) } }
        synchronized(ruleLock) {
            var replaced = false
            stateManager.proxyRules.replaceAll { existing ->
                if (existing.ruleId == rule.ruleId) {
                    replaced = true
                    rule
                } else {
                    existing
                }
            }
            if (!replaced) stateManager.proxyRules.add(rule)
        }
        return buildJsonObject {
            put("rule_set", true)
            put("rule_id", rule.ruleId)
            put("type", rule.type)
            put("action", rule.action)
            put("total_rules", stateManager.proxyRules.size)
        }
    }

    /** Lists proxy rules, optionally only "request" or "response" ones. */
    fun listRules(type: String?): JsonObject {
        val wanted = type?.trim()?.lowercase()
        if (wanted != null && wanted !in RULE_TYPES) {
            return buildJsonObject { put("error", "Invalid type '$type'. Allowed: request, response") }
        }
        val rules = stateManager.proxyRules.filter { wanted == null || it.type.equals(wanted, ignoreCase = true) }
        return buildJsonObject {
            put("total", rules.size)
            put("rules", buildJsonArray { rules.forEach { add(serializeProxyRule(it)) } })
        }
    }

    /** Removes the rule with [ruleId]; `removed` is false when there was none. */
    fun removeRule(ruleId: String): JsonObject {
        val removed = synchronized(ruleLock) { stateManager.proxyRules.removeIf { it.ruleId == ruleId } }
        return buildJsonObject {
            put("rule_id", ruleId)
            put("removed", removed)
            put("remaining_rules", stateManager.proxyRules.size)
        }
    }

    private fun serializeProxyRule(rule: ProxyRule): JsonObject {
        return buildJsonObject {
            put("rule_id", rule.ruleId)
            put("type", rule.type)
            put("action", rule.action)
            put("enabled", rule.enabled)
            if (rule.matchHost != null) put("match_host", rule.matchHost)
            if (rule.matchUrl != null) put("match_url", rule.matchUrl)
            if (rule.matchMethod != null) put("match_method", rule.matchMethod)
            if (rule.matchHeader != null) put("match_header", rule.matchHeader)
            if (rule.matchBody != null) put("match_body", rule.matchBody)
            if (rule.matchStatus != null) put("match_status", rule.matchStatus)
            if (rule.modifyAddHeader != null) put("modify_add_header", rule.modifyAddHeader)
            if (rule.modifyRemoveHeader != null) put("modify_remove_header", rule.modifyRemoveHeader)
            if (rule.modifyReplaceHeader != null) {
                put("modify_replace_header", buildJsonObject {
                    rule.modifyReplaceHeader.forEach { (k, v) -> put(k, v) }
                })
            }
            if (rule.modifySetHeader != null) {
                put("modify_set_header", buildJsonObject {
                    rule.modifySetHeader.forEach { (k, v) -> put(k, v) }
                })
            }
            if (rule.modifyBodyRegex != null) put("modify_body_regex", rule.modifyBodyRegex)
            if (rule.modifyBodyReplacement != null) put("modify_body_replacement", rule.modifyBodyReplacement)
            if (rule.modifyMethod != null) put("modify_method", rule.modifyMethod)
            if (rule.modifyPath != null) put("modify_path", rule.modifyPath)
            if (rule.modifyPathRegex != null) put("modify_path_regex", rule.modifyPathRegex)
            if (rule.modifyStatus != null) put("modify_status", rule.modifyStatus)
            if (rule.tagComment != null) put("tag_comment", rule.tagComment)
            if (rule.tagHighlight != null) put("tag_highlight", rule.tagHighlight)
        }
    }

    /**
     * What happens to [request] under the enabled request rules it matches: dropped at the first
     * `drop`, else modified and tagged in rule order.
     */
    fun applyRequestRules(request: InterceptedRequest): ProxyRequestReceivedAction {
        val matchingRules = stateManager.proxyRules.filter { rule ->
            rule.enabled && rule.type.equals("request", ignoreCase = true) && matchesRequestRule(rule, request)
        }
        if (matchingRules.isEmpty()) return ProxyRequestReceivedAction.continueWith(request)

        val url = safe { request.url() } ?: ""
        var currentRequest: HttpRequest = request
        var currentAnnotations = request.annotations()
        for (rule in matchingRules) {
            when (rule.action.lowercase()) {
                "drop" -> {
                    emitRuleApplied(rule, "drop", url)
                    return ProxyRequestReceivedAction.drop()
                }
                "modify" -> {
                    currentRequest = ProxyRuleEdits.applyTo(rule, currentRequest)
                    emitRuleApplied(rule, "modify", url)
                }
                "tag" -> {
                    currentAnnotations = tagAnnotations(rule, currentAnnotations)
                    emitRuleApplied(rule, "tag", url)
                }
            }
        }
        return ProxyRequestReceivedAction.continueWith(currentRequest, currentAnnotations)
    }

    /**
     * What happens to [response] under the enabled response rules it matches: dropped at the first
     * `drop`, else modified and tagged in rule order.
     */
    fun applyResponseRules(response: InterceptedResponse): ProxyResponseReceivedAction {
        val matchingRules = stateManager.proxyRules.filter { rule ->
            rule.enabled && rule.type.equals("response", ignoreCase = true) && matchesResponseRule(rule, response)
        }
        if (matchingRules.isEmpty()) return ProxyResponseReceivedAction.continueWith(response)

        val url = safe { response.request()?.url() } ?: ""
        var currentResponse: HttpResponse = response
        var currentAnnotations = response.annotations()
        for (rule in matchingRules) {
            when (rule.action.lowercase()) {
                "drop" -> {
                    emitRuleApplied(rule, "drop", url)
                    return ProxyResponseReceivedAction.drop()
                }
                "modify" -> {
                    currentResponse = ProxyRuleEdits.applyTo(rule, currentResponse)
                    emitRuleApplied(rule, "modify", url)
                }
                "tag" -> {
                    currentAnnotations = tagAnnotations(rule, currentAnnotations)
                    emitRuleApplied(rule, "tag", url)
                }
            }
        }
        return ProxyResponseReceivedAction.continueWith(currentResponse, currentAnnotations)
    }

    private fun tagAnnotations(rule: ProxyRule, annotations: Annotations): Annotations {
        var tagged = annotations
        if (rule.tagComment != null) tagged = tagged.withNotes(rule.tagComment)
        if (rule.tagHighlight != null) {
            resolveHighlightColor(rule.tagHighlight)?.let { tagged = tagged.withHighlightColor(it) }
        }
        return tagged
    }

    private fun emitRuleApplied(rule: ProxyRule, action: String, url: String) {
        eventBus.emit("proxy.rule.applied", buildJsonObject {
            put("rule_id", rule.ruleId)
            put("action", action)
            put("url", url)
            put("timestamp", Instant.now().toString())
        })
    }

    // ---------------------------------------------------------------
    // Rule matching helpers
    // ---------------------------------------------------------------

    /**
     * Tests whether a request matches a proxy rule's conditions.
     * All non-null conditions must match (logical AND). A request Burp cannot
     * parse never matches a rule that inspects it.
     */
    private fun matchesRequestRule(rule: ProxyRule, request: InterceptedRequest): Boolean = try {
        matchesRequestConditions(rule, request)
    } catch (_: Exception) {
        false
    }

    private fun matchesRequestConditions(rule: ProxyRule, request: InterceptedRequest): Boolean {
        if (rule.matchHost != null) {
            if (!RuleMatcher.host(rule.matchHost, request.httpService().host())) {
                return false
            }
        }
        if (rule.matchUrl != null) {
            if (!RuleMatcher.url(rule.matchUrl, request.url())) {
                return false
            }
        }
        if (rule.matchMethod != null) {
            if (!request.method().equals(rule.matchMethod, ignoreCase = true)) {
                return false
            }
        }
        if (rule.matchHeader != null) {
            if (!RuleMatcher.headers(rule.matchHeader, request.headers())) {
                return false
            }
        }
        if (rule.matchBody != null) {
            val body = request.bodyToString()
            if (!SafeRegex.containsMatchIn(rule.matchBody, body, ignoreCase = true)) {
                return false
            }
        }
        return true
    }

    /**
     * Tests whether a response matches a proxy rule's conditions.
     * All non-null conditions must match (logical AND); host and URL conditions
     * never match a response whose request is unavailable or unparseable.
     */
    private fun matchesResponseRule(rule: ProxyRule, response: InterceptedResponse): Boolean = try {
        matchesResponseConditions(rule, response)
    } catch (_: Exception) {
        false
    }

    private fun matchesResponseConditions(rule: ProxyRule, response: InterceptedResponse): Boolean {
        if (rule.matchHost != null) {
            val host = safe { response.request()?.httpService()?.host() }
            if (!RuleMatcher.host(rule.matchHost, host)) {
                return false
            }
        }
        if (rule.matchUrl != null) {
            val url = safe { response.request()?.url() }
            if (!RuleMatcher.url(rule.matchUrl, url)) {
                return false
            }
        }
        if (rule.matchStatus != null) {
            if (response.statusCode().toInt() != rule.matchStatus) {
                return false
            }
        }
        if (rule.matchHeader != null) {
            if (!RuleMatcher.headers(rule.matchHeader, response.headers())) {
                return false
            }
        }
        if (rule.matchBody != null) {
            val body = response.bodyToString()
            if (!SafeRegex.containsMatchIn(rule.matchBody, body, ignoreCase = true)) {
                return false
            }
        }
        return true
    }

    /**
     * Resolves a highlight color name to a [HighlightColor] enum value.
     * Tries the Montoya factory method first, then falls back to valueOf.
     */
    private fun resolveHighlightColor(name: String): HighlightColor? {
        return try {
            HighlightColor.highlightColor(name)
        } catch (_: Exception) {
            try { HighlightColor.valueOf(name.uppercase()) } catch (_: Exception) { null }
        }
    }
}
