package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.core.HighlightColorName
import burp.api.montoya.core.HighlightColor
import burp.api.montoya.proxy.http.InterceptedRequest
import burp.api.montoya.proxy.http.InterceptedResponse
import burp.api.montoya.proxy.http.ProxyRequestHandler
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction
import burp.api.montoya.proxy.http.ProxyResponseHandler
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.state.ProxyRule
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.transport.AutorizeFileStore
import io.bitbytelab.raijin.transport.AutorizeStore
import kotlinx.serialization.json.*
import java.time.Instant

/**
 * Bridge wrapping the Montoya Proxy API.
 *
 * Provides MCP-friendly methods for reading proxy history, controlling
 * interception, annotating items, and managing proxy rules. Also creates
 * the [ProxyRequestHandler] and [ProxyResponseHandler] registered during
 * extension initialization, which apply the proxy rules, feed the hold queue
 * of the intercept tools ([interceptHolds]) and the live Autorize tap.
 *
 * History reads are served by [ProxyHistory], and the proxy rules are kept and applied by [ProxyRuleEngine].
 *
 * @param autorizeStore where the Autorize tap persists its matches; this project's are restored
 *   on construction. Null keeps them in memory only.
 */
class ProxyBridge(
    private val api: MontoyaApi,
    private val eventBus: EventBus,
    stateManager: StateManager,
    findings: FindingsBridge,
    autorizeStore: AutorizeFileStore? = AutorizeStore.defaultStore,
) {
    /** Messages held for the proxy intercept tools; see [ProxyInterceptHolds]. */
    internal val interceptHolds = ProxyInterceptHolds(eventBus)

    /** Live Autorize-style tap on proxied responses; see [AutorizeTap] and [AutorizeBridge] for rule CRUD. */
    private val autorizeTap = AutorizeTap(api, eventBus, stateManager, findings, autorizeStore)

    /** HTTP and WebSocket history reads; see [ProxyHistory]. */
    private val history = ProxyHistory(api)

    /** Proxy rule storage, matching and application; see [ProxyRuleEngine]. */
    private val rules = ProxyRuleEngine(eventBus, stateManager)

    init {
        // This project's Autorize matches are back before a rule can be set or traffic tapped.
        autorizeTap.start()
    }

    /** Releases held messages (they are forwarded) and stops background work on extension unload. */
    fun shutdown() {
        interceptHolds.shutdown()
        autorizeTap.shutdown()
    }

    // ---------------------------------------------------------------
    // History retrieval
    // ---------------------------------------------------------------

    /** A page of the HTTP proxy history, optionally filtered; see [ProxyHistory.getHistory]. */
    fun getHistory(
        startIndex: Int,
        count: Int,
        host: String?,
        method: String?,
        statusCode: Int?,
        mimeType: String?,
        inScopeOnly: Boolean,
        includeRequest: Boolean = false,
        includeResponse: Boolean = false,
        statusCodeRange: String? = null,
        maxResponseLength: Int? = null,
        includeHeaders: Boolean = true,
    ): JsonObject = history.getHistory(
        startIndex, count, host, method, statusCode, mimeType, inScopeOnly,
        includeRequest, includeResponse, statusCodeRange, maxResponseLength, includeHeaders,
    )

    /** The HTTP proxy history items a regex matches; see [ProxyHistory.searchHistory]. */
    fun searchHistory(
        pattern: String,
        searchIn: String,
        caseSensitive: Boolean,
        maxResults: Int,
        inScopeOnly: Boolean,
        includeRequest: Boolean = false,
        includeResponse: Boolean = false,
        maxResponseLength: Int? = null,
        startIndex: Int = 0,
    ): JsonObject = history.searchHistory(
        pattern, searchIn, caseSensitive, maxResults, inScopeOnly, includeRequest, includeResponse, maxResponseLength, startIndex
    )

    /** A page of the WebSocket proxy history, optionally filtered; see [ProxyHistory.getWebSocketHistory]. */
    fun getWebSocketHistory(
        startIndex: Int,
        count: Int,
        host: String?,
        direction: String?,
        webSocketId: Int? = null,
        url: String? = null,
    ): JsonObject = history.getWebSocketHistory(startIndex, count, host, direction, webSocketId, url)

    /** The WebSocket proxy history messages whose payload a regex matches; see [ProxyHistory.searchWebSocketHistory]. */
    fun searchWebSocketHistory(
        pattern: String,
        direction: String?,
        maxResults: Int,
        webSocketId: Int? = null,
        url: String? = null,
        startIndex: Int = 0,
    ): JsonObject = history.searchWebSocketHistory(pattern, direction, maxResults, webSocketId, url, startIndex)

    // ---------------------------------------------------------------
    // Intercept control
    // ---------------------------------------------------------------

    /** Enables proxy interception. */
    fun enableIntercept(): JsonObject {
        api.proxy().enableIntercept()
        eventBus.emit("proxy.intercept", buildJsonObject {
            put("enabled", true)
            put("timestamp", Instant.now().toString())
        })
        return buildJsonObject { put("intercept_enabled", true) }
    }

    /** Disables proxy interception. */
    fun disableIntercept(): JsonObject {
        api.proxy().disableIntercept()
        eventBus.emit("proxy.intercept", buildJsonObject {
            put("enabled", false)
            put("timestamp", Instant.now().toString())
        })
        return buildJsonObject { put("intercept_enabled", false) }
    }

    /** Returns the current intercept state: Burp's own Intercept switch, and Raijin's hold queue. */
    fun isInterceptEnabled(): JsonObject {
        return buildJsonObject {
            put("intercept_enabled", api.proxy().isInterceptEnabled)
            put("hold", interceptHolds.status())
        }
    }

    // ---------------------------------------------------------------
    // Annotation
    // ---------------------------------------------------------------

    /**
     * Annotates a proxy history item by its index (message ID).
     *
     * @param index The proxy history item message ID.
     * @param comment Optional comment to set.
     * @param highlight Optional highlight color name (e.g., "RED", "BLUE").
     * @return JSON object confirming the annotation.
     */
    fun annotateHistoryItem(index: Int, comment: String?, highlight: String?): JsonObject {
        val item = api.proxy().history { it.id() == index }.firstOrNull()
            ?: return buildJsonObject {
                put("error", "History item with id $index not found")
            }

        // Validate the highlight colour BEFORE mutating anything. Montoya's
        // HighlightColor.highlightColor(name) returns NONE (not an exception) for an
        // unknown colour, so trusting it used to CLEAR any existing highlight while
        // still reporting annotated:true — a silent clear masquerading as success.
        val canonicalHighlight: String? = if (highlight != null) {
            HighlightColorName.canonical(highlight)
                ?: return buildJsonObject {
                    put(
                        "error",
                        "Invalid highlight color: '$highlight'. Valid values: ${HighlightColorName.validValues()}"
                    )
                }
        } else {
            null
        }

        val annotations = item.annotations()
        if (comment != null) {
            annotations.setNotes(comment)
        }
        if (canonicalHighlight != null) {
            // canonicalHighlight is a validated enum constant name, so valueOf is safe.
            annotations.setHighlightColor(HighlightColor.valueOf(canonicalHighlight))
        }

        return buildJsonObject {
            put("index", index)
            put("annotated", true)
            if (comment != null) put("comment", comment)
            if (canonicalHighlight != null) put("highlight", canonicalHighlight)
        }
    }

    // ---------------------------------------------------------------
    // Proxy rules
    // ---------------------------------------------------------------

    /** Validates [rule] and stores it, replacing (in place) any rule with the same id; see [ProxyRuleEngine.setRule]. */
    fun setRule(rule: ProxyRule): JsonObject = rules.setRule(rule)

    /** Lists proxy rules, optionally only "request" or "response" ones; see [ProxyRuleEngine.listRules]. */
    fun listRules(type: String?): JsonObject = rules.listRules(type)

    /** Removes the rule with [ruleId]; `removed` is false when there was none. See [ProxyRuleEngine.removeRule]. */
    fun removeRule(ruleId: String): JsonObject = rules.removeRule(ruleId)

    // ---------------------------------------------------------------
    // Proxy handlers (registered during extension init)
    // ---------------------------------------------------------------

    /**
     * Creates a [ProxyRequestHandler] that:
     * 1. Emits "proxy.request" events to the [EventBus].
     * 2. Evaluates proxy rules from [StateManager.proxyRules] against each request and applies the
     *    matching rule actions (modify, drop, tag).
     * 3. Just before the request is sent, offers it to the intercept hold queue ([interceptHolds]),
     *    which parks it while an agent inspects, edits, forwards or drops it.
     */
    fun createRequestHandler(): ProxyRequestHandler {
        return object : ProxyRequestHandler {
            override fun handleRequestReceived(interceptedRequest: InterceptedRequest): ProxyRequestReceivedAction {
                // Emit event for every request passing through the proxy
                emitRequestEvent(interceptedRequest)
                return try {
                    rules.applyRequestRules(interceptedRequest)
                } catch (_: Exception) {
                    // A failing rule must never break the proxy: forward the request unchanged.
                    ProxyRequestReceivedAction.continueWith(interceptedRequest)
                }
            }

            override fun handleRequestToBeSent(interceptedRequest: InterceptedRequest): ProxyRequestToBeSentAction {
                val held = try {
                    interceptHolds.holdRequest(interceptedRequest.messageId(), interceptedRequest) {
                        safe { interceptedRequest.isInScope() } ?: false
                    }
                } catch (_: Exception) {
                    null
                } ?: return ProxyRequestToBeSentAction.continueWith(interceptedRequest)
                if (held.drop) return ProxyRequestToBeSentAction.drop()
                val annotations = safe { interceptedRequest.annotations() }
                    ?: return ProxyRequestToBeSentAction.continueWith(held.message)
                return ProxyRequestToBeSentAction.continueWith(held.message, annotations)
            }
        }
    }

    /**
     * Creates a [ProxyResponseHandler] that:
     * 1. Emits "proxy.response" events to the [EventBus].
     * 2. Feeds the live Autorize tap ([AutorizeTap]), which never blocks the handler.
     * 3. Evaluates proxy rules from [StateManager.proxyRules] against each response and applies the
     *    matching rule actions (modify, drop, tag).
     * 4. Just before the response goes back to the client, offers it to the intercept hold queue
     *    ([interceptHolds]).
     */
    fun createResponseHandler(): ProxyResponseHandler {
        return object : ProxyResponseHandler {
            override fun handleResponseReceived(interceptedResponse: InterceptedResponse): ProxyResponseReceivedAction {
                // Emit event for every response passing through the proxy
                emitResponseEvent(interceptedResponse)

                // Live Autorize-style tap: fire-and-forget, never blocks this handler.
                autorizeTap.onResponse(interceptedResponse)

                return try {
                    rules.applyResponseRules(interceptedResponse)
                } catch (_: Exception) {
                    // A failing rule must never break the proxy: forward the response unchanged.
                    ProxyResponseReceivedAction.continueWith(interceptedResponse)
                }
            }

            override fun handleResponseToBeSent(interceptedResponse: InterceptedResponse): ProxyResponseToBeSentAction {
                val held = try {
                    interceptHolds.holdResponse(
                        interceptedResponse.messageId(),
                        interceptedResponse,
                        safe { interceptedResponse.request() },
                    ) { safe { interceptedResponse.request()?.isInScope() } ?: false }
                } catch (_: Exception) {
                    null
                } ?: return ProxyResponseToBeSentAction.continueWith(interceptedResponse)
                if (held.drop) return ProxyResponseToBeSentAction.drop()
                val annotations = safe { interceptedResponse.annotations() }
                    ?: return ProxyResponseToBeSentAction.continueWith(held.message)
                return ProxyResponseToBeSentAction.continueWith(held.message, annotations)
            }
        }
    }

    // ---------------------------------------------------------------
    // Event emission helpers
    // ---------------------------------------------------------------

    private fun emitRequestEvent(request: InterceptedRequest) {
        try {
            eventBus.emit("proxy.request", buildJsonObject {
                put("message_id", request.messageId())
                put("method", safe { request.method() } ?: "")
                put("url", safe { request.url() } ?: "")
                safe { request.httpService() }?.let { service ->
                    put("host", service.host())
                    put("port", service.port())
                    put("secure", service.secure())
                }
                put("in_scope", safe { request.isInScope() } ?: false)
                put("timestamp", Instant.now().toString())
            })
        } catch (_: Exception) {
            // Events are best-effort; a malformed request must not break the proxy flow.
        }
    }

    private fun emitResponseEvent(response: InterceptedResponse) {
        try {
            eventBus.emit("proxy.response", buildJsonObject {
                put("message_id", response.messageId())
                put("status_code", safe { response.statusCode().toInt() } ?: 0)
                put("mime_type", safe { response.mimeType().name } ?: "")
                safe { response.request() }?.let { req ->
                    put("url", safe { req.url() } ?: "")
                    put("host", safe { req.httpService().host() } ?: "")
                }
                put("timestamp", Instant.now().toString())
            })
        } catch (_: Exception) {
            // Events are best-effort; see emitRequestEvent.
        }
    }

    companion object {
        /** Largest page any history read returns. */
        const val MAX_PAGE_SIZE = 1000

        internal val RULE_TYPES = setOf("request", "response")
        private val RULE_ACTIONS = setOf("modify", "drop", "tag")

        /**
         * Error message when a host pattern for [SafeRegex.matchesHostPattern] (proxy `match_host`,
         * Autorize `include_host_pattern`) could never match, else null. Such a pattern is either a
         * glob (`*.example.com`) or a regex (`.*\.example\.com`); only a regex that fails to compile
         * is unusable, and a glob always matches its own text with each `*` filled in.
         */
        internal fun hostPatternError(pattern: String): String? {
            if (pattern.isBlank()) return "Host pattern is blank"
            val regexError = SafeRegex.validate(pattern, ignoreCase = true) ?: return null
            if (SafeRegex.matchesHostPattern(pattern, pattern.replace("*", "x"))) return null
            return "Invalid host pattern '$pattern': $regexError. Use a glob such as *.example.com or a valid regex."
        }

        /**
         * Checks a proxy rule before it reaches live traffic, where an invalid regex would otherwise
         * make it silently never match. Header names and values are not held to the HTTP grammar:
         * CR/LF and any other character are written as given ([ProxyRuleEdits.error] lists what a
         * modification may not do). Returns an error message or null.
         */
        internal fun validateRule(rule: ProxyRule): String? {
            if (rule.type.lowercase() !in RULE_TYPES) return "Invalid rule type '${rule.type}'. Allowed: request, response"
            if (rule.action.lowercase() !in RULE_ACTIONS) return "Invalid rule action '${rule.action}'. Allowed: drop, modify, tag"
            rule.matchHost?.let { pattern -> hostPatternError(pattern)?.let { return "match_host: $it" } }
            regexError("match_url", rule.matchUrl)?.let { return it }
            regexError("match_header", rule.matchHeader)?.let { return it }
            regexError("match_body", rule.matchBody)?.let { return it }
            regexError("modify_body_regex", rule.modifyBodyRegex)?.let { return it }
            rule.matchStatus?.let { if (it !in 0..999) return "match_status must be between 0 and 999 (got $it)" }
            rule.tagHighlight?.let {
                if (!HighlightColorName.isValid(it)) {
                    return "Invalid tag_highlight '$it'. Valid values: ${HighlightColorName.validValues()}"
                }
            }
            ProxyRuleEdits.error(rule)?.let { return it }
            if (rule.action.equals("modify", ignoreCase = true) && !ProxyRuleEdits.modifies(rule)) {
                val specific = if (rule.type.equals("request", ignoreCase = true)) "modify_method, modify_path" else "modify_status"
                return "action 'modify' needs at least one of modify_add_header, modify_remove_header, " +
                    "modify_replace_header, modify_set_header, modify_body_regex, $specific"
            }
            return null
        }

        private fun regexError(param: String, pattern: String?): String? =
            pattern?.let { p -> SafeRegex.validate(p, ignoreCase = true)?.let { "Invalid $param regex: $it" } }

        /** Runs a Montoya accessor that may throw on malformed data (e.g. MalformedRequestException). */
        internal inline fun <T> safe(block: () -> T): T? = try {
            block()
        } catch (_: Exception) {
            null
        }
    }
}
