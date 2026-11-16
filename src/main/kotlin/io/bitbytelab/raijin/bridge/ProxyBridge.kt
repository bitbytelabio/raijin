package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.core.BodyText
import io.bitbytelab.raijin.core.HistoryCriteria
import io.bitbytelab.raijin.core.ProxyHistorySearch
import io.bitbytelab.raijin.core.SensitiveHeaders
import io.bitbytelab.raijin.core.StatusCodeRange
import io.bitbytelab.raijin.core.HighlightColorName
import io.bitbytelab.raijin.core.WebSocketHistoryCriteria
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.HighlightColor
import burp.api.montoya.http.message.MimeType
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.ProxyHistoryFilter
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketHistoryFilter
import burp.api.montoya.proxy.ProxyWebSocketMessage
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
 * @param autorizeStore where the Autorize tap persists its matches; this project's are restored
 *   on construction. Null keeps them in memory only.
 */
class ProxyBridge(
    private val api: MontoyaApi,
    private val eventBus: EventBus,
    private val stateManager: StateManager,
    findings: FindingsBridge,
    autorizeStore: AutorizeFileStore? = AutorizeStore.defaultStore,
) {
    /** Messages held for the proxy intercept tools; see [ProxyInterceptHolds]. */
    internal val interceptHolds = ProxyInterceptHolds(eventBus)

    /** Live Autorize-style tap on proxied responses; see [AutorizeTap] and [AutorizeBridge] for rule CRUD. */
    private val autorizeTap = AutorizeTap(api, eventBus, stateManager, findings, autorizeStore)

    /** Serialises rule writes so concurrent sets of one id cannot both append. */
    private val ruleLock = Any()

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

    /**
     * Returns a slice of the HTTP proxy history with optional filtering.
     *
     * @param startIndex Zero-based offset into the filtered history.
     * @param count Maximum number of items to return; clamped to 0..[MAX_PAGE_SIZE] with a note in the result.
     * @param host Optional hostname filter (case-insensitive substring match).
     * @param method Optional HTTP method filter (exact, case-insensitive).
     * @param statusCode Optional exact status code filter.
     * @param mimeType Optional MIME type filter (case-insensitive name match).
     * @param inScopeOnly When true, only return in-scope items.
     * @param includeRequest Whether to include the full request text.
     * @param includeResponse Whether to include the full response text.
     * @param statusCodeRange Optional "min-max" range string for status codes.
     * @return JSON object with total count, returned count, and items array.
     */
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
        maxResponseLength: Int? = null
    ): JsonObject {
        // Resolve the optional MIME type filter up front so an unrecognized value
        // produces a clear error instead of silently dropping the filter (which
        // would return ALL history as if it matched).
        val resolvedMimeType: MimeType? = if (mimeType != null) {
            resolveMimeType(mimeType)
                ?: return buildJsonObject {
                    put(
                        "error",
                        "Unknown mime_type: $mimeType. Valid values: ${mimeTypeValidValues()}"
                    )
                }
        } else {
            null
        }

        // Validate the status-code range ONCE, up front — a malformed range now
        // returns a clear error instead of silently dropping the filter (which used
        // to return items outside the caller's intended range).
        val resolvedRange: StatusCodeRange.Range? = when (val r = StatusCodeRange.parse(statusCodeRange)) {
            is StatusCodeRange.Result.None -> null
            is StatusCodeRange.Result.Ok -> r.range
            is StatusCodeRange.Result.Invalid -> return buildJsonObject { put("error", r.message) }
        }

        val criteria = HistoryCriteria(host, method, statusCode, resolvedRange)
        val filter = ProxyHistoryFilter { item ->
            try {
                if (inScopeOnly && !item.request().isInScope()) return@ProxyHistoryFilter false
                if (resolvedMimeType != null && item.mimeType() != resolvedMimeType) return@ProxyHistoryFilter false
                // Each value is read only when its criterion is set, and guarded: a malformed
                // request throws from host()/method() and must not abort the whole read.
                criteria.matches(
                    host = if (criteria.host != null) safe { item.httpService().host() } else null,
                    method = if (criteria.method != null) safe { item.finalRequest().method() } else null,
                    status = if (criteria.needsStatus) responseStatus(item) else null,
                )
            } catch (_: Exception) {
                false
            }
        }

        val allItems = api.proxy().history(filter)
        val notes = mutableListOf<String>()
        val safeStart = ProxyLimits.clamp("start_index", startIndex, 0, Int.MAX_VALUE, notes)
        val slice = page(allItems, safeStart, ProxyLimits.clamp("count", count, 0, MAX_PAGE_SIZE, notes))

        return buildJsonObject {
            put("total_filtered", allItems.size)
            put("start_index", safeStart)
            put("returned", slice.size)
            put("items", buildJsonArray {
                slice.forEach { item ->
                    add(serializeHistoryItem(item, includeRequest, includeResponse, maxResponseLength ?: 200_000))
                }
            })
            putNotes(notes)
        }
    }

    /**
     * Searches proxy history using a regex pattern.
     *
     * @param pattern Regex pattern to match.
     * @param searchIn Where to search: "request", "response", or "both".
     * @param caseSensitive Whether the regex is case-sensitive.
     * @param maxResults Maximum number of matching items to return; clamped to 0..[MAX_PAGE_SIZE] with a note in the result.
     * @param inScopeOnly When true, only search in-scope items.
     * @param includeRequest Whether to include the full request text.
     * @param includeResponse Whether to include the full response text.
     * @return JSON object with match count and items array.
     */
    fun searchHistory(
        pattern: String,
        searchIn: String,
        caseSensitive: Boolean,
        maxResults: Int,
        inScopeOnly: Boolean,
        includeRequest: Boolean = false,
        includeResponse: Boolean = false,
        maxResponseLength: Int? = null
    ): JsonObject {
        val ignoreCase = !caseSensitive
        SafeRegex.validate(pattern, ignoreCase = ignoreCase)?.let { err ->
            return buildJsonObject { put("error", "Invalid regex pattern: $err") }
        }
        val t = ProxyHistorySearch.targets(searchIn)

        val filter = ProxyHistoryFilter { item ->
            try {
                if (inScopeOnly && !item.request().isInScope()) return@ProxyHistoryFilter false

                var found = false
                if (t.url) {
                    // Match against the fully-reconstructed URL (scheme+host+path+query),
                    // which the request text does not expose as one contiguous string.
                    val url = safe { item.request().url() } ?: ""
                    found = SafeRegex.containsMatchIn(pattern, url, ignoreCase = ignoreCase)
                }
                if (!found && t.request) {
                    val reqText = safe { item.request().toString() } ?: ""
                    found = SafeRegex.containsMatchIn(pattern, reqText, ignoreCase = ignoreCase)
                }
                if (!found && t.response && item.hasResponse()) {
                    val respText = safe { item.response().toString() } ?: ""
                    found = SafeRegex.containsMatchIn(pattern, respText, ignoreCase = ignoreCase)
                }
                found
            } catch (_: Exception) {
                false
            }
        }

        val matches = api.proxy().history(filter)
        val notes = mutableListOf<String>()
        val limited = page(matches, 0, ProxyLimits.clamp("max_results", maxResults, 0, MAX_PAGE_SIZE, notes))

        return buildJsonObject {
            put("total_matches", matches.size)
            put("returned", limited.size)
            put("pattern", pattern)
            put("search_in", searchIn)
            put("items", buildJsonArray {
                limited.forEach { item ->
                    add(serializeHistoryItem(item, includeRequest, includeResponse, maxResponseLength ?: 200_000))
                }
            })
            putNotes(notes)
        }
    }

    /**
     * Returns WebSocket proxy history with optional filtering.
     *
     * @param startIndex Zero-based offset.
     * @param count Maximum number of items; clamped to 0..[MAX_PAGE_SIZE] with a note in the result.
     * @param host Optional hostname filter.
     * @param direction Optional direction filter: "client_to_server", "server_to_client" or "both" (any case).
     * @param webSocketId Optional Burp id of one proxied connection (`websocket_id` of an item).
     * @param url Optional case-insensitive substring of the upgrade request's URL.
     * @return JSON object with items array.
     */
    fun getWebSocketHistory(
        startIndex: Int,
        count: Int,
        host: String?,
        direction: String?,
        webSocketId: Int? = null,
        url: String? = null,
    ): JsonObject {
        val dirName = when (val d = WebSocketHistoryCriteria.parseDirection(direction)) {
            is WebSocketHistoryCriteria.DirectionFilter.All -> null
            is WebSocketHistoryCriteria.DirectionFilter.Only -> d.name
            is WebSocketHistoryCriteria.DirectionFilter.Invalid -> return buildJsonObject { put("error", d.message) }
        }
        val criteria = WebSocketHistoryCriteria(host, dirName, webSocketId, url)

        val allItems = api.proxy().webSocketHistory { item -> matchesCriteria(criteria, item) }
        val notes = mutableListOf<String>()
        val safeStart = ProxyLimits.clamp("start_index", startIndex, 0, Int.MAX_VALUE, notes)
        val slice = page(allItems, safeStart, ProxyLimits.clamp("count", count, 0, MAX_PAGE_SIZE, notes))

        return buildJsonObject {
            put("total_filtered", allItems.size)
            put("start_index", safeStart)
            put("returned", slice.size)
            put("items", buildJsonArray {
                slice.forEach { item -> add(serializeWebSocketItem(item)) }
            })
            putNotes(notes)
        }
    }

    /**
     * Searches WebSocket proxy history using a regex pattern on message payloads.
     *
     * @param pattern Regex pattern.
     * @param direction Optional direction filter.
     * @param maxResults Maximum results; clamped to 0..[MAX_PAGE_SIZE] with a note in the result.
     * @param webSocketId Optional Burp id of one proxied connection.
     * @param url Optional case-insensitive substring of the upgrade request's URL.
     * @return JSON object with match results.
     */
    fun searchWebSocketHistory(
        pattern: String,
        direction: String?,
        maxResults: Int,
        webSocketId: Int? = null,
        url: String? = null,
    ): JsonObject {
        SafeRegex.validate(pattern, ignoreCase = true)?.let { err ->
            return buildJsonObject { put("error", "Invalid regex pattern: $err") }
        }
        val dirName = when (val d = WebSocketHistoryCriteria.parseDirection(direction)) {
            is WebSocketHistoryCriteria.DirectionFilter.All -> null
            is WebSocketHistoryCriteria.DirectionFilter.Only -> d.name
            is WebSocketHistoryCriteria.DirectionFilter.Invalid -> return buildJsonObject { put("error", d.message) }
        }
        val criteria = WebSocketHistoryCriteria(null, dirName, webSocketId, url)

        val filter = ProxyWebSocketHistoryFilter { item ->
            try {
                if (!matchesCriteria(criteria, item)) return@ProxyWebSocketHistoryFilter false
                val payloadText = safe { item.payload().toString() } ?: ""
                SafeRegex.containsMatchIn(pattern, payloadText, ignoreCase = true)
            } catch (_: Exception) {
                false
            }
        }

        val matches = api.proxy().webSocketHistory(filter)
        val notes = mutableListOf<String>()
        val limited = page(matches, 0, ProxyLimits.clamp("max_results", maxResults, 0, MAX_PAGE_SIZE, notes))

        return buildJsonObject {
            put("total_matches", matches.size)
            put("returned", limited.size)
            put("pattern", pattern)
            put("items", buildJsonArray {
                limited.forEach { item -> add(serializeWebSocketItem(item)) }
            })
            putNotes(notes)
        }
    }

    /**
     * Whether [item] passes [criteria]. Each value is read only when its criterion is set, and
     * guarded: a message Burp cannot describe never matches a criterion that needs the value.
     */
    private fun matchesCriteria(criteria: WebSocketHistoryCriteria, item: ProxyWebSocketMessage): Boolean = try {
        criteria.matches(
            upgradeHost = if (criteria.host != null) safe { item.upgradeRequest()?.httpService()?.host() } else null,
            direction = if (criteria.direction != null) safe { item.direction().name } else null,
            webSocketId = if (criteria.webSocketId != null) safe { item.webSocketId() } else null,
            upgradeUrl = if (criteria.url != null) safe { item.upgradeRequest()?.url() } else null,
        )
    } catch (_: Exception) {
        false
    }

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
                    applyRequestRules(interceptedRequest)
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
                    applyResponseRules(interceptedResponse)
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

    private fun applyRequestRules(request: InterceptedRequest): ProxyRequestReceivedAction {
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

    private fun applyResponseRules(response: InterceptedResponse): ProxyResponseReceivedAction {
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

    // ---------------------------------------------------------------
    // Serialization helpers
    // ---------------------------------------------------------------

    /**
     * Serializes a [ProxyHttpRequestResponse] to a [JsonObject]. Every accessor is guarded: a
     * request Burp cannot parse (MalformedRequestException from method()/url()/path()) is
     * reported with `malformed_request` instead of failing the whole history read.
     */
    private fun serializeHistoryItem(
        item: ProxyHttpRequestResponse,
        includeRequest: Boolean,
        includeResponse: Boolean,
        maxResponseLength: Int? = null
    ): JsonObject {
        return buildJsonObject {
            safe { item.id() }?.let { put("index", it) }
            safe { item.httpService() }?.let { service ->
                put("host", service.host())
                put("port", service.port())
                put("secure", service.secure())
            }
            val method = safe { item.finalRequest().method() }
            val url = safe { item.finalRequest().url() }
            val path = safe { item.finalRequest().path() }
            method?.let { put("method", it) }
            url?.let { put("url", it) }
            path?.let { put("path", it) }
            if (method == null || url == null || path == null) put("malformed_request", true)
            safe { item.edited() }?.let { put("edited", it) }
            safe { item.mimeType().name }?.let { put("mime_type", it) }
            val hasResponse = safe { item.hasResponse() } ?: false
            put("has_response", hasResponse)

            // Timing
            try {
                val time = item.time()
                if (time != null) put("time", time.toString())
            } catch (_: Exception) { }

            // Timing data
            try {
                val td = item.timingData()
                if (td != null) {
                    put("timing", buildJsonObject {
                        put("time_to_first_byte_ms", td.timeBetweenRequestSentAndStartOfResponse().toMillis())
                        put("time_to_complete_ms", td.timeBetweenRequestSentAndEndOfResponse().toMillis())
                    })
                }
            } catch (_: Exception) { }

            // Response metadata
            if (hasResponse) {
                try {
                    val resp = item.response()
                    put("status_code", resp.statusCode().toInt())
                    put("response_length", resp.body().length())
                    put("response_mime_type", resp.mimeType().name)
                } catch (_: Exception) { }
            }

            // Annotations
            try {
                val ann = item.annotations()
                if (ann.hasNotes()) put("comment", ann.notes())
                if (ann.hasHighlightColor()) put("highlight", ann.highlightColor().name)
            } catch (_: Exception) { }

            // Request headers — names/shape always preserved for recon; the VALUES of
            // credential-bearing headers (Cookie, Authorization, …) are redacted unless the
            // caller explicitly requested full request material (issue #20).
            try {
                put("request_headers", buildJsonArray {
                    item.request().headers().forEach { h ->
                        add(buildJsonObject {
                            put("name", h.name())
                            put("value", SensitiveHeaders.value(h.name(), h.value(), includeRequest))
                        })
                    }
                })
            } catch (_: Exception) { }

            // Full request text. Routed through BodyText so a binary body (a file upload) can
            // never put an unencodable lone surrogate into the JSON — see issue #12.
            if (includeRequest) {
                try {
                    val r = BodyText.render(item.request().toString(), maxResponseLength, label = "request body")
                    put("request", r.text)
                    if (r.binary) put("request_binary", true)
                    if (r.truncated) put("request_truncated", true)
                } catch (_: Exception) {
                    put("request", "")
                }
            }

            // Full response text. A binary body (font/image/archive) is replaced by a placeholder
            // rather than string-converted: doing the latter corrupted the WHOLE batch's JSON for
            // the client, not just this item (issue #12).
            if (includeResponse && hasResponse) {
                try {
                    val mime = safe { item.response().mimeType().name }
                    val r = BodyText.render(item.response().toString(), maxResponseLength, mime, "response body")
                    put("response", r.text)
                    if (r.binary) put("response_binary", true)
                    if (r.truncated) put("response_truncated", true)
                } catch (_: Exception) {
                    put("response", "")
                }
            }
        }
    }

    /**
     * Serializes a [ProxyWebSocketMessage] to a [JsonObject].
     */
    private fun serializeWebSocketItem(item: ProxyWebSocketMessage): JsonObject {
        return buildJsonObject {
            safe { item.id() }?.let { put("id", it) }
            safe { item.webSocketId() }?.let { put("websocket_id", it) }
            safe { item.direction().name }?.let { put("direction", it) }
            safe { item.listenerPort() }?.let { put("listener_port", it) }

            try {
                val time = item.time()
                if (time != null) put("time", time.toString())
            } catch (_: Exception) { }

            try {
                val payload = item.payload()
                // Binary WebSocket frames are the same JSON hazard as binary HTTP bodies (issue #12).
                val r = BodyText.render(payload.toString(), label = "payload")
                put("payload", r.text)
                if (r.binary) put("payload_binary", true)
                if (r.truncated) put("payload_truncated", true)
                put("payload_length", payload.length())
            } catch (_: Exception) {
                put("payload", "")
                put("payload_length", 0)
            }

            try {
                val editedPayload = item.editedPayload()
                if (editedPayload != null) {
                    put("edited_payload", BodyText.render(editedPayload.toString(), label = "payload").text)
                }
            } catch (_: Exception) { }

            try {
                val ann = item.annotations()
                if (ann.hasNotes()) put("comment", ann.notes())
                if (ann.hasHighlightColor()) put("highlight", ann.highlightColor().name)
            } catch (_: Exception) { }

            try {
                val upgradeReq = item.upgradeRequest()
                if (upgradeReq != null) {
                    put("upgrade_url", upgradeReq.url())
                    put("upgrade_host", upgradeReq.httpService().host())
                }
            } catch (_: Exception) { }
        }
    }

    /** Status code of [item]'s response, or null when it has none or it cannot be read. */
    private fun responseStatus(item: ProxyHttpRequestResponse): Int? =
        if (item.hasResponse()) safe { item.response().statusCode().toInt() } else null

    /** Up to [count] (capped at [MAX_PAGE_SIZE]) items from [from], as a view (no copy of the list). */
    private fun <T> page(items: List<T>, from: Int, count: Int): List<T> {
        val start = from.coerceIn(0, items.size)
        val end = (start.toLong() + count.coerceIn(0, MAX_PAGE_SIZE)).coerceAtMost(items.size.toLong()).toInt()
        return items.subList(start, end)
    }

    private fun JsonObjectBuilder.putNotes(notes: List<String>) {
        if (notes.isNotEmpty()) put("notes", buildJsonArray { notes.forEach { add(it) } })
    }

    /** Runs a Montoya accessor that may throw on malformed data (e.g. MalformedRequestException). */
    private inline fun <T> safe(block: () -> T): T? = try {
        block()
    } catch (_: Exception) {
        null
    }

    /**
     * Resolves a caller-supplied MIME type string to a [MimeType] enum constant.
     *
     * Accepts both the Montoya enum constant names (e.g. "JSON", "HTML") and a
     * set of common content-type / alias spellings (e.g. "application/json",
     * "text/html", "javascript"). Returns null if it cannot be resolved.
     */
    private fun resolveMimeType(input: String): MimeType? {
        val normalized = input.trim()

        // Direct enum constant match (case-insensitive), e.g. "JSON", "PLAIN_TEXT".
        try {
            return MimeType.valueOf(normalized.uppercase())
        } catch (_: Exception) {
            // fall through to alias resolution
        }

        // Common content-type strings and short aliases mapped to enum constants.
        return when (normalized.lowercase()) {
            "application/json", "json", "text/json" -> MimeType.JSON
            "text/html", "html", "application/xhtml+xml", "xhtml" -> MimeType.HTML
            "text/plain", "plain", "text" -> MimeType.PLAIN_TEXT
            "text/css", "css" -> MimeType.CSS
            "application/javascript", "text/javascript", "javascript", "js", "script" -> MimeType.SCRIPT
            "application/xml", "text/xml", "xml" -> MimeType.XML
            "application/yaml", "text/yaml", "yaml", "yml" -> MimeType.YAML
            "text/event-stream", "sse" -> MimeType.SSE
            "application/rtf", "text/rtf", "rtf" -> MimeType.RTF
            "image/svg+xml", "svg" -> MimeType.IMAGE_SVG_XML
            "image/png", "png" -> MimeType.IMAGE_PNG
            "image/jpeg", "image/jpg", "jpeg", "jpg" -> MimeType.IMAGE_JPEG
            "image/gif", "gif" -> MimeType.IMAGE_GIF
            "image/bmp", "bmp" -> MimeType.IMAGE_BMP
            "image/tiff", "tiff", "tif" -> MimeType.IMAGE_TIFF
            else -> null
        }
    }

    /**
     * A human-readable hint listing the accepted MIME type values, for error messages.
     */
    private fun mimeTypeValidValues(): String {
        val constants = MimeType.values().joinToString(", ") { it.name }
        return "$constants (also accepts common aliases such as application/json, text/html, " +
            "text/plain, application/javascript, application/xml, and image content-types like " +
            "image/png, image/jpeg, image/gif, image/svg+xml)"
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

    companion object {
        /** Largest page any history read returns. */
        const val MAX_PAGE_SIZE = 1000

        private val RULE_TYPES = setOf("request", "response")
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
    }
}
