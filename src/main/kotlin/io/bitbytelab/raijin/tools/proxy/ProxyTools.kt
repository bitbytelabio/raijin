package io.bitbytelab.raijin.tools.proxy

import io.bitbytelab.raijin.bridge.ProxyBridge
import io.bitbytelab.raijin.core.EnumValidation
import io.bitbytelab.raijin.core.asLongSafe
import io.bitbytelab.raijin.core.asStringMap
import io.bitbytelab.raijin.state.ProxyRule
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/**
 * Registers all 13 proxy MCP tools onto the given [Server].
 *
 * Each tool delegates to the [ProxyBridge] and catches exceptions so
 * that errors are returned as structured JSON inside a [CallToolResult]
 * rather than propagating unhandled.
 */
object ProxyTools {

    private val HIGHLIGHT_COLORS = listOf("NONE", "RED", "ORANGE", "YELLOW", "GREEN", "CYAN", "BLUE", "PINK", "MAGENTA", "GRAY")
    private val RULE_ACTIONS = listOf("modify", "drop", "tag")
    private val WS_DIRECTIONS = listOf("client_to_server", "server_to_client", "both")
    private val SEARCH_TARGETS = listOf("url", "request", "response", "both")

    private const val MATCH_HOST_DESCRIPTION =
        "Host to match: a glob such as '*.example.com' or a regex such as '.*\\.example\\.com' (whole host, case-insensitive)"

    fun register(server: Server, bridge: ProxyBridge, stateManager: StateManager) {

        // ---------------------------------------------------------------
        // 1. proxy_history
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_history",
            description = "Get HTTP proxy history entries with optional filtering by host, method, status code, status code range, MIME type. Returns request/response metadata and optionally full request/response text.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    intProp("start_index", "Start index of history entries (default 0)", min = 0)
                    intProp("count", "Maximum number of entries to return (default 100, max ${ProxyBridge.MAX_PAGE_SIZE}; 0 returns only total_filtered)", min = 0, max = ProxyBridge.MAX_PAGE_SIZE)
                    putJsonObject("host") { put("type", "string"); put("description", "Filter by host (case-insensitive substring)") }
                    putJsonObject("method") { put("type", "string"); put("description", "Filter by HTTP method") }
                    intProp("status_code", "Filter by exact status code; items without a response never match", min = 0, max = 999)
                    putJsonObject("status_code_range") { put("type", "string"); put("description", "Filter by status code range: '200-299', '400-', '-399' or '404'; items without a response never match") }
                    putJsonObject("mime_type") { put("type", "string"); put("description", "Filter by MIME type") }
                    putJsonObject("include_request") { put("type", "boolean"); put("description", "Include full request text (default false). Also unmasks sensitive request header values (Cookie, Authorization, …) which are otherwise redacted in request_headers") }
                    putJsonObject("include_response") { put("type", "boolean"); put("description", "Include full response text (default false)") }
                    putJsonObject("in_scope_only") { put("type", "boolean"); put("description", "Restrict to in-scope items (default false)") }
                    intProp("max_response_length", "Truncate request/response text to this many characters (default 200000)", min = 1)
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val result = bridge.getHistory(
                    startIndex = args.int("start_index", 0..Int.MAX_VALUE) ?: 0,
                    count = args.int("count", 0..ProxyBridge.MAX_PAGE_SIZE) ?: 100,
                    host = args.string("host"),
                    method = args.string("method"),
                    statusCode = args.int("status_code", 0..999),
                    mimeType = args.string("mime_type"),
                    inScopeOnly = args.bool("in_scope_only", false),
                    includeRequest = args.bool("include_request", false),
                    includeResponse = args.bool("include_response", false),
                    statusCodeRange = args.string("status_code_range"),
                    maxResponseLength = args.int("max_response_length", 1..Int.MAX_VALUE),
                )
                toolJsonResult(result)
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 2. proxy_history_search
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_history_search",
            description = "Search proxy history using a regex pattern. Can search in request, response, or both. Returns matching history entries.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("pattern") { put("type", "string"); put("description", "Regex pattern to search for") }
                    enumProp("search_in", SEARCH_TARGETS, "Where to search: 'url', 'request', 'response', or 'both' (default 'both' = url+request+response)")
                    putJsonObject("case_sensitive") { put("type", "boolean"); put("description", "Case-sensitive matching (default false)") }
                    intProp("max_results", "Maximum number of results (default 100, max ${ProxyBridge.MAX_PAGE_SIZE})", min = 0, max = ProxyBridge.MAX_PAGE_SIZE)
                    putJsonObject("in_scope_only") { put("type", "boolean"); put("description", "Restrict to in-scope items (default false)") }
                    putJsonObject("include_request") { put("type", "boolean"); put("description", "Include full request text (default false). Also unmasks sensitive request header values (Cookie, Authorization, …) which are otherwise redacted in request_headers") }
                    putJsonObject("include_response") { put("type", "boolean"); put("description", "Include full response text (default false)") }
                    intProp("max_response_length", "Truncate request/response text to this many characters (default 200000)", min = 1)
                },
                required = listOf("pattern")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val pattern = args.string("pattern")
                    ?: return@addTool toolError("Parameter 'pattern' is required")
                val searchIn = args.string("search_in") ?: "both"
                // "all" is accepted as an alias of "both".
                EnumValidation.error(searchIn, SEARCH_TARGETS.toSet() + "all", "search_in")?.let {
                    return@addTool toolJsonResult(it)
                }

                val result = bridge.searchHistory(
                    pattern = pattern,
                    searchIn = searchIn,
                    caseSensitive = args.bool("case_sensitive", false),
                    maxResults = args.int("max_results", 0..ProxyBridge.MAX_PAGE_SIZE) ?: 100,
                    inScopeOnly = args.bool("in_scope_only", false),
                    includeRequest = args.bool("include_request", false),
                    includeResponse = args.bool("include_response", false),
                    maxResponseLength = args.int("max_response_length", 1..Int.MAX_VALUE),
                )
                toolJsonResult(result)
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 3. proxy_websocket_history
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_websocket_history",
            description = "Get WebSocket proxy history entries with optional filtering by host and direction (client_to_server or server_to_client).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    intProp("start_index", "Start index of history entries (default 0)", min = 0)
                    intProp("count", "Maximum number of entries to return (default 100, max ${ProxyBridge.MAX_PAGE_SIZE})", min = 0, max = ProxyBridge.MAX_PAGE_SIZE)
                    putJsonObject("host") { put("type", "string"); put("description", "Filter by upgrade host (case-insensitive substring)") }
                    enumProp("direction", WS_DIRECTIONS, "Direction filter (case-insensitive): 'client_to_server', 'server_to_client', or 'both' (default, no filter)")
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val result = bridge.getWebSocketHistory(
                    startIndex = args.int("start_index", 0..Int.MAX_VALUE) ?: 0,
                    count = args.int("count", 0..ProxyBridge.MAX_PAGE_SIZE) ?: 100,
                    host = args.string("host"),
                    direction = args.string("direction"),
                )
                toolJsonResult(result)
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 4. proxy_websocket_history_search
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_websocket_history_search",
            description = "Search WebSocket proxy history using a regex pattern on message payloads. Can filter by direction.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("pattern") { put("type", "string"); put("description", "Regex pattern to search message payloads") }
                    enumProp("direction", WS_DIRECTIONS, "Direction filter (case-insensitive): 'client_to_server', 'server_to_client', or 'both' (default, no filter)")
                    intProp("max_results", "Maximum number of results (default 100, max ${ProxyBridge.MAX_PAGE_SIZE})", min = 0, max = ProxyBridge.MAX_PAGE_SIZE)
                },
                required = listOf("pattern")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val pattern = args.string("pattern")
                    ?: return@addTool toolError("Parameter 'pattern' is required")

                val result = bridge.searchWebSocketHistory(
                    pattern = pattern,
                    direction = args.string("direction"),
                    maxResults = args.int("max_results", 0..ProxyBridge.MAX_PAGE_SIZE) ?: 100,
                )
                toolJsonResult(result)
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 5. proxy_intercept_enable
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_intercept_enable",
            description = "Enable proxy interception. When enabled, requests/responses will be held for review before forwarding.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { _ ->
            try {
                toolJsonResult(bridge.enableIntercept())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 6. proxy_intercept_disable
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_intercept_disable",
            description = "Disable proxy interception. Requests/responses will pass through without being held.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { _ ->
            try {
                toolJsonResult(bridge.disableIntercept())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 7. proxy_intercept_status
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_intercept_status",
            description = "Get the current proxy interception state (enabled or disabled).",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { _ ->
            try {
                toolJsonResult(bridge.isInterceptEnabled())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 8. proxy_annotate
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_annotate",
            description = "Annotate a proxy history item by setting a comment and/or highlight color. Highlight colors: NONE, RED, ORANGE, YELLOW, GREEN, CYAN, BLUE, PINK, MAGENTA, GRAY.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    intProp("index", "Proxy history item ID", min = 0)
                    putJsonObject("comment") { put("type", "string"); put("description", "Comment to set on the item") }
                    enumProp("highlight", HIGHLIGHT_COLORS, "Highlight color (case-insensitive); NONE clears it")
                },
                required = listOf("index")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val index = args.int("index", 0..Int.MAX_VALUE)
                    ?: return@addTool toolError("Parameter 'index' is required (proxy history item ID)")

                toolJsonResult(bridge.annotateHistoryItem(index, args.string("comment"), args.string("highlight")))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 9. proxy_set_request_rule
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_set_request_rule",
            description = "Set a proxy request interception rule. Rules can match on host, URL, method, header, or body patterns and perform actions: 'modify' (add/remove/replace headers, body regex replacement), 'drop' (silently drop the request), or 'tag' (annotate in proxy history). If rule_id matches an existing rule, it is replaced.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("rule_id") { put("type", "string"); put("description", "Rule ID; auto-generated if omitted") }
                    enumProp("action", RULE_ACTIONS, "Action: 'modify', 'drop', or 'tag'")
                    putJsonObject("match_host") { put("type", "string"); put("description", MATCH_HOST_DESCRIPTION) }
                    putJsonObject("match_url") { put("type", "string"); put("description", "Regex (case-insensitive) searched in the full URL") }
                    putJsonObject("match_method") { put("type", "string"); put("description", "HTTP method to match (exact, case-insensitive)") }
                    putJsonObject("match_header") { put("type", "string"); put("description", "Regex (case-insensitive) searched in the 'Name: value' header lines") }
                    putJsonObject("match_body") { put("type", "string"); put("description", "Regex (case-insensitive) searched in the body") }
                    putJsonObject("modify_add_header") { put("type", "string"); put("description", "Header to add when action is 'modify', as one 'Name: Value' line") }
                    putJsonObject("modify_remove_header") { put("type", "string"); put("description", "Header name to remove when action is 'modify'") }
                    putJsonObject("modify_replace_header") { put("type", "object"); put("description", "Map of header names to replacement values") }
                    putJsonObject("modify_body_regex") { put("type", "string"); put("description", "Regex for body replacement (requires modify_body_replacement)") }
                    putJsonObject("modify_body_replacement") { put("type", "string"); put("description", "Replacement for body regex matches (\"\" deletes them)") }
                    putJsonObject("tag_comment") { put("type", "string"); put("description", "Comment to attach when action is 'tag'") }
                    enumProp("tag_highlight", HIGHLIGHT_COLORS, "Highlight color when action is 'tag'")
                    putJsonObject("enabled") { put("type", "boolean"); put("description", "Whether the rule is active (default true)") }
                },
                required = listOf("action")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val rule = buildRule(args, "request", stateManager)
                    ?: return@addTool toolError("A rule action is required: 'modify', 'drop', or 'tag'")
                toolJsonResult(bridge.setRule(rule))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 10. proxy_set_response_rule
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_set_response_rule",
            description = "Set a proxy response interception rule. Rules can match on host, URL, status code, header, or body patterns and perform actions: 'modify' (add/remove/replace headers, body regex replacement), 'drop' (silently drop the response), or 'tag' (annotate in proxy history). If rule_id matches an existing rule, it is replaced.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("rule_id") { put("type", "string"); put("description", "Rule ID; auto-generated if omitted") }
                    enumProp("action", RULE_ACTIONS, "Action: 'modify', 'drop', or 'tag'")
                    putJsonObject("match_host") { put("type", "string"); put("description", MATCH_HOST_DESCRIPTION) }
                    putJsonObject("match_url") { put("type", "string"); put("description", "Regex (case-insensitive) searched in the full URL") }
                    putJsonObject("match_header") { put("type", "string"); put("description", "Regex (case-insensitive) searched in the 'Name: value' header lines") }
                    putJsonObject("match_body") { put("type", "string"); put("description", "Regex (case-insensitive) searched in the body") }
                    intProp("match_status", "Status code to match", min = 0, max = 999)
                    putJsonObject("modify_add_header") { put("type", "string"); put("description", "Header to add when action is 'modify', as one 'Name: Value' line") }
                    putJsonObject("modify_remove_header") { put("type", "string"); put("description", "Header name to remove when action is 'modify'") }
                    putJsonObject("modify_replace_header") { put("type", "object"); put("description", "Map of header names to replacement values") }
                    putJsonObject("modify_body_regex") { put("type", "string"); put("description", "Regex for body replacement (requires modify_body_replacement)") }
                    putJsonObject("modify_body_replacement") { put("type", "string"); put("description", "Replacement for body regex matches (\"\" deletes them)") }
                    putJsonObject("tag_comment") { put("type", "string"); put("description", "Comment to attach when action is 'tag'") }
                    enumProp("tag_highlight", HIGHLIGHT_COLORS, "Highlight color when action is 'tag'")
                    putJsonObject("enabled") { put("type", "boolean"); put("description", "Whether the rule is active (default true)") }
                },
                required = listOf("action")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val rule = buildRule(args, "response", stateManager)
                    ?: return@addTool toolError("A rule action is required: 'modify', 'drop', or 'tag'")
                toolJsonResult(bridge.setRule(rule))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 11. proxy_list_rules
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_list_rules",
            description = "List all proxy interception rules. Optionally filter by type ('request' or 'response').",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    enumProp("type", listOf("request", "response"), "Filter by rule type ('request' or 'response')")
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                toolJsonResult(bridge.listRules(args.string("type")))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 12. proxy_remove_rule
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_remove_rule",
            description = "Remove a proxy interception rule by its rule ID.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("rule_id") { put("type", "string"); put("description", "ID of the rule to remove") }
                },
                required = listOf("rule_id")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val ruleId = args.string("rule_id")
                    ?: return@addTool toolError("Parameter 'rule_id' is required")

                toolJsonResult(bridge.removeRule(ruleId))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 13. proxy_auto_auth
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_auto_auth",
            description = "Convenience tool: auto-inject an authentication header into all proxy requests matching a host pattern. Creates a proxy request rule that adds the specified header. Use proxy_remove_rule with the returned rule_id to remove it later. Parameters: header_name (default 'Authorization'), header_value (required), host_pattern (glob or regex, default '.*' for all hosts).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("header_name") { put("type", "string"); put("description", "Header name to inject (default 'Authorization')") }
                    putJsonObject("header_value") { put("type", "string"); put("description", "Header value to inject") }
                    putJsonObject("host_pattern") { put("type", "string"); put("description", "$MATCH_HOST_DESCRIPTION; default '.*' for all hosts") }
                },
                required = listOf("header_value")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val headerName = args.string("header_name") ?: "Authorization"
                val headerValue = args.string("header_value")
                    ?: return@addTool toolError("Parameter 'header_value' is required")
                val hostPattern = args.string("host_pattern") ?: ".*"

                val ruleId = stateManager.generateId("auto-auth")
                val stored = bridge.setRule(ProxyRule(
                    ruleId = ruleId,
                    type = "request",
                    matchHost = hostPattern,
                    action = "modify",
                    modifyAddHeader = "$headerName: $headerValue",
                    enabled = true
                ))
                if (stored["error"] != null) return@addTool toolJsonResult(stored)

                toolJsonResult(buildJsonObject {
                    put("rule_id", ruleId)
                    put("status", "active")
                    put("header", "$headerName: $headerValue")
                    put("host_pattern", hostPattern)
                    put("note", "Use proxy_remove_rule with rule_id to deactivate")
                })
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }

    /**
     * Builds the request/response rule described by [args], or null when no action was given.
     * Pattern, header and colour checks happen in [ProxyBridge.setRule].
     */
    private fun buildRule(args: Map<String, JsonElement>, type: String, stateManager: StateManager): ProxyRule? {
        val action = args.string("action")?.trim()?.lowercase() ?: return null
        val replaceHeader = args["modify_replace_header"]?.takeUnless { it is JsonNull }?.let { element ->
            element.asStringMap()
                ?: throw IllegalArgumentException("Parameter 'modify_replace_header' must be an object of header name to value")
        }
        return ProxyRule(
            ruleId = args.string("rule_id") ?: stateManager.generateId("prule"),
            type = type,
            matchHost = args.string("match_host"),
            matchUrl = args.string("match_url"),
            matchMethod = if (type == "request") args.string("match_method") else null,
            matchHeader = args.string("match_header"),
            matchBody = args.string("match_body"),
            matchStatus = if (type == "response") args.int("match_status", 0..999) else null,
            action = action,
            modifyAddHeader = args.string("modify_add_header"),
            modifyRemoveHeader = args.string("modify_remove_header"),
            modifyReplaceHeader = replaceHeader,
            modifyBodyRegex = args.string("modify_body_regex"),
            modifyBodyReplacement = args.string("modify_body_replacement"),
            tagComment = args.string("tag_comment"),
            tagHighlight = args.string("tag_highlight"),
            enabled = args.bool("enabled", true)
        )
    }

    // ---------------------------------------------------------------
    // Argument and schema helpers
    // ---------------------------------------------------------------

    private fun Map<String, JsonElement>.string(name: String): String? = (this[name] as? JsonPrimitive)?.contentOrNull

    private fun Map<String, JsonElement>.bool(name: String, default: Boolean): Boolean =
        (this[name] as? JsonPrimitive)?.booleanOrNull ?: default

    /** Optional integer argument; a non-integer or a value outside [range] throws, reported as a tool error. */
    private fun Map<String, JsonElement>.int(name: String, range: IntRange): Int? {
        val element = this[name]
        if (element == null || element is JsonNull) return null
        val value = element.asLongSafe() ?: throw IllegalArgumentException("Parameter '$name' must be an integer")
        require(value >= range.first && value <= range.last) {
            if (range.last == Int.MAX_VALUE) "Parameter '$name' must be at least ${range.first} (got $value)"
            else "Parameter '$name' must be between ${range.first} and ${range.last} (got $value)"
        }
        return value.toInt()
    }

    private fun JsonObjectBuilder.intProp(name: String, description: String, min: Int? = null, max: Int? = null) {
        putJsonObject(name) {
            put("type", "integer")
            if (min != null) put("minimum", min)
            if (max != null) put("maximum", max)
            put("description", description)
        }
    }

    private fun JsonObjectBuilder.enumProp(name: String, values: List<String>, description: String) {
        putJsonObject(name) {
            put("type", "string")
            putJsonArray("enum") { values.forEach { add(it) } }
            put("description", description)
        }
    }
}
