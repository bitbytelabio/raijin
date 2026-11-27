package io.bitbytelab.raijin.tools.proxy

import io.bitbytelab.raijin.bridge.HoldPolicy
import io.bitbytelab.raijin.bridge.InterceptEdit
import io.bitbytelab.raijin.bridge.ProxyBridge
import io.bitbytelab.raijin.bridge.ProxyInterceptHolds
import io.bitbytelab.raijin.bridge.ProxyRuleEdits
import io.bitbytelab.raijin.core.EnumValidation
import io.bitbytelab.raijin.core.asLongSafe
import io.bitbytelab.raijin.core.asStringList
import io.bitbytelab.raijin.core.asStringMap
import io.bitbytelab.raijin.state.ProxyRule
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.*

/**
 * Registers the proxy MCP tools onto the given [Server]: history and WebSocket history, Burp's
 * Intercept switch and Raijin's hold queue, annotations, rules and auto-auth.
 *
 * Each tool delegates to the [ProxyBridge] and catches exceptions so that errors are returned as
 * structured JSON inside a [CallToolResult] rather than propagating unhandled.
 */
object ProxyTools {

    private val HIGHLIGHT_COLORS =
        listOf(
            "NONE",
            "RED",
            "ORANGE",
            "YELLOW",
            "GREEN",
            "CYAN",
            "BLUE",
            "PINK",
            "MAGENTA",
            "GRAY",
        )
    private val RULE_ACTIONS = listOf("modify", "drop", "tag")
    private val WS_DIRECTIONS = listOf("client_to_server", "server_to_client", "both")
    private val SEARCH_TARGETS = listOf("url", "request", "response", "both")
    private val HOLD_TARGETS = listOf("request", "response", "both")

    private const val MATCH_HOST_DESCRIPTION =
        "Host to match: a glob such as '*.example.com' or a regex such as '.*\\.example\\.com' (whole host, case-insensitive)"

    private const val MODIFY_ADD_HEADER_DESCRIPTION =
        "Header to add when action is 'modify', as one 'Name: Value' line, written as given (CR/LF and any other character included)"

    private const val MODIFY_SET_HEADER_DESCRIPTION =
        "Map of header names to values when action is 'modify': each replaces the header (every occurrence, so it is never sent twice) or is added when absent"

    /**
     * proxy_history's page size when `count` is not given: small enough to stay inline in the CLI.
     */
    private const val DEFAULT_HISTORY_COUNT = 20

    fun register(server: Server, bridge: ProxyBridge, stateManager: StateManager) {

        // ---------------------------------------------------------------
        // 1. proxy_history
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_history",
            description =
                "Get HTTP proxy history entries with optional filtering by host, method, status code, status code range, MIME type. Returns request/response metadata and optionally full request/response text. " +
                    "Each item has 'id' (Burp's message id, what proxy_annotate takes) and 'index' (its place in the filtered list); next_start_index pages on.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            intProp(
                                "start_index",
                                "Start index of history entries (default 0)",
                                min = 0,
                            )
                            intProp(
                                "count",
                                "Maximum number of entries to return (default $DEFAULT_HISTORY_COUNT; above ${ProxyBridge.MAX_PAGE_SIZE} is served as ${ProxyBridge.MAX_PAGE_SIZE} with a note; 0 returns only total_filtered)",
                                min = 0,
                            )
                            putJsonObject("host") {
                                put("type", "string")
                                put("description", "Filter by host (case-insensitive substring)")
                            }
                            putJsonObject("method") {
                                put("type", "string")
                                put("description", "Filter by HTTP method")
                            }
                            intProp(
                                "status_code",
                                "Filter by exact status code; items without a response never match",
                                min = 0,
                                max = 999,
                            )
                            putJsonObject("status_code_range") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Filter by status code range: '200-299', '400-', '-399' or '404'; items without a response never match",
                                )
                            }
                            putJsonObject("mime_type") {
                                put("type", "string")
                                put("description", "Filter by MIME type")
                            }
                            putJsonObject("include_headers") {
                                put("type", "boolean")
                                put(
                                    "description",
                                    "Include each item's request_headers (default false)",
                                )
                            }
                            putJsonObject("include_request") {
                                put("type", "boolean")
                                put(
                                    "description",
                                    "Include full request text (default false). Also unmasks sensitive request header values (Cookie, Authorization, …) which are otherwise redacted in request_headers",
                                )
                            }
                            putJsonObject("include_response") {
                                put("type", "boolean")
                                put("description", "Include full response text (default false)")
                            }
                            putJsonObject("in_scope_only") {
                                put("type", "boolean")
                                put("description", "Restrict to in-scope items (default false)")
                            }
                            intProp(
                                "max_response_length",
                                "Truncate request/response text to this many characters (default 200000)",
                                min = 1,
                            )
                        },
                    required = emptyList(),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val result =
                    bridge.getHistory(
                        startIndex = args.integer("start_index") ?: 0,
                        count = args.integer("count") ?: DEFAULT_HISTORY_COUNT,
                        includeHeaders = args.bool("include_headers", false),
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
            description =
                "Search proxy history using a regex pattern. Can search in request, response, or both. Returns matching history entries: " +
                    "id is Burp's message id, index the place in the match list; next_start_index pages on. Texts over 5,000,000 characters " +
                    "are not searched and counted in skipped_oversize.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("pattern") {
                                put("type", "string")
                                put("description", "Regex pattern to search for")
                            }
                            enumProp(
                                "search_in",
                                SEARCH_TARGETS,
                                "Where to search: 'url', 'request', 'response', or 'both' (default 'both' = url+request+response)",
                            )
                            putJsonObject("case_sensitive") {
                                put("type", "boolean")
                                put("description", "Case-sensitive matching (default false)")
                            }
                            intProp(
                                "max_results",
                                "Maximum number of results (default 100; above ${ProxyBridge.MAX_PAGE_SIZE} is served as ${ProxyBridge.MAX_PAGE_SIZE} with a note)",
                                min = 0,
                            )
                            putJsonObject("in_scope_only") {
                                put("type", "boolean")
                                put("description", "Restrict to in-scope items (default false)")
                            }
                            putJsonObject("include_request") {
                                put("type", "boolean")
                                put(
                                    "description",
                                    "Include full request text (default false). Also unmasks sensitive request header values (Cookie, Authorization, …) which are otherwise redacted in request_headers",
                                )
                            }
                            putJsonObject("include_response") {
                                put("type", "boolean")
                                put("description", "Include full response text (default false)")
                            }
                            intProp(
                                "max_response_length",
                                "Truncate request/response text to this many characters (default 200000)",
                                min = 1,
                            )
                            intProp(
                                "start_index",
                                "Index of the first match to return (default 0); pass the result's next_start_index for the next page",
                                min = 0,
                            )
                        },
                    required = listOf("pattern"),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val pattern =
                    args.string("pattern")
                        ?: return@addTool toolError("Parameter 'pattern' is required")
                val given = args.string("search_in")
                // "all" means "both" (url+request+response): read it so, and say so.
                val searchIn =
                    if (given?.trim().equals("all", ignoreCase = true)) "both" else given ?: "both"
                val notes =
                    if (searchIn != given && given != null)
                        listOf("read search_in \"$given\" as \"both\"")
                    else emptyList()
                EnumValidation.error(searchIn, SEARCH_TARGETS.toSet(), "search_in")?.let {
                    return@addTool toolJsonResult(it)
                }

                val result =
                    bridge.searchHistory(
                        pattern = pattern,
                        searchIn = searchIn,
                        caseSensitive = args.bool("case_sensitive", false),
                        maxResults = args.integer("max_results") ?: 100,
                        inScopeOnly = args.bool("in_scope_only", false),
                        includeRequest = args.bool("include_request", false),
                        includeResponse = args.bool("include_response", false),
                        maxResponseLength = args.int("max_response_length", 1..Int.MAX_VALUE),
                        startIndex = args.integer("start_index") ?: 0,
                    )
                io.bitbytelab.raijin.tools.ToolArgs.withNotes(toolJsonResult(result), notes)
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 3. proxy_websocket_history
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_websocket_history",
            description =
                "Get WebSocket proxy history entries with optional filtering by connection (websocket_id), upgrade URL, host and direction (client_to_server or server_to_client).",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            intProp(
                                "start_index",
                                "Start index of history entries (default 0)",
                                min = 0,
                            )
                            intProp(
                                "count",
                                "Maximum number of entries to return (default 100; above ${ProxyBridge.MAX_PAGE_SIZE} is served as ${ProxyBridge.MAX_PAGE_SIZE} with a note)",
                                min = 0,
                            )
                            putJsonObject("host") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Filter by upgrade host (case-insensitive substring)",
                                )
                            }
                            enumProp(
                                "direction",
                                WS_DIRECTIONS,
                                "Direction filter (case-insensitive): 'client_to_server', 'server_to_client', or 'both' (default, no filter)",
                            )
                            intProp(
                                "websocket_id",
                                "Only messages of this proxied connection (the 'websocket_id' of an item)",
                                min = 0,
                            )
                            putJsonObject("url") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Only messages whose upgrade request URL contains this (case-insensitive)",
                                )
                            }
                        },
                    required = emptyList(),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val result =
                    bridge.getWebSocketHistory(
                        startIndex = args.integer("start_index") ?: 0,
                        count = args.integer("count") ?: 100,
                        host = args.string("host"),
                        direction = args.string("direction"),
                        webSocketId = args.integer("websocket_id"),
                        url = args.string("url"),
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
            description =
                "Search WebSocket proxy history using a regex pattern on message payloads. Can filter by direction, connection (websocket_id) and upgrade URL.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("pattern") {
                                put("type", "string")
                                put("description", "Regex pattern to search message payloads")
                            }
                            enumProp(
                                "direction",
                                WS_DIRECTIONS,
                                "Direction filter (case-insensitive): 'client_to_server', 'server_to_client', or 'both' (default, no filter)",
                            )
                            intProp(
                                "max_results",
                                "Maximum number of results (default 100; above ${ProxyBridge.MAX_PAGE_SIZE} is served as ${ProxyBridge.MAX_PAGE_SIZE} with a note)",
                                min = 0,
                            )
                            intProp(
                                "websocket_id",
                                "Only messages of this proxied connection (the 'websocket_id' of an item)",
                                min = 0,
                            )
                            putJsonObject("url") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Only messages whose upgrade request URL contains this (case-insensitive)",
                                )
                            }
                            intProp(
                                "start_index",
                                "Index of the first match to return (default 0); pass the result's next_start_index for the next page",
                                min = 0,
                            )
                        },
                    required = listOf("pattern"),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val pattern =
                    args.string("pattern")
                        ?: return@addTool toolError("Parameter 'pattern' is required")

                val result =
                    bridge.searchWebSocketHistory(
                        pattern = pattern,
                        direction = args.string("direction"),
                        maxResults = args.integer("max_results") ?: 100,
                        webSocketId = args.integer("websocket_id"),
                        url = args.string("url"),
                        startIndex = args.integer("start_index") ?: 0,
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
            description =
                "Turn on Burp's own proxy interception: the Intercept tab holds each message for a person at Burp to review. To hold messages for yourself instead, use action 'hold'.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList()),
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
            description =
                "Turn off Burp's own proxy interception: messages pass through Burp's Intercept tab without being held. Raijin's hold queue is separate (action 'release').",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList()),
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
            description =
                "Get the proxy interception state: Burp's own Intercept switch, and Raijin's hold queue (armed, filters, held count, totals).",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList()),
        ) { _ ->
            try {
                toolJsonResult(bridge.isInterceptEnabled())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // Raijin's hold queue: hold, list_held, forward, drop, release
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_intercept_hold",
            description =
                "Hold proxied requests and/or responses that match the filters until you forward, edit or drop them " +
                    "(Raijin's own queue; Burp's Intercept tab is separate). Messages are held just before they are sent, after " +
                    "Burp's Intercept tab and the proxy rules, so what you see and edit is what goes on the wire. A held message " +
                    "nobody decides on within timeout_seconds is forwarded unchanged, and after 3 such timeouts in a row holding " +
                    "stops by itself, so traffic is never stuck. Call again to change the filters; action 'release' stops holding.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            enumProp(
                                "target",
                                HOLD_TARGETS,
                                "What to hold: 'request' (default), 'response' or 'both'",
                            )
                            putJsonObject("match_host") {
                                put("type", "string")
                                put(
                                    "description",
                                    "$MATCH_HOST_DESCRIPTION; omit to hold every host",
                                )
                            }
                            putJsonObject("match_url") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Regex (case-insensitive) searched in the full URL; omit to hold every URL",
                                )
                            }
                            putJsonObject("match_method") {
                                put("type", "string")
                                put(
                                    "description",
                                    "HTTP method to hold (case-insensitive); for a response, the method of its request",
                                )
                            }
                            putJsonObject("in_scope_only") {
                                put("type", "boolean")
                                put(
                                    "description",
                                    "Only hold messages Burp's scope considers in scope (default false)",
                                )
                            }
                            intProp(
                                "timeout_seconds",
                                "Seconds one message is held without a decision before it is forwarded unchanged (default ${HoldPolicy.DEFAULT_TIMEOUT_SECONDS}, 1-${HoldPolicy.MAX_TIMEOUT_SECONDS}; other values are clamped with a note)",
                                min = 1,
                            )
                            intProp(
                                "max_held",
                                "Most messages held at once; more pass straight through (default ${HoldPolicy.DEFAULT_MAX_HELD}, 1-${HoldPolicy.MAX_HELD}; other values are clamped with a note)",
                                min = 1,
                            )
                            intProp(
                                "max_messages",
                                "Stop holding after this many messages (default: no limit)",
                                min = 1,
                            )
                        },
                    required = emptyList(),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val result =
                    bridge.interceptHolds.arm(
                        target = args.string("target"),
                        matchHost = args.string("match_host"),
                        matchUrl = args.string("match_url"),
                        matchMethod = args.string("match_method"),
                        inScopeOnly = args.bool("in_scope_only", false),
                        timeoutSeconds = args.integer("timeout_seconds"),
                        maxHeld = args.integer("max_held"),
                        maxMessages = args.integer("max_messages"),
                    )
                toolJsonResult(result)
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "proxy_intercept_list_held",
            description =
                "List the messages held right now, oldest first, with their raw text, optionally waiting for one to arrive. " +
                    "Each has an 'id' for actions 'forward' and 'drop', and 'expires_in_ms' before it is forwarded unchanged.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            intProp(
                                "wait_seconds",
                                "When nothing is held, wait up to this many seconds for a message (default 0, max ${ProxyInterceptHolds.MAX_WAIT_SECONDS})",
                                min = 0,
                            )
                            putJsonObject("include_raw") {
                                put("type", "boolean")
                                put("description", "Include each message's raw text (default true)")
                            }
                            intProp(
                                "max_length",
                                "Body characters returned per message (default ${ProxyInterceptHolds.DEFAULT_RAW_LENGTH}); the request or status line and headers are always complete",
                                min = 1,
                            )
                        },
                    required = emptyList(),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                toolJsonResult(
                    bridge.interceptHolds.listHeld(
                        waitSeconds = args.integer("wait_seconds"),
                        includeRaw = args.bool("include_raw", true),
                        maxLength = args.integer("max_length"),
                    ),
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "proxy_intercept_forward",
            description =
                "Forward a held message, edited or as it is, or every held message unchanged (all=true). " +
                    "Edits apply in this order: raw (the whole replacement message), then method, path, status_code, remove_headers, " +
                    "set_headers, body. Nothing is held to the HTTP grammar: header names and values may carry CR/LF or any other character.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            intProp(
                                "id",
                                "Id of the held message (from action 'list_held')",
                                min = 1,
                            )
                            putJsonObject("all") {
                                put("type", "boolean")
                                put(
                                    "description",
                                    "Forward every held message unchanged (default false)",
                                )
                            }
                            putJsonObject("raw") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Whole replacement message, request or response. Header line endings become CRLF; the body is sent as written. A request still goes to the held request's host, port and protocol",
                                )
                            }
                            putJsonObject("auto_fix_content_length") {
                                put("type", "boolean")
                                put(
                                    "description",
                                    "With raw: correct a single mismatching Content-Length (default true). A message framed by Transfer-Encoding or several Content-Length headers is never touched",
                                )
                            }
                            putJsonObject("method") {
                                put("type", "string")
                                put("description", "Held request: HTTP method to send instead")
                            }
                            putJsonObject("path") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Held request: path and query string to send instead",
                                )
                            }
                            intProp(
                                "status_code",
                                "Held response: status code to answer with instead",
                                min = 0,
                                max = ProxyRuleEdits.MAX_STATUS,
                            )
                            putJsonObject("set_headers") {
                                put("type", "object")
                                put(
                                    "description",
                                    "Headers to set, name to value: each replaces every occurrence of that header, or is added when absent",
                                )
                            }
                            putJsonObject("remove_headers") {
                                put("type", "array")
                                putJsonObject("items") { put("type", "string") }
                                put("description", "Header names to remove (every occurrence)")
                            }
                            putJsonObject("body") {
                                put("type", "string")
                                put("description", "Body to send instead")
                            }
                        },
                    required = emptyList(),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val edit =
                    InterceptEdit(
                        raw = args.string("raw"),
                        autoFixContentLength = args.bool("auto_fix_content_length", true),
                        method = args.string("method"),
                        path = args.string("path"),
                        statusCode = args.integer("status_code"),
                        setHeaders = args.headerMap("set_headers").orEmpty(),
                        removeHeaders = args.nameList("remove_headers"),
                        body = args.string("body"),
                    )
                toolJsonResult(
                    bridge.interceptHolds.forward(args.long("id"), args.bool("all", false), edit),
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "proxy_intercept_drop",
            description =
                "Drop a held message so it never reaches the server (request) or the browser (response), or drop every held message (all=true).",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            intProp(
                                "id",
                                "Id of the held message (from action 'list_held')",
                                min = 1,
                            )
                            putJsonObject("all") {
                                put("type", "boolean")
                                put("description", "Drop every held message (default false)")
                            }
                        },
                    required = emptyList(),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                toolJsonResult(bridge.interceptHolds.drop(args.long("id"), args.bool("all", false)))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "proxy_intercept_release",
            description = "Stop holding and forward every held message unchanged.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList()),
        ) { _ ->
            try {
                toolJsonResult(bridge.interceptHolds.release())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 8. proxy_annotate
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_annotate",
            description =
                "Annotate a proxy history item by setting a comment and/or highlight color. Highlight colors: NONE, RED, ORANGE, YELLOW, GREEN, CYAN, BLUE, PINK, MAGENTA, GRAY.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            intProp(
                                "id",
                                "Burp's id of the proxy history item (the 'id' of a proxy_history item, not its 'index')",
                                min = 0,
                            )
                            putJsonObject("comment") {
                                put("type", "string")
                                put("description", "Comment to set on the item")
                            }
                            enumProp(
                                "highlight",
                                HIGHLIGHT_COLORS,
                                "Highlight color (case-insensitive); NONE clears it",
                            )
                        },
                    required = listOf("id"),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val id =
                    args.int("id", 0..Int.MAX_VALUE)
                        ?: return@addTool toolError(
                            "Parameter 'id' is required (the 'id' of a proxy_history item)",
                        )

                toolJsonResult(
                    bridge.annotateHistoryItem(
                        id,
                        args.string("comment"),
                        args.string("highlight"),
                    ),
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 9. proxy_set_request_rule
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_set_request_rule",
            description =
                "Set a proxy request interception rule. Rules can match on host, URL, method, header, or body patterns and perform actions: 'modify' (add/remove/replace/set headers, body regex replacement, method, path), 'drop' (silently drop the request), or 'tag' (annotate in proxy history). Headers are written as given, CR/LF included. If rule_id matches an existing rule, it is replaced.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("rule_id") {
                                put("type", "string")
                                put("description", "Rule ID; auto-generated if omitted")
                            }
                            enumProp("action", RULE_ACTIONS, "Action: 'modify', 'drop', or 'tag'")
                            putJsonObject("match_host") {
                                put("type", "string")
                                put("description", MATCH_HOST_DESCRIPTION)
                            }
                            putJsonObject("match_url") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Regex (case-insensitive) searched in the full URL",
                                )
                            }
                            putJsonObject("match_method") {
                                put("type", "string")
                                put("description", "HTTP method to match (exact, case-insensitive)")
                            }
                            putJsonObject("match_header") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Regex (case-insensitive) searched in the 'Name: value' header lines",
                                )
                            }
                            putJsonObject("match_body") {
                                put("type", "string")
                                put("description", "Regex (case-insensitive) searched in the body")
                            }
                            putJsonObject("modify_add_header") {
                                put("type", "string")
                                put("description", MODIFY_ADD_HEADER_DESCRIPTION)
                            }
                            putJsonObject("modify_remove_header") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Header name to remove (every occurrence) when action is 'modify'",
                                )
                            }
                            putJsonObject("modify_replace_header") {
                                put("type", "object")
                                put(
                                    "description",
                                    "Map of header names to values, applied to headers the request already has",
                                )
                            }
                            putJsonObject("modify_set_header") {
                                put("type", "object")
                                put("description", MODIFY_SET_HEADER_DESCRIPTION)
                            }
                            putJsonObject("modify_body_regex") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Regex for body replacement (requires modify_body_replacement)",
                                )
                            }
                            putJsonObject("modify_body_replacement") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Replacement for body regex matches (\"\" deletes them)",
                                )
                            }
                            putJsonObject("modify_method") {
                                put("type", "string")
                                put(
                                    "description",
                                    "HTTP method to send instead when action is 'modify'",
                                )
                            }
                            putJsonObject("modify_path") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Path and query string to send instead when action is 'modify'; with modify_path_regex, the replacement for each match ($1 refers to a group, \"\" deletes)",
                                )
                            }
                            putJsonObject("modify_path_regex") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Regex (case-insensitive) searched in the path and query string; its matches are replaced by modify_path",
                                )
                            }
                            putJsonObject("tag_comment") {
                                put("type", "string")
                                put("description", "Comment to attach when action is 'tag'")
                            }
                            enumProp(
                                "tag_highlight",
                                HIGHLIGHT_COLORS,
                                "Highlight color when action is 'tag'",
                            )
                            putJsonObject("enabled") {
                                put("type", "boolean")
                                put("description", "Whether the rule is active (default true)")
                            }
                        },
                    required = listOf("action"),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val rule =
                    buildRule(args, "request", stateManager)
                        ?: return@addTool toolError(
                            "A rule action is required: 'modify', 'drop', or 'tag'",
                        )
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
            description =
                "Set a proxy response interception rule. Rules can match on host, URL, status code, header, or body patterns and perform actions: 'modify' (add/remove/replace/set headers, body regex replacement, status code), 'drop' (silently drop the response), or 'tag' (annotate in proxy history). Headers are written as given, CR/LF included. If rule_id matches an existing rule, it is replaced.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("rule_id") {
                                put("type", "string")
                                put("description", "Rule ID; auto-generated if omitted")
                            }
                            enumProp("action", RULE_ACTIONS, "Action: 'modify', 'drop', or 'tag'")
                            putJsonObject("match_host") {
                                put("type", "string")
                                put("description", MATCH_HOST_DESCRIPTION)
                            }
                            putJsonObject("match_url") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Regex (case-insensitive) searched in the full URL",
                                )
                            }
                            putJsonObject("match_header") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Regex (case-insensitive) searched in the 'Name: value' header lines",
                                )
                            }
                            putJsonObject("match_body") {
                                put("type", "string")
                                put("description", "Regex (case-insensitive) searched in the body")
                            }
                            intProp("match_status", "Status code to match", min = 0, max = 999)
                            putJsonObject("modify_add_header") {
                                put("type", "string")
                                put("description", MODIFY_ADD_HEADER_DESCRIPTION)
                            }
                            putJsonObject("modify_remove_header") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Header name to remove (every occurrence) when action is 'modify'",
                                )
                            }
                            putJsonObject("modify_replace_header") {
                                put("type", "object")
                                put(
                                    "description",
                                    "Map of header names to values, applied to headers the response already has",
                                )
                            }
                            putJsonObject("modify_set_header") {
                                put("type", "object")
                                put("description", MODIFY_SET_HEADER_DESCRIPTION)
                            }
                            putJsonObject("modify_body_regex") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Regex for body replacement (requires modify_body_replacement)",
                                )
                            }
                            putJsonObject("modify_body_replacement") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Replacement for body regex matches (\"\" deletes them)",
                                )
                            }
                            intProp(
                                "modify_status",
                                "Status code to answer with instead when action is 'modify'",
                                min = 0,
                                max = ProxyRuleEdits.MAX_STATUS,
                            )
                            putJsonObject("tag_comment") {
                                put("type", "string")
                                put("description", "Comment to attach when action is 'tag'")
                            }
                            enumProp(
                                "tag_highlight",
                                HIGHLIGHT_COLORS,
                                "Highlight color when action is 'tag'",
                            )
                            putJsonObject("enabled") {
                                put("type", "boolean")
                                put("description", "Whether the rule is active (default true)")
                            }
                        },
                    required = listOf("action"),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val rule =
                    buildRule(args, "response", stateManager)
                        ?: return@addTool toolError(
                            "A rule action is required: 'modify', 'drop', or 'tag'",
                        )
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
            description =
                "List all proxy interception rules. Optionally filter by type ('request' or 'response').",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            enumProp(
                                "type",
                                listOf("request", "response"),
                                "Filter by rule type ('request' or 'response')",
                            )
                        },
                    required = emptyList(),
                ),
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
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("rule_id") {
                                put("type", "string")
                                put("description", "ID of the rule to remove")
                            }
                        },
                    required = listOf("rule_id"),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val ruleId =
                    args.string("rule_id")
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
            description =
                "Convenience tool: auto-inject an authentication header into all proxy requests matching a host pattern. Creates a proxy request rule that sets the header: one the request already has is replaced (never sent twice), a missing one is added. Use proxy_rule.remove with the returned rule_id to remove it later. Parameters: header_name (default 'Authorization'), header_value (required), host_pattern (glob or regex, default '.*' for all hosts).",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("header_name") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Header name to inject (default 'Authorization')",
                                )
                            }
                            putJsonObject("header_value") {
                                put("type", "string")
                                put("description", "Header value to inject")
                            }
                            putJsonObject("host_pattern") {
                                put("type", "string")
                                put(
                                    "description",
                                    "$MATCH_HOST_DESCRIPTION; default '.*' for all hosts",
                                )
                            }
                        },
                    required = listOf("header_value"),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val headerName = args.string("header_name") ?: "Authorization"
                val headerValue =
                    args.string("header_value")
                        ?: return@addTool toolError("Parameter 'header_value' is required")
                val hostPattern = args.string("host_pattern") ?: ".*"

                val ruleId = stateManager.generateId("auto-auth")
                val stored =
                    bridge.setRule(
                        ProxyRule(
                            ruleId = ruleId,
                            type = "request",
                            matchHost = hostPattern,
                            action = "modify",
                            modifySetHeader = mapOf(headerName to headerValue),
                            enabled = true,
                        ),
                    )
                if (stored["error"] != null) return@addTool toolJsonResult(stored)

                toolJsonResult(
                    buildJsonObject {
                        put("rule_id", ruleId)
                        put("status", "active")
                        put("header", "$headerName: $headerValue")
                        put("host_pattern", hostPattern)
                        put("note", "Use proxy_rule.remove with rule_id to deactivate")
                    },
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }

    /**
     * Builds the request/response rule described by [args], or null when no action was given.
     * Pattern, header and colour checks happen in [ProxyBridge.setRule].
     */
    private fun buildRule(
        args: Map<String, JsonElement>,
        type: String,
        stateManager: StateManager,
    ): ProxyRule? {
        val action = args.string("action")?.trim()?.lowercase() ?: return null
        val request = type == "request"
        return ProxyRule(
            ruleId = args.string("rule_id") ?: stateManager.generateId("prule"),
            type = type,
            matchHost = args.string("match_host"),
            matchUrl = args.string("match_url"),
            matchMethod = if (request) args.string("match_method") else null,
            matchHeader = args.string("match_header"),
            matchBody = args.string("match_body"),
            matchStatus = if (!request) args.int("match_status", 0..999) else null,
            action = action,
            modifyAddHeader = args.string("modify_add_header"),
            modifyRemoveHeader = args.string("modify_remove_header"),
            modifyReplaceHeader = args.headerMap("modify_replace_header"),
            modifyBodyRegex = args.string("modify_body_regex"),
            modifyBodyReplacement = args.string("modify_body_replacement"),
            tagComment = args.string("tag_comment"),
            tagHighlight = args.string("tag_highlight"),
            enabled = args.bool("enabled", true),
            modifyMethod = if (request) args.string("modify_method") else null,
            modifyPath = if (request) args.string("modify_path") else null,
            modifyPathRegex = if (request) args.string("modify_path_regex") else null,
            modifyStatus = if (!request) args.integer("modify_status") else null,
            modifySetHeader = args.headerMap("modify_set_header"),
        )
    }

    // ---------------------------------------------------------------
    // Argument and schema helpers
    // ---------------------------------------------------------------

    private fun Map<String, JsonElement>.string(name: String): String? =
        (this[name] as? JsonPrimitive)?.contentOrNull

    private fun Map<String, JsonElement>.bool(name: String, default: Boolean): Boolean =
        (this[name] as? JsonPrimitive)?.booleanOrNull ?: default

    /**
     * Optional integer argument; a non-integer or a value outside [range] throws, reported as a
     * tool error.
     */
    private fun Map<String, JsonElement>.int(name: String, range: IntRange): Int? {
        val element = this[name]
        if (element == null || element is JsonNull) return null
        val value =
            element.asLongSafe()
                ?: throw IllegalArgumentException("Parameter '$name' must be an integer")
        require(value >= range.first && value <= range.last) {
            if (range.last == Int.MAX_VALUE)
                "Parameter '$name' must be at least ${range.first} (got $value)"
            else "Parameter '$name' must be between ${range.first} and ${range.last} (got $value)"
        }
        return value.toInt()
    }

    /** Optional integer argument as a Long; a non-integer throws, reported as a tool error. */
    private fun Map<String, JsonElement>.long(name: String): Long? {
        val element = this[name]
        if (element == null || element is JsonNull) return null
        return element.asLongSafe()
            ?: throw IllegalArgumentException("Parameter '$name' must be an integer")
    }

    /**
     * Optional integer argument without a range: the bridge serves an out-of-range value at the
     * nearest bound and says so in `notes`. A non-integer throws, reported as a tool error.
     */
    private fun Map<String, JsonElement>.integer(name: String): Int? =
        long(name)?.coerceIn(Int.MIN_VALUE.toLong(), Int.MAX_VALUE.toLong())?.toInt()

    /** Optional map of header name to value; anything else throws, reported as a tool error. */
    private fun Map<String, JsonElement>.headerMap(name: String): Map<String, String>? =
        this[name]
            ?.takeUnless { it is JsonNull }
            ?.let { element ->
                element.asStringMap()
                    ?: throw IllegalArgumentException(
                        "Parameter '$name' must be an object of header name to value",
                    )
            }

    /**
     * Optional list of header names (a single string is one name); anything else throws, reported
     * as a tool error.
     */
    private fun Map<String, JsonElement>.nameList(name: String): List<String> {
        val element = this[name]
        if (element == null || element is JsonNull) return emptyList()
        return element.asStringList()
            ?: throw IllegalArgumentException("Parameter '$name' must be a list of header names")
    }

    private fun JsonObjectBuilder.intProp(
        name: String,
        description: String,
        min: Int? = null,
        max: Int? = null,
    ) {
        putJsonObject(name) {
            put("type", "integer")
            if (min != null) put("minimum", min)
            if (max != null) put("maximum", max)
            put("description", description)
        }
    }

    private fun JsonObjectBuilder.enumProp(
        name: String,
        values: List<String>,
        description: String,
    ) {
        putJsonObject(name) {
            put("type", "string")
            putJsonArray("enum") { values.forEach { add(it) } }
            put("description", description)
        }
    }
}
