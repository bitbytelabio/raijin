package io.bitbytelab.raijin.tools.websocket

import io.bitbytelab.raijin.bridge.WebSocketBridge
import io.bitbytelab.raijin.core.asLongSafe
import io.bitbytelab.raijin.core.asStringMap
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object WebSocketTools {

    /** Shared by every `direction` parameter in the websocket tool group, so the merged schema fits all of them. */
    private val DIRECTIONS = listOf("client_to_server", "server_to_client", "both")

    fun register(server: Server, bridge: WebSocketBridge, stateManager: StateManager) {

        server.addTool(
            name = "websocket_create",
            description = "Create a new WebSocket connection to a target URL. Constructs an " +
                "HTTP upgrade request and establishes a WebSocket connection through Burp. " +
                "All messages are automatically captured and available via websocket_get_messages. " +
                "Parameters: url (WebSocket URL, e.g. 'wss://example.com/ws', required), " +
                "headers (optional object of additional HTTP headers as key-value pairs), " +
                "subprotocol (optional string, WebSocket subprotocol to request).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url") { put("type", "string"); put("description", "WebSocket URL, e.g. 'wss://example.com/ws'") }
                    putJsonObject("headers") { put("type", "object"); put("description", "Additional HTTP headers as key-value pairs") }
                    putJsonObject("subprotocol") { put("type", "string"); put("description", "WebSocket subprotocol to request") }
                },
                required = listOf("url")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val url = args.string("url")
                    ?: return@addTool toolError("Missing required parameter: url")

                val headers = args["headers"]?.takeUnless { it is JsonNull }?.let { element ->
                    element.asStringMap()
                        ?: return@addTool toolError("Parameter 'headers' must be an object of header name to value")
                }
                val subprotocol = args.string("subprotocol")

                toolJsonResult(bridge.createConnection(url, headers, subprotocol))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "websocket_send_text",
            description = "Send a text message on an existing WebSocket connection. The message " +
                "is tracked and can be retrieved later via websocket_get_messages. " +
                "Parameters: connection_id (string, the WebSocket connection ID, required), " +
                "message (string, the text message to send, required).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("connection_id") { put("type", "string"); put("description", "The WebSocket connection ID") }
                    putJsonObject("message") { put("type", "string"); put("description", "The text message to send") }
                },
                required = listOf("connection_id", "message")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val connectionId = args.string("connection_id")
                    ?: return@addTool toolError("Missing required parameter: connection_id")
                val message = args.string("message")
                    ?: return@addTool toolError("Missing required parameter: message")

                toolJsonResult(bridge.sendText(connectionId, message))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "websocket_send_binary",
            description = "Send a binary message on an existing WebSocket connection. The data " +
                "must be base64-encoded and will be decoded before transmission. " +
                "Parameters: connection_id (string, the WebSocket connection ID, required), " +
                "data (string, base64-encoded binary data to send, required).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("connection_id") { put("type", "string"); put("description", "The WebSocket connection ID") }
                    putJsonObject("data") { put("type", "string"); put("description", "Base64-encoded binary data to send") }
                },
                required = listOf("connection_id", "data")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val connectionId = args.string("connection_id")
                    ?: return@addTool toolError("Missing required parameter: connection_id")
                val data = args.string("data")
                    ?: return@addTool toolError("Missing required parameter: data")

                toolJsonResult(bridge.sendBinary(connectionId, data))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "websocket_close",
            description = "Close an existing WebSocket connection. The connection status is " +
                "updated to 'closed' and all captured messages remain available for retrieval. " +
                "Parameters: connection_id (string, the WebSocket connection ID to close, required).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("connection_id") { put("type", "string"); put("description", "The WebSocket connection ID to close") }
                },
                required = listOf("connection_id")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val connectionId = args.string("connection_id")
                    ?: return@addTool toolError("Missing required parameter: connection_id")

                toolJsonResult(bridge.close(connectionId))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "websocket_list",
            description = "List all tracked WebSocket connections, including both programmatically " +
                "created connections and those intercepted through Burp's proxy. Returns " +
                "connection summaries with ID, URL, status, and message counts. No parameters required.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { _ ->
            try {
                toolJsonResult(bridge.listConnections())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "websocket_get_messages",
            description = "Retrieve messages from a specific WebSocket connection with optional " +
                "filtering and pagination. Supports cursor-based polling via since_index: pass the " +
                "index of the last message you read; no frame is ever skipped, and missed_messages " +
                "counts frames evicted from the buffer (newest ${io.bitbytelab.raijin.state.WebSocketConnection.MAX_MESSAGES} " +
                "kept) before you read them. Parameters: connection_id (string, required), direction " +
                "(optional, 'client_to_server', 'server_to_client' or 'both'), since_index (optional " +
                "integer, only return messages with index greater than this value, default -1 " +
                "for all), max_results (optional integer, maximum messages to return, default 100).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("connection_id") { put("type", "string"); put("description", "The WebSocket connection ID") }
                    enumProp("direction", DIRECTIONS, "Direction filter (case-insensitive): 'client_to_server', 'server_to_client', or 'both' (default, no filter)")
                    putJsonObject("since_index") { put("type", "integer"); put("minimum", -1); put("description", "Only return messages with index greater than this (default -1 for all)") }
                    putJsonObject("max_results") { put("type", "integer"); put("minimum", 0); put("description", "Maximum messages to return (default 100)") }
                },
                required = listOf("connection_id")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val connectionId = args.string("connection_id")
                    ?: return@addTool toolError("Missing required parameter: connection_id")
                val sinceIndex = args.long("since_index") ?: -1L
                val maxResults = args.long("max_results") ?: 100L
                if (maxResults !in 0L..Int.MAX_VALUE.toLong()) {
                    return@addTool toolError("Invalid max_results: $maxResults. Must be zero or a positive integer")
                }

                toolJsonResult(bridge.getMessages(connectionId, args.string("direction"), sinceIndex, maxResults.toInt()))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "websocket_set_intercept_rule",
            description = "Create or update a WebSocket message interception rule. Rules can " +
                "modify, drop, or tag messages matching specified criteria. Rules are evaluated " +
                "against all WebSocket traffic passing through Burp. " +
                "Parameters: rule_id (optional string, unique ID; auto-generated if not " +
                "provided), match_url (optional string, regex to match against WebSocket URL), " +
                "match_message (optional string, regex to match against message content), " +
                "direction (optional string, 'client_to_server', 'server_to_client', or " +
                "'both', default 'both'), action (string, 'modify', 'drop', or 'tag', required), " +
                "modify_regex (optional string, regex for content replacement when action is " +
                "'modify'), modify_replacement (optional string, replacement for regex matches), " +
                "tag_comment (optional string, comment to attach when action is 'tag'), " +
                "enabled (optional boolean, whether the rule is active, default true).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("rule_id") { put("type", "string"); put("description", "Unique rule ID; auto-generated if not provided") }
                    putJsonObject("match_url") { put("type", "string"); put("description", "Regex to match against WebSocket URL") }
                    putJsonObject("match_message") { put("type", "string"); put("description", "Regex to match against message content") }
                    enumProp("direction", DIRECTIONS, "Direction filter (case-insensitive): 'client_to_server', 'server_to_client', or 'both' (default, no filter)")
                    enumProp("action", listOf("modify", "drop", "tag"), "'modify', 'drop', or 'tag'")
                    putJsonObject("modify_regex") { put("type", "string"); put("description", "Regex for content replacement; required when action is 'modify'") }
                    putJsonObject("modify_replacement") { put("type", "string"); put("description", "Replacement for regex matches (default \"\")") }
                    putJsonObject("tag_comment") { put("type", "string"); put("description", "Comment to attach when action is 'tag'") }
                    putJsonObject("enabled") { put("type", "boolean"); put("description", "Whether the rule is active (default true)") }
                },
                required = listOf("action")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val action = args.string("action")
                    ?: return@addTool toolError("Missing required parameter: action ('modify', 'drop', or 'tag')")

                toolJsonResult(bridge.setInterceptRule(
                    ruleId = args.string("rule_id"),
                    matchUrl = args.string("match_url"),
                    matchMessage = args.string("match_message"),
                    direction = args.string("direction") ?: "both",
                    action = action,
                    modifyRegex = args.string("modify_regex"),
                    modifyReplacement = args.string("modify_replacement"),
                    tagComment = args.string("tag_comment"),
                    enabled = (args["enabled"] as? JsonPrimitive)?.booleanOrNull ?: true,
                ))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }

    private fun Map<String, JsonElement>.string(name: String): String? = (this[name] as? JsonPrimitive)?.contentOrNull

    /** Optional integer argument; a non-integer throws, reported as a tool error. */
    private fun Map<String, JsonElement>.long(name: String): Long? {
        val element = this[name]
        if (element == null || element is JsonNull) return null
        return element.asLongSafe() ?: throw IllegalArgumentException("Parameter '$name' must be an integer")
    }

    private fun JsonObjectBuilder.enumProp(name: String, values: List<String>, description: String) {
        putJsonObject(name) {
            put("type", "string")
            putJsonArray("enum") { values.forEach { add(it) } }
            put("description", description)
        }
    }
}
