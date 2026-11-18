package io.bitbytelab.raijin.tools.websocket

import io.bitbytelab.raijin.bridge.WebSocketBridge
import io.bitbytelab.raijin.bridge.WebSocketFrames
import io.bitbytelab.raijin.bridge.WebSocketFuzzPlan
import io.bitbytelab.raijin.bridge.WebSocketFuzzRequest
import io.bitbytelab.raijin.core.EnumValidation
import io.bitbytelab.raijin.core.PayloadLibraries
import io.bitbytelab.raijin.core.asBodyString
import io.bitbytelab.raijin.core.asBooleanSafe
import io.bitbytelab.raijin.core.asLongSafe
import io.bitbytelab.raijin.core.asStringList
import io.bitbytelab.raijin.core.asStringMap
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.safety.ScopeGate
import io.bitbytelab.raijin.state.WebSocketConnection
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runInterruptible
import kotlinx.serialization.json.*

object WebSocketTools {

    /** Shared by every `direction` parameter in the websocket tool group, so the merged schema fits all of them. */
    private val DIRECTIONS = listOf("client_to_server", "server_to_client", "both")

    /** Shared by every `message_type` parameter in the group, for the same reason. */
    private val MESSAGE_TYPES = WebSocketFrames.MESSAGE_TYPES

    fun register(server: Server, bridge: WebSocketBridge, stateManager: StateManager) {

        server.addTool(
            name = "websocket_create",
            description = "Create a new WebSocket connection to a target URL. Constructs an " +
                "HTTP upgrade request and establishes a WebSocket connection through Burp. " +
                "All messages are automatically captured and available via websocket_get_messages. " +
                "Parameters: url (WebSocket URL, e.g. 'wss://example.com/ws', required), " +
                "headers (optional object of additional HTTP headers as key-value pairs), " +
                "subprotocol (optional string, WebSocket subprotocol to request). The upgrade goes out exactly as given: " +
                "a raw CR/LF in the path, query or a header is sent as written and reported in warnings. " + ScopeGate.ADVISORY_NOTE,
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
                "is base64 (standard or URL-safe alphabet, padding optional, whitespace ignored) and is " +
                "decoded before transmission; the frame is recorded as the canonical base64 of the bytes sent. " +
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
                "counts frames evicted from the buffer (newest ${WebSocketConnection.MAX_MESSAGES} " +
                "kept) before you read them. The payload of a BINARY frame is base64; length is always the " +
                "frame size in bytes. To block until a frame arrives use websocket_wait_message instead of polling. " +
                "Parameters: connection_id (string, required), direction " +
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
                if (maxResults < 0) {
                    return@addTool toolError("Invalid max_results: $maxResults. Must be zero or a positive integer")
                }

                // More than Int.MAX_VALUE cannot be retained anyway: it means "all of them".
                val limit = maxResults.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
                toolJsonResult(bridge.getMessages(connectionId, args.string("direction"), sinceIndex, limit))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "websocket_wait_message",
            description = "Wait for the next WebSocket frame that matches a direction, type and/or regex, instead of " +
                "polling websocket_get_messages. Blocks until a frame recorded after since_index matches, the " +
                "connection closes, or timeout_ms passes. Frames already buffered after since_index count: pass the " +
                "message_index returned by websocket_send_text / websocket_send_binary to get the reply to that " +
                "message even when it arrived before this call. Without since_index only frames that arrive after " +
                "the call starts count. Returns {matched: true, message} or {matched: false, reason: 'timeout' | " +
                "'connection_closed'}, plus next_since_index to pass as since_index when waiting again. Works on " +
                "every tracked connection, including those opened through Burp's proxy.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("connection_id") { put("type", "string"); put("description", "The WebSocket connection ID") }
                    putJsonObject("since_index") {
                        put("type", "integer")
                        put("minimum", -1)
                        put("description", "Only frames with an index greater than this count: the message_index of a sent message, or next_since_index of a previous wait; -1 for any retained frame. Default: only frames that arrive after the call starts")
                    }
                    enumProp("direction", DIRECTIONS, "Direction of the awaited frame (case-insensitive): 'server_to_client' (default), 'client_to_server', or 'both'")
                    enumProp("message_type", MESSAGE_TYPES, "Only frames of this type (case-insensitive); default either")
                    putJsonObject("pattern") { put("type", "string"); put("description", "Regex (case-insensitive; start it with (?-i) for an exact match) the frame payload must contain; a BINARY frame is matched as ISO-8859-1 text, so \\xNN matches a raw byte") }
                    intProp("timeout_ms", "How long to wait (default ${WebSocketBridge.DEFAULT_WAIT_MS}; clamped to ${WebSocketBridge.MAX_WAIT_MS}; 0 only checks what is already buffered). Keep it below your client's request timeout, often 60000", min = 0)
                },
                required = listOf("connection_id")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val connectionId = args.string("connection_id")
                    ?: return@addTool toolError("Missing required parameter: connection_id")
                val sinceIndex = args.long("since_index")
                val direction = args.string("direction") ?: "server_to_client"
                val messageType = args.string("message_type")
                val pattern = args.string("pattern")
                val timeoutMs = args.long("timeout_ms") ?: WebSocketBridge.DEFAULT_WAIT_MS

                // The wait blocks its thread; a cancelled call interrupts it.
                toolJsonResult(
                    runInterruptible(Dispatchers.IO) {
                        bridge.waitForMessage(connectionId, sinceIndex, direction, messageType, pattern, timeoutMs)
                    }
                )
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "websocket_fuzz",
            description = "Fuzz a WebSocket endpoint: send each payload as one message and get back the frames it " +
                "triggered, plus clusters of similar responses. Payloads come from 'payloads' and/or a built-in " +
                "'payload_library'; with 'template' each payload replaces the marker (default FUZZ) in that " +
                "message, and payload_encoding 'json' escapes it first for a JSON string. Give connection_id to " +
                "fuzz over an open connection (one created with websocket_create), or url to open a fresh " +
                "connection for every payload (for servers that close on bad input); setup_messages are sent " +
                "first on each connection used. After each payload, server frames are collected until idle_ms " +
                "pass without a new one (at most window_ms), then delay_ms is waited before the next payload; " +
                "server frames that arrive before the next payload goes out still count for the previous one. " +
                "The result lists per payload its frames, response_ms and cluster; 'clusters' groups the payloads " +
                "whose responses are the same once the echoed payload, timestamps and ids are masked, largest " +
                "first, so the small clusters are the anomalies. The run stops early (stopped_early, with " +
                "next_index to pass as start_index) when timeout_ms runs out or the open connection closes. " +
                "Numbers out of range are clamped and listed under 'clamped'. " + ScopeGate.ADVISORY_NOTE,
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("connection_id") { put("type", "string"); put("description", "Open connection to fuzz over (from websocket_create); alternative to url") }
                    putJsonObject("url") { put("type", "string"); put("description", "WebSocket URL to open a fresh connection to for every payload; alternative to connection_id") }
                    putJsonObject("headers") { put("type", "object"); put("description", "Additional HTTP headers for the upgrade request (with url)") }
                    putJsonObject("subprotocol") { put("type", "string"); put("description", "WebSocket subprotocol to request (with url)") }
                    putJsonObject("payloads") {
                        put("type", "array")
                        putJsonObject("items") { put("type", "string") }
                        put("description", "Payloads to send, one message each")
                    }
                    enumProp("payload_library", PayloadLibraries.names(), "Built-in payload set, sent after 'payloads'")
                    putJsonObject("template") { put("type", "string"); put("description", "Message to place each payload in, e.g. {\"message\":\"FUZZ\"}: every occurrence of the marker is replaced. Without it the payload is the whole message") }
                    putJsonObject("marker") { put("type", "string"); put("description", "Placeholder in 'template' (default ${WebSocketFuzzPlan.DEFAULT_MARKER})") }
                    enumProp("payload_encoding", WebSocketFuzzPlan.ENCODINGS, "'none' (default) places the payload as is; 'json' escapes it for the inside of a JSON string")
                    enumProp("message_type", MESSAGE_TYPES, "'TEXT' (default), or 'BINARY': each message is base64 and is sent decoded as a binary frame")
                    putJsonObject("setup_messages") {
                        put("type", "array")
                        putJsonObject("items") { put("type", "string") }
                        put("description", "Text messages sent before the payloads on each connection used (login, subscribe, READY, ...); their replies are let through first")
                    }
                    putJsonObject("pattern") { put("type", "string"); put("description", "Regex (case-insensitive; start it with (?-i) for an exact match): only server frames containing it count as responses, e.g. to leave out heartbeats. A BINARY frame is matched as ISO-8859-1 text") }
                    intProp("start_index", "Index of the first payload to send (default 0); pass a stopped run's next_index to resume it", min = 0)
                    intProp("delay_ms", "Pause between payloads (default 0, max ${WebSocketFuzzRequest.MAX_DELAY_MS})", min = 0)
                    intProp("window_ms", "Longest wait for the responses to one payload (default ${WebSocketFuzzRequest.DEFAULT_WINDOW_MS}, max ${WebSocketFuzzRequest.MAX_WINDOW_MS})", min = 0)
                    intProp("idle_ms", "Once a response arrived, the window ends after this long without another (default ${WebSocketFuzzRequest.DEFAULT_IDLE_MS}; 0 ends it at the first response; equal to window_ms always waits the whole window). Also how long a connection must be quiet before a payload goes out after setup", min = 0)
                    intProp("timeout_ms", "Time budget of the whole run, checked before each payload (default ${WebSocketFuzzRequest.DEFAULT_TIMEOUT_MS}, max ${WebSocketFuzzRequest.MAX_TIMEOUT_MS}; 0 means the maximum)", min = 0)
                    intProp("max_frame_length", "Characters kept of each returned frame and echoed payload (default ${WebSocketFuzzRequest.DEFAULT_MAX_FRAME_LENGTH}; 0 keeps everything). websocket_get_messages returns the frames in full", min = 0)
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val library = args.string("payload_library")
                EnumValidation.error(library, PayloadLibraries.names().toSet(), "payload_library")?.let {
                    return@addTool toolJsonResult(it)
                }
                val headers = args["headers"]?.takeUnless { it is JsonNull }?.let { element ->
                    element.asStringMap()
                        ?: return@addTool toolError("Parameter 'headers' must be an object of header name to value")
                }
                val fuzz = WebSocketFuzzRequest(
                    payloads = args["payloads"].asStringList().orEmpty() + library?.let { PayloadLibraries.get(it) }.orEmpty(),
                    connectionId = args.string("connection_id"),
                    url = args.string("url"),
                    headers = headers,
                    subprotocol = args.string("subprotocol"),
                    // A template given as a JSON object is taken as its JSON text.
                    template = args["template"].asBodyString(),
                    marker = args.string("marker"),
                    payloadEncoding = args.string("payload_encoding"),
                    messageType = args.string("message_type"),
                    setupMessages = args["setup_messages"].asStringList().orEmpty(),
                    pattern = args.string("pattern"),
                    startIndex = args.long("start_index") ?: 0L,
                    delayMs = args.long("delay_ms") ?: 0L,
                    windowMs = args.long("window_ms") ?: WebSocketFuzzRequest.DEFAULT_WINDOW_MS,
                    idleMs = args.long("idle_ms") ?: WebSocketFuzzRequest.DEFAULT_IDLE_MS,
                    timeoutMs = args.long("timeout_ms") ?: WebSocketFuzzRequest.DEFAULT_TIMEOUT_MS,
                    maxFrameLength = args.long("max_frame_length") ?: WebSocketFuzzRequest.DEFAULT_MAX_FRAME_LENGTH,
                )

                // The run blocks its thread; a cancelled call interrupts it between and during payloads.
                toolJsonResult(runInterruptible(Dispatchers.IO) { bridge.fuzz(fuzz) })
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "websocket_set_intercept_rule",
            description = "Create or update a WebSocket message interception rule. Rules can " +
                "modify, drop, or tag messages matching specified criteria. Rules are evaluated " +
                "against all WebSocket traffic passing through Burp, text and binary frames alike: " +
                "a binary frame is matched and rewritten as ISO-8859-1 text (one character per byte), " +
                "so \\xNN in a regex matches a raw byte and a replacement character U+0000..U+00FF writes one. " +
                "Parameters: rule_id (optional string, unique ID; auto-generated if not " +
                "provided), match_url (optional string, regex to match against WebSocket URL), " +
                "match_message (optional string, regex to match against message content), " +
                "direction (optional string, 'client_to_server', 'server_to_client', or " +
                "'both', default 'both'), action (string, 'modify', 'drop', or 'tag', required), " +
                "modify_regex (optional string, regex for content replacement when action is " +
                "'modify'), modify_replacement (optional string, replacement for regex matches), " +
                "tag_comment (optional string, comment to attach when action is 'tag'), " +
                "message_type (optional string, 'TEXT' or 'BINARY' to limit the rule to that kind of frame), " +
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
                    enumProp("message_type", MESSAGE_TYPES, "Limit the rule to 'TEXT' or 'BINARY' frames (case-insensitive); default both")
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
                    enabled = args["enabled"].asBooleanSafe() ?: true,
                    messageType = args.string("message_type"),
                ))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "websocket_list_intercept_rules",
            description = "List the WebSocket intercept rules in the order they are evaluated, each with its " +
                "match criteria, action and enabled state. No parameters required.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { _ ->
            try {
                toolJsonResult(bridge.listInterceptRules())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "websocket_remove_intercept_rule",
            description = "Remove a WebSocket intercept rule by its rule ID. 'removed' is false when no rule has that ID. " +
                "Parameters: rule_id (string, the rule to remove, required).",
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
                    ?: return@addTool toolError("Missing required parameter: rule_id")

                toolJsonResult(bridge.removeInterceptRule(ruleId))
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

    private fun JsonObjectBuilder.intProp(name: String, description: String, min: Int) {
        putJsonObject(name) {
            put("type", "integer")
            put("minimum", min)
            put("description", description)
        }
    }
}
