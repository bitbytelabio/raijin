package io.bitbytelab.raijin.tools.intruder

import io.bitbytelab.raijin.bridge.IntruderBridge
import io.bitbytelab.raijin.core.asLongSafe
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object IntruderTools {

    fun register(server: Server, bridge: IntruderBridge, stateManager: StateManager) {

        server.addTool(
            name = "intruder_send",
            description = "Send an HTTP request to Burp Suite's Intruder tool, ready to be configured for a " +
                "payload run. Creates a new Intruder tab with the specified request. " +
                "Parameters: request (raw HTTP request string), host (target hostname), " +
                "port (target port), use_tls (boolean), tab_name (optional tab name).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("request") { put("type", "string"); put("description", "Raw HTTP request string") }
                    putJsonObject("host") { put("type", "string"); put("description", "Target hostname") }
                    portProperty()
                    putJsonObject("use_tls") { put("type", "boolean"); put("description", "Whether to use TLS, default false") }
                    putJsonObject("tab_name") { put("type", "string"); put("description", "Optional Intruder tab name") }
                },
                required = listOf("request", "host", "port")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val rawRequest = args.text("request") ?: return@addTool toolError("Missing required parameter: request")
                val host = args.text("host") ?: return@addTool toolError("Missing required parameter: host")
                val port = IntruderValidation.port(args["port"])

                toolJsonResult(
                    bridge.sendToIntruder(rawRequest, host, port, args.flag("use_tls") ?: false, args.text("tab_name"))
                )
            } catch (e: IllegalArgumentException) {
                toolError(e.message ?: "invalid arguments")
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "intruder_send_with_positions",
            description = "Send an HTTP request to Intruder with pre-defined payload insertion " +
                "point positions. Each position is a [start, end] byte offset pair marking " +
                "where payloads should be inserted. Parameters: request (raw HTTP request), " +
                "host (target hostname), port (target port), use_tls (boolean), " +
                "positions (array of [start, end] pairs), tab_name (optional tab name).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("request") { put("type", "string"); put("description", "Raw HTTP request string") }
                    putJsonObject("host") { put("type", "string"); put("description", "Target hostname") }
                    portProperty()
                    putJsonObject("use_tls") { put("type", "boolean"); put("description", "Whether to use TLS, default false") }
                    putJsonObject("positions") {
                        put("type", "array")
                        put("description", "Array of [start, end] byte offset pairs marking payload insertion points (0 <= start <= end)")
                        putJsonObject("items") {
                            put("type", "array")
                            putJsonObject("items") { put("type", "integer"); put("minimum", 0) }
                            put("minItems", 2)
                            put("maxItems", 2)
                        }
                    }
                    putJsonObject("tab_name") { put("type", "string"); put("description", "Optional Intruder tab name") }
                },
                required = listOf("request", "host", "port", "positions")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val rawRequest = args.text("request") ?: return@addTool toolError("Missing required parameter: request")
                val host = args.text("host") ?: return@addTool toolError("Missing required parameter: host")
                val port = IntruderValidation.port(args["port"])
                val rawPositions = args["positions"] as? JsonArray
                    ?: return@addTool toolError("Missing required parameter: positions (array of [start, end] pairs)")

                val positions = rawPositions.map { pos ->
                    when (pos) {
                        is JsonArray -> IntruderValidation.parsePositionArray(pos)
                        is JsonObject -> IntruderValidation.parsePositionObject(pos)
                        else -> throw IllegalArgumentException("Invalid position format: $pos")
                    }
                }

                toolJsonResult(
                    bridge.sendWithPositions(
                        rawRequest, host, port, args.flag("use_tls") ?: false, positions, args.text("tab_name")
                    )
                )
            } catch (e: IllegalArgumentException) {
                // Validation failures carry a clean, descriptive message safe to surface.
                toolError(e.message ?: "invalid positions")
            } catch (e: Exception) {
                // Never leak raw JDK internals (e.g. IndexOutOfBoundsException bounds text).
                toolError("internal error processing positions")
            }
        }

        server.addTool(
            name = "intruder_register_payload_processor",
            description = "Register a custom payload processor with Intruder that transforms " +
                "payloads during a run. Supported transform types: encode_base64, encode_url, " +
                "hash_md5, hash_sha1, hash_sha256, prefix (prepend string), suffix (append " +
                "string), regex_replace (apply regex replacement). Parameters: name (processor " +
                "name; registering a name again replaces that processor), transform_type (one of the " +
                "supported types), prefix_value (string to prepend, for prefix type), suffix_value " +
                "(string to append, for suffix type), regex_pattern (regex pattern, for regex_replace " +
                "type), regex_replacement (replacement string, for regex_replace type; group " +
                "references must name groups of regex_pattern). The pattern and the replacement are " +
                "validated here, not when the first payload is processed.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("name") { put("type", "string"); put("description", "Processor name") }
                    putJsonObject("transform_type") {
                        put("type", "string")
                        putJsonArray("enum") { IntruderBridge.TRANSFORM_TYPES.forEach { add(it) } }
                        put("description", "The transform to apply to each payload")
                    }
                    putJsonObject("prefix_value") { put("type", "string"); put("description", "String to prepend, for prefix type") }
                    putJsonObject("suffix_value") { put("type", "string"); put("description", "String to append, for suffix type") }
                    putJsonObject("regex_pattern") { put("type", "string"); put("description", "Regex pattern, for regex_replace type") }
                    putJsonObject("regex_replacement") { put("type", "string"); put("description", "Replacement string, for regex_replace type") }
                },
                required = listOf("name", "transform_type")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val name = args.text("name") ?: return@addTool toolError("Missing required parameter: name")
                val transformType = args.text("transform_type")
                    ?: return@addTool toolError("Missing required parameter: transform_type")

                val params = mutableMapOf<String, String>()
                for (key in listOf("prefix_value", "suffix_value", "regex_pattern", "regex_replacement")) {
                    args.text(key)?.let { params[key] = it }
                }

                // The bridge rejects an unknown transform_type and an invalid regex or replacement
                // at registration, instead of failing once per payload during a run (BUG #33).
                toolJsonResult(bridge.registerPayloadProcessor(name, transformType, params))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }

    private fun JsonObjectBuilder.portProperty() {
        putJsonObject("port") { put("type", "integer"); put("minimum", 1); put("maximum", 65535); put("description", "Target port") }
    }
}

private fun Map<String, JsonElement>.text(name: String): String? = (this[name] as? JsonPrimitive)?.contentOrNull

private fun Map<String, JsonElement>.flag(name: String): Boolean? = (this[name] as? JsonPrimitive)?.booleanOrNull

/**
 * Pure, Burp-free validation helpers for the Intruder tools. Kept in this file (which the
 * owning agent controls) so the parsing/validation rules can be unit-tested without a live
 * Montoya API.
 */
internal object IntruderValidation {

    /**
     * The required `port` argument as a TCP port.
     *
     * @throws IllegalArgumentException when it is missing, not an integer or outside 1..65535.
     */
    fun port(element: JsonElement?): Int {
        if (element == null || element is JsonNull) throw IllegalArgumentException("Missing required parameter: port")
        val value = element.asLongSafe() ?: throw IllegalArgumentException("Parameter 'port' must be an integer")
        if (value !in 1..65535) throw IllegalArgumentException("Parameter 'port' must be between 1 and 65535")
        return value.toInt()
    }

    /**
     * BUG #16: parse a JSON `[start, end]` position pair with strict arity validation.
     *
     * The previous implementation indexed `pos[0]`/`pos[1]` directly, which leaked a raw
     * [IndexOutOfBoundsException] for a too-short array and silently ignored extra elements
     * for a too-long array. This validates exact arity and integer-ness up front so both
     * failure modes surface an identical, descriptive [IllegalArgumentException] that the
     * tool layer renders as a clean `{"error":...}` response.
     */
    fun parsePositionArray(pos: JsonArray): Pair<Int, Int> {
        if (pos.size != 2) throw IllegalArgumentException(
            "each position must be a [start,end] pair (got ${pos.size} element(s))")
        val start = (pos[0] as? JsonPrimitive)?.intOrNull
            ?: throw IllegalArgumentException("position start must be an integer")
        val end = (pos[1] as? JsonPrimitive)?.intOrNull
            ?: throw IllegalArgumentException("position end must be an integer")
        return checked(start, end)
    }

    /** The `{start, end}` form of a position (`{"0": .., "1": ..}` is accepted too). */
    fun parsePositionObject(pos: JsonObject): Pair<Int, Int> {
        val start = ((pos["start"] ?: pos["0"]) as? JsonPrimitive)?.intOrNull
            ?: throw IllegalArgumentException("Position missing 'start' field")
        val end = ((pos["end"] ?: pos["1"]) as? JsonPrimitive)?.intOrNull
            ?: throw IllegalArgumentException("Position missing 'end' field")
        return checked(start, end)
    }

    private fun checked(start: Int, end: Int): Pair<Int, Int> {
        if (start < 0) throw IllegalArgumentException("position start ($start) must be >= 0")
        if (end < start) throw IllegalArgumentException(
            "position end ($end) must be >= start ($start)")
        return Pair(start, end)
    }

    /**
     * BUG #33: eagerly validate the regex of a `regex_replace` payload processor.
     *
     * Returns a `{"error":...}` [JsonObject] when the pattern is missing/blank, cannot be
     * compiled, or the replacement refers to a group the pattern does not have; `null` when
     * both are valid. Registering with an invalid pattern used to succeed and only blow up
     * later, once per payload, during a live run. The rules are [IntruderBridge.regexReplaceError]'s.
     */
    fun regexError(params: Map<String, String>): JsonObject? =
        IntruderBridge.regexReplaceError(params)?.let { message -> buildJsonObject { put("error", message) } }
}
