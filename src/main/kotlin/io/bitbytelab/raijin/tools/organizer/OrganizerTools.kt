package io.bitbytelab.raijin.tools.organizer

import burp.api.montoya.core.HighlightColor
import io.bitbytelab.raijin.bridge.OrganizerBridge
import io.bitbytelab.raijin.core.BodyText
import io.bitbytelab.raijin.core.asBooleanSafe
import io.bitbytelab.raijin.core.asBoundedInt
import io.bitbytelab.raijin.core.asClampedInt
import io.bitbytelab.raijin.core.withClampReport
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

object OrganizerTools {

    private const val MAX_RESULTS = 10_000

    fun register(server: Server, bridge: OrganizerBridge) {

        server.addTool(
            name = "organizer_send",
            description = "Send an HTTP request (and optionally a response) to Burp Suite's " +
                "Organizer tool for bookmarking and note-taking. The Organizer provides a " +
                "persistent store for interesting requests found during testing. Parameters: " +
                "request (raw HTTP request string, required), response (raw HTTP response " +
                "string, optional), host (target hostname, required), port (target port " +
                "number, required), use_tls (boolean, whether to use HTTPS, default false).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("request") { put("type", "string"); put("description", "Raw HTTP request string") }
                    putJsonObject("response") { put("type", "string"); put("description", "Raw HTTP response string") }
                    putJsonObject("host") { put("type", "string"); put("description", "Target hostname") }
                    putJsonObject("port") {
                        put("type", "integer"); put("minimum", 1); put("maximum", 65535)
                        put("description", "Target port number")
                    }
                    putJsonObject("use_tls") { put("type", "boolean"); put("description", "Whether to use HTTPS, default false") }
                },
                required = listOf("request", "host", "port")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val rawRequest = args["request"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: request")
                val host = args["host"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: host")
                val port = args["port"].asBoundedInt("port", 1, 65535)
                    .getOrElse { return@addTool toolError(it.message ?: "Invalid port") }
                    ?: return@addTool toolError("Missing required parameter: port")
                val useTls = args["use_tls"].asBooleanSafe() ?: false
                val response = args["response"]?.jsonPrimitive?.contentOrNull

                toolJsonResult(bridge.send(rawRequest, response, host, port, useTls))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "organizer_get_items",
            description = "Retrieve items from Burp Suite's Organizer tool. Returns a list " +
                "of bookmarked requests with id, URL, method, host, port, notes, highlight, " +
                "and response status code (plus optional request/response bodies).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url_prefix") { put("type", "string"); put("description", "Filter items whose URL contains this text (case-insensitive)") }
                    putJsonObject("max_results") {
                        put("type", "integer"); put("minimum", 0); put("maximum", MAX_RESULTS)
                        put("description", "Maximum number of items to return, default 100; a larger value is clamped to $MAX_RESULTS and reported as max_results_clamped_to")
                    }
                    putJsonObject("include_request") { put("type", "boolean"); put("description", "Include full request text (default false)") }
                    putJsonObject("include_response") { put("type", "boolean"); put("description", "Include full response text (default false)") }
                    putJsonObject("max_response_length") {
                        put("type", "integer"); put("minimum", 0)
                        put("description", "Truncate request/response text at N characters; 0 keeps the default (${BodyText.DEFAULT_MAX_LENGTH})")
                    }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val urlPrefix = args["url_prefix"]?.jsonPrimitive?.contentOrNull
                val maxResults = args["max_results"].asClampedInt("max_results", 0, MAX_RESULTS)
                    .getOrElse { return@addTool toolError(it.message ?: "Invalid max_results") }
                val includeRequest = args["include_request"].asBooleanSafe() ?: false
                val includeResponse = args["include_response"].asBooleanSafe() ?: false
                val maxResponseLength = args["max_response_length"].asClampedInt("max_response_length", 0, Int.MAX_VALUE)
                    .getOrElse { return@addTool toolError(it.message ?: "Invalid max_response_length") }

                toolJsonResult(
                    bridge.getItems(urlPrefix, maxResults?.value ?: 100, includeRequest, includeResponse, maxResponseLength?.value)
                        .withClampReport("max_results", maxResults)
                        .withClampReport("max_response_length", maxResponseLength)
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "organizer_annotate",
            description = "Set notes and/or a highlight color on an Organizer item by id (from organizer_get_items).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("id") { put("type", "integer"); put("description", "Organizer item id, from organizer_get_items") }
                    putJsonObject("notes") { put("type", "string"); put("description", "Note text to set") }
                    putJsonObject("highlight") {
                        put("type", "string")
                        putJsonArray("enum") { HighlightColor.entries.forEach { add(it.name) } }
                        put("description", "Highlight color; NONE clears it")
                    }
                },
                required = listOf("id")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val id = args["id"].asBoundedInt("id", Int.MIN_VALUE, Int.MAX_VALUE)
                    .getOrElse { return@addTool toolError(it.message ?: "Invalid id") }
                    ?: return@addTool toolError("Missing required parameter: id")
                val notes = args["notes"]?.jsonPrimitive?.contentOrNull
                val highlight = args["highlight"]?.jsonPrimitive?.contentOrNull
                toolJsonResult(bridge.annotate(id, notes, highlight))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }
}
