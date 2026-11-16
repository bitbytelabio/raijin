package io.bitbytelab.raijin.tools.organizer

import io.bitbytelab.raijin.bridge.OrganizerBridge
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

object OrganizerTools {

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
                    put("request", buildJsonObject { put("type", "string"); put("description", "Raw HTTP request string") })
                    put("response", buildJsonObject { put("type", "string"); put("description", "Raw HTTP response string") })
                    put("host", buildJsonObject { put("type", "string"); put("description", "Target hostname") })
                    put("port", buildJsonObject { put("type", "integer"); put("description", "Target port number") })
                    put("use_tls", buildJsonObject { put("type", "boolean"); put("description", "Whether to use HTTPS, default false") })
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
                val port = args["port"]?.jsonPrimitive?.intOrNull
                    ?: return@addTool toolError("Missing required parameter: port")
                val useTls = args["use_tls"]?.jsonPrimitive?.booleanOrNull ?: false
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
                    put("url_prefix", buildJsonObject { put("type", "string"); put("description", "Filter items whose URL contains this prefix") })
                    put("max_results", buildJsonObject { put("type", "integer"); put("description", "Maximum number of items to return, default 100") })
                    put("include_request", buildJsonObject { put("type", "boolean"); put("description", "Include full request text (default false)") })
                    put("include_response", buildJsonObject { put("type", "boolean"); put("description", "Include full response text (default false)") })
                    put("max_response_length", buildJsonObject { put("type", "integer"); put("description", "Truncate request/response text at N characters") })
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val urlPrefix = args["url_prefix"]?.jsonPrimitive?.contentOrNull
                val maxResults = args["max_results"]?.jsonPrimitive?.intOrNull ?: 100
                val includeRequest = args["include_request"]?.jsonPrimitive?.booleanOrNull ?: false
                val includeResponse = args["include_response"]?.jsonPrimitive?.booleanOrNull ?: false
                val maxResponseLength = args["max_response_length"]?.jsonPrimitive?.intOrNull

                toolJsonResult(bridge.getItems(urlPrefix, maxResults, includeRequest, includeResponse, maxResponseLength))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "organizer_annotate",
            description = "Set notes and/or a highlight color on an Organizer item by id (from organizer_get_items).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    put("id", buildJsonObject { put("type", "integer"); put("description", "Organizer item id, from organizer_get_items") })
                    put("notes", buildJsonObject { put("type", "string"); put("description", "Note text to set") })
                    put("highlight", buildJsonObject { put("type", "string"); put("description", "RED|ORANGE|YELLOW|GREEN|CYAN|BLUE|PINK|MAGENTA|GRAY|NONE (NONE clears it)") })
                },
                required = listOf("id")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val id = args["id"]?.jsonPrimitive?.intOrNull
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
