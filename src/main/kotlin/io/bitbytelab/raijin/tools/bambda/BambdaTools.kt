package io.bitbytelab.raijin.tools.bambda

import io.bitbytelab.raijin.bridge.BambdaBridge
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object BambdaTools {

    fun register(server: Server, bridge: BambdaBridge) {

        // 1. bambda_import
        server.addTool(
            name = "bambda_import",
            description = "Import a Bambda into Burp Suite. A real .bambda file is a YAML-ish envelope — id, name, " +
                "function, location, then a 'source:' block holding the Java-like lambda body — not a bare lambda " +
                "expression. 'script' may be that full envelope (starting with 'id:'), or just the bare lambda body, " +
                "which is auto-wrapped using 'name'/'function'/'location' (or sensible defaults) and a generated id.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("script") { put("type", "string"); put("description", "A full .bambda envelope (starting with 'id:'), or a bare lambda body to auto-wrap") }
                    putJsonObject("name") { put("type", "string"); put("description", "Display name, when auto-wrapping a bare lambda (default 'Raijin <generated-id>')") }
                    putJsonObject("function") { put("type", "string"); put("description", "Bambda function type, when auto-wrapping (default VIEW_FILTER). Burp's own values include VIEW_FILTER, CUSTOM_COLUMN, MATCH_AND_REPLACE_REQUEST, MATCH_AND_REPLACE_RESPONSE, SCAN_CHECK_ACTIVE_PER_REQUEST — not validated here, Burp's own import result reports an invalid one.") }
                    putJsonObject("location") { put("type", "string"); put("description", "Where it applies, when auto-wrapping (default PROXY_HTTP_HISTORY). Burp's own values include PROXY_HTTP_HISTORY, PROXY_WS_HISTORY, LOGGER, SITE_MAP, SCANNER — not validated here.") }
                },
                required = listOf("script")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val script = args["script"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: script"}""")),
                        isError = true
                    )

                if (script.isBlank()) {
                    return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Script cannot be empty"}""")),
                        isError = true
                    )
                }

                val name = args["name"]?.jsonPrimitive?.contentOrNull
                val function = args["function"]?.jsonPrimitive?.contentOrNull
                val location = args["location"]?.jsonPrimitive?.contentOrNull

                val result = bridge.importBambda(script, name, function, location)
                // Surface a compile failure as a hard error so the caller does not
                // mistake a LOADED_WITH_ERRORS import for a clean success.
                val importFailed = result["status"]?.jsonPrimitive?.contentOrNull == "imported_with_errors" ||
                    result.containsKey("error")
                CallToolResult(
                    content = listOf(TextContent(result.toString())),
                    isError = importFailed
                )
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }
    }
}
