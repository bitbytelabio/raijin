package io.bitbytelab.raijin.tools.bambda

import io.bitbytelab.raijin.bridge.BambdaBridge
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object BambdaTools {

    fun register(server: Server, bridge: BambdaBridge) {

        // 1. bambda_import
        server.addTool(
            name = "bambda_import",
            description = "Import a Bambda into Burp Suite. A real .bambda file is a YAML-ish envelope — id, name, " +
                "function, location, then a 'source:' block holding the Java-like lambda body — not a bare lambda " +
                "expression. 'script' may be that envelope (header keys at the start of a line, in any order, " +
                "comments allowed), or just the bare lambda body, which is wrapped using 'name'/'function'/'location' " +
                "(or sensible defaults) and a generated id. An envelope missing id, name, function or location gets " +
                "them the same way. The result carries the Bambda's 'id'; importing that id again replaces it. " +
                "Use bambda_templates for the format, the known functions and locations, and starting points.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("script") { put("type", "string"); put("description", "A .bambda envelope, or a bare lambda body to wrap") }
                    putJsonObject("name") { put("type", "string"); put("description", "Display name, for a script without one (default 'Raijin <generated-id>'). One line") }
                    putJsonObject("function") { put("type", "string"); put("description", "Bambda function type, for a script without one (default VIEW_FILTER), e.g. VIEW_FILTER, CUSTOM_COLUMN, MATCH_AND_REPLACE_REQUEST, CUSTOM_ACTION, SCAN_CHECK_ACTIVE_PER_REQUEST. bambda_templates lists the known ones; Burp's import result reports one it does not know") }
                    putJsonObject("location") { put("type", "string"); put("description", "Where it applies, for a script without one (default PROXY_HTTP_HISTORY), e.g. PROXY_HTTP_HISTORY, PROXY_WEBSOCKET, LOGGER, SITEMAP, REPEATER, SCANNER") }
                },
                required = listOf("script")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val script = args.text("script") ?: return@addTool toolError("Missing required parameter: script")
                if (script.isBlank()) return@addTool toolError("Script cannot be empty")

                // A compile failure (imported_with_errors) carries an "error" key, so it is a tool
                // error and cannot be mistaken for a clean import.
                toolJsonResult(bridge.importBambda(script, args.text("name"), args.text("function"), args.text("location")))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 2. bambda_templates
        server.addTool(
            name = "bambda_templates",
            description = "Get the .bambda envelope format, the function types and locations known from PortSwigger's " +
                "public Bambda repository (with what each one receives and must return), and a starting lambda body " +
                "for each kind: proxy, WebSocket, Logger and site map filters, a custom column, match and replace, " +
                "a Repeater custom action, and passive and active scan checks. Pass a template's 'source' to " +
                "bambda_import as 'script' with its name, function and location. No parameters required.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { _ ->
            try {
                toolJsonResult(BambdaBridge.templates())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }
}

private fun Map<String, JsonElement>.text(name: String): String? = (this[name] as? JsonPrimitive)?.contentOrNull
