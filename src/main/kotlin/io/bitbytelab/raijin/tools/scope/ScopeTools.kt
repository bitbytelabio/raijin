package io.bitbytelab.raijin.tools.scope

import io.bitbytelab.raijin.bridge.ScopeBridge
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object ScopeTools {

    fun register(server: Server, bridge: ScopeBridge) {

        server.addTool(
            name = "scope_check",
            description = "Check whether a given URL is within Burp Suite's target scope. " +
                "Returns true if the URL matches the current scope include/exclude rules. " +
                "Parameters: url (the full URL to check, e.g. 'https://example.com/path').",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url") { put("type", "string"); put("description", "Full URL to check against scope") }
                },
                required = listOf("url")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val url = args["url"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: url")

                toolJsonResult(bridge.check(url))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "scope_include",
            description = "Add a URL to Burp Suite's target scope. All URLs matching the " +
                "specified pattern will be included in scope for scanning, proxy interception, " +
                "and other scope-aware operations. Parameters: url (the URL to include in " +
                "scope, e.g. 'https://example.com').",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url") { put("type", "string"); put("description", "URL to include in scope") }
                },
                required = listOf("url")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val url = args["url"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: url")

                toolJsonResult(bridge.include(url))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "scope_exclude",
            description = "Exclude a URL from Burp Suite's target scope. The specified URL " +
                "pattern will be excluded even if it matches an include rule. Useful for " +
                "preventing scanning of logout endpoints, admin panels, or third-party " +
                "resources. Parameters: url (the URL to exclude from scope).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url") { put("type", "string"); put("description", "URL to exclude from scope") }
                },
                required = listOf("url")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val url = args["url"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: url")

                toolJsonResult(bridge.exclude(url))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "scope_get_config",
            description = "Retrieve the current Burp Suite target scope configuration. " +
                "Returns the scope include and exclude rules as configured in the " +
                "Target > Scope settings. No parameters required.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {},
                required = emptyList()
            )
        ) { _ ->
            try {
                toolJsonResult(bridge.getConfig())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "scope_list",
            description = "Lists Burp Suite's target scope include/exclude rules individually, with the index each " +
                "needs for scope_remove. scope_get_config returns the same data as one opaque exported JSON blob; " +
                "this is the per-rule, indexed view.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {},
                required = emptyList()
            )
        ) { _ ->
            try {
                toolJsonResult(bridge.list())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "scope_remove",
            description = "Removes one scope rule by its index in the include or exclude list (use scope_list first " +
                "to find the index). Montoya's Scope API can only add rules (scope_include/scope_exclude); removing " +
                "one is done by re-exporting Burp's target.scope config with that entry dropped and re-importing it, " +
                "then reading it back to confirm Burp actually accepted the change.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("list") { put("type", "string"); put("description", "'include' or 'exclude'") }
                    putJsonObject("index") { put("type", "integer"); put("description", "Index of the rule to remove, from scope_list") }
                },
                required = listOf("list", "index")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val list = args["list"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: list")
                val index = args["index"]?.jsonPrimitive?.intOrNull
                    ?: return@addTool toolError("Missing required parameter: index")
                toolJsonResult(bridge.remove(list, index))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }
}
