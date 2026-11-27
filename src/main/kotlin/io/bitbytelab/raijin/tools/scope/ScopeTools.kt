package io.bitbytelab.raijin.tools.scope

import io.bitbytelab.raijin.bridge.HttpRequestBuilder
import io.bitbytelab.raijin.bridge.ScopeBridge
import io.bitbytelab.raijin.core.asBoundedInt
import io.bitbytelab.raijin.tools.ToolArgs
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.*

object ScopeTools {

    /**
     * `invalid_arguments` for a `url` without a scheme, with both schemes as `did_you_mean`; with
     * [retry], the `https` guess as `retry`. Null when [url] has a scheme.
     */
    private fun schemeError(action: String, url: String, retry: Boolean): CallToolResult? {
        if (HttpRequestBuilder.hasScheme(url)) return null
        val guesses = HttpRequestBuilder.schemeGuesses(url)
        return ToolArgs.error(
            "invalid_arguments",
            "scope.$action: 'url' must be an absolute URL with a scheme, got \"$url\".",
        ) {
            put("param", "url")
            put("got", url)
            putJsonArray("did_you_mean") { guesses.forEach { add(it) } }
            if (retry && guesses.isNotEmpty())
                putJsonObject("retry") {
                    put("action", action)
                    put("url", guesses[0])
                }
        }
    }

    fun register(server: Server, bridge: ScopeBridge) {

        server.addTool(
            name = "scope_check",
            description =
                "Check whether a given URL is within Burp Suite's target scope. " +
                    "Returns true if the URL matches the current scope include/exclude rules. " +
                    "Parameters: url (the full URL to check, e.g. 'https://example.com/path').",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("url") {
                                put("type", "string")
                                put("description", "Full URL to check against scope")
                            }
                        },
                    required = listOf("url"),
                ),
        ) { request ->
            val args = request.params.arguments ?: emptyMap()
            val url =
                (args["url"] as? JsonPrimitive)?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: url")
            schemeError("check", url, retry = true)?.let {
                return@addTool it
            }
            try {
                toolJsonResult(bridge.check(url))
            } catch (e: Exception) {
                toolError(
                    "'url' \"$url\" is not a URL Burp accepts: ${e.message ?: "unknown error"}",
                )
            }
        }

        server.addTool(
            name = "scope_include",
            description =
                "Add a URL to Burp Suite's target scope. All URLs matching the " +
                    "specified pattern will be included in scope for scanning, proxy interception, " +
                    "and other scope-aware operations. Parameters: url (the URL to include in " +
                    "scope, e.g. 'https://example.com').",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("url") {
                                put("type", "string")
                                put("description", "URL to include in scope")
                            }
                        },
                    required = listOf("url"),
                ),
        ) { request ->
            val args = request.params.arguments ?: emptyMap()
            val url =
                (args["url"] as? JsonPrimitive)?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: url")
            schemeError("include", url, retry = false)?.let {
                return@addTool it
            }
            try {
                toolJsonResult(bridge.include(url))
            } catch (e: Exception) {
                toolError(
                    "'url' \"$url\" is not a URL Burp accepts: ${e.message ?: "unknown error"}",
                )
            }
        }

        server.addTool(
            name = "scope_exclude",
            description =
                "Exclude a URL from Burp Suite's target scope. The specified URL " +
                    "pattern will be excluded even if it matches an include rule. Useful for " +
                    "preventing scanning of logout endpoints, admin panels, or third-party " +
                    "resources. Parameters: url (the URL to exclude from scope).",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("url") {
                                put("type", "string")
                                put("description", "URL to exclude from scope")
                            }
                        },
                    required = listOf("url"),
                ),
        ) { request ->
            val args = request.params.arguments ?: emptyMap()
            val url =
                (args["url"] as? JsonPrimitive)?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: url")
            schemeError("exclude", url, retry = false)?.let {
                return@addTool it
            }
            try {
                toolJsonResult(bridge.exclude(url))
            } catch (e: Exception) {
                toolError(
                    "'url' \"$url\" is not a URL Burp accepts: ${e.message ?: "unknown error"}",
                )
            }
        }

        server.addTool(
            name = "scope_get_config",
            description =
                "Retrieve the current Burp Suite target scope configuration. " +
                    "Returns the scope include and exclude rules as configured in the " +
                    "Target > Scope settings. No parameters required.",
            inputSchema =
                ToolSchema(
                    properties = buildJsonObject {},
                    required = emptyList(),
                ),
        ) { _ ->
            try {
                toolJsonResult(bridge.getConfig())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "scope_list",
            description =
                "Lists Burp Suite's target scope include/exclude rules individually, with the index each " +
                    "needs for scope_remove. scope_get_config returns the same data as one opaque exported JSON blob; " +
                    "this is the per-rule, indexed view.",
            inputSchema =
                ToolSchema(
                    properties = buildJsonObject {},
                    required = emptyList(),
                ),
        ) { _ ->
            try {
                toolJsonResult(bridge.list())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "scope_remove",
            description =
                "Removes one scope rule by its index in the include or exclude list (use scope_list first " +
                    "to find the index). Montoya's Scope API can only add rules (scope_include/scope_exclude); removing " +
                    "one is done by re-exporting Burp's target.scope config with that entry dropped and re-importing it, " +
                    "then reading it back to confirm Burp actually accepted the change.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("list") {
                                put("type", "string")
                                putJsonArray("enum") {
                                    add("include")
                                    add("exclude")
                                }
                                put("description", "Which rule list the index refers to")
                            }
                            putJsonObject("index") {
                                put("type", "integer")
                                put("minimum", 0)
                                put("description", "Index of the rule to remove, from scope_list")
                            }
                        },
                    required = listOf("list", "index"),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val list =
                    args["list"]?.jsonPrimitive?.contentOrNull
                        ?: return@addTool toolError("Missing required parameter: list")
                val index =
                    args["index"].asBoundedInt("index", 0, Int.MAX_VALUE).getOrElse {
                        return@addTool toolError(it.message ?: "Invalid index")
                    } ?: return@addTool toolError("Missing required parameter: index")
                toolJsonResult(bridge.remove(list, index))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }
}
