package io.bitbytelab.raijin.tools.config

import io.bitbytelab.raijin.bridge.BurpSuiteBridge
import io.bitbytelab.raijin.bridge.ConfigBridge
import io.bitbytelab.raijin.core.EnumValidation
import io.bitbytelab.raijin.core.asBooleanSafe
import io.bitbytelab.raijin.core.asBoundedInt
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/**
 * Configuration shortcut tools that wrap the ConfigBridge for common
 * Burp Suite configuration operations (proxy listeners, match/replace
 * rules, upstream proxy).
 *
 * The ConfigBridge is created on-the-fly from the BurpSuiteBridge's
 * underlying MontoyaApi, keeping the tool registration consistent
 * with the ToolRegistry call signature.
 */
object ConfigTools {

    /** Burp's `rule_type` values for proxy match/replace rules. */
    private val MATCH_REPLACE_TYPES = listOf(
        "request_header", "request_body", "request_param_name", "request_param_value",
        "request_first_line", "response_header", "response_body",
    )
    private val UPSTREAM_PROXY_TYPES = listOf("HTTP", "SOCKS4", "SOCKS5")

    fun register(server: Server, burpSuiteBridge: BurpSuiteBridge) {

        // Extract the MontoyaApi from BurpSuiteBridge via reflection
        val apiField = burpSuiteBridge.javaClass.getDeclaredField("api")
        apiField.isAccessible = true
        val api = apiField.get(burpSuiteBridge) as burp.api.montoya.MontoyaApi
        val bridge = ConfigBridge(api)

        // 1. config_proxy_listeners_list
        server.addTool(
            name = "config_proxy_listeners_list",
            description = "List all configured proxy listeners in the current Burp Suite project. " +
                "Returns each listener's interface binding, TLS settings, and redirect " +
                "configuration. No parameters required.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {},
                required = emptyList()
            )
        ) { _ ->
            try {
                toolJsonResult(bridge.listProxyListeners())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 2. config_proxy_listener_add
        server.addTool(
            name = "config_proxy_listener_add",
            description = "Add a new proxy listener to Burp Suite's proxy configuration. " +
                "Parameters: interface (string, e.g. '127.0.0.1:8081'), " +
                "tls (boolean, enable TLS termination; defaults to false), " +
                "redirect_host (optional string, hostname to redirect to), " +
                "redirect_port (optional number, port to redirect to), " +
                "certificate (optional string, certificate mode e.g. 'per_host', 'self_signed').",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("interface") { put("type", "string"); put("description", "Interface binding, e.g. '127.0.0.1:8081'") }
                    putJsonObject("tls") { put("type", "boolean"); put("description", "Enable TLS termination (default false)") }
                    putJsonObject("redirect_host") { put("type", "string"); put("description", "Hostname to redirect to (optional)") }
                    putJsonObject("redirect_port") {
                        put("type", "integer"); put("minimum", 1); put("maximum", 65535)
                        put("description", "Port to redirect to (optional, default 80 when redirect_host is set)")
                    }
                    putJsonObject("certificate") { put("type", "string"); put("description", "Certificate mode, e.g. 'per_host', 'self_signed' (optional)") }
                },
                required = listOf("interface")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val listenerInterface = args["interface"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: interface")
                val tls = args["tls"].asBooleanSafe() ?: false
                val redirectHost = args["redirect_host"]?.jsonPrimitive?.contentOrNull
                val redirectPort = args["redirect_port"].asBoundedInt("redirect_port", 1, 65535)
                    .getOrElse { return@addTool toolError(it.message ?: "Invalid redirect_port") }
                val certificate = args["certificate"]?.jsonPrimitive?.contentOrNull

                toolJsonResult(bridge.addProxyListener(listenerInterface, tls, redirectHost, redirectPort, certificate))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 3. config_proxy_listener_remove
        server.addTool(
            name = "config_proxy_listener_remove",
            description = "Remove a proxy listener by its interface binding string. " +
                "Parameters: interface (string, the listener interface to remove, " +
                "e.g. '127.0.0.1:8081').",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("interface") { put("type", "string"); put("description", "Listener interface to remove, e.g. '127.0.0.1:8081'") }
                },
                required = listOf("interface")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val listenerInterface = args["interface"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: interface")
                toolJsonResult(bridge.removeProxyListener(listenerInterface))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 4. config_match_replace_add
        server.addTool(
            name = "config_match_replace_add",
            description = "Add a match-and-replace rule to Burp Suite's proxy configuration. " +
                "These rules automatically modify requests/responses passing through the proxy. " +
                "Parameters: type (string, e.g. 'request_header', 'request_body', " +
                "'response_header', 'response_body'), match (string, text or regex to match), " +
                "replace (string, replacement text), comment (optional string, rule description), " +
                "enabled (boolean, whether the rule is active; defaults to true).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("type") {
                        put("type", "string")
                        putJsonArray("enum") { MATCH_REPLACE_TYPES.forEach { add(it) } }
                        put("description", "Rule type: which part of the message the rule rewrites")
                    }
                    putJsonObject("match") { put("type", "string"); put("description", "Text or regex to match") }
                    putJsonObject("replace") { put("type", "string"); put("description", "Replacement text") }
                    putJsonObject("comment") { put("type", "string"); put("description", "Rule description (optional)") }
                    putJsonObject("enabled") { put("type", "boolean"); put("description", "Whether the rule is active (default true)") }
                },
                required = listOf("type", "match", "replace")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val type = args["type"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: type")
                EnumValidation.error(type, MATCH_REPLACE_TYPES.toSet(), "type")?.let { return@addTool toolJsonResult(it) }
                val match = args["match"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: match")
                val replace = args["replace"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: replace")
                val comment = args["comment"]?.jsonPrimitive?.contentOrNull
                val enabled = args["enabled"].asBooleanSafe() ?: true

                toolJsonResult(bridge.addMatchReplaceRule(type.trim().lowercase(), match, replace, comment, enabled))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 5. config_match_replace_list
        server.addTool(
            name = "config_match_replace_list",
            description = "List all match-and-replace rules configured in Burp Suite's proxy. " +
                "Returns each rule's type, match pattern, replacement, comment, and enabled " +
                "status along with its index for removal. No parameters required.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {},
                required = emptyList()
            )
        ) { _ ->
            try {
                toolJsonResult(bridge.listMatchReplaceRules())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 6. config_match_replace_remove
        server.addTool(
            name = "config_match_replace_remove",
            description = "Remove a match-and-replace rule by its index. Use config_match_replace_list " +
                "first to find the correct index. " +
                "Parameters: rule_index (number, zero-based index of the rule to remove).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("rule_index") {
                        put("type", "integer"); put("minimum", 0)
                        put("description", "Zero-based index of the rule to remove")
                    }
                },
                required = listOf("rule_index")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val ruleIndex = args["rule_index"].asBoundedInt("rule_index", 0, Int.MAX_VALUE)
                    .getOrElse { return@addTool toolError(it.message ?: "Invalid rule_index") }
                    ?: return@addTool toolError("Missing required parameter: rule_index")
                toolJsonResult(bridge.removeMatchReplaceRule(ruleIndex))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 7. config_upstream_proxy_set
        server.addTool(
            name = "config_upstream_proxy_set",
            description = "Configure an upstream proxy server that Burp Suite will route traffic " +
                "through. Useful for chaining with other tools (e.g. corporate proxy, Tor). " +
                "Parameters: host (string, upstream proxy hostname), port (number, proxy port), " +
                "type (string, proxy type: 'HTTP', 'SOCKS4', 'SOCKS5'; defaults to 'HTTP'), " +
                "auth_user (optional string, proxy authentication username), " +
                "auth_pass (optional string, proxy authentication password), " +
                "destination_host (optional string, destination host filter pattern; " +
                "defaults to '*' for all traffic).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("host") { put("type", "string"); put("description", "Upstream proxy hostname") }
                    putJsonObject("port") {
                        put("type", "integer"); put("minimum", 1); put("maximum", 65535)
                        put("description", "Upstream proxy port")
                    }
                    putJsonObject("type") {
                        put("type", "string")
                        putJsonArray("enum") { UPSTREAM_PROXY_TYPES.forEach { add(it) } }
                        put("description", "Proxy type (default 'HTTP')")
                    }
                    putJsonObject("auth_user") { put("type", "string"); put("description", "Proxy authentication username (optional)") }
                    putJsonObject("auth_pass") { put("type", "string"); put("description", "Proxy authentication password (optional)") }
                    putJsonObject("destination_host") { put("type", "string"); put("description", "Destination host filter pattern (default '*')") }
                },
                required = listOf("host", "port")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val host = args["host"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: host")
                val port = args["port"].asBoundedInt("port", 1, 65535)
                    .getOrElse { return@addTool toolError(it.message ?: "Invalid port") }
                    ?: return@addTool toolError("Missing required parameter: port")
                val proxyType = args["type"]?.jsonPrimitive?.contentOrNull ?: "HTTP"
                EnumValidation.error(proxyType, UPSTREAM_PROXY_TYPES.toSet(), "type")?.let { return@addTool toolJsonResult(it) }
                val authUser = args["auth_user"]?.jsonPrimitive?.contentOrNull
                val authPass = args["auth_pass"]?.jsonPrimitive?.contentOrNull
                val destinationHost = args["destination_host"]?.jsonPrimitive?.contentOrNull

                toolJsonResult(bridge.setUpstreamProxy(host, port, proxyType, authUser, authPass, destinationHost))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }
}
