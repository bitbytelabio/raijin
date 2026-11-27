package io.bitbytelab.raijin.tools.accesscontrol

import io.bitbytelab.raijin.bridge.AccessControlBridge
import io.bitbytelab.raijin.core.asJsonObjectList
import io.bitbytelab.raijin.safety.ScopeGate
import io.bitbytelab.raijin.tools.ToolArgs
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.*

/** Registers the `access_control_sweep` MCP tool. */
object AccessControlTools {
    private fun missing(param: String, what: String): CallToolResult =
        ToolArgs.error("missing_parameter", "probe.access_control needs '$param': $what.") {
            put("param", param)
        }

    fun register(server: Server, bridge: AccessControlBridge) {
        server.addTool(
            name = "access_control_sweep",
            description =
                "Batch broken-access-control / IDOR test: replays each request under every identity and " +
                    "flags where a lower-privilege or unauthenticated identity gets a response matching a higher-privilege " +
                    "one. Scales auth_diff across many endpoints in one call. Provide 'identities' as " +
                    "[{name, header_name?, header_value?, headers?, remove_headers?}] — an identity's headers replace the " +
                    "request's own, and a name of none/unauth/anonymous sends the request without any credential header. " +
                    "Uniform refusals (same 401/403/404, a redirect to a login page, a 200 login page or denial message) are " +
                    "informational, never high or critical. " +
                    ScopeGate.TOOL_NOTE,
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("requests") {
                                put("type", "array")
                                putJsonObject("items") { put("type", "object") }
                                put(
                                    "description",
                                    "Requests to test: each {raw_request, host, port?, use_tls?}",
                                )
                            }
                            putJsonObject("identities") {
                                put("type", "array")
                                putJsonObject("items") { put("type", "object") }
                                put(
                                    "description",
                                    "At least 2 identities: each {name, header_name?, header_value?, headers?, remove_headers?}; name none/unauth/anonymous strips every credential header",
                                )
                            }
                            putJsonObject("denied_regex") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Optional regex (case-insensitive): a response whose body matches is treated as denied whatever its status",
                                )
                            }
                        },
                    required = listOf("requests", "identities"),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val requests =
                    args["requests"].asJsonObjectList()?.takeIf { it.isNotEmpty() }
                        ?: return@addTool missing(
                            "requests",
                            "a list of {raw_request, host, port?, use_tls?}",
                        )
                val identities =
                    args["identities"].asJsonObjectList()?.takeIf { it.isNotEmpty() }
                        ?: return@addTool missing(
                            "identities",
                            "at least 2 of {name, header_name?, header_value?}, the owner first",
                        )
                if (identities.size < 2) {
                    return@addTool ToolArgs.error(
                        "invalid_arguments",
                        "probe.access_control: 'identities' needs at least 2 entries (the first is the owner), got ${identities.size}.",
                    ) {
                        put("param", "identities")
                    }
                }
                // A bad entry is reported on that entry by the sweep; with no usable entry there is
                // nothing to test.
                val usable = requests.any { r ->
                    !(r["raw_request"] as? JsonPrimitive)?.contentOrNull.isNullOrEmpty() &&
                        !(r["host"] as? JsonPrimitive)?.contentOrNull.isNullOrEmpty()
                }
                if (!usable) {
                    return@addTool ToolArgs.error(
                        "invalid_arguments",
                        "probe.access_control: no entry of 'requests' has both 'raw_request' and 'host'; " +
                            "each is {raw_request, host, port?, use_tls?}.",
                    ) {
                        put("param", "requests")
                    }
                }
                val deniedRegex =
                    (args["denied_regex"] as? JsonPrimitive)?.contentOrNull?.takeIf {
                        it.isNotEmpty()
                    }
                toolJsonResult(bridge.sweep(requests, identities, deniedRegex))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }
}
