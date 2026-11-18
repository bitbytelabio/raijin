package io.bitbytelab.raijin.tools.accesscontrol

import io.bitbytelab.raijin.bridge.AccessControlBridge
import io.bitbytelab.raijin.core.asJsonObjectList
import io.bitbytelab.raijin.safety.ScopeGate
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/** Registers the `access_control_sweep` MCP tool. */
object AccessControlTools {
    fun register(server: Server, bridge: AccessControlBridge) {
        server.addTool(
            name = "access_control_sweep",
            description = "Batch broken-access-control / IDOR test: replays each request under every identity and " +
                "flags where a lower-privilege or unauthenticated identity gets a response matching a higher-privilege " +
                "one. Scales auth_diff across many endpoints in one call. Provide 'identities' as " +
                "[{name, header_name?, header_value?, headers?, remove_headers?}] — an identity's headers replace the " +
                "request's own, and a name of none/unauth/anonymous sends the request without any credential header. " +
                "Uniform refusals (same 401/403/404, a redirect to a login page, a 200 login page or denial message) are " +
                "informational, never high or critical. " + ScopeGate.TOOL_NOTE,
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("requests") {
                        put("type", "array"); putJsonObject("items") { put("type", "object") }
                        put("description", "Requests to test: each {raw_request, host, port?, use_tls?}")
                    }
                    putJsonObject("identities") {
                        put("type", "array"); putJsonObject("items") { put("type", "object") }
                        put("description", "At least 2 identities: each {name, header_name?, header_value?, headers?, remove_headers?}; name none/unauth/anonymous strips every credential header")
                    }
                    putJsonObject("denied_regex") {
                        put("type", "string")
                        put("description", "Optional regex (case-insensitive): a response whose body matches is treated as denied whatever its status")
                    }
                },
                required = listOf("requests", "identities")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val requests = args["requests"].asJsonObjectList()
                    ?: return@addTool toolError("Parameter 'requests' (array of objects) is required")
                val identities = args["identities"].asJsonObjectList()
                    ?: return@addTool toolError("Parameter 'identities' (array of objects) is required")
                val deniedRegex = (args["denied_regex"] as? JsonPrimitive)?.contentOrNull?.takeIf { it.isNotEmpty() }
                toolJsonResult(bridge.sweep(requests, identities, deniedRegex))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }
}
