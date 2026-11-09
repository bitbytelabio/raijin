package io.bitbytelab.raijin.tools.injection

import io.bitbytelab.raijin.bridge.InjectionBridge
import io.bitbytelab.raijin.core.asStringList
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/** Registers the `injection_probe` MCP tool. */
object InjectionTools {
    fun register(server: Server, bridge: InjectionBridge) {
        server.addTool(
            name = "injection_probe",
            description = "Guided injection detection with confirmation oracles (not blind fuzzing). Mark the injection " +
                "point with the FUZZ keyword anywhere in the raw request — including inside a header line, e.g. " +
                "'Cookie: TrackingId=FUZZ' to target a cookie. Tests sqli (error-based, time-based with both comment-" +
                "truncation and string-concatenation-breakout payload shapes, and boolean-differential for when errors " +
                "are suppressed and no delay lands), ssti (math-evaluation), and lfi/traversal (file-content markers), " +
                "and returns only CONFIRMED findings with the triggering payload. Optional 'classes' to limit which are " +
                "tested; 'delay_seconds' to tune the timing oracle. Scope-gated (mcp_scope_mode). For blind/OOB (SSRF, " +
                "blind cmdi) pair collaborator_* with http_fuzz.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("request") { put("type", "string"); put("description", "Raw HTTP request with the FUZZ keyword at the injection point (any header line or the body)") }
                    putJsonObject("host") { put("type", "string"); put("description", "Target hostname") }
                    putJsonObject("port") { put("type", "integer"); put("description", "Target port (default 443)") }
                    putJsonObject("use_tls") { put("type", "boolean"); put("description", "Use HTTPS (default: port==443)") }
                    putJsonObject("classes") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "Subset to test: sqli | ssti | lfi (default: all)") }
                    putJsonObject("delay_seconds") { put("type", "integer"); put("description", "Sleep duration for time-based sqli payloads, default 5. Raise it for network jitter or a lab that requires a longer sleep.") }
                },
                required = listOf("request", "host")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val req = args["request"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool err("Parameter 'request' is required (mark the injection point with FUZZ)")
                val host = args["host"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool err("Parameter 'host' is required")
                val port = args["port"]?.jsonPrimitive?.intOrNull ?: 443
                val useTls = args["use_tls"]?.jsonPrimitive?.booleanOrNull ?: (port == 443)
                val classes = args["classes"].asStringList()
                val delaySeconds = args["delay_seconds"]?.jsonPrimitive?.intOrNull ?: 5
                CallToolResult(content = listOf(TextContent(bridge.probe(req, host, port, useTls, classes, delaySeconds).toString())))
            } catch (e: Exception) {
                err(e.message)
            }
        }
    }

    private fun err(msg: String?): CallToolResult =
        CallToolResult(content = listOf(TextContent(buildJsonObject { put("error", msg ?: "Unknown error") }.toString())), isError = true)
}
