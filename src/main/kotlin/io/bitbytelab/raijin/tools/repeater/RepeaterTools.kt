package io.bitbytelab.raijin.tools.repeater

import io.bitbytelab.raijin.bridge.RepeaterBridge
import io.bitbytelab.raijin.core.asBooleanSafe
import io.bitbytelab.raijin.core.asBoundedInt
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object RepeaterTools {

    fun register(server: Server, bridge: RepeaterBridge) {
        server.addTool(
            name = "repeater_send",
            description = "Send an HTTP request to Burp Suite's Repeater tool. " +
                "Creates a new Repeater tab with the specified request, allowing manual " +
                "replay and modification. Parameters: request (raw HTTP request string), " +
                "host (target hostname), port (target port number), use_tls (boolean, " +
                "whether to use HTTPS), tab_name (optional, name for the Repeater tab).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("request") { put("type", "string"); put("description", "Raw HTTP request string") }
                    putJsonObject("host") { put("type", "string"); put("description", "Target hostname") }
                    putJsonObject("port") {
                        put("type", "integer"); put("minimum", 1); put("maximum", 65535)
                        put("description", "Target port number")
                    }
                    putJsonObject("use_tls") { put("type", "boolean"); put("description", "Whether to use HTTPS (TLS)") }
                    putJsonObject("tab_name") { put("type", "string"); put("description", "Optional name for the Repeater tab") }
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
                val tabName = args["tab_name"]?.jsonPrimitive?.contentOrNull

                toolJsonResult(bridge.sendToRepeater(rawRequest, host, port, useTls, tabName))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }
}
