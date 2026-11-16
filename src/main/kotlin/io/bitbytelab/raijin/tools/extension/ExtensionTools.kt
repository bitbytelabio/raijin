package io.bitbytelab.raijin.tools.extension

import io.bitbytelab.raijin.bridge.ExtensionBridge
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object ExtensionTools {

    fun register(server: Server, bridge: ExtensionBridge) {

        server.addTool(
            name = "extension_info",
            description = "Get comprehensive information about the Raijin extension including " +
                "its version, filename, Burp Suite version/edition, MCP server bind host and ports, " +
                "remote-access state (auth_required, source IP and host allowlists; never the token), " +
                "active runtime state (proxy rules, traffic rules, session rules, scan tasks, " +
                "WebSocket connections, Collaborator clients), and registered handlers " +
                "(scan checks, payload processors). No parameters required.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {},
                required = emptyList()
            )
        ) { _ ->
            try {
                toolJsonResult(bridge.getInfo())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }
}
