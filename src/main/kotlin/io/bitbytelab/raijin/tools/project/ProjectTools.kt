package io.bitbytelab.raijin.tools.project

import io.bitbytelab.raijin.bridge.ProjectBridge
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object ProjectTools {

    fun register(server: Server, bridge: ProjectBridge) {

        server.addTool(
            name = "project_info",
            description = "Get information about the current Burp Suite project including its " +
                "name, unique identifier, and description. No parameters required.",
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
