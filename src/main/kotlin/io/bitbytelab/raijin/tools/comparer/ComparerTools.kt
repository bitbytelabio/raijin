package io.bitbytelab.raijin.tools.comparer

import io.bitbytelab.raijin.bridge.ComparerBridge
import io.bitbytelab.raijin.core.asStringList
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object ComparerTools {

    fun register(server: Server, bridge: ComparerBridge) {

        server.addTool(
            name = "comparer_send",
            description = "Send data items to Burp Suite's Comparer tool for side-by-side " +
                "comparison. Useful for comparing HTTP requests, responses, or any text data " +
                "to identify differences. Parameters: data (array of strings, each string " +
                "becomes a separate item in the Comparer). At least one item is required; " +
                "typically two items are sent for comparison.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("data") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "Array of strings, each becomes a separate item in the Comparer") }
                },
                required = listOf("data")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val dataItems = args["data"].asStringList()
                    ?: return@addTool toolError("Missing required parameter: data (array of strings)")

                if (dataItems.isEmpty()) {
                    return@addTool toolError("data array must contain at least one item")
                }

                toolJsonResult(bridge.send(dataItems))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }
}
