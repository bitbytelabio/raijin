package io.bitbytelab.raijin.tools.decoder

import io.bitbytelab.raijin.bridge.DecoderBridge
import io.bitbytelab.raijin.core.asStringList
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object DecoderTools {

    fun register(server: Server, bridge: DecoderBridge) {

        server.addTool(
            name = "decoder_send",
            description = "Send data to Burp Suite's Decoder tool for manual encoding, " +
                "decoding, and hashing operations. The data will appear in a new Decoder " +
                "tab where various transformations can be applied interactively. " +
                "Parameters: data (array of strings, each string becomes a separate Decoder item). " +
                "A single string is accepted as one item.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("data") {
                        put("type", "array")
                        putJsonObject("items") { put("type", "string") }
                        put("description", "Array of strings, each becomes a separate item in the Decoder")
                    }
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
