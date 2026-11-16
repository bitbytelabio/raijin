package io.bitbytelab.raijin.tools

import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** Builds an MCP error result with safe JSON serialization and `isError = true`. */
fun toolError(message: String): CallToolResult = CallToolResult(
    content = listOf(TextContent(buildJsonObject { put("error", message) }.toString())),
    isError = true,
)

/** Builds an MCP JSON result, setting `isError = true` automatically when an `"error"` key is present. */
fun toolJsonResult(result: JsonElement): CallToolResult = CallToolResult(
    content = listOf(TextContent(result.toString())),
    isError = (result as? JsonObject)?.get("error") != null,
)
