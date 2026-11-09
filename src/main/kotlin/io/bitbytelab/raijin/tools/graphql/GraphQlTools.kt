package io.bitbytelab.raijin.tools.graphql

import io.bitbytelab.raijin.bridge.GraphQlBridge
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/** Registers the `graphql_probe` MCP tool. */
object GraphQlTools {
    fun register(server: Server, bridge: GraphQlBridge) {
        server.addTool(
            name = "graphql_probe",
            description = "Probe a GraphQL endpoint. Three outcomes, in 'verdict': introspection_enabled (full schema " +
                "disclosed, summarized); introspection_disabled (a real GraphQL server, introspection off — 'Did you " +
                "mean' field suggestions are tried as a fallback); not_graphql (neither probe got a response shaped " +
                "like GraphQL at all — re-check the URL, this is a different condition from introspection_disabled, " +
                "not the same thing worded differently). Respects the operator scope policy (mcp_scope_mode).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url") { put("type", "string"); put("description", "GraphQL endpoint URL (e.g. https://target/graphql)") }
                },
                required = listOf("url")
            )
        ) { request ->
            try {
                val url = request.params.arguments?.get("url")?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Parameter 'url' is required"}""")),
                        isError = true
                    )
                CallToolResult(content = listOf(TextContent(bridge.probe(url).toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent(buildJsonObject { put("error", e.message ?: "Unknown error") }.toString())),
                    isError = true
                )
            }
        }
    }
}
