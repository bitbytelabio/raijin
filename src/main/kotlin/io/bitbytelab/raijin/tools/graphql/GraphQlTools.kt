package io.bitbytelab.raijin.tools.graphql

import io.bitbytelab.raijin.bridge.GraphQlBridge
import io.bitbytelab.raijin.core.asStringList
import io.bitbytelab.raijin.graphql.scanners.POIScanner
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
            description = "Probe or exploit a GraphQL endpoint; pick 'mode'. probe (default): three outcomes in " +
                "'verdict' — introspection_enabled (full schema disclosed, summarized); introspection_disabled (a " +
                "real GraphQL server, introspection off — 'Did you mean' field suggestions tried as a fallback); " +
                "not_graphql (neither probe got a GraphQL-shaped response — re-check the URL). query_templates: " +
                "generates a runnable example query/mutation/subscription per schema field (needs introspection " +
                "enabled). poi_scan: flags security-interesting fields by name (auth/privileged/pii/payment/" +
                "database/debugging/files), deprecated fields, and custom scalars. cycles_scan: flags types that " +
                "recurse into themselves (deep-nesting/DoS risk). batch_attack: expands a \$[INT:first:last] or " +
                "\$[LIST] placeholder in 'template' into N aliased sub-operations in one request — for 2FA brute " +
                "force, IDOR enumeration, or rate-limit-bypass testing; generates only unless 'send' is true. " +
                "Respects the operator scope policy (mcp_scope_mode).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url") { put("type", "string"); put("description", "GraphQL endpoint URL (e.g. https://target/graphql)") }
                    putJsonObject("mode") { put("type", "string"); put("description", "probe (default) | query_templates | poi_scan | cycles_scan | batch_attack") }
                    putJsonObject("max_depth") { put("type", "integer"); put("description", "query_templates: recursion depth limit (default 6)") }
                    putJsonObject("categories") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "poi_scan: keyword categories to flag, from ${POIScanner.DEFAULT_CATEGORIES}; omit for the default set") }
                    putJsonObject("custom_keywords") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "poi_scan: extra field-name keywords/regex fragments to flag") }
                    putJsonObject("template") { put("type", "string"); put("description", "batch_attack: a GraphQL query body containing \$[INT:first:last] or \$[LIST]") }
                    putJsonObject("values") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "batch_attack: values to substitute for a \$[LIST] placeholder") }
                    putJsonObject("send") { put("type", "boolean"); put("description", "batch_attack: also send the generated request (default false: generate only)") }
                },
                required = listOf("url")
            )
        ) { request ->
            try {
                val a = request.params.arguments ?: emptyMap()
                val url = a["url"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Parameter 'url' is required"}""")),
                        isError = true
                    )
                val result = when (a["mode"]?.jsonPrimitive?.contentOrNull ?: "probe") {
                    "query_templates" -> bridge.queryTemplates(url, a["max_depth"]?.jsonPrimitive?.intOrNull ?: 6)
                    "poi_scan" -> bridge.poiScan(url, a["categories"].asStringList()?.toSet(), a["custom_keywords"].asStringList())
                    "cycles_scan" -> bridge.cyclesScan(url)
                    "batch_attack" -> {
                        val template = a["template"]?.jsonPrimitive?.contentOrNull
                            ?: return@addTool CallToolResult(content = listOf(TextContent("""{"error":"Parameter 'template' is required for mode=batch_attack"}""")), isError = true)
                        bridge.batchAttack(url, template, a["values"].asStringList(), a["send"]?.jsonPrimitive?.booleanOrNull ?: false)
                    }
                    else -> bridge.probe(url)
                }
                CallToolResult(content = listOf(TextContent(result.toString())), isError = result["error"] != null)
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent(buildJsonObject { put("error", e.message ?: "Unknown error") }.toString())),
                    isError = true
                )
            }
        }
    }
}
