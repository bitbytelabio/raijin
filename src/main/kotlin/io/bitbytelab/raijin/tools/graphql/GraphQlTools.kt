package io.bitbytelab.raijin.tools.graphql

import io.bitbytelab.raijin.bridge.GraphQlBridge
import io.bitbytelab.raijin.core.asStringList
import io.bitbytelab.raijin.core.asStringMap
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
                "fingerprint_engine: detects the GraphQL backend engine (Apollo, Hasura, graphql-java, ...) from " +
                "malformed-query error signatures. bruteforce_schema: reconstructs the schema from error-message " +
                "analysis when introspection is disabled — noisy and request-heavy (every field/arg guess is a " +
                "live request). Every mode accepts 'headers' and 'auto_headers' for auth; query_templates/" +
                "poi_scan/cycles_scan additionally cache the fetched schema (bypass with 'refresh_schema'). " +
                "Respects the operator scope policy (mcp_scope_mode).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url") { put("type", "string"); put("description", "GraphQL endpoint URL (e.g. https://target/graphql)") }
                    putJsonObject("mode") { put("type", "string"); put("description", "probe (default) | query_templates | poi_scan | cycles_scan | batch_attack | fingerprint_engine | bruteforce_schema") }
                    putJsonObject("max_depth") { put("type", "integer"); put("description", "query_templates: recursion depth limit (default 6)") }
                    putJsonObject("categories") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "poi_scan: keyword categories to flag, from ${POIScanner.DEFAULT_CATEGORIES}; omit for the default set") }
                    putJsonObject("custom_keywords") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "poi_scan: extra field-name keywords/regex fragments to flag") }
                    putJsonObject("template") { put("type", "string"); put("description", "batch_attack: a GraphQL query body containing \$[INT:first:last] or \$[LIST]") }
                    putJsonObject("values") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "batch_attack: values to substitute for a \$[LIST] placeholder") }
                    putJsonObject("send") { put("type", "boolean"); put("description", "batch_attack: also send the generated request (default false: generate only)") }
                    putJsonObject("headers") { put("type", "object"); put("description", "Extra headers (e.g. Authorization, Cookie) to send on every request this call makes. Explicit entries always override auto_headers.") }
                    putJsonObject("auto_headers") { put("type", "boolean"); put("description", "Auto-fill identity headers (Authorization/Cookie/X-Api-Key/X-Auth-Token) from the most recent Proxy-history request to this host (default false)") }
                    putJsonObject("refresh_schema") { put("type", "boolean"); put("description", "query_templates/poi_scan/cycles_scan: bypass the cached schema and re-fetch introspection (default false)") }
                    putJsonObject("bucket_size") { put("type", "integer"); put("description", "bruteforce_schema: wordlist guesses per request, aliased together (default 64)") }
                    putJsonObject("depth_limit") { put("type", "integer"); put("description", "bruteforce_schema: max nesting depth to recurse into discovered object types (default 2)") }
                    putJsonObject("bruteforce_arguments") { put("type", "boolean"); put("description", "bruteforce_schema: fall back to a wordlist brute force for argument names when the cheap probes find none (default true)") }
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
                val headers = a["headers"].asStringMap()
                val autoHeaders = a["auto_headers"]?.jsonPrimitive?.booleanOrNull ?: false
                val refreshSchema = a["refresh_schema"]?.jsonPrimitive?.booleanOrNull ?: false
                val result = when (a["mode"]?.jsonPrimitive?.contentOrNull ?: "probe") {
                    "query_templates" -> bridge.queryTemplates(url, a["max_depth"]?.jsonPrimitive?.intOrNull ?: 6, headers, autoHeaders, refreshSchema)
                    "poi_scan" -> bridge.poiScan(url, a["categories"].asStringList()?.toSet(), a["custom_keywords"].asStringList(), headers, autoHeaders, refreshSchema)
                    "cycles_scan" -> bridge.cyclesScan(url, headers, autoHeaders, refreshSchema)
                    "batch_attack" -> {
                        val template = a["template"]?.jsonPrimitive?.contentOrNull
                            ?: return@addTool CallToolResult(content = listOf(TextContent("""{"error":"Parameter 'template' is required for mode=batch_attack"}""")), isError = true)
                        bridge.batchAttack(url, template, a["values"].asStringList(), a["send"]?.jsonPrimitive?.booleanOrNull ?: false, headers, autoHeaders)
                    }
                    "fingerprint_engine" -> bridge.fingerprintEngine(url, headers, autoHeaders)
                    "bruteforce_schema" -> bridge.bruteforceSchema(
                        url, headers, autoHeaders,
                        a["bucket_size"]?.jsonPrimitive?.intOrNull ?: 64,
                        a["depth_limit"]?.jsonPrimitive?.intOrNull ?: 2,
                        a["bruteforce_arguments"]?.jsonPrimitive?.booleanOrNull ?: true,
                    )
                    else -> bridge.probe(url, headers, autoHeaders)
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
