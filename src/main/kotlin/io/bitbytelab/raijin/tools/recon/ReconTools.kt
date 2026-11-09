package io.bitbytelab.raijin.tools.recon

import io.bitbytelab.raijin.bridge.ReconBridge
import io.bitbytelab.raijin.core.asStringList
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/** Registers the recon/discovery tools: JS endpoint harvest, content discovery, param mining. */
object ReconTools {
    fun register(server: Server, bridge: ReconBridge) {

        server.addTool(
            name = "recon_js_endpoints",
            description = "Harvest endpoint paths and URLs from JavaScript responses already in proxy history " +
                "(SPAs leak their API surface in JS). Browse the target first, then run this.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("max_items") { put("type", "integer"); put("description", "Max recent history items to scan (default 500)") }
                    putJsonObject("host_filter") { put("type", "string"); put("description", "Optional host regex filter") }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val a = request.params.arguments ?: emptyMap()
                val result = bridge.jsEndpoints(
                    a["max_items"]?.jsonPrimitive?.intOrNull ?: 500,
                    a["host_filter"]?.jsonPrimitive?.contentOrNull
                )
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) { err(e.message) }
        }

        server.addTool(
            name = "recon_content_discovery",
            description = "Brute-force a wordlist of paths under a base URL, calibrating against a known-missing " +
                "path to filter soft-404s. Returns paths whose status/size differ from the catch-all baseline. " +
                "Respects the operator scope policy (mcp_scope_mode).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("base_url") { put("type", "string"); put("description", "Base URL, e.g. https://target.com") }
                    putJsonObject("paths") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "Candidate paths (with or without leading /)") }
                },
                required = listOf("base_url", "paths")
            )
        ) { request ->
            try {
                val a = request.params.arguments ?: emptyMap()
                val baseUrl = a["base_url"]?.jsonPrimitive?.contentOrNull ?: return@addTool err("Parameter 'base_url' is required")
                val paths = a["paths"].asStringList() ?: return@addTool err("Parameter 'paths' (array) is required")
                CallToolResult(content = listOf(TextContent(bridge.contentDiscovery(baseUrl, paths).toString())))
            } catch (e: Exception) { err(e.message) }
        }

        server.addTool(
            name = "recon_param_mine",
            description = "Probe parameter names on a URL for hidden params — IDOR/XSS/SSRF/cache-poisoning often hide " +
                "there. mode=reflection (default) flags names whose value is echoed back; mode=diff flags names that " +
                "change server behavior (status/body) WITHOUT reflecting, catching params reflection alone misses; " +
                "mode=both reports both. inject_in picks where the name is placed: query (default), body, json_body, " +
                "cookie, or header. Omit candidates to use a bundled dictionary (param-miner-params by default, or " +
                "param-miner-headers for header names). Respects the operator scope policy.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url") { put("type", "string"); put("description", "Target URL") }
                    putJsonObject("candidates") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "Candidate parameter/header names; omit to use a bundled wordlist") }
                    putJsonObject("mode") { put("type", "string"); put("description", "reflection (default) | diff | both") }
                    putJsonObject("inject_in") { put("type", "string"); put("description", "query (default) | body | json_body | cookie | header") }
                    putJsonObject("method") { put("type", "string"); put("description", "HTTP method; defaults to GET, or POST when inject_in is body/json_body") }
                    putJsonObject("wordlist") { put("type", "string"); put("description", "Bundled wordlist name when candidates is omitted (default: param-miner-params)") }
                },
                required = listOf("url")
            )
        ) { request ->
            try {
                val a = request.params.arguments ?: emptyMap()
                val url = a["url"]?.jsonPrimitive?.contentOrNull ?: return@addTool err("Parameter 'url' is required")
                val candidates = a["candidates"].asStringList()
                val mode = a["mode"]?.jsonPrimitive?.contentOrNull ?: "reflection"
                val injectIn = a["inject_in"]?.jsonPrimitive?.contentOrNull ?: "query"
                val method = a["method"]?.jsonPrimitive?.contentOrNull
                val wordlist = a["wordlist"]?.jsonPrimitive?.contentOrNull
                CallToolResult(content = listOf(TextContent(bridge.paramMine(url, candidates, mode, injectIn, method, wordlist).toString())))
            } catch (e: Exception) { err(e.message) }
        }
    }

    private fun err(msg: String?): CallToolResult =
        CallToolResult(content = listOf(TextContent(buildJsonObject { put("error", msg ?: "Unknown error") }.toString())), isError = true)
}
