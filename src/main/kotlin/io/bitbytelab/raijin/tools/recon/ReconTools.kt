package io.bitbytelab.raijin.tools.recon

import io.bitbytelab.raijin.bridge.ReconBridge
import io.bitbytelab.raijin.core.ClampedInt
import io.bitbytelab.raijin.core.EnumValidation
import io.bitbytelab.raijin.core.ParamMinerWordlists
import io.bitbytelab.raijin.core.asBodyString
import io.bitbytelab.raijin.core.asClampedInt
import io.bitbytelab.raijin.core.asLongSafe
import io.bitbytelab.raijin.core.asStringList
import io.bitbytelab.raijin.core.asStringMapResult
import io.bitbytelab.raijin.core.withClampReport
import io.bitbytelab.raijin.recon.ParamLocation
import io.bitbytelab.raijin.safety.ScopeGate
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/** Registers the recon/discovery tools: JS endpoint harvest, content discovery, param mining. */
object ReconTools {
    private val HISTORY_ITEMS = 1..ReconBridge.MAX_HISTORY_ITEMS
    private val OFFSETS = 0..1_000_000
    private val LIMITS = 1..1_000_000
    private val BUCKET_SIZES = 1..256
    private val REQUEST_BUDGETS = 20..5000

    fun register(server: Server, bridge: ReconBridge) {

        server.addTool(
            name = "recon_js_endpoints",
            description = "Harvest endpoint paths and URLs from JavaScript responses already in proxy history " +
                "(SPAs leak their API surface in JS). Reads .js/.mjs responses: quoted paths, full URLs and template " +
                "literals (`/users/\${id}` comes back as /users/{id}). Also follows source maps: a map already in history " +
                "(.js.map) is read for its original file names and the endpoints in its embedded sources; maps a script " +
                "only points to (sourceMappingURL comment, SourceMap header) are listed, and requested when " +
                "fetch_source_maps=true (scope-checked per mcp_scope_mode). Browse the target first, then run this. " +
                ScopeGate.TOOL_NOTE,
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    intProp("max_items", "Max recent history items to scan (default 500); a larger value is clamped to ${ReconBridge.MAX_HISTORY_ITEMS} and reported as max_items_clamped_to", HISTORY_ITEMS)
                    putJsonObject("host_filter") { put("type", "string"); put("description", "Optional host regex filter") }
                    putJsonObject("fetch_source_maps") {
                        put("type", "boolean")
                        put("description", "Request source maps that scripts point to but that are not in history (default false: no traffic is sent)")
                    }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val a = request.params.arguments ?: emptyMap()
                val maxItems = a["max_items"].asClampedInt("max_items", HISTORY_ITEMS.first, HISTORY_ITEMS.last).getOrThrow()
                toolJsonResult(
                    bridge.jsEndpoints(
                        maxItems?.value ?: 500,
                        a.string("host_filter"),
                        a.bool("fetch_source_maps") ?: false,
                    ).withClampReport("max_items", maxItems)
                )
            } catch (e: Exception) { toolError(e.message ?: "Unknown error") }
        }

        server.addTool(
            name = "recon_content_discovery",
            description = "Brute-force a wordlist of paths under a base URL and return the ones the target treats " +
                "differently from paths that do not exist. Not-found behaviour is learned first from made-up paths of " +
                "several lengths and shapes (plain, directory, .json, .php, and the extensions in your list), so a " +
                "host that answers 200 to everything, repeats the path in its error page or redirects every unknown " +
                "path yields no false finds. A 429 is waited out and the pace slowed; if it persists, or a WAF starts " +
                "answering, the scan stops and reports stopped_at so you can continue later. At most " +
                "${ReconBridge.MAX_PATHS} paths per call. " + ScopeGate.TOOL_NOTE + " Checked per path.",
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
                val baseUrl = a.string("base_url") ?: return@addTool toolError("Parameter 'base_url' is required")
                val paths = a["paths"].asStringList() ?: return@addTool toolError("Parameter 'paths' (array) is required")
                if (paths.isEmpty()) return@addTool toolError("Parameter 'paths' must contain at least one path")
                toolJsonResult(bridge.contentDiscovery(baseUrl, paths))
            } catch (e: Exception) { toolError(e.message ?: "Unknown error") }
        }

        server.addTool(
            name = "recon_param_mine",
            description = "Probe parameter names on a URL for hidden params — IDOR/XSS/SSRF/cache-poisoning often hide " +
                "there. Works like Param Miner: many names per request, each with its own canary value, and a binary " +
                "search inside a bucket only when its response stands out, so the whole bundled list costs a few hundred " +
                "requests. mode=reflection (default) reports names whose value is echoed back (body or headers); " +
                "mode=diff reports names that change the response (status, body, Location / Set-Cookie / X-Cache) " +
                "WITHOUT reflecting, judged against repeated baselines so a page's own noise is not reported; mode=both " +
                "reports both. inject_in picks where the name is placed: query (default), body, json_body, cookie, or " +
                "header. Omit candidates to use a bundled dictionary (param-miner-params; param-miner-headers when " +
                "inject_in=header). A candidate may be 'name~value' to send a value of that shape (%s = canary, " +
                "%h = target host), as the header list does for host/origin/x-forwarded-host. headers/cookies/body set " +
                "the request the names are added to; offset/limit page through the list (the result gives next_offset); " +
                "max_requests caps the run. " + ScopeGate.TOOL_NOTE,
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url") { put("type", "string"); put("description", "Target URL") }
                    putJsonObject("candidates") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "Candidate parameter/header names ('name' or 'name~value'); omit to use a bundled wordlist") }
                    enumProp("mode", ReconBridge.MODES, "reflection (default) | diff | both")
                    enumProp("inject_in", ParamLocation.IDS, "query (default) | body | json_body | cookie | header")
                    putJsonObject("method") { put("type", "string"); put("description", "HTTP method; defaults to GET, or POST when inject_in is body/json_body") }
                    enumProp("wordlist", ParamMinerWordlists.names().sorted(), "Bundled wordlist when candidates is omitted (default: param-miner-params, or param-miner-headers for inject_in=header)")
                    intProp("offset", "Index of the first candidate to test (default 0); pass next_offset from the previous result to continue. An offset past the end tests nothing and is reported as offset_clamped_to", OFFSETS)
                    intProp("limit", "How many candidates to test from offset (default: all the rest)", LIMITS)
                    putJsonObject("headers") { put("type", "object"); put("description", "Request headers sent with every probe, e.g. {\"Authorization\": \"Bearer ...\"}") }
                    putJsonObject("cookies") { put("type", "object"); put("description", "Cookies sent with every probe, as {name: value} (or a 'a=1; b=2' string)") }
                    putJsonObject("body") { put("type", "string"); put("description", "Request body the candidates are added to (inject_in=body: form fields; json_body: a JSON object)") }
                    putJsonObject("cache_buster") { put("type", "boolean"); put("description", "Add a query parameter with a new value to every request, so no response comes from a cache and nothing a probe causes is cached for others (default true). Left off, and reported as cache_buster_dropped, when the target rejects unknown query parameters") }
                    intProp("bucket_size", "Names per request (default: query 64, body/json_body 128, cookie 32, header 20); halved automatically while the target rejects the size", BUCKET_SIZES)
                    intProp("max_requests", "Request budget for the run (default ${ReconBridge.DEFAULT_MAX_REQUESTS}); when reached the result says where to continue", REQUEST_BUDGETS)
                },
                required = listOf("url")
            )
        ) { request ->
            try {
                val a = request.params.arguments ?: emptyMap()
                val url = a.string("url") ?: return@addTool toolError("Parameter 'url' is required")
                // Limits out of range are clamped and reported (<name>_clamped_to), not refused.
                val limit = a.clamped("limit", LIMITS)
                val bucketSize = a.clamped("bucket_size", BUCKET_SIZES)
                val maxRequests = a.clamped("max_requests", REQUEST_BUDGETS)
                val options = ReconBridge.ParamMineOptions(
                    offset = a.int("offset", OFFSETS) ?: 0,
                    limit = limit?.value,
                    headers = a.mapArg("headers", "an object of header names to values"),
                    cookies = a.cookiesArg("cookies"),
                    body = a["body"].asBodyString(),
                    cacheBuster = a.bool("cache_buster") ?: true,
                    bucketSize = bucketSize?.value,
                    maxRequests = maxRequests?.value ?: ReconBridge.DEFAULT_MAX_REQUESTS,
                )
                toolJsonResult(
                    bridge.paramMine(
                        url,
                        a["candidates"].asStringList(),
                        a.oneOf("mode", ReconBridge.MODES) ?: "reflection",
                        a.oneOf("inject_in", ParamLocation.IDS) ?: "query",
                        a.string("method"),
                        a.oneOf("wordlist", ParamMinerWordlists.names().sorted()),
                        options,
                    ).withClampReport("limit", limit).withClampReport("bucket_size", bucketSize)
                        .withClampReport("max_requests", maxRequests)
                )
            } catch (e: Exception) { toolError(e.message ?: "Unknown error") }
        }
    }

    /** An optional limit moved into [range] when outside it; only a non-integer throws. */
    private fun Map<String, JsonElement>.clamped(name: String, range: IntRange): ClampedInt? =
        this[name].asClampedInt(name, range.first, range.last).getOrThrow()

    // ---------------------------------------------------------------
    // Argument and schema helpers: a bad value throws IllegalArgumentException with the message
    // the handler's catch returns through toolError.
    // ---------------------------------------------------------------

    private fun Map<String, JsonElement>.string(name: String): String? = (this[name] as? JsonPrimitive)?.contentOrNull

    private fun Map<String, JsonElement>.bool(name: String): Boolean? {
        val element = this[name]
        if (element == null || element is JsonNull) return null
        return (element as? JsonPrimitive)?.booleanOrNull ?: throw IllegalArgumentException("Parameter '$name' must be true or false")
    }

    /** Optional integer argument; a non-integer or a value outside [range] throws, reported as a tool error. */
    private fun Map<String, JsonElement>.int(name: String, range: IntRange): Int? {
        val element = this[name]
        if (element == null || element is JsonNull) return null
        val value = element.asLongSafe() ?: throw IllegalArgumentException("Parameter '$name' must be an integer")
        require(value >= range.first && value <= range.last) {
            "Parameter '$name' must be between ${range.first} and ${range.last} (got $value)"
        }
        return value.toInt()
    }

    /** Optional string argument from the closed set [allowed] (case-insensitive); null when absent or blank. */
    private fun Map<String, JsonElement>.oneOf(name: String, allowed: List<String>): String? {
        val element = this[name]
        if (element == null || element is JsonNull) return null
        val value = (element as? JsonPrimitive)?.contentOrNull ?: throw IllegalArgumentException("Parameter '$name' must be a string")
        EnumValidation.error(value, allowed.toSet(), name)?.let {
            throw IllegalArgumentException(it["error"]?.jsonPrimitive?.contentOrNull ?: "Parameter '$name' has an invalid value")
        }
        return value.trim().ifEmpty { null }
    }

    /** Optional name-to-value object argument; present but unreadable throws. */
    private fun Map<String, JsonElement>.mapArg(name: String, shape: String): Map<String, String> {
        val element = this[name]
        if (element == null || element is JsonNull) return emptyMap()
        val (map, problem) = element.asStringMapResult()
        return map ?: throw IllegalArgumentException("Parameter '$name' must be $shape" + (problem?.let { " ($it)" } ?: ""))
    }

    /** Cookies as an object of names to values, or as a `a=1; b=2` string. */
    private fun Map<String, JsonElement>.cookiesArg(name: String): Map<String, String> {
        val text = (this[name] as? JsonPrimitive)?.takeIf { it.isString }?.content?.trim()
        if (text != null && !text.startsWith("{") && !text.startsWith("[")) {
            return text.split(';').mapNotNull { pair ->
                val eq = pair.indexOf('=')
                if (eq <= 0) null else pair.substring(0, eq).trim() to pair.substring(eq + 1).trim()
            }.toMap()
        }
        return mapArg(name, "an object of cookie names to values, or a 'a=1; b=2' string")
    }

    private fun JsonObjectBuilder.intProp(name: String, description: String, range: IntRange) {
        putJsonObject(name) {
            put("type", "integer")
            put("minimum", range.first)
            put("maximum", range.last)
            put("description", description)
        }
    }

    private fun JsonObjectBuilder.enumProp(name: String, values: List<String>, description: String) {
        putJsonObject(name) {
            put("type", "string")
            putJsonArray("enum") { values.forEach { add(it) } }
            put("description", description)
        }
    }
}
