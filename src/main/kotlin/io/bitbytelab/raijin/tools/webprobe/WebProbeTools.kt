package io.bitbytelab.raijin.tools.webprobe

import io.bitbytelab.raijin.bridge.WebProbeBridge
import io.bitbytelab.raijin.core.EnumValidation
import io.bitbytelab.raijin.core.asClampedInt
import io.bitbytelab.raijin.core.asLongSafe
import io.bitbytelab.raijin.core.withClampReport
import io.bitbytelab.raijin.core.asStringList
import io.bitbytelab.raijin.core.asStringMapResult
import io.bitbytelab.raijin.safety.ScopeGate
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/** Registers cors_probe, cache_probe and recon_fingerprint. */
object WebProbeTools {
    private val CACHE_REQUEST_BUDGETS = 20..1000

    fun register(server: Server, bridge: WebProbeBridge) {

        server.addTool(
            name = "cors_probe",
            description = "Probe a URL's CORS policy by sending crafted Origin headers and classifying the " +
                "Access-Control-Allow-Origin/-Credentials response (compared trimmed, case-insensitively). Besides an " +
                "unrelated origin and 'null', it sends origins built from the target's own host to catch allowlist " +
                "mistakes: <host>.<other domain> (prefix match), <junk><domain> (suffix match), a dot replaced by a " +
                "letter (unescaped regex dot), <host>_.<other domain>, a made-up subdomain, and the http:// origin. Each " +
                "origin is sent as a GET and as an OPTIONS preflight (asking for PUT and a custom header), and a " +
                "response whose ACAO follows the Origin without 'Vary: Origin' is flagged. " + ScopeGate.TOOL_NOTE,
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url") { put("type", "string"); put("description", "Target URL") }
                },
                required = listOf("url")
            )
        ) { request ->
            try {
                val url = request.params.arguments.orEmpty().string("url")
                    ?: return@addTool toolError("Parameter 'url' is required")
                toolJsonResult(bridge.corsProbe(url))
            } catch (e: Exception) { toolError(e.message ?: "Unknown error") }
        }

        server.addTool(
            name = "cache_probe",
            description = "Probe a URL for web cache poisoning and web cache deception. First reads the cache from the " +
                "response headers (X-Cache, CF-Cache-Status, Age, Cache-Status, ...: hit / miss / not stored, and the CDN). " +
                "Poisoning: sends headers and cookies a cache often leaves out of its key (X-Forwarded-Host, " +
                "X-Forwarded-Scheme, X-Original-URL, method overrides, cookies the target sets, ...), each under a " +
                "cache-buster query value used for nothing else, then asks for the same URL without the input and " +
                "without a session. Status/redirect/path probes wait until cache-buster isolation is demonstrated. " +
                "Unproven isolation or a changed visitor baseline gives an inconclusive verdict, not confirmation. " +
                "Stops can report rate_limited, baseline_changed or cache_buster_ignored. A unique query value " +
                "cannot guarantee isolation when the cache key is unknown. Deception: requests path variants the " +
                "origin may treat as the page and the cache as a static file (/page/x.css, " +
                "/page;x.css, /page%23x.css, ...) as the user, then without a session. Pass the logged-in user's request " +
                "headers as 'headers' to prove a private page gets stored. " + ScopeGate.TOOL_NOTE,
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url") { put("type", "string"); put("description", "Target URL") }
                    putJsonObject("checks") {
                        put("type", "array")
                        putJsonObject("items") {
                            put("type", "string")
                            putJsonArray("enum") { WebProbeBridge.CACHE_CHECKS.forEach { add(it) } }
                        }
                        put("description", "Which checks to run: poisoning, deception (default: both)")
                    }
                    putJsonObject("headers") { put("type", "object"); put("description", "Request headers of a logged-in user (Cookie, Authorization); sent with every request except the ones made as a visitor without a session") }
                    putJsonObject("probe_headers") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "Further headers to try as unkeyed inputs: 'Name' or 'Name~value' (%s = canary, %h = target host, %p = a random port)") }
                    putJsonObject("probe_cookies") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "Further cookies to try as unkeyed inputs: 'name' or 'name~value'") }
                    putJsonObject("max_requests") {
                        put("type", "integer")
                        put("minimum", CACHE_REQUEST_BUDGETS.first)
                        put("maximum", CACHE_REQUEST_BUDGETS.last)
                        put("description", "Request budget (default ${WebProbeBridge.DEFAULT_CACHE_REQUESTS})")
                    }
                },
                required = listOf("url")
            )
        ) { request ->
            try {
                val a = request.params.arguments.orEmpty()
                val url = a.string("url") ?: return@addTool toolError("Parameter 'url' is required")
                val checks = a["checks"].asStringList()
                checks?.forEach { name ->
                    EnumValidation.error(name, WebProbeBridge.CACHE_CHECKS.toSet(), "checks", required = true)?.let { return@addTool toolJsonResult(it) }
                }
                // Out of range is clamped and reported (max_requests_clamped_to), not refused.
                val maxRequests = a["max_requests"]
                    .asClampedInt("max_requests", CACHE_REQUEST_BUDGETS.first, CACHE_REQUEST_BUDGETS.last).getOrThrow()
                toolJsonResult(
                    bridge.cacheProbe(
                        url = url,
                        checks = checks,
                        headers = a.mapArg("headers", "an object of header names to values"),
                        probeHeaders = a["probe_headers"].asStringList().orEmpty(),
                        probeCookies = a["probe_cookies"].asStringList().orEmpty(),
                        maxRequests = maxRequests?.value ?: WebProbeBridge.DEFAULT_CACHE_REQUESTS,
                    ).withClampReport("max_requests", maxRequests)
                )
            } catch (e: Exception) { toolError(e.message ?: "Unknown error") }
        }

        server.addTool(
            name = "recon_fingerprint",
            description = "Fingerprint server/tech/WAF/framework from a single GET (Server, X-Powered-By, " +
                "Set-Cookie, WAF headers, and body markers). Drives downstream payload selection. " + ScopeGate.TOOL_NOTE,
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url") { put("type", "string"); put("description", "Target URL") }
                },
                required = listOf("url")
            )
        ) { request ->
            try {
                val url = request.params.arguments.orEmpty().string("url")
                    ?: return@addTool toolError("Parameter 'url' is required")
                toolJsonResult(bridge.fingerprint(url))
            } catch (e: Exception) { toolError(e.message ?: "Unknown error") }
        }
    }

    private fun Map<String, JsonElement>.string(name: String): String? = (this[name] as? JsonPrimitive)?.contentOrNull

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

    /** Optional name-to-value object argument; present but unreadable throws. */
    private fun Map<String, JsonElement>.mapArg(name: String, shape: String): Map<String, String> {
        val element = this[name]
        if (element == null || element is JsonNull) return emptyMap()
        val (map, problem) = element.asStringMapResult()
        return map ?: throw IllegalArgumentException("Parameter '$name' must be $shape" + (problem?.let { " ($it)" } ?: ""))
    }
}
