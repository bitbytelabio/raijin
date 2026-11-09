package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.safety.BoundedHttp
import burp.api.montoya.http.message.params.HttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import io.bitbytelab.raijin.core.BehavioralDiff
import io.bitbytelab.raijin.core.JsonBodyMerge
import io.bitbytelab.raijin.core.ParamMinerWordlists
import io.bitbytelab.raijin.core.ProbeResult
import io.bitbytelab.raijin.recon.JsEndpoints
import io.bitbytelab.raijin.recon.ReconHeuristics
import io.bitbytelab.raijin.safety.ScopeGate
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Reconnaissance/discovery — the capability gap that left the agent only able to
 * test endpoints it was explicitly handed. Provides JS endpoint harvesting,
 * wordlist content discovery (with soft-404 calibration), and reflected-param
 * mining. Active probes respect the operator scope policy.
 */
class ReconBridge(private val api: MontoyaApi) {

    private companion object {
        const val MARKER = "zZmcpR3c0nMk7Qx"
        const val CALIBRATION_PATH = "/zzz_mcp_recon_calibration_404page"
    }

    private val scopeGate = ScopeGate(api)

    /** GET [url], returning (status, bodyLength); (0,0) on failure. */
    private fun sendGet(url: String): Pair<Int, Int> = try {
        val resp = BoundedHttp.send(api, HttpRequest.httpRequestFromUrl(url))?.response()
        Pair(resp?.statusCode()?.toInt() ?: 0, resp?.body()?.length() ?: 0)
    } catch (_: Exception) {
        Pair(0, 0)
    }

    /** Harvest endpoint paths/URLs from JavaScript responses already in proxy history. */
    fun jsEndpoints(maxItems: Int, hostFilter: String?): JsonObject {
        return try {
            var items = api.proxy().history().toList()
            if (hostFilter != null) {
                val rx = Regex(hostFilter, RegexOption.IGNORE_CASE)
                items = items.filter { try { rx.containsMatchIn(it.finalRequest().httpService().host()) } catch (_: Exception) { false } }
            }
            items = items.takeLast(maxItems.coerceIn(1, 2000))
            val endpoints = linkedSetOf<String>()
            var scanned = 0
            for (item in items) {
                val url = try { item.finalRequest().url() } catch (_: Exception) { "" }
                val isJs = url.substringBefore('?').endsWith(".js", true) || try {
                    item.hasResponse() && (item.originalResponse().headerValue("Content-Type")?.contains("javascript", true) == true)
                } catch (_: Exception) { false }
                if (!isJs) continue
                scanned++
                val body = try { if (item.hasResponse()) item.originalResponse().bodyToString() else "" } catch (_: Exception) { "" }
                endpoints.addAll(JsEndpoints.extract(body))
            }
            buildJsonObject {
                put("js_responses_scanned", scanned)
                put("endpoint_count", endpoints.size)
                put("endpoints", buildJsonArray { endpoints.take(2000).forEach { add(it) } })
            }
        } catch (e: Exception) {
            buildJsonObject { put("error", "JS endpoint scan failed: ${e.message}") }
        }
    }

    /** Brute a wordlist of [paths] under [baseUrl], calibrating against a known-missing path to filter soft-404s. */
    fun contentDiscovery(baseUrl: String, paths: List<String>): JsonObject {
        return try {
            val base = baseUrl.trimEnd('/')
            val baseCheck = scopeGate.check("$base/")
            baseCheck.deny?.let { return it }
            val (calStatus, calLen) = sendGet(base + CALIBRATION_PATH)
            val tested = paths.take(2000)
            val found = mutableListOf<JsonObject>()
            var skippedOutOfScope = 0
            for (path in tested) {
                val full = base + (if (path.startsWith("/")) path else "/$path")
                // Per-path scope check: Burp scope can exclude specific paths under an in-scope host.
                if (scopeGate.deny(full) != null) { skippedOutOfScope++; continue }
                val (status, len) = sendGet(full)
                if (ReconHeuristics.isInteresting(calStatus, calLen, status, len)) {
                    found.add(buildJsonObject { put("path", path); put("url", full); put("status", status); put("length", len) })
                }
            }
            buildJsonObject {
                put("base_url", base)
                baseCheck.warning?.let { put("scope_warning", it) }
                put("calibration", buildJsonObject { put("status", calStatus); put("length", calLen) })
                put("tested", tested.size)
                if (skippedOutOfScope > 0) put("skipped_out_of_scope", skippedOutOfScope)
                put("found_count", found.size)
                put("found", buildJsonArray { found.forEach { add(it) } })
            }
        } catch (e: Exception) {
            buildJsonObject { put("error", "Content discovery failed: ${e.message}") }
        }
    }

    /**
     * Probe [candidates] (or a bundled dictionary, when null) for hidden parameters on [url].
     *
     * [mode] `"reflection"` (default) flags only candidates whose value is echoed back verbatim —
     * cheap, but blind to params that change server behavior without reflecting it. `"diff"` instead
     * compares each candidate's response against an unmodified baseline (status/body similarity via
     * [BehavioralDiff]), catching params that affect control flow (auth, caching, feature flags)
     * without reflecting. `"both"` runs both checks and reports each separately.
     *
     * [injectIn] selects where the candidate name is placed: `"query"` (default), `"body"`
     * (form-encoded), `"json_body"` (top-level key in a JSON object body), `"cookie"`, or `"header"`.
     */
    fun paramMine(
        url: String,
        candidates: List<String>?,
        mode: String = "reflection",
        injectIn: String = "query",
        method: String? = null,
        wordlist: String? = null,
    ): JsonObject {
        return try {
            val check = scopeGate.check(url)
            check.deny?.let { return it }

            val useDiff = mode == "diff" || mode == "both"
            val useReflection = mode == "reflection" || mode == "both"
            val resolvedMethod = method ?: if (injectIn == "body" || injectIn == "json_body") "POST" else "GET"

            val wordlistName = wordlist ?: ParamMinerWordlists.DEFAULT
            val source = when (val resolved = ParamMinerWordlists.resolve(candidates, wordlistName)) {
                is ParamMinerWordlists.Resolved.Error -> return buildJsonObject { put("error", resolved.message) }
                is ParamMinerWordlists.Resolved.Ok -> resolved.candidates
            }
            // Caller-supplied lists get the existing generous cap; an auto-loaded dictionary is capped
            // tighter by default so a bare call doesn't silently fire ~1000 requests at the target.
            val tested = source.take(if (candidates != null) 1000 else 300)

            val baseRequest = HttpRequest.httpRequestFromUrl(url).withMethod(resolvedMethod)
            val baseline = if (useDiff) sendProbe(baseRequest) else null

            val interesting = mutableListOf<JsonObject>()
            for (cand in tested) {
                val mutated = injectCandidate(baseRequest, injectIn, cand, MARKER)
                val resp = try {
                    BoundedHttp.send(api, mutated)
                } catch (_: Exception) {
                    null
                }
                val body = try { resp?.response()?.bodyToString() ?: "" } catch (_: Exception) { "" }
                val status = try { resp?.response()?.statusCode()?.toInt() ?: 0 } catch (_: Exception) { 0 }

                val reflects = useReflection && ReconHeuristics.reflects(body, MARKER)
                val diffFlag = useDiff && baseline != null && status != 0 &&
                    BehavioralDiff.changed(baseline, ProbeResult(status, body))

                if (reflects || diffFlag) {
                    interesting.add(buildJsonObject {
                        put("param", cand)
                        put("inject_in", injectIn)
                        if (useReflection) put("reflected", reflects)
                        if (useDiff) put("behavior_diff", diffFlag)
                    })
                }
            }
            buildJsonObject {
                put("url", url)
                check.warning?.let { put("scope_warning", it) }
                put("mode", mode)
                put("inject_in", injectIn)
                put("marker", MARKER)
                put("wordlist_used", if (candidates == null) wordlistName else null)
                put("tested", tested.size)
                put("interesting_count", interesting.size)
                put("interesting_params", buildJsonArray { interesting.forEach { add(it) } })
                put(
                    "note",
                    "Reflected params are candidate injection points (XSS/SSRF/IDOR). " +
                        "behavior_diff params changed status/body without reflecting — worth manual follow-up.",
                )
            }
        } catch (e: Exception) {
            buildJsonObject { put("error", "Param mining failed: ${e.message}") }
        }
    }

    private fun sendProbe(request: HttpRequest): ProbeResult? {
        val resp = try {
            BoundedHttp.send(api, request)
        } catch (_: Exception) {
            null
        } ?: return null
        return try {
            ProbeResult(resp.response().statusCode().toInt(), resp.response().bodyToString())
        } catch (_: Exception) {
            null
        }
    }

    private fun injectCandidate(request: HttpRequest, injectIn: String, name: String, value: String): HttpRequest =
        when (injectIn) {
            "body" -> upsertParam(request, HttpParameter.bodyParameter(name, value))
            "json_body" -> injectJsonBody(request, name, value)
            "cookie" -> upsertParam(request, HttpParameter.cookieParameter(name, value))
            "header" -> request.withAddedHeader(name, value)
            else -> upsertParam(request, HttpParameter.urlParameter(name, value))
        }

    private fun upsertParam(request: HttpRequest, param: HttpParameter): HttpRequest =
        if (request.hasParameter(param.name(), param.type())) request.withUpdatedParameters(param)
        else request.withAddedParameters(param)

    /** Adds [name]:[value] as a top-level key to a JSON object body (see [JsonBodyMerge]). */
    private fun injectJsonBody(request: HttpRequest, name: String, value: String): HttpRequest {
        val bodyText = try { request.bodyToString() } catch (_: Exception) { "" }
        val merged = JsonBodyMerge.mergeKey(bodyText, name, value)
        return request.withBody(merged).withHeader("Content-Type", "application/json")
    }
}
