package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import io.bitbytelab.raijin.core.BodyText
import io.bitbytelab.raijin.core.EnumValidation
import io.bitbytelab.raijin.core.ParamMinerWordlists
import io.bitbytelab.raijin.core.ProbeResult
import io.bitbytelab.raijin.recon.ContentDiscovery
import io.bitbytelab.raijin.recon.JsEndpoints
import io.bitbytelab.raijin.recon.ParamInjection
import io.bitbytelab.raijin.recon.ParamLocation
import io.bitbytelab.raijin.recon.ParamMiner
import io.bitbytelab.raijin.recon.ProbeRequest
import io.bitbytelab.raijin.recon.ProbeText
import io.bitbytelab.raijin.recon.SourceMaps
import io.bitbytelab.raijin.safety.BoundedHttp
import io.bitbytelab.raijin.safety.RequestHygiene
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.safety.ScopeGate
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.math.min
import kotlin.random.Random

/**
 * Sends the plain [ProbeRequest]s the recon and web-probe engines plan through Burp, bounded in
 * time ([BoundedHttp]) and in how much of a response body is kept.
 */
internal class ProbeTransport(private val api: MontoyaApi) {

    /** Where a URL's requests go, and Burp's own request for it (its usual browser headers) as a [ProbeRequest]. */
    class Seed(val service: HttpService, val request: ProbeRequest)

    /** @throws IllegalArgumentException when Burp cannot tell the target host from [url]. */
    fun seed(url: String, method: String = "GET"): Seed {
        val burp = HttpRequest.httpRequestFromUrl(url)
        val service: HttpService = burp.httpService() ?: throw IllegalArgumentException("Not a URL Burp can send a request to: $url")
        var headers = burp.headers().map { it.name() to it.value() }.filterNot { it.first.startsWith(":") }
        if (headers.none { it.first.equals("Host", ignoreCase = true) }) {
            val defaultPort = if (service.secure()) 443 else 80
            headers = listOf("Host" to (if (service.port() == defaultPort) service.host() else "${service.host()}:${service.port()}")) + headers
        }
        // Bodies are compared and searched as text, so they are asked for uncompressed.
        val request = ProbeRequest(method, burp.path().ifEmpty { "/" }, headers).withHeader("Accept-Encoding", "identity")
        return Seed(service, request)
    }

    /**
     * Sends [request]; null on a timeout or error. An [internal] request skips Raijin's own
     * session and traffic rules ([BoundedHttp.sendInternal]), so nothing adds a session to it.
     */
    fun send(service: HttpService, request: ProbeRequest, internal: Boolean = false, maxBodyChars: Int = MAX_BODY_CHARS): ProbeResult? = try {
        val text = request.render()
        val burp = HttpRequest.httpRequest(service, BurpByteArray.byteArray(*text.toByteArray(RequestHygiene.wireCharset(text))))
        val response = (if (internal) BoundedHttp.sendInternal(api, burp) else BoundedHttp.send(api, burp))?.response()
        response?.let { ProbeResult.of(it.statusCode().toInt(), bodyText(it, maxBodyChars), it.headers().map { h -> h.name() to h.value() }) }
    } catch (_: Exception) {
        null
    }

    companion object {
        /** Response body kept per probe; what the engines compare needs no more. */
        const val MAX_BODY_CHARS = 2_000_000

        /** The body as text, cut at [maxChars] without first building the whole of a larger one. */
        fun bodyText(response: HttpResponse, maxChars: Int): String {
            val body = response.body()
            return if (body.length() > maxChars) body.subArray(0, maxChars).toString() else response.bodyToString()
        }
    }
}

/**
 * Reconnaissance/discovery — the capability gap that left the agent only able to
 * test endpoints it was explicitly handed. Provides JS endpoint harvesting,
 * wordlist content discovery (with soft-404 calibration), and hidden-parameter
 * mining. Active probes respect the operator scope policy.
 */
class ReconBridge(private val api: MontoyaApi) {

    /**
     * Optional settings of [paramMine].
     *
     * @param offset index of the first candidate to test, [limit] how many from there (null: all).
     * @param headers request headers sent with every probe; [cookies] are added to its Cookie header.
     * @param body request body the body / JSON candidates are added to.
     * @param cacheBuster add a query parameter with a new value to every request.
     * @param bucketSize candidates per request (null: the default of the location).
     */
    class ParamMineOptions(
        val offset: Int = 0,
        val limit: Int? = null,
        val headers: Map<String, String> = emptyMap(),
        val cookies: Map<String, String> = emptyMap(),
        val body: String? = null,
        val cacheBuster: Boolean = true,
        val bucketSize: Int? = null,
        val maxRequests: Int = DEFAULT_MAX_REQUESTS,
    )

    companion object {
        val MODES: List<String> = listOf("reflection", "diff", "both")
        const val DEFAULT_MAX_REQUESTS = 500
        const val MAX_PATHS = 2000
        const val MAX_HISTORY_ITEMS = 2000

        private const val MAX_ENDPOINTS = 2000
        private const val MAX_LISTED = 50

        /** Time the passive JS scan may take in total. */
        private const val JS_SCAN_BUDGET_MS = 30_000L

        /** Source maps fetched per call when fetching is asked for. */
        private const val MAX_MAP_FETCHES = 15

        /** End of a script that is read for its source-map comment when the script itself is cut short. */
        private const val TAIL_CHARS = 4096
    }

    private val scopeGate = ScopeGate(api)
    private val transport = ProbeTransport(api)

    private fun error(message: String): JsonObject = buildJsonObject { put("error", message) }

    // --- JS endpoints -----------------------------------------------------------------------

    private class MapNote(val url: String, val script: String?, val source: String, val parsed: SourceMaps.Parsed?, val status: Int? = null)

    /**
     * Harvest endpoint paths/URLs from JavaScript responses already in proxy history, and from
     * the source maps those scripts point to: maps found in history are read, the others are
     * listed, or fetched when [fetchSourceMaps] is set (in scope only).
     */
    fun jsEndpoints(maxItems: Int, hostFilter: String?, fetchSourceMaps: Boolean = false): JsonObject {
        return try {
            if (hostFilter != null) {
                SafeRegex.validate(hostFilter, ignoreCase = true)?.let { return error("Invalid host_filter regex: $it") }
            }
            var items = api.proxy().history().toList()
            if (hostFilter != null) {
                items = items.filter {
                    val h = try { it.finalRequest().httpService().host() } catch (_: Exception) { "" }
                    SafeRegex.containsMatchIn(hostFilter, h, ignoreCase = true)
                }
            }
            items = items.takeLast(maxItems.coerceIn(1, MAX_HISTORY_ITEMS))

            val deadline = System.nanoTime() + JS_SCAN_BUDGET_MS * 1_000_000
            val endpoints = linkedSetOf<String>()
            val maps = LinkedHashMap<String, MapNote>()
            val referenced = LinkedHashMap<String, String>()
            var scanned = 0
            var incomplete = 0
            var binary = 0
            var outOfTime = false

            for (item in items) {
                val leftMs = (deadline - System.nanoTime()) / 1_000_000
                if (leftMs <= 0) {
                    outOfTime = true
                    break
                }
                val url = try { item.finalRequest().url() } catch (_: Exception) { continue }
                val response = try { if (item.hasResponse()) item.originalResponse() else null } catch (_: Exception) { null } ?: continue
                try {
                    if (SourceMaps.isMapUrl(url)) {
                        if (response.body().length() > SourceMaps.MAX_MAP_CHARS) continue
                        val parsed = SourceMaps.parse(response.bodyToString(), min(leftMs, SourceMaps.DEFAULT_BUDGET_MS)) ?: continue
                        endpoints.addAll(parsed.endpoints)
                        maps[url] = MapNote(url, null, "history", parsed)
                        continue
                    }
                    val path = url.substringBefore('?').substringBefore('#')
                    val contentType = response.headerValue("Content-Type").orEmpty()
                    val isScript = path.endsWith(".js", true) || path.endsWith(".mjs", true) || path.endsWith(".cjs", true) ||
                        contentType.contains("javascript", true) || contentType.contains("ecmascript", true)
                    if (!isScript) continue

                    val length = response.body().length()
                    val body = ProbeTransport.bodyText(response, JsEndpoints.MAX_SCAN_CHARS)
                    if (BodyText.isProbablyBinary(body)) {
                        binary++
                        continue
                    }
                    scanned++
                    val scan = JsEndpoints.scan(body, min(leftMs, JsEndpoints.DEFAULT_BUDGET_MS))
                    endpoints.addAll(scan.endpoints)
                    if (!scan.complete || length > JsEndpoints.MAX_SCAN_CHARS) incomplete++

                    // The map is named in a header or in a comment on the script's last line.
                    val tail = if (length > JsEndpoints.MAX_SCAN_CHARS) response.body().subArray(length - TAIL_CHARS, length).toString() else body
                    val reference = SourceMaps.headerReference(mapOf(
                        "sourcemap" to response.headerValue("SourceMap").orEmpty(),
                        "x-sourcemap" to response.headerValue("X-SourceMap").orEmpty(),
                    ).filterValues { it.isNotEmpty() }) ?: SourceMaps.reference(tail) ?: continue
                    val inline = SourceMaps.inline(reference)
                    if (inline != null) {
                        val parsed = SourceMaps.parse(inline, min(leftMs, SourceMaps.DEFAULT_BUDGET_MS)) ?: continue
                        endpoints.addAll(parsed.endpoints)
                        maps["inline:$url"] = MapNote("(inline)", url, "inline", parsed)
                    } else {
                        SourceMaps.resolve(url, reference)?.let { referenced.putIfAbsent(it, url) }
                    }
                } catch (_: Exception) {
                    // One unreadable history item does not end the scan.
                }
            }

            var skippedOutOfScope = 0
            var fetched = 0
            var scopeWarning: String? = null
            for ((mapUrl, script) in referenced) {
                if (mapUrl in maps) continue
                if (!fetchSourceMaps || fetched >= MAX_MAP_FETCHES) {
                    maps[mapUrl] = MapNote(mapUrl, script, "referenced", null)
                    continue
                }
                val check = scopeGate.check(mapUrl)
                if (check.deny != null) {
                    skippedOutOfScope++
                    maps[mapUrl] = MapNote(mapUrl, script, "referenced", null)
                    continue
                }
                check.warning?.let { scopeWarning = it }
                fetched++
                val result = try {
                    val seed = transport.seed(mapUrl)
                    transport.send(seed.service, seed.request, maxBodyChars = SourceMaps.MAX_MAP_CHARS)
                } catch (_: Exception) {
                    null
                }
                val parsed = result?.takeIf { it.status == 200 }?.let { SourceMaps.parse(it.body) }
                parsed?.let { endpoints.addAll(it.endpoints) }
                maps[mapUrl] = MapNote(mapUrl, script, "fetched", parsed, result?.status ?: 0)
            }

            buildJsonObject {
                put("js_responses_scanned", scanned)
                put("endpoint_count", endpoints.size)
                put("endpoints", buildJsonArray { endpoints.take(MAX_ENDPOINTS).forEach { add(it) } })
                put("source_map_count", maps.size)
                put("source_maps", buildJsonArray {
                    maps.values.forEach { note ->
                        add(buildJsonObject {
                            put("url", note.url)
                            note.script?.let { put("script", it) }
                            put("source", note.source)
                            note.status?.let { put("status", it) }
                            note.parsed?.let { parsed ->
                                put("sources_count", parsed.sources.size)
                                put("sources_with_content", parsed.sourcesWithContent)
                                put("endpoints_found", parsed.endpoints.size)
                                put("sources", buildJsonArray { parsed.sources.take(MAX_LISTED).forEach { add(it) } })
                                if (!parsed.complete) put("incomplete", true)
                            }
                        })
                    }
                })
                scopeWarning?.let { put("scope_warning", it) }
                if (skippedOutOfScope > 0) put("source_maps_out_of_scope", skippedOutOfScope)
                if (incomplete > 0) put("scripts_partly_scanned", incomplete)
                if (binary > 0) put("binary_skipped", binary)
                if (outOfTime) put("stopped", "time_budget")
                if (maps.values.any { it.source == "referenced" } && !fetchSourceMaps) {
                    put("note", "Source maps marked 'referenced' are named by a script but are not in proxy history; set fetch_source_maps=true to request them.")
                }
            }
        } catch (e: Exception) {
            error("JS endpoint scan failed: ${e.message}")
        }
    }

    // --- content discovery ------------------------------------------------------------------

    /**
     * Requests [paths] under [baseUrl] and reports the ones the target treats differently from
     * paths that do not exist (see [ContentDiscovery]).
     */
    fun contentDiscovery(baseUrl: String, paths: List<String>): JsonObject {
        return try {
            val base = baseUrl.trimEnd('/')
            val baseCheck = scopeGate.check("$base/")
            baseCheck.deny?.let { return it }
            val seed = transport.seed("$base/")
            val prefix = seed.request.path.trimEnd('/')

            // Per-path scope check: Burp scope can exclude specific paths under an in-scope host.
            val considered = paths.take(MAX_PATHS).map { if (it.startsWith("/")) it else "/$it" }
            val allowed = considered.indices.filter { scopeGate.deny(base + considered[it]) == null }
            val engine = ContentDiscovery({ path ->
                if (scopeGate.deny(base + path) != null) null else transport.send(seed.service, seed.request.copy(target = prefix + path))
            })
            val outcome = engine.run(allowed.map { considered[it] })
            outcome.error?.let { return error(it) }

            buildJsonObject {
                put("base_url", base)
                baseCheck.warning?.let { put("scope_warning", it) }
                put("calibration", buildJsonObject {
                    put("status", outcome.calibration.firstOrNull()?.status ?: 0)
                    put("length", outcome.calibration.firstOrNull()?.length ?: 0)
                    put("wildcard", outcome.wildcard)
                    put("samples", buildJsonArray {
                        outcome.calibration.forEach { sample ->
                            add(buildJsonObject {
                                put("path", sample.path)
                                put("status", sample.status)
                                put("length", sample.length)
                            })
                        }
                    })
                })
                put("tested", outcome.tested)
                put("requests_sent", outcome.requests)
                if (allowed.size < considered.size) put("skipped_out_of_scope", considered.size - allowed.size)
                if (paths.size > considered.size) put("paths_over_limit", paths.size - considered.size)
                put("found_count", outcome.found.size)
                put("found", buildJsonArray {
                    outcome.found.forEach { hit ->
                        add(buildJsonObject {
                            put("path", paths[allowed[hit.index]])
                            put("url", base + hit.path)
                            put("status", hit.status)
                            put("length", hit.length)
                            hit.location?.let { put("redirect", it) }
                        })
                    }
                })
                outcome.stopped?.let { reason ->
                    put("stopped", reason)
                    if (outcome.tested < allowed.size) {
                        put("stopped_at", allowed[outcome.tested])
                        put("remaining", considered.size - allowed[outcome.tested])
                    }
                    put("stopped_note", when (reason) {
                        ContentDiscovery.STOP_RATE_LIMITED ->
                            "The target kept answering 429 after waiting and slowing down. Continue later from paths[stopped_at]."
                        ContentDiscovery.STOP_BLOCKED ->
                            "The target (or a WAF in front of it) began refusing every request, so later answers would say nothing about the paths. Continue later from paths[stopped_at]."
                        else -> "The target stopped answering."
                    })
                }
                if (outcome.blocked.isNotEmpty() || outcome.blockedBy != null) {
                    put("waf_blocked", buildJsonObject {
                        put("by", outcome.blockedBy)
                        put("count", outcome.blocked.size)
                        put("paths", buildJsonArray { outcome.blocked.take(MAX_LISTED).forEach { add(it) } })
                    })
                }
                if (outcome.catchAllDirectories.isNotEmpty()) {
                    put("catch_all_directories", buildJsonArray { outcome.catchAllDirectories.forEach { add(it) } })
                    put("dropped_as_catch_all", outcome.droppedAsCatchAll)
                }
                if (outcome.unanswered > 0) put("no_response", outcome.unanswered)
                if (outcome.throttled > 0) put("rate_limited_responses", outcome.throttled)
            }
        } catch (e: Exception) {
            error("Content discovery failed: ${e.message}")
        }
    }

    // --- parameter mining -------------------------------------------------------------------

    /**
     * Probe [candidates] (or a bundled dictionary, when null) for hidden parameters on [url].
     *
     * [mode] `"reflection"` (default) reports only candidates whose value is echoed back —
     * blind to params that change server behavior without reflecting it. `"diff"` instead
     * reports candidates that change the response (status, body, or one of
     * [io.bitbytelab.raijin.core.BehavioralDiff.SIGNAL_HEADERS]) compared with repeated baselines,
     * catching params that affect control flow (auth, caching, feature flags) without
     * reflecting. `"both"` runs both checks and reports each separately.
     *
     * [injectIn] selects where the candidate name is placed: `"query"` (default), `"body"`
     * (form-encoded), `"json_body"` (top-level key in a JSON object body), `"cookie"`, or `"header"`.
     * Candidates go out many per request and a bucket is searched only when its response stands
     * out ([ParamMiner]).
     */
    fun paramMine(
        url: String,
        candidates: List<String>?,
        mode: String = "reflection",
        injectIn: String = "query",
        method: String? = null,
        wordlist: String? = null,
        options: ParamMineOptions = ParamMineOptions(),
    ): JsonObject {
        return try {
            EnumValidation.error(mode, MODES.toSet(), "mode", required = true)?.let { return it }
            val modeId = mode.trim().lowercase()
            val location = ParamLocation.of(injectIn)
                ?: return EnumValidation.error(injectIn, ParamLocation.IDS.toSet(), "inject_in", required = true)
                    ?: error("Parameter 'inject_in' has an invalid value")

            val check = scopeGate.check(url)
            check.deny?.let { return it }

            val wordlistName = wordlist
                ?: if (location == ParamLocation.HEADER) ParamMinerWordlists.HEADERS else ParamMinerWordlists.DEFAULT
            val all = when (val resolved = ParamMinerWordlists.resolve(candidates, wordlistName)) {
                is ParamMinerWordlists.Resolved.Error -> return error(resolved.message)
                is ParamMinerWordlists.Resolved.Ok -> resolved.entries
            }
            if (all.isEmpty()) return error("No candidates to test")
            if (options.offset < 0 || options.offset >= all.size) {
                return error("offset ${options.offset} is outside the candidate list (${all.size} candidates)")
            }
            val end = if (options.limit == null) all.size else min(all.size.toLong(), options.offset.toLong() + options.limit).toInt()
            val slice = all.subList(options.offset, end.coerceAtLeast(options.offset))

            val seed = transport.seed(url, method?.trim()?.ifEmpty { null } ?: location.method)
            var base = seed.request.withHeaders(options.headers.toList())
            if (options.cookies.isNotEmpty()) {
                // As given: a session value is not ours to re-encode.
                base = base.withCookies(options.cookies.entries.joinToString("; ") { "${it.key}=${it.value}" })
            }
            if (options.body != null) base = base.withBody(options.body)

            // What is left to mine: not the names the request already carries, and from a bundled
            // header list not the headers that frame the message.
            val existing = ParamInjection.existingNames(base, location)
            val skippedExisting = ArrayList<String>()
            val skippedFraming = ArrayList<String>()
            val mined = ArrayList<ParamMinerWordlists.Entry>()
            val positions = ArrayList<Int>()
            slice.forEachIndexed { position, entry ->
                when {
                    entry.name in existing -> skippedExisting.add(entry.name)
                    candidates == null && location == ParamLocation.HEADER && entry.name.lowercase() in ParamInjection.FRAMING_HEADERS ->
                        skippedFraming.add(entry.name)
                    else -> {
                        mined.add(entry)
                        positions.add(position)
                    }
                }
            }

            val busterName = "zqcb" + ProbeText.token(Random.Default, 4)
            val config = ParamMiner.Config(
                host = seed.service.host(),
                reflection = modeId != "diff",
                diff = modeId != "reflection",
                bucketSize = options.bucketSize ?: location.bucketSize,
                maxRequests = options.maxRequests,
                ignoreNameCase = location.ignoresNameCase,
            )
            val outcome = ParamMiner(mined, config) { params ->
                // A new value per request: no response comes from a cache, and nothing a probe
                // makes the target store is served to anyone else.
                val buster = if (options.cacheBuster) ProbeText.token(Random.Default, 12) else null
                val request = ParamInjection.inject(if (buster == null) base else base.withQuery("$busterName=$buster"), location, params)
                val result = transport.send(seed.service, request)
                if (result == null || buster == null) result
                else result.copy(body = result.body.replace(buster, ""), headers = result.headers.mapValues { it.value.replace(buster, "") })
            }.run()
            outcome.error?.let { message ->
                return buildJsonObject {
                    put("error", message)
                    put("requests_sent", outcome.requests)
                }
            }

            val nextOffset = options.offset + (if (outcome.tested >= mined.size) slice.size else positions[outcome.tested])
            buildJsonObject {
                put("url", url)
                check.warning?.let { put("scope_warning", it) }
                put("mode", modeId)
                put("inject_in", location.id)
                put("method", base.method)
                put("marker", outcome.canaryPrefix)
                put("wordlist_used", if (candidates == null) wordlistName else null)
                put("total_candidates", all.size)
                put("offset", options.offset)
                put("tested", outcome.tested)
                if (nextOffset < all.size) put("next_offset", nextOffset)
                put("bucket_size", outcome.bucketSize)
                put("requests_sent", outcome.requests)
                outcome.baseline?.let { baseline ->
                    put("baseline", buildJsonObject {
                        put("status", baseline.status)
                        put("samples", baseline.sampleCount)
                        put("similarity_floor", baseline.similarityFloor)
                        put("compared_headers", buildJsonArray { baseline.comparedHeaders.forEach { add(it) } })
                        if (outcome.echoesValues) put("echoes_unknown_values", true)
                        if (outcome.echoesPairs) put("echoes_name_value_pairs", true)
                        if (outcome.rejectsUnknownNames) put("rejects_unknown_names", true)
                    })
                }
                put("interesting_count", outcome.hits.size)
                put("interesting_params", buildJsonArray {
                    outcome.hits.forEach { hit ->
                        add(buildJsonObject {
                            put("param", hit.candidate.name)
                            hit.candidate.valueTemplate?.let { put("value_template", it) }
                            put("inject_in", location.id)
                            if (config.reflection) {
                                put("reflected", hit.reflectedIn.isNotEmpty())
                                if (hit.reflectedIn.isNotEmpty()) put("reflected_in", buildJsonArray { hit.reflectedIn.forEach { add(it) } })
                            }
                            if (config.diff) {
                                put("behavior_diff", hit.diff.isNotEmpty())
                                if (hit.diff.isNotEmpty()) put("changes", buildJsonArray { hit.diff.forEach { add(it) } })
                            }
                        })
                    }
                })
                if (outcome.responseChanging.isNotEmpty()) {
                    put("response_changing_params", buildJsonArray { outcome.responseChanging.forEach { add(it.name) } })
                }
                if (skippedExisting.isNotEmpty()) put("skipped_already_present", buildJsonArray { skippedExisting.take(MAX_LISTED).forEach { add(it) } })
                if (skippedFraming.isNotEmpty()) put("skipped_framing_headers", buildJsonArray { skippedFraming.forEach { add(it) } })
                if (outcome.unanswered.isNotEmpty()) {
                    // Their request got no response, so they say nothing either way: worth another run with a smaller bucket_size.
                    put("no_response_candidates", outcome.unanswered.size)
                    put("no_response_names", buildJsonArray { outcome.unanswered.take(MAX_LISTED).forEach { add(it.name) } })
                }
                outcome.stopped?.let { reason ->
                    put("stopped", reason)
                    put("stopped_note", when (reason) {
                        ParamMiner.STOP_BUDGET -> "max_requests reached. Continue with offset=next_offset."
                        ParamMiner.STOP_RATE_LIMITED -> "The target began answering 429/503 to every request. Continue later with offset=next_offset."
                        ParamMiner.STOP_BASELINE_CHANGED ->
                            "The target began answering identical requests with another status (session expired? blocked?). Fix that, then continue with offset=next_offset."
                        ParamMiner.STOP_UNSTABLE -> "The target's answers to identical requests keep changing, so differences cannot be told from noise."
                        else -> "The target stopped answering."
                    })
                }
                put(
                    "note",
                    "Reflected params are candidate injection points (XSS/SSRF/IDOR). behavior_diff params changed the response " +
                        "(see changes) without relying on reflection — worth manual follow-up." +
                        (if (outcome.rejectsUnknownNames) " The target answers any unknown name differently, so candidates were sent one per request." else "") +
                        (if (outcome.responseChanging.isNotEmpty()) " response_changing_params changed the response while echoes were being read; run mode=diff or both to confirm them." else "")
                )
            }
        } catch (e: Exception) {
            error("Param mining failed: ${e.message}")
        }
    }
}
