package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.RedirectionMode
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.safety.RequestHygiene
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.safety.ScopeGate
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.state.TrafficRule
import io.bitbytelab.raijin.transport.ToolCallTracker
import kotlinx.serialization.json.*
import java.time.ZonedDateTime
import burp.api.montoya.core.ByteArray as BurpByteArray

/**
 * Bridge wrapping the Montoya HTTP API for the `http_*` tools: sending requests (one, in parallel,
 * chained, raw bytes, native HTTP/2), the cookie jar, response analysis, fuzzing and race testing,
 * plus the global [HttpHandler] registered during extension initialization. The work itself lives
 * in focused helpers: [HttpRequestBuilder], [HttpRequestChain], [HttpExchangeJson],
 * [HttpGlobalHandler], [HttpFuzzRunner], [HttpRace], [HttpPipelineBridge].
 */
class HttpBridge(
    private val api: MontoyaApi,
    private val eventBus: EventBus,
    private val stateManager: StateManager
) {

    /** Shared, centralized scope gate used by EVERY outbound path in this bridge. */
    private val scopeGate = ScopeGate(api)

    private val timeouts = HttpTimeouts()

    internal val chain = HttpRequestChain(api, scopeGate, timeouts)

    /** Session login macros (`session_macro_*` tools), run by the global handler when a session expires. */
    internal val sessionMacros = SessionMacroEngine(api, eventBus, stateManager, chain)

    private val race = HttpRace(api, scopeGate, timeouts)

    // ---------------------------------------------------------------
    // Send request
    // ---------------------------------------------------------------

    /**
     * Sends a single HTTP request and returns the serialized exchange.
     *
     * The request is built from raw text, from a URL with structured headers and body
     * ([HttpRequestBuilder.build]), or, when [http2Fields] is given, as a native HTTP/2 request whose
     * header list (pseudo-headers included) is sent as given ([HttpRequestBuilder.http2]).
     *
     * @param httpMode "AUTO", "HTTP_1", "HTTP_2" or "HTTP_2_IGNORE_ALPN"; a native HTTP/2 request
     *   is sent with HTTP_2 unless HTTP_2_IGNORE_ALPN is asked for.
     * @param connectionId pins/reuses one Montoya connection.
     * @param timeoutMs hard timeout; null or 0 waits for Burp.
     * @param options Burp request options (redirects, SNI, response timeout, TLS verification).
     */
    fun sendRequest(
        url: String?,
        method: String?,
        headers: Map<String, String>?,
        body: String?,
        rawRequest: String?,
        host: String?,
        port: Int?,
        useTls: Boolean?,
        httpMode: String?,
        connectionId: String?,
        maxBodyLength: Int? = null,
        timeoutMs: Long? = null,
        preserveHeaders: Boolean = true,
        autoFixContentLength: Boolean = true,
        http2Fields: List<Pair<String, String>>? = null,
        options: HttpSendOptions = HttpSendOptions(),
    ): JsonObject {
        var scope: ScopeGate.Check? = null
        return try {
            val fixReport = mutableMapOf<String, JsonElement>()
            var mode = HttpModes.resolve(httpMode)
            val httpRequest = if (http2Fields != null) {
                require(rawRequest == null && headers.isNullOrEmpty()) {
                    "http2_headers is the whole HTTP/2 header list: send it without raw_request or headers"
                }
                require(mode != HttpMode.HTTP_1) { "http2_headers builds an HTTP/2 request: http_mode HTTP_1 cannot send it" }
                if (mode == HttpMode.AUTO) mode = HttpMode.HTTP_2
                HttpRequestBuilder.http2(url, method, http2Fields, body, host, port, useTls)
            } else {
                HttpRequestBuilder.build(
                    url, method, headers, body, rawRequest, host, port, useTls,
                    preserveHeaders = preserveHeaders,
                    autoFixContentLength = autoFixContentLength,
                    fixReport = fixReport
                )
            }

            val targetUrl = try { httpRequest.url() } catch (_: Exception) { url ?: "" }
            // Where the bytes go (service + path), not what url() reads off the Host header.
            val check = scopeGate.checkHttpRequest(httpRequest, url)
            if (check.blocked) return check.denyJson()
            scope = check

            val startTime = System.nanoTime()
            val result: HttpRequestResponse = timeouts.run(timeoutMs) {
                when {
                    !options.isDefault -> sendWithOptions(httpRequest, options, mode, connectionId)
                    connectionId != null -> api.http().sendRequest(httpRequest, mode, connectionId)
                    else -> api.http().sendRequest(httpRequest, mode)
                }
            }
            val elapsedMs = (System.nanoTime() - startTime) / 1_000_000

            api.recordToolExchange(result, "[MCP] http_send_request via Raijin", "http_send_request")
            ToolCallTracker.recordSentResult(result)

            val hygiene = if (http2Fields != null) emptyList() else RequestHygiene.scan(method, url, headers)
            var json = check.annotate(withFixReport(withRequestWarnings(HttpExchangeJson.serialize(result, elapsedMs, maxBodyLength), hygiene), fixReport))
            // A followed redirect may land outside scope: flagged, never blocked (advisory).
            if (options.redirects != null && options.redirects != RedirectionMode.NEVER) {
                val finalUrl = runCatching { result.request().url() }.getOrNull()
                if (finalUrl != null && finalUrl != targetUrl) json = scopeGate.advise(finalUrl, "redirect").annotate(json)
            }
            json
        } catch (e: Exception) {
            val error = buildJsonObject {
                put("error", "Failed to send request: ${e.message}")
                put("is_timeout", e is HttpRequestTimeoutException)
                put("close_reason", if (e is HttpRequestTimeoutException) "timeout" else "error")
            }
            scope?.annotate(error) ?: error
        }
    }

    /** Sends through Montoya's `RequestOptions`, which an older Burp does not have. */
    private fun sendWithOptions(request: HttpRequest, options: HttpSendOptions, mode: HttpMode, connectionId: String?): HttpRequestResponse =
        try {
            api.http().sendRequest(request, options.toRequestOptions(mode, connectionId))
        } catch (e: LinkageError) {
            throw IllegalStateException(
                "This Burp does not support request options (follow_redirects, sni, response_timeout_ms, verify_tls): ${e.message}"
            )
        }

    /**
     * Sends multiple HTTP requests in parallel.
     *
     * @param requests Request objects (url/method/headers/body/raw_request/host/port/use_tls).
     * @param httpMode HTTP mode for all requests.
     * @return JSON object with results array.
     */
    fun sendRequestsParallel(
        requests: List<JsonObject>,
        httpMode: String?,
        maxBodyLength: Int? = null,
        timeoutMs: Long? = null
    ): JsonObject {
        return try {
            val mode = HttpModes.resolve(httpMode)

            // Build all requests, recording original index, per-item fix reports and build errors.
            class Built(
                val originalIndex: Int,
                val request: HttpRequest?,
                val error: String?,
                val fixReport: Map<String, JsonElement>,
                var scope: ScopeGate.Check? = null,
            )
            val built = requests.mapIndexed { idx, reqObj ->
                val fixReport = LinkedHashMap<String, JsonElement>()
                try {
                    val request = HttpRequestBuilder.fromObject(reqObj, fixReport)
                    val service = runCatching { request.httpService() }.getOrNull()
                    if (service == null) {
                        Built(idx, null, "no target: raw_request has no Host header and no host argument", fixReport)
                    } else {
                        Built(idx, request, null, fixReport)
                    }
                } catch (e: Exception) {
                    Built(idx, null, e.message ?: "Failed to build request", fixReport)
                }
            }

            // Scope per item: a blocked item is not sent, the rest go out (warned ones flagged).
            for (b in built) {
                val request = b.request ?: continue
                b.scope = scopeGate.checkHttpRequest(request)
            }
            val blocked = built.filter { it.scope?.blocked == true }
            val sendable = built.filter { it.request != null && it.scope?.blocked != true }

            // Burp's sendRequests() rejects mixed services ("HTTP service on each request must be
            // the same"), so requests are grouped by service and each group dispatched separately.
            val grouped = sendable.groupBy { b ->
                val svc = b.request!!.httpService()
                Triple(svc.host(), svc.port(), svc.secure())
            }

            // Storage for results and per-slot failures in original-input order.
            val resultsArray = arrayOfNulls<HttpRequestResponse>(requests.size)
            val failures = arrayOfNulls<JsonObject>(requests.size)
            val perGroupTimings = mutableMapOf<String, Long>()

            val totalStart = System.nanoTime()
            // One deadline for the batch: each group gets what is left, so one slow host never
            // discards the responses other groups already have.
            val deadline = timeoutMs?.takeIf { it > 0 }?.let { totalStart + it * 1_000_000 }
            grouped.forEach { (svc, group) ->
                val groupKey = "${svc.first}:${svc.second}:${if (svc.third) "tls" else "plain"}"
                val remainingMs = deadline?.let { (it - System.nanoTime()) / 1_000_000 }
                if (remainingMs != null && remainingMs <= 0) {
                    val notSent = buildJsonObject {
                        put("error", "not sent: batch deadline passed")
                        put("phase", "send")
                        put("not_sent", true)
                    }
                    group.forEach { failures[it.originalIndex] = notSent }
                    return@forEach
                }
                val groupStart = System.nanoTime()
                try {
                    val groupResults = timeouts.run(remainingMs) { api.http().sendRequests(group.map { it.request!! }, mode) }
                    group.forEachIndexed { gIdx, b ->
                        if (gIdx < groupResults.size) resultsArray[b.originalIndex] = groupResults[gIdx]
                    }
                } catch (e: Exception) {
                    val failure = buildJsonObject {
                        if (e is HttpRequestTimeoutException) {
                            put("error", "group send timed out: ${e.message}")
                            put("is_timeout", true)
                        } else {
                            put("error", "group send failed: ${e.message}")
                        }
                        put("phase", "send")
                    }
                    group.forEach { failures[it.originalIndex] = failure }
                }
                perGroupTimings[groupKey] = (System.nanoTime() - groupStart) / 1_000_000
            }
            val totalElapsedMs = (System.nanoTime() - totalStart) / 1_000_000

            resultsArray.filterNotNull().forEach { api.recordToolExchange(it, "[MCP] Parallel request via Raijin", "http_send_requests_parallel") }

            val sentOutOfScope = sendable.count { it.scope?.warning != null }
            buildJsonObject {
                if (blocked.isNotEmpty() && blocked.size == requests.size) {
                    put("error", "Not sent: all ${blocked.size} requests are outside Burp's target scope (mcp_scope_mode=enforce).")
                }
                put("total_requests", requests.size)
                put("total_responses", resultsArray.count { it != null })
                put("total_elapsed_ms", totalElapsedMs)
                put("groups_dispatched", grouped.size)
                if (blocked.isNotEmpty()) put(ScopeGate.SKIPPED, blocked.size)
                if (sentOutOfScope > 0) put(ScopeGate.SENT, sentOutOfScope)
                put("group_timings_ms", buildJsonObject {
                    perGroupTimings.forEach { (k, v) -> put(k, v) }
                })
                put("results", buildJsonArray {
                    built.forEach { b ->
                        val result = resultsArray[b.originalIndex]
                        val item = buildJsonObject {
                            put("index", b.originalIndex)
                            val scope = b.scope
                            when {
                                b.error != null -> {
                                    put("error", b.error)
                                    put("phase", "build")
                                }
                                scope != null && scope.blocked -> scope.denyJson().forEach { (k, v) -> put(k, v) }
                                result != null -> HttpExchangeJson.serialize(result, null, maxBodyLength).forEach { (k, v) -> put(k, v) }
                                failures[b.originalIndex] != null -> failures[b.originalIndex]!!.forEach { (k, v) -> put(k, v) }
                                else -> {
                                    put("error", "Send failed (no response)")
                                    put("phase", "send")
                                }
                            }
                            b.fixReport.forEach { (k, v) -> put(k, v) }
                        }
                        add(b.scope?.annotate(item) ?: item)
                    }
                })
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to send parallel requests: ${e.message}")
                put("is_timeout", e is HttpRequestTimeoutException)
                put("close_reason", if (e is HttpRequestTimeoutException) "timeout" else "error")
            }
        }
    }

    /**
     * Executes a chain of HTTP requests sequentially ([HttpRequestChain]), extracting values from
     * each response (regex, JSONPath or XPath) into `{{variable}}` placeholders of later steps.
     *
     * @param stopOnError Whether to stop the chain if a step fails.
     * @param timeoutMs hard timeout of each step; null or 0 waits for Burp.
     * @return JSON object with step results and extracted variables.
     */
    fun sendRequestChain(
        steps: List<JsonObject>,
        httpMode: String?,
        stopOnError: Boolean,
        connectionId: String? = null,
        timeoutMs: Long? = null
    ): JsonObject {
        val result = chain.run(steps, HttpModes.resolve(httpMode), stopOnError, connectionId, timeoutMs)
        val blocked = result.steps.count { it.outOfScope }
        val sentOutOfScope = result.steps.count { it.exchange != null && it.scope?.warning != null }
        return buildJsonObject {
            if (blocked > 0 && blocked == result.steps.size) {
                put("error", "Not sent: all $blocked requests are outside Burp's target scope (mcp_scope_mode=enforce).")
            }
            put("total_steps", steps.size)
            put("completed_steps", result.steps.count { it.exchange != null })
            if (blocked > 0) put(ScopeGate.SKIPPED, blocked)
            if (sentOutOfScope > 0) put(ScopeGate.SENT, sentOutOfScope)
            put("variables", buildJsonObject { result.variables.forEach { (k, v) -> put(k, v) } })
            put("steps", buildJsonArray {
                result.steps.forEach { step ->
                    val item = buildJsonObject {
                        put("step", step.index)
                        put("success", step.success)
                        val exchange = step.exchange
                        val scope = step.scope
                        if (exchange != null) {
                            HttpExchangeJson.serialize(exchange, step.elapsedMs).forEach { (k, v) -> put(k, v) }
                            if (connectionId != null) {
                                put("connection_id", connectionId)
                                put("connection_reused", step.index > 0)
                            }
                            if (step.extracted.isNotEmpty()) {
                                put("extracted", buildJsonObject { step.extracted.forEach { (k, v) -> put(k, v) } })
                            }
                            if (step.extractMissed.isNotEmpty()) {
                                put("extract_missed", buildJsonArray { step.extractMissed.forEach { add(it) } })
                            }
                        } else if (scope != null && scope.blocked) {
                            scope.denyJson().forEach { (k, v) -> put(k, v) }
                        } else {
                            put("error", step.error ?: "Unknown error")
                            if (step.timeout) put("is_timeout", true)
                        }
                        if (step.unresolvedPlaceholders.isNotEmpty()) {
                            put("unresolved_placeholders", buildJsonArray { step.unresolvedPlaceholders.forEach { add(it) } })
                        }
                        step.fixReport.forEach { (k, v) -> put(k, v) }
                    }
                    add(step.scope?.annotate(item) ?: item)
                }
            })
        }
    }

    // ---------------------------------------------------------------
    // Cookie jar
    // ---------------------------------------------------------------

    /**
     * Returns cookies from the Burp cookie jar, optionally filtered by domain.
     *
     * @param domain Optional domain filter (case-insensitive substring match).
     * @return JSON object with cookies array.
     */
    fun getCookieJar(domain: String?): JsonObject {
        return try {
            val allCookies = api.http().cookieJar().cookies()
            val filtered = if (domain != null) {
                allCookies.filter { it.domain().contains(domain, ignoreCase = true) }
            } else {
                allCookies
            }

            buildJsonObject {
                put("total", filtered.size)
                put("cookies", buildJsonArray {
                    filtered.forEach { cookie ->
                        add(buildJsonObject {
                            put("name", cookie.name())
                            put("value", cookie.value())
                            put("domain", cookie.domain())
                            put("path", cookie.path())
                            val exp = cookie.expiration()
                            if (exp.isPresent) {
                                put("expiration", exp.get().toString())
                            }
                        })
                    }
                })
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to get cookie jar: ${e.message}")
            }
        }
    }

    /**
     * Sets a cookie in the Burp cookie jar.
     *
     * @param name Cookie name.
     * @param value Cookie value.
     * @param domain Cookie domain.
     * @param path Cookie path.
     * @param expiration Optional expiration as ISO-8601 date-time string.
     * @return JSON object confirming the cookie was set.
     */
    fun setCookie(
        name: String,
        value: String,
        domain: String,
        path: String,
        expiration: String?
    ): JsonObject {
        return try {
            val expirationDate: ZonedDateTime? = if (expiration != null) {
                try {
                    ZonedDateTime.parse(expiration)
                } catch (_: Exception) {
                    return buildJsonObject {
                        put("error", "Invalid 'expiration' '$expiration': use an ISO-8601 date-time with offset, e.g. 2027-01-01T00:00:00Z")
                    }
                }
            } else {
                null
            }

            // Montoya's signature is setCookie(name, value, path, domain, expiration):
            // path comes BEFORE domain. Passing our (domain, path) in Montoya's (path, domain)
            // slots transposes them, so a cookie set for domain=example.com path=/app would
            // land as path=example.com domain=/app. Order the args to match Montoya exactly.
            api.http().cookieJar().setCookie(name, value, path, domain, expirationDate)

            buildJsonObject {
                put("cookie_set", true)
                put("name", name)
                put("domain", domain)
                put("path", path)
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to set cookie: ${e.message}")
            }
        }
    }

    /**
     * Deletes a cookie from Burp's cookie jar. Montoya's `CookieJar` has no delete method —
     * only `setCookie(name, value, path, domain, expiration)` — so this sets an empty value
     * with an expiration a year in the past, the standard cookie-expiry idiom. Whether Burp's
     * jar actually drops the entry (vs. retaining an expired record) is not documented; this
     * re-reads the jar afterward and reports `deleted` from what it actually finds rather than
     * assuming the idiom worked.
     */
    fun deleteCookie(name: String, domain: String, path: String): JsonObject {
        return try {
            val past = ZonedDateTime.now().minusYears(1)
            // Same (path, domain) argument order as setCookie above — see its comment.
            api.http().cookieJar().setCookie(name, "", path, domain, past)

            val stillPresent = try {
                api.http().cookieJar().cookies().any {
                    it.name() == name && it.domain().equals(domain, ignoreCase = true) && it.path() == path
                }
            } catch (_: Exception) { null }

            buildJsonObject {
                put("name", name)
                put("domain", domain)
                put("path", path)
                when (stillPresent) {
                    false -> put("deleted", true)
                    true -> {
                        put("deleted", false)
                        put("note", "The cookie still appears in the jar after setting an expired value — Burp may retain an expired record rather than dropping it. Try an empty 'value' lookup, or clear it manually in the Proxy > HTTP history > Cookie jar UI.")
                    }
                    null -> {
                        put("deleted", "unknown")
                        put("note", "Could not confirm removal by re-reading the cookie jar.")
                    }
                }
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to delete cookie: ${e.message}")
            }
        }
    }

    // ---------------------------------------------------------------
    // Response analysis
    // ---------------------------------------------------------------

    /**
     * Analyzes a response for keyword occurrences using Burp's
     * [ResponseKeywordsAnalyzer].
     *
     * @param response Raw HTTP response string.
     * @param keywords List of keywords to search for.
     * @param caseSensitive Whether keyword matching is case-sensitive.
     * @return JSON object with keyword counts.
     */
    fun analyzeKeywords(
        response: String,
        keywords: List<String>,
        caseSensitive: Boolean
    ): JsonObject {
        return try {
            val normalizedResponse = RequestHygiene.normalizeCrlf(response)
            if (caseSensitive) {
                // Montoya's analyzer is case-INSENSITIVE only. Honour case_sensitive=true by
                // counting exact substring occurrences ourselves over the normalized response,
                // then deriving present (variant) vs absent (invariant) from those manual counts.
                // A single response has no cross-response variation baseline, so "present" == count>0.
                val counts = HttpKeywordCount.countCaseSensitive(normalizedResponse, keywords)
                buildJsonObject {
                    put("case_sensitive", true)
                    put("variant_keywords", buildJsonArray {
                        counts.filterValues { it > 0 }.keys.forEach { add(it) }
                    })
                    put("invariant_keywords", buildJsonArray {
                        counts.filterValues { it == 0 }.keys.forEach { add(it) }
                    })
                    put("keyword_counts", buildJsonArray {
                        counts.forEach { (kw, c) ->
                            add(buildJsonObject {
                                put("keyword", kw)
                                put("count", c)
                            })
                        }
                    })
                }
            } else {
                val httpResponse = HttpResponse.httpResponse(normalizedResponse)
                val analyzer = api.http().createResponseKeywordsAnalyzer(keywords)
                analyzer.updateWith(httpResponse)

                buildJsonObject {
                    put("case_sensitive", false)
                    put("variant_keywords", buildJsonArray {
                        analyzer.variantKeywords().forEach { add(it) }
                    })
                    put("invariant_keywords", buildJsonArray {
                        analyzer.invariantKeywords().forEach { add(it) }
                    })
                    put("keyword_counts", buildJsonArray {
                        httpResponse.keywordCounts(*keywords.toTypedArray()).forEach { kc ->
                            add(buildJsonObject {
                                put("keyword", kc.keyword())
                                put("count", kc.count())
                            })
                        }
                    })
                }
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to analyze keywords: ${e.message}")
            }
        }
    }

    /**
     * Analyzes variations across multiple responses using Burp's
     * [ResponseVariationsAnalyzer].
     *
     * @param responses List of raw HTTP response strings.
     * @return JSON object with variant and invariant attributes.
     */
    fun analyzeVariations(responses: List<String>): JsonObject {
        return try {
            val analyzer: ResponseVariationsAnalyzer = api.http().createResponseVariationsAnalyzer()

            responses.forEach { rawResp ->
                val normalizedResp = RequestHygiene.normalizeCrlf(rawResp)
                val httpResponse = HttpResponse.httpResponse(normalizedResp)
                analyzer.updateWith(httpResponse)
            }

            buildJsonObject {
                put("responses_analyzed", responses.size)
                put("variant_attributes", buildJsonArray {
                    analyzer.variantAttributes().forEach { attr ->
                        add(attr.name)
                    }
                })
                put("invariant_attributes", buildJsonArray {
                    analyzer.invariantAttributes().forEach { attr ->
                        add(attr.name)
                    }
                })
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to analyze variations: ${e.message}")
            }
        }
    }

    // ---------------------------------------------------------------
    // Global HTTP handler (registered during extension init)
    // ---------------------------------------------------------------

    /**
     * The [HttpHandler] applying traffic rules, session rules and session login macros to all HTTP
     * traffic ([HttpGlobalHandler]). Registered once in [io.bitbytelab.raijin.core.RaijinExtension].
     */
    fun createGlobalHttpHandler(): HttpHandler = HttpGlobalHandler(api, eventBus, stateManager, sessionMacros)

    /** Shuts down the timeout pool on extension unload. */
    fun shutdown() {
        timeouts.shutdown()
    }

    // ---------------------------------------------------------------
    // Raw bytes request (byte-level control for smuggling)
    // ---------------------------------------------------------------

    /**
     * Raijin's own raw-socket HTTP/1.1 pipelining (`http_send_pipeline`): several requests over one
     * socket, several responses read back — see [HttpPipelineBridge] for why Montoya's `api.http()`
     * cannot do this.
     */
    val pipeline = HttpPipelineBridge(api)

    /**
     * Sends a raw byte-level HTTP request for HTTP request smuggling testing.
     * Preserves exact byte sequences including CRLF injection characters.
     *
     * @param rawHex Hex-encoded raw bytes (e.g. "474554202f...").
     * @param rawString Request text; literal \r\n / \n escapes become real line breaks only when it
     *   has no real ones ([RequestHygiene.unescapeLineEndings]), sent in [RequestHygiene.wireCharset].
     * @param timeoutMs hard timeout; null or 0 waits for Burp.
     */
    fun sendRawBytes(
        rawHex: String?,
        rawString: String?,
        host: String,
        port: Int,
        useTls: Boolean,
        httpMode: String?,
        maxBodyLength: Int? = null,
        timeoutMs: Long? = null
    ): JsonObject {
        var scope: ScopeGate.Check? = null
        return try {
            val bytes = if (rawHex != null) {
                RequestHygiene.decodeHex(rawHex)
            } else if (rawString != null) {
                RequestHygiene.unescapeLineEndings(rawString).let { it.toByteArray(RequestHygiene.wireCharset(it)) }
            } else {
                throw IllegalArgumentException("Either raw_request_hex or raw_request must be provided")
            }

            val service = HttpService.httpService(host, port, useTls)
            val httpRequest = HttpRequest.httpRequest(service, BurpByteArray.byteArray(*bytes))
            // Byte-level smuggling tests need HTTP/1 framing: AUTO would negotiate h2 and re-frame the bytes.
            val mode = if (httpMode.isNullOrBlank()) HttpMode.HTTP_1 else HttpModes.resolve(httpMode)

            val check = scopeGate.checkRequest(host, port, useTls, String(bytes, Charsets.ISO_8859_1))
            if (check.blocked) return check.denyJson()
            scope = check

            val startTime = System.nanoTime()
            val result = timeouts.run(timeoutMs) { api.http().sendRequest(httpRequest, mode) }
            val elapsedMs = (System.nanoTime() - startTime) / 1_000_000

            api.recordToolExchange(result, "[MCP] Raw bytes request via Raijin", "http_send_raw_bytes")
            ToolCallTracker.recordSentResult(result)

            var json = HttpExchangeJson.serialize(result, elapsedMs, maxBodyLength)
            if (runCatching { result.response()?.httpVersion() }.getOrNull()?.startsWith("HTTP/2") == true) {
                json = JsonObject(json + ("notes" to buildJsonArray { add("response came back over HTTP/2") }))
            }
            check.annotate(json)
        } catch (e: Exception) {
            val error = buildJsonObject {
                put("error", "Failed to send raw bytes: ${e.message}")
                put("is_timeout", e is HttpRequestTimeoutException)
                put("close_reason", if (e is HttpRequestTimeoutException) "timeout" else "error")
            }
            scope?.annotate(error) ?: error
        }
    }

    /** Merges in any out-of-band fields [HttpRequestBuilder.build] recorded via its `fixReport` parameter
     * (currently just `content_length_rewritten`), so a silent Content-Length rewrite is visible
     * to the caller instead of only being observable by diffing bytes on the wire. */
    private fun withFixReport(base: JsonObject, fixReport: Map<String, JsonElement>): JsonObject =
        if (fixReport.isEmpty()) base else JsonObject(base + fixReport)

    /**
     * Attaches advisory request-hygiene warnings (raw CR/LF in method/url/headers — the cause of
     * Burp "kettled" requests, GitHub issue #7) so the agent can self-correct. Advisory only.
     */
    private fun withRequestWarnings(base: JsonObject, warnings: List<String>): JsonObject =
        if (warnings.isEmpty()) base
        else JsonObject(base + ("warnings" to JsonArray(warnings.map { JsonPrimitive(it) })))

    // ---------------------------------------------------------------
    // Fuzzer (Intruder-style payload injection)
    // ---------------------------------------------------------------

    /**
     * Runs an Intruder-style attack ([HttpFuzzPlan.planAttack]) through Burp: sniper,
     * battering_ram, pitchfork or cluster_bomb over the request's injection points (`§` marker
     * pairs or a custom [marker], the `FUZZ` keyword, or [positions] offsets), payloads run through
     * [encoders] before they are placed, every request with its Content-Length recomputed and sent
     * as UTF-8. [HttpFuzzRunner] sends them (in order or several at a time, rate limited), applies
     * the stop condition and response filter, and clusters every response.
     *
     * @param maxRequests cap on the requests the attack sends.
     * @param timeoutMs hard timeout of each request; null or 0 waits for Burp. A request that fails
     *   or times out is reported in its own entry and the run goes on.
     */
    internal fun fuzz(
        request: String,
        host: String,
        port: Int,
        useTls: Boolean,
        positions: List<Pair<Int, Int>>?,
        payloadSets: List<List<String>>,
        marker: String?,
        attackMode: HttpFuzzPlan.AttackMode,
        encoders: List<String>,
        maxRequests: Long,
        httpMode: String?,
        maxBodyLength: Int?,
        timeoutMs: Long?,
        runOptions: HttpFuzzRunner.Options,
        autoFixContentLength: Boolean = true,
    ): JsonObject {
        runOptions.stopOnBodyRegex?.let { pattern ->
            SafeRegex.validate(pattern)?.let { return buildJsonObject { put("error", "Invalid stop_on_match.body_regex: $it") } }
        }
        var scope: ScopeGate.Check? = null
        return try {
            val service = HttpService.httpService(host, port, useTls)
            val mode = HttpModes.resolve(httpMode)
            val encode = PayloadEncoders.chain(encoders)
            val planned = HttpFuzzPlan.planAttack(
                request, positions, payloadSets, marker, attackMode, encode, maxRequests, autoFixContentLength,
            )
            val plan = when (planned) {
                is HttpFuzzPlan.AttackResult.Error -> return buildJsonObject { put("error", planned.message) }
                is HttpFuzzPlan.AttackResult.Ok -> planned.plan
            }
            // Every distinct target the run will send (a payload may sit in the path), on host:port.
            val check = scopeGate.checkRequests(host, port, useTls, plan.requests.map { it.request }.ifEmpty { sequenceOf(request) })
            if (check.blocked) return check.denyJson()
            scope = check
            val runner = HttpFuzzRunner { attack -> sendFuzzRequest(attack, service, mode, plan.mode, maxBodyLength, timeoutMs) }
            check.annotate(runner.run(plan, runOptions))
        } catch (e: Exception) {
            val error = buildJsonObject { put("error", "Fuzz failed: ${e.message}") }
            scope?.annotate(error) ?: error
        }
    }

    private fun sendFuzzRequest(
        attack: HttpFuzzPlan.AttackRequest,
        service: HttpService,
        mode: HttpMode,
        attackMode: HttpFuzzPlan.AttackMode,
        maxBodyLength: Int?,
        timeoutMs: Long?,
    ): HttpFuzzRunner.Sent {
        val wire = attack.request.toByteArray(RequestHygiene.wireCharset(attack.request))
        val httpRequest = HttpRequest.httpRequest(service, BurpByteArray.byteArray(*wire))
        val start = System.nanoTime()
        val result = try {
            timeouts.run(timeoutMs) { api.http().sendRequest(httpRequest, mode) }
        } catch (e: Exception) {
            return HttpFuzzRunner.Sent.Failed(e.message ?: "send failed", e is HttpRequestTimeoutException)
        }
        val elapsedMs = (System.nanoTime() - start) / 1_000_000
        api.recordInSiteMap(result, "[MCP] Fuzz ${attackMode.id} pos=${attack.position} payload=${attack.label}")
        val response: HttpResponse? = if (result.hasResponse()) result.response() else null
        val head = response?.let { r ->
            buildString {
                append(r.httpVersion()).append(' ').append(r.statusCode().toInt()).append(' ').append(r.reasonPhrase() ?: "")
                r.headers().forEach { append("\r\n").append(it.name()).append(": ").append(it.value()) }
            }
        } ?: ""
        return HttpFuzzRunner.Sent.Answered(
            status = response?.statusCode()?.toInt() ?: 0,
            bodyLength = response?.body()?.length() ?: 0,
            head = head,
            body = response?.bodyToString() ?: "",
            elapsedMs = elapsedMs,
            json = { HttpExchangeJson.serialize(result, elapsedMs, maxBodyLength) },
        )
    }

    // ---------------------------------------------------------------
    // Race condition tester
    // ---------------------------------------------------------------

    /**
     * Releases [count] copies of [request] (or one request per payload, `FUZZ` replaced) at once
     * behind a real synchronisation barrier ([HttpRace]): an HTTP/2 single-packet attack through
     * Burp, or HTTP/1.1 last-byte synchronisation on Raijin's own connections. Responses are
     * clustered (status, length, body similarity) to show whether the race changed the outcome.
     */
    internal fun raceCondition(
        request: String,
        host: String,
        port: Int,
        useTls: Boolean,
        count: Int,
        payloads: List<String>?,
        sync: HttpRace.Sync,
        httpMode: String?,
        sni: String?,
        maxBodyLength: Int?,
        timeoutMs: Long?,
        similarity: Double,
        autoFixContentLength: Boolean = true,
    ): JsonObject = race.run(
        HttpFuzzPlan.raceRequests(request, count, payloads, autoFixContentLength),
        payloads?.takeIf { it.isNotEmpty() },
        host, port, useTls, sync, HttpModes.resolve(httpMode), sni, maxBodyLength, timeoutMs, similarity,
    )

    companion object {
        /**
         * Whether [rule]'s tool filter admits traffic from [toolName]. An internal probe only takes
         * rules whose filter explicitly names its tool (EXTENSIONS): an unfiltered rule is meant for
         * the operator's traffic and would contaminate an unauthenticated probe.
         */
        internal fun trafficRuleAppliesTo(rule: TrafficRule, toolName: String?, internalProbe: Boolean): Boolean {
            val filter = rule.toolFilter ?: return !internalProbe
            return toolName != null && filter.any { it.equals(toolName, ignoreCase = true) }
        }
    }
}
