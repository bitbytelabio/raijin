package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import io.bitbytelab.raijin.safety.BoundedHttp
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.http.HttpService
import burp.api.montoya.sitemap.SiteMapFilter
import io.bitbytelab.raijin.core.BodyText
import io.bitbytelab.raijin.core.TextSimilarity
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.safety.ScopeGate
import kotlinx.serialization.json.*

/**
 * Cross-cutting analysis bridge that combines multiple Montoya APIs
 * to perform request/response analysis, reflection detection,
 * parameter extraction, diff comparison, and response body searching.
 */
class AnalysisBridge(private val api: MontoyaApi) {

    private val scopeGate = ScopeGate(api)

    /**
     * Parses a raw HTTP request and extracts its components: method, URL,
     * path, headers, cookies, parameters, body, and content type.
     */
    fun analyzeRequest(rawRequest: String): JsonObject {
        if (rawRequest.isBlank()) {
            return buildJsonObject {
                put("error", "Empty request: provide a raw HTTP request (e.g. 'GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n').")
            }
        }
        val httpRequest = try {
            HttpRequest.httpRequest(normalizeCrlf(rawRequest))
        } catch (e: Exception) {
            return buildJsonObject { put("error", "Failed to parse request: ${describe(e)}") }
        }

        val headers = buildJsonArray {
            for (header in httpRequest.headers()) {
                addJsonObject {
                    put("name", header.name())
                    put("value", header.value())
                }
            }
        }

        val parameters = buildJsonArray {
            for (param in httpRequest.parameters()) {
                addJsonObject {
                    put("name", param.name())
                    put("value", param.value())
                    put("type", param.type().name)
                }
            }
        }

        val cookies = buildJsonArray {
            for (param in httpRequest.parameters()) {
                if (param.type().name.equals("COOKIE", ignoreCase = true)) {
                    addJsonObject {
                        put("name", param.name())
                        put("value", param.value())
                    }
                }
            }
        }

        return buildJsonObject {
            put("method", httpRequest.method())
            put("url", httpRequest.url())
            put("path", httpRequest.path())
            put("content_type", httpRequest.contentType()?.name ?: "NONE")
            put("header_count", httpRequest.headers().size)
            put("headers", headers)
            put("parameter_count", httpRequest.parameters().size)
            put("parameters", parameters)
            put("cookies", cookies)
            put("has_body", httpRequest.body() != null && httpRequest.body().length() > 0)
            put("body_length", httpRequest.body()?.length() ?: 0)
            put("body", httpRequest.bodyToString())
        }
    }

    /**
     * Parses a raw HTTP response and extracts its components: status code,
     * reason phrase, headers, cookies, body, and MIME types.
     */
    fun analyzeResponse(rawResponse: String): JsonObject {
        if (rawResponse.isBlank()) {
            return buildJsonObject {
                put("error", "Empty response: provide a raw HTTP response (e.g. 'HTTP/1.1 200 OK\\r\\n\\r\\n...').")
            }
        }
        val httpResponse = try {
            HttpResponse.httpResponse(normalizeCrlf(rawResponse))
        } catch (e: Exception) {
            return buildJsonObject { put("error", "Failed to parse response: ${describe(e)}") }
        }

        val headers = buildJsonArray {
            for (header in httpResponse.headers()) {
                addJsonObject {
                    put("name", header.name())
                    put("value", header.value())
                }
            }
        }

        val cookies = buildJsonArray {
            for (cookie in httpResponse.cookies()) {
                addJsonObject {
                    put("name", cookie.name())
                    put("value", cookie.value())
                    put("domain", cookie.domain() ?: "")
                    put("path", cookie.path() ?: "")
                    put("expiration", cookie.expiration()?.toString() ?: "")
                }
            }
        }

        return buildJsonObject {
            put("status_code", httpResponse.statusCode())
            put("reason_phrase", httpResponse.reasonPhrase() ?: "")
            put("stated_mime_type", httpResponse.statedMimeType()?.toString() ?: "unknown")
            put("inferred_mime_type", httpResponse.inferredMimeType()?.toString() ?: "unknown")
            put("header_count", httpResponse.headers().size)
            put("headers", headers)
            put("cookie_count", httpResponse.cookies().size)
            put("cookies", cookies)
            put("has_body", httpResponse.body() != null && httpResponse.body().length() > 0)
            put("body_length", httpResponse.body()?.length() ?: 0)
            put("body", httpResponse.bodyToString())
        }
    }

    /**
     * Finds reflected values by extracting parameter values from a request
     * and searching for them in the response body. For each reflection,
     * determines the surrounding context (HTML body, attribute, JavaScript,
     * URL, comment).
     *
     * @param rawRequest The raw HTTP request string.
     * @param rawResponse The raw HTTP response string.
     * @param additionalValues Extra values to search for beyond request params.
     */
    fun findReflected(
        rawRequest: String,
        rawResponse: String,
        additionalValues: List<String>
    ): JsonObject {
        if (rawRequest.isBlank() || rawResponse.isBlank()) {
            return buildJsonObject {
                put("error", "Both request and response must be non-empty raw HTTP messages.")
            }
        }
        val httpRequest: HttpRequest
        val httpResponse: HttpResponse
        try {
            httpRequest = HttpRequest.httpRequest(normalizeCrlf(rawRequest))
            httpResponse = HttpResponse.httpResponse(normalizeCrlf(rawResponse))
        } catch (e: Exception) {
            return buildJsonObject { put("error", "Failed to parse request/response: ${describe(e)}") }
        }
        val responseBody = httpResponse.bodyToString()

        // Collect all candidate values from request parameters
        val candidateValues = mutableMapOf<String, String>()
        for (param in httpRequest.parameters()) {
            val value = param.value()
            if (value.length >= 3) {
                candidateValues["${param.type().name}:${param.name()}"] = value
            }
        }
        // Add user-supplied additional values
        additionalValues.forEachIndexed { idx, v ->
            if (v.length >= 3) {
                candidateValues["additional:$idx"] = v
            }
        }

        val reflections = buildJsonArray {
            for ((source, value) in candidateValues) {
                if (responseBody.contains(value)) {
                    // Find all occurrences and their contexts
                    var searchFrom = 0
                    var occurrenceIndex = 0
                    while (true) {
                        val pos = responseBody.indexOf(value, searchFrom)
                        if (pos == -1) break

                        val context = determineReflectionContext(responseBody, pos, value.length)
                        addJsonObject {
                            put("source", source)
                            put("value", value)
                            put("position", pos)
                            put("occurrence", occurrenceIndex)
                            put("context", context)
                            // Show surrounding chars for analysis
                            val snippetStart = maxOf(0, pos - 40)
                            val snippetEnd = minOf(responseBody.length, pos + value.length + 40)
                            put("surrounding", responseBody.substring(snippetStart, snippetEnd))
                        }
                        searchFrom = pos + 1
                        occurrenceIndex++
                    }
                }
            }
        }

        return buildJsonObject {
            put("candidates_checked", candidateValues.size)
            put("reflection_count", reflections.size)
            put("reflections", reflections)
        }
    }

    /**
     * Extracts all parameters from an HTTP request: URL query params,
     * body params, cookies, and header values. For JSON bodies, recursively
     * extracts nested keys. For XML bodies, extracts element/attribute values.
     */
    fun extractParams(rawRequest: String): JsonObject {
        if (rawRequest.isBlank()) {
            return buildJsonObject {
                put("error", "Empty request: provide a raw HTTP request (e.g. 'GET /?a=1 HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n').")
            }
        }
        val httpRequest = try {
            HttpRequest.httpRequest(normalizeCrlf(rawRequest))
        } catch (e: Exception) {
            return buildJsonObject { put("error", "Failed to parse request: ${describe(e)}") }
        }

        val urlParams = buildJsonArray {
            for (param in httpRequest.parameters()) {
                if (param.type().name.equals("URL", ignoreCase = true)) {
                    addJsonObject {
                        put("name", param.name())
                        put("value", param.value())
                    }
                }
            }
        }

        val bodyParams = buildJsonArray {
            for (param in httpRequest.parameters()) {
                if (param.type().name.equals("BODY", ignoreCase = true)) {
                    addJsonObject {
                        put("name", param.name())
                        put("value", param.value())
                    }
                }
            }
        }

        val cookieParams = buildJsonArray {
            for (param in httpRequest.parameters()) {
                if (param.type().name.equals("COOKIE", ignoreCase = true)) {
                    addJsonObject {
                        put("name", param.name())
                        put("value", param.value())
                    }
                }
            }
        }

        val headerParams = buildJsonArray {
            for (header in httpRequest.headers()) {
                addJsonObject {
                    put("name", header.name())
                    put("value", header.value())
                }
            }
        }

        // Attempt to parse JSON body for nested params
        val jsonParams = buildJsonArray {
            val body = httpRequest.bodyToString()
            if (body.isNotEmpty() && (body.trimStart().startsWith("{") || body.trimStart().startsWith("["))) {
                try {
                    val jsonElement = Json.parseToJsonElement(body)
                    flattenJson("", jsonElement, this)
                } catch (_: Exception) {
                    // Not valid JSON, skip
                }
            }
        }

        // Attempt to parse XML body for values
        val xmlParams = buildJsonArray {
            val body = httpRequest.bodyToString()
            if (body.isNotEmpty() && body.trimStart().startsWith("<")) {
                try {
                    extractXmlValues(body, this)
                } catch (_: Exception) {
                    // Not valid XML, skip
                }
            }
        }

        return buildJsonObject {
            put("url_params", urlParams)
            put("body_params", bodyParams)
            put("cookie_params", cookieParams)
            put("header_params", headerParams)
            put("json_params", jsonParams)
            put("xml_params", xmlParams)
            put("total_params",
                urlParams.size + bodyParams.size + cookieParams.size +
                    jsonParams.size + xmlParams.size
            )
        }
    }

    /**
     * Identifies all potential injection/insertion points in a request.
     */
    fun getInsertionPoints(
        rawRequest: String,
        host: String,
        port: Int,
        useTls: Boolean
    ): JsonObject {
        val httpService = HttpService.httpService(host, port, useTls)
        val httpRequest = HttpRequest.httpRequest(httpService, normalizeCrlf(rawRequest))

        val insertionPoints = buildJsonArray {
            // URL parameters
            for (param in httpRequest.parameters()) {
                if (param.type().name.equals("URL", ignoreCase = true)) {
                    addJsonObject {
                        put("type", "url_parameter")
                        put("name", param.name())
                        put("value", param.value())
                        put("base_value", param.value())
                    }
                }
            }

            // Body parameters
            for (param in httpRequest.parameters()) {
                if (param.type().name.equals("BODY", ignoreCase = true)) {
                    addJsonObject {
                        put("type", "body_parameter")
                        put("name", param.name())
                        put("value", param.value())
                        put("base_value", param.value())
                    }
                }
            }

            // JSON body leaf nodes — Burp's BODY params don't descend into nested JSON,
            // so enumerate each scalar leaf as an insertion point (path notation: a.b[0].c).
            val jsonBody = try { httpRequest.bodyToString() } catch (_: Exception) { "" }
            val contentType = httpRequest.headers().firstOrNull { it.name().equals("Content-Type", true) }?.value() ?: ""
            if (contentType.contains("json", true) || jsonBody.trimStart().startsWith("{") || jsonBody.trimStart().startsWith("[")) {
                for ((jpath, jval) in io.bitbytelab.raijin.core.JsonInsertionPoints.leaves(jsonBody)) {
                    addJsonObject {
                        put("type", "json_body")
                        put("name", jpath)
                        put("value", jval)
                        put("base_value", jval)
                    }
                }
            }

            // Cookie parameters
            for (param in httpRequest.parameters()) {
                if (param.type().name.equals("COOKIE", ignoreCase = true)) {
                    addJsonObject {
                        put("type", "cookie")
                        put("name", param.name())
                        put("value", param.value())
                        put("base_value", param.value())
                    }
                }
            }

            // Common injectable headers
            val injectableHeaders = listOf(
                "User-Agent", "Referer", "Origin", "X-Forwarded-For",
                "X-Forwarded-Host", "X-Real-IP", "Accept-Language",
                "Content-Type", "Accept"
            )
            for (header in httpRequest.headers()) {
                if (header.name() in injectableHeaders) {
                    addJsonObject {
                        put("type", "header")
                        put("name", header.name())
                        put("value", header.value())
                        put("base_value", header.value())
                    }
                }
            }

            // URL path segments
            val path = httpRequest.path()
            if (path != null) {
                // Strip the query string (and any fragment) so the final path
                // segment isn't polluted with "?foo=bar"; URL parameters are
                // enumerated separately above as url_parameter insertion points.
                val segments = pathSegments(path)
                segments.forEachIndexed { idx, segment ->
                    addJsonObject {
                        put("type", "url_path_segment")
                        put("name", "path_segment_$idx")
                        put("value", segment)
                        put("base_value", segment)
                    }
                }
            }
        }

        return buildJsonObject {
            put("host", host)
            put("port", port)
            put("use_tls", useTls)
            put("method", httpRequest.method())
            put("url", httpRequest.url())
            put("insertion_point_count", insertionPoints.size)
            put("insertion_points", insertionPoints)
        }
    }

    /**
     * Compares two requests or two responses, identifying differences in
     * status codes, headers, and body content.
     *
     * @param item1 First raw HTTP request or response.
     * @param item2 Second raw HTTP request or response.
     * @param type "request" or "response".
     */
    fun diff(item1: String, item2: String, type: String): JsonObject {
        if (item1.isBlank() || item2.isBlank()) {
            return buildJsonObject {
                put("error", "Both item1 and item2 must be non-empty raw HTTP messages for type='$type'.")
            }
        }
        return when (type.lowercase()) {
            "request" -> diffRequests(item1, item2)
            "response" -> diffResponses(item1, item2)
            else -> buildJsonObject { put("error", "Invalid type: $type. Must be 'request' or 'response'.") }
        }
    }

    /**
     * Searches response bodies across proxy history for a regex pattern (case-insensitive).
     *
     * The pattern is caller-supplied, so every match goes through [SafeRegex]: an invalid pattern
     * is reported instead of thrown, one body holds the search for at most [SEARCH_BODY_TIMEOUT_MS],
     * and the whole call stops after [SEARCH_BUDGET_MS] with what it found so far (`incomplete`).
     *
     * @param pattern Regex pattern to search for.
     * @param maxResults Maximum number of matching results (1..[SEARCH_MAX_RESULTS]).
     * @param inScopeOnly Whether to limit search to in-scope items.
     */
    fun searchResponseBodies(pattern: String, maxResults: Int, inScopeOnly: Boolean): JsonObject {
        SafeRegex.validate(pattern, ignoreCase = true)?.let { err ->
            return buildJsonObject { put("error", "Invalid regex: $err") }
        }
        val limit = maxResults.coerceIn(1, SEARCH_MAX_RESULTS)

        val proxyHistory = api.proxy().history()
        val deadline = System.nanoTime() + SEARCH_BUDGET_MS * 1_000_000
        var scanned = 0
        var oversize = 0
        var incomplete = false
        val matches = buildJsonArray {
            var matchCount = 0
            for (entry in proxyHistory) {
                if (matchCount >= limit) break
                if (System.nanoTime() > deadline) {
                    incomplete = true
                    break
                }

                try {
                    val req = entry.finalRequest() ?: continue
                    val resp = entry.originalResponse() ?: continue
                    val url = req.url()

                    if (inScopeOnly && !api.scope().isInScope(url)) continue

                    val responseBody = resp.bodyToString()
                    scanned++
                    if (responseBody.length > SEARCH_MAX_BODY_CHARS) {
                        oversize++
                        continue
                    }
                    val match = matchBody(pattern, responseBody) ?: continue
                    addJsonObject {
                        put("url", url)
                        put("method", req.method())
                        put("status_code", resp.statusCode())
                        put("match_value", match.value)
                        put("match_position", match.position)
                        put("snippet", match.snippet)
                    }
                    matchCount++
                } catch (_: Exception) {
                    // Skip entries that fail to parse
                }
            }
        }

        return buildJsonObject {
            put("pattern", pattern)
            put("in_scope_only", inScopeOnly)
            put("match_count", matches.size)
            put("max_results", limit)
            put("entries_scanned", scanned)
            if (oversize > 0) put("skipped_oversize_bodies", oversize)
            if (incomplete) {
                put("incomplete", true)
                put(
                    "note",
                    "Stopped after ${SEARCH_BUDGET_MS / 1000}s with part of the history searched: narrow it with in_scope_only or use a cheaper pattern."
                )
            }
            put("matches", matches)
        }
    }

    /**
     * Auth level diffing: sends the same request as each identity and compares the responses to
     * detect authorization issues. Identities are applied by [AuthIdentityApplier]; a level that
     * gets no HTTP response (timeout, connection error) is reported under `errors` and takes no
     * part in the comparison.
     *
     * @param request Base HTTP request string
     * @param host Target host
     * @param port Target port
     * @param useTls Use TLS
     * @param authLevels Identity objects: name plus header_name/header_value, headers and/or
     *   remove_headers; a name of none / unauth / anonymous sends the request without credentials
     * @param compareFields What to compare: any of [AUTH_DIFF_FIELDS] (default: all)
     * @param deniedRegex Optional regex; a response whose body matches it is treated as denied
     *   whatever its status (applications that refuse with a 200)
     */
    fun authDiff(
        request: String,
        host: String,
        port: Int,
        useTls: Boolean,
        authLevels: List<JsonObject>,
        compareFields: List<String>?,
        deniedRegex: String? = null
    ): JsonObject {
        if (request.isBlank()) {
            return buildJsonObject {
                put("error", "Empty request: provide a raw HTTP request (e.g. 'GET /api/resource HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n').")
            }
        }
        if (authLevels.size < 2) {
            return buildJsonObject {
                put("error", "Provide at least 2 auth levels to compare, e.g. an authenticated level plus {\"name\":\"none\"}.")
            }
        }
        val fields = compareFields?.map { it.trim().lowercase() }?.filter { it.isNotEmpty() }?.takeIf { it.isNotEmpty() }
            ?: AUTH_DIFF_FIELDS
        fields.firstOrNull { it !in AUTH_DIFF_FIELDS }?.let { bad ->
            return buildJsonObject {
                put("error", "Parameter 'compare_fields' has invalid value '$bad'. Allowed: ${AUTH_DIFF_FIELDS.joinToString(", ")}")
            }
        }
        deniedRegex?.let { pattern ->
            SafeRegex.validate(pattern, ignoreCase = true)?.let { err ->
                return buildJsonObject { put("error", "Invalid denied_regex: $err") }
            }
        }
        val identities = authLevels.mapIndexed { i, level -> AuthIdentityApplier.parse(level, defaultName = "level_${i + 1}") }
        AuthIdentityApplier.indistinguishableError(identities)?.let { err ->
            return buildJsonObject { put("error", err) }
        }
        return try {
            val scope = scopeGate.check((if (useTls) "https" else "http") + "://$host:$port/")
            scope.deny?.let { return it }
            val service = HttpService.httpService(host, port, useTls)
            // Normalize request
            val baseRequest = normalizeCrlf(request)
            val identityHeaders = AuthIdentityApplier.identityHeaders(identities)

            // Every level hits the same path (only headers vary across the loop below) — used
            // only for AuthDiffVerdict's static-asset downgrade (file-extension fallback).
            val sharedUrl = try { HttpRequest.httpRequest(service, baseRequest).url() } catch (_: Exception) { null }

            val results = mutableListOf<AuthLevelResponse>()
            val errors = mutableListOf<String>()

            for (identity in identities) {
                try {
                    val applied = AuthIdentityApplier.apply(baseRequest, identity, identityHeaders)
                    val httpRequest = HttpRequest.httpRequest(
                        service, BurpByteArray.byteArray(*AuthIdentityApplier.wireBytes(applied.request))
                    )

                    val startTime = System.nanoTime()
                    val resp = BoundedHttp.sendInternal(api, httpRequest)?.response()
                    val elapsed = (System.nanoTime() - startTime) / 1_000_000

                    val status = resp?.statusCode()?.toInt() ?: 0
                    // No response, or one without a status: a failed level, not a level that answered "0".
                    if (resp == null || status == 0) {
                        errors.add(levelFailure(identity.name, elapsed))
                        continue
                    }
                    results.add(AuthLevelResponse(
                        level = identity.name,
                        statusCode = status,
                        bodyLength = resp.body()?.length() ?: 0,
                        body = resp.bodyToString() ?: "",
                        headers = resp.headers()?.associate { it.name() to it.value() } ?: emptyMap(),
                        responseTimeMs = elapsed,
                        contentType = try { resp.headerValue("Content-Type") } catch (_: Exception) { null },
                        location = try { resp.headerValue("Location") } catch (_: Exception) { null },
                        applied = applied,
                        sentUnchanged = identity.sendsRequestUnchanged
                    ))
                } catch (e: Exception) {
                    errors.add("Level '${identity.name}' failed: ${describe(e)}")
                }
            }

            val report = authDiffReport(results, errors, fields, sharedUrl, deniedRegex)
            scope.warning?.let { JsonObject(report + ("scope_warning" to JsonPrimitive(it))) } ?: report
        } catch (e: Exception) {
            buildJsonObject { put("error", "Auth diff failed: ${describe(e)}") }
        }
    }

    // ---------------------------------------------------------------
    // Private helper methods
    // ---------------------------------------------------------------

    private fun normalizeCrlf(raw: String): String = normalizeCrlfMessage(raw)

    private fun describe(e: Throwable): String = describeException(e)

    /**
     * Determines the HTML/JS context surrounding a reflected value.
     */
    private fun determineReflectionContext(body: String, position: Int, length: Int): String {
        // Look at surrounding content to determine context
        val before = body.substring(maxOf(0, position - 200), position)
        val after = body.substring(
            minOf(body.length, position + length),
            minOf(body.length, position + length + 200)
        )

        // Check if inside HTML comment
        val lastCommentOpen = before.lastIndexOf("<!--")
        val lastCommentClose = before.lastIndexOf("-->")
        if (lastCommentOpen > lastCommentClose) {
            return "html_comment"
        }

        // Check if inside <script> block
        val lastScriptOpen = before.lowercase().lastIndexOf("<script")
        val lastScriptClose = before.lowercase().lastIndexOf("</script")
        if (lastScriptOpen > lastScriptClose) {
            // Inside a script tag -- check if in a string
            val lastSingleQuote = before.substring(maxOf(0, lastScriptOpen)).count { it == '\'' } % 2
            val lastDoubleQuote = before.substring(maxOf(0, lastScriptOpen)).count { it == '"' } % 2
            return when {
                lastSingleQuote == 1 -> "javascript_single_quoted_string"
                lastDoubleQuote == 1 -> "javascript_double_quoted_string"
                else -> "javascript"
            }
        }

        // Check if inside <style> block
        val lastStyleOpen = before.lowercase().lastIndexOf("<style")
        val lastStyleClose = before.lowercase().lastIndexOf("</style")
        if (lastStyleOpen > lastStyleClose) {
            return "css"
        }

        // Check if inside an HTML tag attribute
        val lastTagOpen = before.lastIndexOf('<')
        val lastTagClose = before.lastIndexOf('>')
        if (lastTagOpen > lastTagClose) {
            // Inside a tag -- check for attribute context
            val tagContent = before.substring(lastTagOpen)
            val inDoubleQuoteAttr = tagContent.count { it == '"' } % 2 == 1
            val inSingleQuoteAttr = tagContent.count { it == '\'' } % 2 == 1
            return when {
                inDoubleQuoteAttr -> "html_attribute_double_quoted"
                inSingleQuoteAttr -> "html_attribute_single_quoted"
                tagContent.contains("=") -> "html_attribute_unquoted"
                else -> "html_tag"
            }
        }

        // Check if it looks like a URL context
        val urlPatterns = listOf("href=", "src=", "action=", "url(", "location")
        for (pattern in urlPatterns) {
            if (before.lowercase().endsWith(pattern) ||
                before.lowercase().endsWith("$pattern\"") ||
                before.lowercase().endsWith("$pattern'")
            ) {
                return "url"
            }
        }

        return "html_body"
    }

    /**
     * Recursively flattens a JSON element into dot-notation key-value pairs.
     */
    private fun flattenJson(prefix: String, element: JsonElement, builder: JsonArrayBuilder) {
        when (element) {
            is JsonObject -> {
                for ((key, value) in element) {
                    val newPrefix = if (prefix.isEmpty()) key else "$prefix.$key"
                    flattenJson(newPrefix, value, builder)
                }
            }
            is JsonArray -> {
                element.forEachIndexed { idx, value ->
                    flattenJson("$prefix[$idx]", value, builder)
                }
            }
            is JsonPrimitive -> {
                builder.addJsonObject {
                    put("name", prefix)
                    put("value", element.content)
                    put("type", when {
                        element.isString -> "string"
                        element.booleanOrNull != null -> "boolean"
                        element.longOrNull != null -> "number"
                        element.doubleOrNull != null -> "number"
                        else -> "unknown"
                    })
                }
            }
        }
    }

    /**
     * Basic XML value extraction using regex patterns (avoids requiring
     * an XML parser dependency). Extracts element text content and
     * attribute values.
     */
    private fun extractXmlValues(xml: String, builder: JsonArrayBuilder) {
        // Extract attribute values: name="value"
        val attrRegex = Regex("""(\w+)\s*=\s*"([^"]*?)"""")
        for (match in attrRegex.findAll(xml)) {
            builder.addJsonObject {
                put("name", "attr:${match.groupValues[1]}")
                put("value", match.groupValues[2])
                put("type", "attribute")
            }
        }

        // Extract element text content: <tag>value</tag>
        val elementRegex = Regex("""<(\w+)[^>]*>([^<]+)</\1>""")
        for (match in elementRegex.findAll(xml)) {
            val text = match.groupValues[2].trim()
            if (text.isNotEmpty()) {
                builder.addJsonObject {
                    put("name", "element:${match.groupValues[1]}")
                    put("value", text)
                    put("type", "element_text")
                }
            }
        }
    }

    /**
     * Compares two raw HTTP requests.
     */
    private fun diffRequests(raw1: String, raw2: String): JsonObject {
        val req1: HttpRequest
        val req2: HttpRequest
        try {
            req1 = HttpRequest.httpRequest(normalizeCrlf(raw1))
            req2 = HttpRequest.httpRequest(normalizeCrlf(raw2))
        } catch (e: Exception) {
            return buildJsonObject { put("error", "Failed to parse request: ${describe(e)}") }
        }

        val headerDiffs = diffHeaders(
            req1.headers().associate { it.name() to it.value() },
            req2.headers().associate { it.name() to it.value() }
        )

        val paramDiffs = buildJsonArray {
            val params1 = req1.parameters().associate { "${it.type().name}:${it.name()}" to it.value() }
            val params2 = req2.parameters().associate { "${it.type().name}:${it.name()}" to it.value() }
            val allKeys = params1.keys + params2.keys
            for (key in allKeys) {
                val v1 = params1[key]
                val v2 = params2[key]
                if (v1 != v2) {
                    addJsonObject {
                        put("parameter", key)
                        put("item1_value", v1 ?: "(absent)")
                        put("item2_value", v2 ?: "(absent)")
                        put("change", when {
                            v1 == null -> "added"
                            v2 == null -> "removed"
                            else -> "modified"
                        })
                    }
                }
            }
        }

        val body1 = req1.bodyToString()
        val body2 = req2.bodyToString()
        val bodySimilarity = calculateSimilarity(body1, body2)

        return buildJsonObject {
            put("type", "request")
            put("method_match", req1.method() == req2.method())
            put("item1_method", req1.method())
            put("item2_method", req2.method())
            put("path_match", req1.path() == req2.path())
            put("item1_path", req1.path())
            put("item2_path", req2.path())
            put("header_differences", headerDiffs)
            put("parameter_differences", paramDiffs)
            put("body_match", body1 == body2)
            put("body_similarity_percent", bodySimilarity)
            put("item1_body_length", body1.length)
            put("item2_body_length", body2.length)
        }
    }

    /**
     * Compares two raw HTTP responses.
     */
    private fun diffResponses(raw1: String, raw2: String): JsonObject {
        val resp1: HttpResponse
        val resp2: HttpResponse
        try {
            resp1 = HttpResponse.httpResponse(normalizeCrlf(raw1))
            resp2 = HttpResponse.httpResponse(normalizeCrlf(raw2))
        } catch (e: Exception) {
            return buildJsonObject { put("error", "Failed to parse response: ${describe(e)}") }
        }

        val headerDiffs = diffHeaders(
            resp1.headers().associate { it.name() to it.value() },
            resp2.headers().associate { it.name() to it.value() }
        )

        val body1 = resp1.bodyToString()
        val body2 = resp2.bodyToString()
        val bodySimilarity = calculateSimilarity(body1, body2)

        return buildJsonObject {
            put("type", "response")
            put("status_code_match", resp1.statusCode() == resp2.statusCode())
            put("item1_status_code", resp1.statusCode())
            put("item2_status_code", resp2.statusCode())
            put("header_differences", headerDiffs)
            put("body_match", body1 == body2)
            put("body_similarity_percent", bodySimilarity)
            put("item1_body_length", body1.length)
            put("item2_body_length", body2.length)
            put("item1_mime_type", resp1.statedMimeType()?.toString() ?: "unknown")
            put("item2_mime_type", resp2.statedMimeType()?.toString() ?: "unknown")
        }
    }

    /**
     * Compares two header maps and produces an array of differences.
     */
    private fun diffHeaders(
        headers1: Map<String, String>,
        headers2: Map<String, String>
    ): JsonArray {
        return buildJsonArray {
            val allKeys = headers1.keys + headers2.keys
            for (key in allKeys) {
                val v1 = headers1[key]
                val v2 = headers2[key]
                if (v1 != v2) {
                    addJsonObject {
                        put("header", key)
                        put("item1_value", v1 ?: "(absent)")
                        put("item2_value", v2 ?: "(absent)")
                        put("change", when {
                            v1 == null -> "added"
                            v2 == null -> "removed"
                            else -> "modified"
                        })
                    }
                }
            }
        }
    }

    /**
     * Calculates a rough similarity percentage between two strings using
     * character-level bigram overlap (Dice coefficient).
     */
    private fun calculateSimilarity(s1: String, s2: String): Double = TextSimilarity.dice(s1, s2)

    /**
     * Pure, Burp-independent helpers. Kept `internal` so unit tests can
     * exercise the parsing/validation logic without a live Montoya API
     * (the API is compileOnly and cannot be instantiated in tests).
     */
    internal companion object {

        /**
         * Normalizes line endings in a raw HTTP message to canonical CRLF.
         *
         * Callers frequently supply messages using bare LF delimiters (either
         * as literal newlines or as the escaped "\n"/"\r\n" sequences that
         * survive JSON transport). Montoya's parser is strict about CRLF header
         * delimiting, so an LF-only message would otherwise have its headers
         * silently dropped. Mirrors the 3-step normalization used in authDiff().
         */
        fun normalizeCrlfMessage(raw: String): String =
            io.bitbytelab.raijin.safety.RequestHygiene.normalizeCrlf(raw)

        /**
         * Produces a caller-safe description of a thrown exception. Some Montoya
         * internals raise exceptions with a null message (e.g. a bare
         * StringIndexOutOfBoundsException), which would otherwise surface as the
         * literal string "null" to MCP callers. Falling back to the simple class
         * name keeps the error actionable without leaking raw internals.
         */
        fun describeException(e: Throwable): String {
            val msg = e.message
            return if (msg.isNullOrBlank()) e.javaClass.simpleName else msg
        }

        /**
         * Splits a request path into non-empty segments, stripping any query
         * string and fragment first so the final segment isn't polluted with
         * "?foo=bar". URL parameters are enumerated separately as insertion
         * points, so they must not leak into the path-segment enumeration.
         */
        fun pathSegments(path: String): List<String> =
            path.substringBefore("?").substringBefore("#")
                .split("/")
                .filter { it.isNotEmpty() }

        /** Response fields `auth_diff` can compare between two levels. */
        val AUTH_DIFF_FIELDS = listOf("status_code", "body_length", "body", "headers")

        /** Largest `max_results` of a response-body search. */
        const val SEARCH_MAX_RESULTS = 500

        /** Whole-call budget of a response-body search; it returns what it has when this runs out. */
        const val SEARCH_BUDGET_MS = 20_000L

        /** Longest time one body may hold the search (a pattern that backtracks on it is abandoned). */
        const val SEARCH_BODY_TIMEOUT_MS = 500L

        /** Bodies longer than this are not searched; they are counted as skipped. */
        const val SEARCH_MAX_BODY_CHARS = 2_000_000

        private const val SEARCH_MATCH_CHARS = 500
        private const val SEARCH_CONTEXT_CHARS = 50
        private const val PREVIEW_CHARS = 500

        /** [value] is the matched text (capped), [snippet] the match with some context around it. */
        data class BodyMatch(val value: String, val position: Int, val snippet: String)

        /**
         * First match of the caller-supplied [pattern] in [body], or null when there is none, the
         * pattern is invalid, or matching ran out of time. Output is capped and safe to serialize
         * whatever the body holds.
         */
        fun matchBody(pattern: String, body: String): BodyMatch? {
            val match = SafeRegex.find(
                pattern, body, ignoreCase = true,
                maxInputLen = SEARCH_MAX_BODY_CHARS, timeoutMs = SEARCH_BODY_TIMEOUT_MS
            ) ?: return null
            val start = match.range.first
            val shownEnd = minOf(match.range.last + 1, start + SEARCH_MATCH_CHARS)
            val snippet = body.substring(
                maxOf(0, start - SEARCH_CONTEXT_CHARS),
                minOf(body.length, shownEnd + SEARCH_CONTEXT_CHARS)
            )
            return BodyMatch(
                value = BodyText.stripLoneSurrogates(BodyText.truncate(match.value, SEARCH_MATCH_CHARS)),
                position = start,
                snippet = BodyText.stripLoneSurrogates(snippet)
            )
        }

        /** The `errors` entry for a level that produced no HTTP response within [elapsedMs]. */
        fun levelFailure(levelName: String, elapsedMs: Long, timeoutMs: Long = BoundedHttp.DEFAULT_TIMEOUT_MS): String =
            if (elapsedMs >= timeoutMs) {
                "Level '$levelName' failed: timed out after $elapsedMs ms without a response"
            } else {
                "Level '$levelName' failed: no response received (connection error)"
            }

        /**
         * Builds the `auth_diff` result from the levels that answered. Pure: the bridge only
         * supplies what came back, so the comparison and the verdict are unit tested.
         *
         * @param fields which of [AUTH_DIFF_FIELDS] to compare pairwise.
         * @param url the shared target URL, for the static-asset downgrade.
         * @param deniedRegex an already validated caller pattern that marks a response as denied.
         */
        fun authDiffReport(
            results: List<AuthLevelResponse>,
            errors: List<String>,
            fields: List<String> = AUTH_DIFF_FIELDS,
            url: String? = null,
            deniedRegex: String? = null
        ): JsonObject {
            val differences = mutableListOf<JsonObject>()

            // Compare each pair
            for (i in results.indices) {
                for (j in i + 1 until results.size) {
                    val a = results[i]
                    val b = results[j]
                    val diffs = mutableListOf<JsonObject>()

                    if ("status_code" in fields && a.statusCode != b.statusCode) {
                        diffs.add(buildJsonObject {
                            put("field", "status_code")
                            put(a.level, a.statusCode)
                            put(b.level, b.statusCode)
                        })
                    }
                    if ("body_length" in fields && a.bodyLength != b.bodyLength) {
                        diffs.add(buildJsonObject {
                            put("field", "body_length")
                            put(a.level, a.bodyLength)
                            put(b.level, b.bodyLength)
                            put("length_diff", kotlin.math.abs(a.bodyLength - b.bodyLength))
                        })
                    }
                    if ("body" in fields && a.body != b.body) {
                        diffs.add(buildJsonObject {
                            put("field", "body_content")
                            put("similarity_percent", TextSimilarity.dice(a.body, b.body))
                            put("bodies_identical", false)
                        })
                    }
                    if ("headers" in fields) {
                        val diffHeaders = (a.headers.keys + b.headers.keys).distinct().filter { a.headers[it] != b.headers[it] }
                        if (diffHeaders.isNotEmpty()) {
                            diffs.add(buildJsonObject {
                                put("field", "headers")
                                put("different_headers", buildJsonArray { diffHeaders.forEach { add(it) } })
                            })
                        }
                    }

                    if (diffs.isNotEmpty()) {
                        differences.add(buildJsonObject {
                            put("level_a", a.level)
                            put("level_b", b.level)
                            put("differences", buildJsonArray { diffs.forEach { add(it) } })
                        })
                    }
                }
            }

            // Security analysis
            val verdict = AuthDiffVerdict.assess(
                results.map { AuthDiffVerdict.LevelResult(it.level, it.statusCode, it.body, it.contentType, it.location) },
                similarity = TextSimilarity::dice,
                url = url,
                denied = { level ->
                    AuthDenialHeuristic.looksDenied(level.body) || (
                        deniedRegex != null && SafeRegex.containsMatchIn(
                            deniedRegex, level.body, ignoreCase = true, maxInputLen = SEARCH_MAX_BODY_CHARS
                        )
                        )
                }
            )

            val notes = mutableListOf<String>()
            results.filter { it.sentUnchanged }.forEach {
                notes += "Level '${it.level}' sets no header and is not named none/unauth/anonymous: it was sent with the request's own credentials."
            }
            if (results.size < 2) notes += "Fewer than two levels answered, so nothing could be compared: see errors."

            return buildJsonObject {
                put("auth_levels_tested", results.size)
                put("responses", buildJsonArray {
                    results.forEach { r ->
                        add(buildJsonObject {
                            put("level", r.level)
                            put("status_code", r.statusCode)
                            put("body_length", r.bodyLength)
                            put("response_time_ms", r.responseTimeMs)
                            r.location?.takeIf { it.isNotBlank() }?.let { put("redirect_location", it) }
                            r.applied?.let { applied ->
                                if (applied.set.isNotEmpty()) put("headers_set", strings(applied.set))
                                if (applied.removed.isNotEmpty()) put("headers_removed", strings(applied.removed))
                                if (applied.keptCredentials.isNotEmpty()) put("credential_headers_kept", strings(applied.keptCredentials))
                            }
                            put("body_preview", BodyText.render(r.body, PREVIEW_CHARS, label = "response body").text)
                        })
                    }
                })
                put("differences", buildJsonArray { differences.forEach { add(it) } })
                put("findings", buildJsonArray {
                    verdict.forEach {
                        add(buildJsonObject {
                            put("severity", it.severity)
                            put("id", it.id)
                            put("detail", it.detail)
                        })
                    }
                })
                put("all_same_status", results.map { it.statusCode }.distinct().size == 1)
                put("all_same_body", results.map { it.body }.distinct().size == 1)
                if (notes.isNotEmpty()) put("notes", strings(notes))
                if (errors.isNotEmpty()) put("errors", strings(errors))
            }
        }

        private fun strings(values: List<String>): JsonArray = buildJsonArray { values.forEach { add(it) } }
    }
}

/**
 * One auth level's answer, as [AnalysisBridge.authDiffReport] compares it.
 *
 * @param applied what [AuthIdentityApplier] did to the request for this level.
 * @param sentUnchanged the level changed nothing about the request (it carries the captured credentials).
 */
internal data class AuthLevelResponse(
    val level: String,
    val statusCode: Int,
    val body: String,
    val bodyLength: Int = body.length,
    val headers: Map<String, String> = emptyMap(),
    val responseTimeMs: Long = 0,
    val contentType: String? = null,
    val location: String? = null,
    val applied: AuthIdentityApplier.Applied? = null,
    val sentUnchanged: Boolean = false
)
