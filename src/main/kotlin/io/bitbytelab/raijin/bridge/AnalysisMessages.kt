package io.bitbytelab.raijin.bridge

import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import io.bitbytelab.raijin.bridge.AnalysisBridge.Companion.describeException
import io.bitbytelab.raijin.bridge.AnalysisBridge.Companion.normalizeCrlfMessage
import kotlinx.serialization.json.*

/**
 * Offline analysis of raw HTTP messages for [AnalysisBridge]: their parts, the request values a
 * response reflects, the parameters of a request and its insertion points. Nothing is sent.
 */
internal object AnalysisMessages {

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
            HttpRequest.httpRequest(normalizeCrlfMessage(rawRequest))
        } catch (e: Exception) {
            return buildJsonObject { put("error", "Failed to parse request: ${describeException(e)}") }
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
            HttpResponse.httpResponse(normalizeCrlfMessage(rawResponse))
        } catch (e: Exception) {
            return buildJsonObject { put("error", "Failed to parse response: ${describeException(e)}") }
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
            httpRequest = HttpRequest.httpRequest(normalizeCrlfMessage(rawRequest))
            httpResponse = HttpResponse.httpResponse(normalizeCrlfMessage(rawResponse))
        } catch (e: Exception) {
            return buildJsonObject { put("error", "Failed to parse request/response: ${describeException(e)}") }
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
            HttpRequest.httpRequest(normalizeCrlfMessage(rawRequest))
        } catch (e: Exception) {
            return buildJsonObject { put("error", "Failed to parse request: ${describeException(e)}") }
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
        val httpRequest = HttpRequest.httpRequest(httpService, normalizeCrlfMessage(rawRequest))

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
     * Splits a request path into non-empty segments, stripping any query
     * string and fragment first so the final segment isn't polluted with
     * "?foo=bar". URL parameters are enumerated separately as insertion
     * points, so they must not leak into the path-segment enumeration.
     */
    fun pathSegments(path: String): List<String> =
        path.substringBefore("?").substringBefore("#")
            .split("/")
            .filter { it.isNotEmpty() }

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
}
