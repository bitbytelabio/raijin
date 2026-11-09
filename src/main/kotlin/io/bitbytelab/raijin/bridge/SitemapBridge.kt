package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.http.HttpService
import burp.api.montoya.sitemap.SiteMapFilter
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import io.bitbytelab.raijin.core.HighlightColorName
import io.bitbytelab.raijin.core.ProxyHistorySearch
import io.bitbytelab.raijin.core.ServiceParts
import io.bitbytelab.raijin.core.StatusCodeRange
import io.bitbytelab.raijin.safety.RequestHygiene
import kotlinx.serialization.json.*
import burp.api.montoya.core.HighlightColor

class SitemapBridge(private val api: MontoyaApi) {

    /** Default noise exclusion for [query]'s `exclude_noise` (overridable). */
    private val defaultNoisePattern =
        Regex("""/cdn-cgi/|/favicon\.ico(\?|$)|/\.well-known/|/__webpack_hmr""", RegexOption.IGNORE_CASE)

    /**
     * Queries the site map, with enough filtering to tell "the crawl is still running" from
     * "it's done" and to separate real pages from noise — unlike the old bare-array form, which
     * returned `status_code: 0` / `mime_type: "unknown"` for both "genuinely empty response" and
     * "no response yet", had no way to exclude Cloudflare/cdn-cgi noise, and silently truncated
     * past [maxResults] with no total count to tell you so.
     *
     * @param onlyWithResponse When true, entries with no response yet are excluded entirely.
     * @param statusCodeRange `"min-max"` / `"200-"` / `"-299"` / `"200"` — see [StatusCodeRange.parse].
     * @param mime Case-insensitive match against the entry's stated OR inferred MIME type.
     * @param excludeNoise When true (default), drops common non-content noise (`/cdn-cgi/`, `/favicon.ico`, `/.well-known/`, webpack HMR).
     * @param excludePattern Additional caller-supplied regex to exclude (checked against the URL).
     * @param inScopeOnly When true, entries outside Burp's target scope are excluded.
     * @param searchIn Which parts [searchPattern] matches against: url (default), request, response, or all — see [ProxyHistorySearch.targets].
     * @param noteContains Substring match against the entry's annotation notes (e.g. `[MCP] Raijin` — see http_send_* tool docs).
     */
    fun query(
        urlPrefix: String?,
        searchPattern: String?,
        maxResults: Int,
        includeRequest: Boolean,
        includeResponse: Boolean,
        onlyWithResponse: Boolean = false,
        statusCodeRange: String? = null,
        mime: List<String>? = null,
        excludeNoise: Boolean = true,
        excludePattern: String? = null,
        inScopeOnly: Boolean = false,
        searchIn: String? = null,
        noteContains: String? = null
    ): JsonObject {
        val filter = if (urlPrefix != null) SiteMapFilter.prefixFilter(urlPrefix) else null
        val all = if (filter != null) api.siteMap().requestResponses(filter) else api.siteMap().requestResponses()

        val totalInSitemap = all.size
        val withResponse = all.count { it.hasResponse() }

        val range = when (val r = StatusCodeRange.parse(statusCodeRange)) {
            is StatusCodeRange.Result.Invalid -> return buildJsonObject { put("error", r.message) }
            is StatusCodeRange.Result.Ok -> r.range
            StatusCodeRange.Result.None -> null
        }
        val mimeLower = mime?.map { it.lowercase() }
        val extraExclude = excludePattern?.let { Regex(it, RegexOption.IGNORE_CASE) }
        val targets = ProxyHistorySearch.targets(searchIn)
        val searchRegex = searchPattern?.let { Regex(it, RegexOption.IGNORE_CASE) }

        var matched = all.asSequence()
        if (onlyWithResponse) matched = matched.filter { it.hasResponse() }
        if (range != null) matched = matched.filter { it.hasResponse() && range.contains(it.response()!!.statusCode().toInt()) }
        if (mimeLower != null) matched = matched.filter { entry ->
            val resp = entry.response() ?: return@filter false
            val stated = resp.statedMimeType()?.toString()?.lowercase()
            val inferred = resp.inferredMimeType()?.toString()?.lowercase()
            mimeLower.any { it == stated || it == inferred }
        }
        if (excludeNoise) matched = matched.filter { entry -> !defaultNoisePattern.containsMatchIn(entry.request()?.url() ?: "") }
        if (extraExclude != null) matched = matched.filter { entry -> !extraExclude.containsMatchIn(entry.request()?.url() ?: "") }
        if (inScopeOnly) matched = matched.filter { entry ->
            try { api.scope().isInScope(entry.request()?.url() ?: "") } catch (_: Exception) { false }
        }
        if (noteContains != null) matched = matched.filter { entry ->
            (try { entry.annotations()?.notes() } catch (_: Exception) { null })?.contains(noteContains, ignoreCase = true) == true
        }
        if (searchRegex != null) matched = matched.filter { entry ->
            val req = entry.request()
            val resp = entry.response()
            (targets.url && searchRegex.containsMatchIn(req?.url() ?: "")) ||
                (targets.request && req != null && searchRegex.containsMatchIn(req.toString())) ||
                (targets.response && resp != null && searchRegex.containsMatchIn(resp.toString()))
        }

        val matchedList = matched.toList()
        val limited = matchedList.take(maxResults.coerceAtLeast(0))

        val statusHistogram = sortedMapOf<String, Int>()
        val mimeHistogram = sortedMapOf<String, Int>()
        for (entry in matchedList) {
            val resp = entry.response()
            val statusKey = resp?.statusCode()?.toString() ?: "no_response"
            statusHistogram[statusKey] = (statusHistogram[statusKey] ?: 0) + 1
            val mimeKey = resp?.let { it.statedMimeType()?.toString() ?: it.inferredMimeType()?.toString() } ?: "no_response"
            mimeHistogram[mimeKey] = (mimeHistogram[mimeKey] ?: 0) + 1
        }

        return buildJsonObject {
            put("total_in_sitemap", totalInSitemap)
            put("with_response", withResponse)
            put("without_response", totalInSitemap - withResponse)
            put("matched", matchedList.size)
            put("returned", limited.size)
            put("status_histogram", buildJsonObject { statusHistogram.forEach { (k, v) -> put(k, v) } })
            put("mime_histogram", buildJsonObject { mimeHistogram.forEach { (k, v) -> put(k, v) } })
            put("entries", buildJsonArray {
                for (entry in limited) {
                    addJsonObject {
                        val req = entry.request()
                        val resp = entry.response()
                        val hasResponse = entry.hasResponse()

                        put("url", req?.url() ?: "unknown")
                        put("method", req?.method() ?: "unknown")
                        put("has_response", hasResponse)
                        put("status_code", if (hasResponse) resp?.statusCode()?.toInt() else null)
                        put("content_length", if (hasResponse) resp?.body()?.length() else null)
                        put("mime_type", if (hasResponse) (resp?.statedMimeType()?.toString() ?: resp?.inferredMimeType()?.toString()) else null)

                        if (includeRequest && req != null) {
                            put("request", req.toString())
                        }

                        if (includeResponse && resp != null) {
                            val responseStr = resp.toString()
                            if (responseStr.length > 100_000) {
                                put("response", responseStr.substring(0, 100_000) + "... [truncated]")
                                put("response_truncated", true)
                            } else {
                                put("response", responseStr)
                            }
                        }
                    }
                }
            })
        }
    }

    /**
     * Sets notes/highlight on the site map entry whose request URL exactly matches [url].
     * Unlike Proxy history, Montoya's `SiteMap` interface exposes no per-entry update call —
     * only `add()`. This mutates the live [burp.api.montoya.core.Annotations] object
     * `requestResponses()` returns for the match, the same way [ProxyBridge.annotateHistoryItem]
     * already does for proxy history; whether that mutation actually persists in Burp's own
     * Site map view is **not documented** and should be confirmed once against a running Burp.
     */
    fun annotate(url: String, notes: String?, highlight: String?): JsonObject {
        val canonicalHighlight = if (highlight != null) {
            HighlightColorName.canonical(highlight)
                ?: return buildJsonObject {
                    put("error", "Invalid highlight color: '$highlight'. Valid values: ${HighlightColorName.validValues()}")
                }
        } else null

        val candidates = try {
            api.siteMap().requestResponses(SiteMapFilter.prefixFilter(url))
        } catch (e: Exception) {
            return buildJsonObject { put("error", "Failed to query site map: ${e.message}") }
        }
        val matches = candidates.filter { it.request()?.url() == url }
        val target = matches.firstOrNull()
            ?: return buildJsonObject {
                put("annotated", false)
                put("matched_count", 0)
                put("error", "No site map entry found with URL '$url' (use sitemap_query to find the exact URL)")
            }

        val annotations = target.annotations()
        if (notes != null) annotations.setNotes(notes)
        if (canonicalHighlight != null) annotations.setHighlightColor(HighlightColor.valueOf(canonicalHighlight))

        return buildJsonObject {
            put("annotated", true)
            put("matched_count", matches.size)
            put("url", url)
            if (notes != null) put("notes", notes)
            if (canonicalHighlight != null) put("highlight", canonicalHighlight)
            if (matches.size > 1) put("note", "${matches.size} site map entries share this exact URL; only the first was annotated.")
        }
    }

    fun getIssues(urlPrefix: String?, severity: String?): JsonArray {
        var issues = if (urlPrefix != null) {
            api.siteMap().issues(SiteMapFilter.prefixFilter(urlPrefix))
        } else {
            api.siteMap().issues()
        }

        if (severity != null) {
            val targetSeverity = try {
                AuditIssueSeverity.valueOf(severity.uppercase())
            } catch (_: IllegalArgumentException) {
                throw IllegalArgumentException("Invalid severity '$severity'. Allowed: high, medium, low, information")
            }
            issues = issues.filter { it.severity() == targetSeverity }
        }

        return buildJsonArray {
            for (issue in issues) {
                addJsonObject {
                    put("name", issue.name())
                    put("detail", issue.detail() ?: "")
                    put("remediation", issue.remediation() ?: "")
                    put("severity", issue.severity().toString())
                    put("confidence", issue.confidence().toString())
                    put("base_url", issue.baseUrl())

                    val requestResponses = issue.requestResponses()
                    if (requestResponses != null && requestResponses.isNotEmpty()) {
                        putJsonArray("affected_urls") {
                            for (rr in requestResponses) {
                                val url = rr.request()?.url()
                                if (url != null) add(url)
                            }
                        }
                        put("request_response_count", requestResponses.size)
                    }
                }
            }
        }
    }

    fun addRequest(
        request: String,
        response: String?,
        host: String,
        port: Int,
        useTls: Boolean
    ): JsonObject {
        val httpService = HttpService.httpService(host, port, useTls)
        // Build the request from bytes (UTF-8) rather than the lossy String overload,
        // which mangles multibyte codepoints to Latin-1 and corrupts Content-Length.
        val httpRequest = HttpRequest.httpRequest(httpService, requestToByteArray(RequestHygiene.normalizeCrlf(request)))

        val httpResponse = if (response != null) {
            HttpResponse.httpResponse(response)
        } else {
            HttpResponse.httpResponse()
        }

        val requestResponse = HttpRequestResponse.httpRequestResponse(httpRequest, httpResponse)

        api.siteMap().add(requestResponse)

        return buildJsonObject {
            put("status", "added")
            put("url", httpRequest.url())
            put("method", httpRequest.method())
            put("host", host)
            put("port", port)
            put("use_tls", useTls)
            put("has_response", response != null)
        }
    }

    fun addIssue(
        name: String,
        detail: String,
        remediation: String?,
        severity: String,
        confidence: String,
        url: String,
        request: String?,
        response: String?
    ): JsonObject {
        val issueSeverity = try {
            AuditIssueSeverity.valueOf(severity.uppercase())
        } catch (_: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid severity '$severity'. Allowed: high, medium, low, information")
        }

        val issueConfidence = try {
            AuditIssueConfidence.valueOf(confidence.uppercase())
        } catch (_: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid confidence '$confidence'. Allowed: certain, firm, tentative")
        }

        val requestResponses = mutableListOf<HttpRequestResponse>()
        if (request != null) {
            // A request built without an HttpService has no host to resolve, which crashes
            // the Montoya API internals (NPE) once it tries to file the issue into the site
            // map (PR #13). Derive host/port/TLS from the issue's own `url`.
            val parts = ServiceParts.fromUrl(url)
            val httpService = HttpService.httpService(parts.host, parts.port, parts.useTls)

            val httpRequest = HttpRequest.httpRequest(RequestHygiene.normalizeCrlf(request)).withService(httpService)
            val httpResponse = if (response != null) {
                HttpResponse.httpResponse(response)
            } else {
                HttpResponse.httpResponse()
            }
            val rr = HttpRequestResponse.httpRequestResponse(httpRequest, httpResponse)
            requestResponses.add(rr)
        }

        val auditIssue = AuditIssue.auditIssue(
            name,
            detail,
            remediation ?: "",
            url,
            issueSeverity,
            issueConfidence,
            null, // background
            null, // remediation background
            issueSeverity, // typicalSeverity
            requestResponses
        )

        api.siteMap().add(auditIssue)

        return buildJsonObject {
            put("status", "added")
            put("name", name)
            put("severity", issueSeverity.toString())
            put("confidence", issueConfidence.toString())
            put("url", url)
            put("has_request_response", request != null)
        }
    }

    companion object {
        /**
         * Encode a raw HTTP request String to raw bytes using UTF-8, preserving multibyte
         * codepoints so Content-Length stays byte-accurate. This is the pure, testable core
         * of the fix: the previous code path handed the String to the lossy
         * HttpRequest.httpRequest(service, String) overload, which silently narrowed each
         * character to Latin-1 and corrupted any non-ASCII body/path. UTF-8 is used to match
         * the byte-oriented http_send_raw_bytes construction.
         */
        fun encodeRequestBytes(request: String): kotlin.ByteArray =
            request.toByteArray(Charsets.UTF_8)

        /**
         * Wrap [encodeRequestBytes] into a Montoya ByteArray for HttpRequest construction.
         * Kept separate so the charset behaviour above can be unit-tested without the
         * compileOnly Montoya runtime.
         */
        fun requestToByteArray(request: String): BurpByteArray =
            BurpByteArray.byteArray(*encodeRequestBytes(request))
    }
}
