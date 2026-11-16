package io.bitbytelab.raijin.tools.sitemap

import burp.api.montoya.core.HighlightColor
import io.bitbytelab.raijin.bridge.SitemapBridge
import io.bitbytelab.raijin.core.EnumValidation
import io.bitbytelab.raijin.core.asBooleanSafe
import io.bitbytelab.raijin.core.asBoundedInt
import io.bitbytelab.raijin.core.asClampedInt
import io.bitbytelab.raijin.core.asStringList
import io.bitbytelab.raijin.core.withClampReport
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object SitemapTools {

    private val SEARCH_IN = listOf("url", "request", "response", "all")
    private val SEVERITIES = listOf("HIGH", "MEDIUM", "LOW", "INFORMATION")
    /** An issue the operator marked as a false positive keeps that as its severity, so it can be filtered on. */
    private val ISSUE_FILTER_SEVERITIES = SEVERITIES + "FALSE_POSITIVE"
    private val CONFIDENCES = listOf("CERTAIN", "FIRM", "TENTATIVE")
    private const val MAX_RESULTS = 10_000

    fun register(server: Server, bridge: SitemapBridge) {

        server.addTool(
            name = "sitemap_query",
            description = "Query the Burp Suite site map for HTTP request/response entries, with enough filtering to tell crawl progress " +
                "from noise. Returns an object (not a bare array): total_in_sitemap, with_response, without_response, matched, returned, " +
                "status_histogram, mime_histogram, entries[]. An entry with no response yet has has_response=false and status_code/mime_type " +
                "are null (not 0/\"unknown\") — use that, or only_with_response, to tell 'crawl still running' from 'page genuinely empty'. " +
                "Noise like /cdn-cgi/ is excluded by default (exclude_noise). Traffic sent by http_send_* lands here (annotated '[MCP] Raijin'), " +
                "not in proxy_history — use note_contains or search_in to find it.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url_prefix") { put("type", "string"); put("description", "Filter entries whose URL starts with this prefix") }
                    putJsonObject("search_pattern") { put("type", "string"); put("description", "Regex pattern to match (see search_in for where)") }
                    putJsonObject("search_in") {
                        put("type", "string")
                        putJsonArray("enum") { SEARCH_IN.forEach { add(it) } }
                        put("description", "Where search_pattern matches (default url; all = url, request and response)")
                    }
                    putJsonObject("note_contains") { put("type", "string"); put("description", "Substring match against the entry's annotation notes, e.g. '[MCP]' to find http_send_* traffic") }
                    putJsonObject("max_results") {
                        put("type", "integer"); put("minimum", 0); put("maximum", MAX_RESULTS)
                        put("description", "Maximum entries to return, default 100, 0 for counts only; a larger value is clamped to $MAX_RESULTS " +
                            "and reported as max_results_clamped_to (see 'matched' in the response for the true total)")
                    }
                    putJsonObject("include_request") { put("type", "boolean"); put("description", "Include full request text, default false") }
                    putJsonObject("include_response") { put("type", "boolean"); put("description", "Include full response text, default false") }
                    putJsonObject("only_with_response") { put("type", "boolean"); put("description", "Exclude entries with no response yet, default false") }
                    putJsonObject("status_code_range") { put("type", "string"); put("description", "e.g. '200-299', '200-', '-299', or a single code '200'") }
                    putJsonObject("mime") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "Match stated OR inferred MIME type (case-insensitive)") }
                    putJsonObject("exclude_noise") { put("type", "boolean"); put("description", "Exclude /cdn-cgi/, /favicon.ico, /.well-known/, webpack HMR — default true") }
                    putJsonObject("exclude_pattern") { put("type", "string"); put("description", "Additional regex to exclude, matched against the URL") }
                    putJsonObject("in_scope_only") { put("type", "boolean"); put("description", "Exclude entries outside Burp's target scope, default false") }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val urlPrefix = args["url_prefix"]?.jsonPrimitive?.contentOrNull
                val searchPattern = args["search_pattern"]?.jsonPrimitive?.contentOrNull
                val maxResults = args["max_results"].asClampedInt("max_results", 0, MAX_RESULTS)
                    .getOrElse { return@addTool toolError(it.message ?: "Invalid max_results") }
                val includeRequest = args["include_request"].asBooleanSafe() ?: false
                val includeResponse = args["include_response"].asBooleanSafe() ?: false
                val onlyWithResponse = args["only_with_response"].asBooleanSafe() ?: false
                val statusCodeRange = args["status_code_range"]?.jsonPrimitive?.contentOrNull
                val mime = args["mime"].asStringList()
                val excludeNoise = args["exclude_noise"].asBooleanSafe() ?: true
                val excludePattern = args["exclude_pattern"]?.jsonPrimitive?.contentOrNull
                val inScopeOnly = args["in_scope_only"].asBooleanSafe() ?: false
                val searchIn = args["search_in"]?.jsonPrimitive?.contentOrNull
                EnumValidation.error(searchIn, SEARCH_IN.toSet() + "both", "search_in")?.let { return@addTool toolJsonResult(it) }
                val noteContains = args["note_contains"]?.jsonPrimitive?.contentOrNull

                toolJsonResult(bridge.query(
                    urlPrefix, searchPattern, maxResults?.value ?: 100, includeRequest, includeResponse,
                    onlyWithResponse, statusCodeRange, mime, excludeNoise, excludePattern,
                    inScopeOnly, searchIn, noteContains
                ).withClampReport("max_results", maxResults))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "sitemap_annotate",
            description = "Set notes and/or a highlight color on the site map entry with an exact URL match. Montoya's SiteMap API has no " +
                "documented per-entry update call (only add()) — this mutates the entry's live Annotations object, the same mechanism " +
                "proxy_annotate uses for proxy history; verify once against a running Burp that the note/highlight actually shows in the " +
                "Site map UI. Use sitemap_query first to confirm the exact URL.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url") { put("type", "string"); put("description", "Exact site map entry URL to annotate") }
                    putJsonObject("notes") { put("type", "string"); put("description", "Note text to set") }
                    putJsonObject("highlight") {
                        put("type", "string")
                        putJsonArray("enum") { HighlightColor.entries.forEach { add(it.name) } }
                        put("description", "Highlight color; NONE clears it")
                    }
                },
                required = listOf("url")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val url = args["url"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Parameter 'url' is required")
                val notes = args["notes"]?.jsonPrimitive?.contentOrNull
                val highlight = args["highlight"]?.jsonPrimitive?.contentOrNull
                toolJsonResult(bridge.annotate(url, notes, highlight))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "sitemap_get_issues",
            description = "Retrieve audit issues from the Burp Suite site map. Returns scanner-reported " +
                "vulnerabilities with severity, confidence, and affected URLs. Parameters: " +
                "url_prefix (optional, filter issues by URL prefix), severity (optional, " +
                "filter by severity: HIGH, MEDIUM, LOW, INFORMATION, FALSE_POSITIVE).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url_prefix") { put("type", "string"); put("description", "Filter issues by URL prefix") }
                    putJsonObject("severity") {
                        put("type", "string")
                        putJsonArray("enum") { ISSUE_FILTER_SEVERITIES.forEach { add(it) } }
                        put("description", "Filter by severity")
                    }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val urlPrefix = args["url_prefix"]?.jsonPrimitive?.contentOrNull
                val severity = args["severity"]?.jsonPrimitive?.contentOrNull
                EnumValidation.error(severity, ISSUE_FILTER_SEVERITIES.toSet(), "severity")?.let { return@addTool toolJsonResult(it) }

                toolJsonResult(bridge.getIssues(urlPrefix, severity))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "sitemap_add_request",
            description = "Add an HTTP request (and optional response) to the Burp Suite site map. " +
                "This allows programmatic population of the site map with discovered endpoints. " +
                "Parameters: request (raw HTTP request string), response (optional, raw HTTP " +
                "response string), host (target hostname), port (target port), use_tls (boolean).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("request") { put("type", "string"); put("description", "Raw HTTP request string") }
                    putJsonObject("response") { put("type", "string"); put("description", "Raw HTTP response string") }
                    putJsonObject("host") { put("type", "string"); put("description", "Target hostname") }
                    putJsonObject("port") {
                        put("type", "integer"); put("minimum", 1); put("maximum", 65535)
                        put("description", "Target port")
                    }
                    putJsonObject("use_tls") { put("type", "boolean"); put("description", "Whether to use TLS, default false") }
                },
                required = listOf("request", "host", "port")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val rawRequest = args["request"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: request")
                val rawResponse = args["response"]?.jsonPrimitive?.contentOrNull
                val host = args["host"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: host")
                val port = args["port"].asBoundedInt("port", 1, 65535)
                    .getOrElse { return@addTool toolError(it.message ?: "Invalid port") }
                    ?: return@addTool toolError("Missing required parameter: port")
                val useTls = args["use_tls"].asBooleanSafe() ?: false

                toolJsonResult(bridge.addRequest(rawRequest, rawResponse, host, port, useTls))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "sitemap_add_issue",
            description = "Add a custom audit issue to the Burp Suite site map. Used to report " +
                "custom-discovered vulnerabilities alongside Burp's built-in scanner findings. " +
                "Parameters: name (issue title), detail (HTML description of the issue), " +
                "remediation (optional, HTML remediation advice), severity (HIGH, MEDIUM, LOW, " +
                "or INFORMATION), confidence (CERTAIN, FIRM, or TENTATIVE), url (affected URL), " +
                "request (optional, raw HTTP request demonstrating the issue), response (optional, " +
                "raw HTTP response demonstrating the issue).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("name") { put("type", "string"); put("description", "Issue title") }
                    putJsonObject("detail") { put("type", "string"); put("description", "HTML description of the issue") }
                    putJsonObject("remediation") { put("type", "string"); put("description", "HTML remediation advice") }
                    putJsonObject("severity") {
                        put("type", "string")
                        putJsonArray("enum") { SEVERITIES.forEach { add(it) } }
                        put("description", "Issue severity")
                    }
                    putJsonObject("confidence") {
                        put("type", "string")
                        putJsonArray("enum") { CONFIDENCES.forEach { add(it) } }
                        put("description", "Issue confidence")
                    }
                    putJsonObject("url") { put("type", "string"); put("description", "Affected URL") }
                    putJsonObject("request") { put("type", "string"); put("description", "Raw HTTP request demonstrating the issue") }
                    putJsonObject("response") { put("type", "string"); put("description", "Raw HTTP response demonstrating the issue") }
                },
                required = listOf("name", "detail", "severity", "confidence", "url")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val name = args["name"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: name")
                val detail = args["detail"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: detail")
                val remediation = args["remediation"]?.jsonPrimitive?.contentOrNull
                val severity = args["severity"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: severity")
                val confidence = args["confidence"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: confidence")
                val url = args["url"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: url")
                val rawRequest = args["request"]?.jsonPrimitive?.contentOrNull
                val rawResponse = args["response"]?.jsonPrimitive?.contentOrNull

                toolJsonResult(bridge.addIssue(name, detail, remediation, severity, confidence, url, rawRequest, rawResponse))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }
}
