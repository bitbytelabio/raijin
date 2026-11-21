package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.scanner.ReportFormat
import burp.api.montoya.scanner.audit.Audit
import burp.api.montoya.scanner.audit.AuditIssueHandler
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import burp.api.montoya.sitemap.SiteMapFilter
import io.bitbytelab.raijin.core.EnumValidation
import io.bitbytelab.raijin.core.ServiceParts
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.safety.RequestHygiene
import io.bitbytelab.raijin.transport.ExchangeArchive
import kotlinx.serialization.json.*
import java.util.Base64

/**
 * The scanner issues of [ScannerBridge]: an audit task's issues, the site map's issues, reports,
 * custom issues, and the JSON an issue is reported as, which is also emitted on the [EventBus]
 * as Burp reports new issues.
 */
internal class ScannerIssues(
    private val api: MontoyaApi,
    private val eventBus: EventBus
) {
    /**
     * Returns the issues audit [task] (task [taskId]) found.
     *
     * Some Burp versions cannot list a task's issues. The response then carries the site map's
     * issues under the task's targets ([prefixes]), marked `"source": "site_map"`: scans other than
     * this task may have reported some of them.
     *
     * @return JSON object with the issues.
     */
    fun taskIssues(taskId: String, task: Audit, prefixes: Set<String>): JsonObject {
        val own = try { task.issues() } catch (_: Throwable) { null }
        if (own != null) {
            return buildJsonObject {
                put("task_id", taskId)
                put("issue_count", own.size)
                put("issues", serializeIssues(own))
            }
        }

        // The site map can only be asked by URL, so the fallback is limited to the task's targets
        // and labelled; the whole site map must never be passed off as this task's issues.
        val underTargets = try {
            prefixes.flatMap { api.siteMap().issues(SiteMapFilter.prefixFilter(it)) }
        } catch (_: Throwable) {
            emptyList<AuditIssue>()
        }
        return buildJsonObject {
            put("task_id", taskId)
            put("issue_count", underTargets.size)
            put("issues", serializeIssues(underTargets))
            put("source", "site_map")
            putJsonArray("url_prefixes") { prefixes.forEach { add(it) } }
            put(
                "note",
                if (prefixes.isEmpty()) {
                    "This Burp version cannot list a task's issues and the task's targets are unknown, " +
                        "so nothing could be looked up. Use scanner_get_all_issues with a url_prefix."
                } else {
                    "This Burp version cannot list a task's issues. These are the site map's issues under " +
                        "the task's targets (url_prefixes); other scans of them may have reported some."
                }
            )
        }
    }

    /**
     * Returns all issues from the site map, with optional filtering.
     *
     * @param urlPrefix Optional URL prefix filter.
     * @param severity Optional severity filter: high, medium, low, information, false_positive.
     * @param confidence Optional confidence filter: certain, firm, tentative.
     * @param maxResults Maximum number of results to return.
     * @return JSON object with issues array.
     */
    fun getAllIssues(
        urlPrefix: String?,
        severity: String?,
        confidence: String?,
        maxResults: Int?
    ): JsonObject {
        // An unknown filter value used to match nothing and return an empty list as if there were no issues.
        EnumValidation.error(severity, FILTER_SEVERITIES, "severity")?.let { return it }
        EnumValidation.error(confidence, ScanCheckLogic.CONFIDENCES, "confidence")?.let { return it }
        val wantedSeverity = severity?.takeIf { it.isNotBlank() }?.let { severityName(it) }
        val wantedConfidence = confidence?.takeIf { it.isNotBlank() }?.trim()?.uppercase()
        return try {
            val allIssues = if (urlPrefix != null) {
                api.siteMap().issues(SiteMapFilter.prefixFilter(urlPrefix))
            } else {
                api.siteMap().issues()
            }

            val filteredIssues = allIssues.filter { issue ->
                (wantedSeverity == null || issue.severity().name == wantedSeverity) &&
                    (wantedConfidence == null || issue.confidence().name == wantedConfidence)
            }

            val limited = if (maxResults != null && maxResults > 0) {
                filteredIssues.take(maxResults)
            } else {
                filteredIssues
            }

            buildJsonObject {
                put("total_unfiltered", allIssues.size)
                put("total_filtered", filteredIssues.size)
                put("returned", limited.size)
                put("issues", serializeIssues(limited))
            }
        } catch (e: UnsupportedOperationException) {
            buildJsonObject {
                put("error", "Scanner API is not available in Burp Suite Community Edition")
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to get issues: ${e.message}")
            }
        }
    }

    /**
     * Generates a scan report in HTML or XML format.
     *
     * @param format Report format: "HTML" or "XML"; blank means HTML.
     * @param urlPrefix Optional URL prefix to filter issues.
     * @param severityFilter Optional list of severities to include.
     * @param outputPath File system path to write the report.
     * @return JSON object confirming report generation.
     */
    fun generateReport(
        format: String,
        urlPrefix: String?,
        severityFilter: List<String>?,
        outputPath: String
    ): JsonObject {
        EnumValidation.error(format, REPORT_FORMATS, "format")?.let { return it }
        severityFilter?.forEachIndexed { i, value ->
            EnumValidation.error(value, FILTER_SEVERITIES, "severity_filter[$i]", required = true)?.let { return it }
        }
        val reportFormat = reportFormat(format)
        val xml = reportFormat == ReportFormat.XML
        val wantedSeverities = severityFilter.orEmpty().map { severityName(it) }.toSet()
        return try {
            val allIssues = if (urlPrefix != null) {
                api.siteMap().issues(SiteMapFilter.prefixFilter(urlPrefix))
            } else {
                api.siteMap().issues()
            }

            val filteredIssues =
                if (wantedSeverities.isEmpty()) allIssues else allIssues.filter { it.severity().name in wantedSeverities }

            // Confine writes to a reports directory. Without this, an attacker-
            // controlled (or prompt-injected) outputPath is an arbitrary file-write
            // primitive (e.g. ~/.bashrc, autostart entries). Absolute paths outside
            // the base and ".." traversal are rejected; everything else resolves
            // under <user.home>/.raijin/reports/.
            val ext = if (xml) "xml" else "html"
            val baseDir = java.io.File(System.getProperty("user.home"), ".raijin/reports").canonicalFile
            baseDir.mkdirs()
            // Issue #20: a blank output_path (or one that resolves to the reports directory itself)
            // must NOT be handed to Burp as the report file — Burp would try to write to a directory
            // and throw FileNotFoundException ("Is a directory"). Fall back to a generated filename.
            val requestedName = outputPath.trim()
            val requested =
                if (requestedName.isBlank()) java.io.File(baseDir, "report-${System.currentTimeMillis()}.$ext")
                else java.io.File(requestedName)
            var target = (if (requested.isAbsolute) requested else java.io.File(baseDir, requestedName)).canonicalFile
            if (target.path != baseDir.path && !target.path.startsWith(baseDir.path + java.io.File.separator)) {
                return buildJsonObject {
                    put("error", "output_path escapes the allowed reports directory ($baseDir): $outputPath")
                }
            }
            // Still pointing at a directory (base dir or an existing dir) → give it a real filename.
            if (target.path == baseDir.path || target.isDirectory) {
                target = java.io.File(target, "report-${System.currentTimeMillis()}.$ext").canonicalFile
            }
            target.parentFile?.mkdirs()

            api.scanner().generateReport(filteredIssues, reportFormat, target.toPath())

            buildJsonObject {
                put("report_generated", true)
                put("format", if (xml) "XML" else "HTML")
                put("output_path", target.path)
                put("issue_count", filteredIssues.size)
            }
        } catch (e: UnsupportedOperationException) {
            buildJsonObject {
                put("error", "Scanner API is not available in Burp Suite Community Edition")
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to generate report: ${e.message}")
            }
        }
    }

    /**
     * Creates a custom audit issue and adds it to the site map.
     *
     * @return JSON object confirming issue creation.
     */
    fun createCustomIssue(
        name: String,
        detail: String?,
        remediation: String?,
        severity: String,
        confidence: String,
        url: String,
        request: String?,
        response: String?
    ): JsonObject {
        EnumValidation.error(severity, CREATE_SEVERITIES, "severity", required = true)?.let { return it }
        EnumValidation.error(confidence, ScanCheckLogic.CONFIDENCES, "confidence", required = true)?.let { return it }
        val issueSeverity = AuditIssueSeverity.valueOf(severityName(severity))
        val issueConfidence = AuditIssueConfidence.valueOf(confidence.trim().uppercase())
        return try {
            // The schema documents 'request'/'response' as plain HTTP messages,
            // so accept plain HTTP text directly. Base64 is still accepted for
            // backward compatibility (see decodeMessagePayload). Evidence is
            // attached only when both request and response are supplied.
            var requestResponse: HttpRequestResponse? = null
            if (request != null && response != null) {
                // A request built without an HttpService has no host to resolve, which NPEs
                // inside the Montoya API once the issue is filed into the site map (PR #13).
                val parts = ServiceParts.fromUrl(url)
                val httpService = HttpService.httpService(parts.host, parts.port, parts.useTls)

                val reqBytes = decodeMessagePayload(request)
                val httpRequest = HttpRequest.httpRequest(BurpByteArray.byteArray(*reqBytes)).withService(httpService)
                val respBytes = decodeMessagePayload(response)
                val httpResponse = HttpResponse.httpResponse(BurpByteArray.byteArray(*respBytes))
                requestResponse = HttpRequestResponse.httpRequestResponse(httpRequest, httpResponse)
            } else if ((request == null) != (response == null)) {
                throw IllegalArgumentException(
                    "Attaching HTTP evidence requires both 'request' and 'response' to be provided"
                )
            }

            val issue = AuditIssue.auditIssue(
                name,
                detail ?: "",
                remediation ?: "",
                url,
                issueSeverity,
                issueConfidence,
                null, // background
                null, // remediation background
                issueSeverity, // typicalSeverity
                if (requestResponse != null) listOf(requestResponse) else emptyList()
            )

            api.siteMap().add(issue)

            buildJsonObject {
                put("created", true)
                put("name", name)
                put("url", url)
                put("severity", issueSeverity.name)
                put("confidence", issueConfidence.name)
            }
        } catch (e: UnsupportedOperationException) {
            buildJsonObject {
                put("error", "Scanner API is not available in Burp Suite Community Edition")
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to create issue: ${e.message}")
            }
        }
    }

    /**
     * Creates an [AuditIssueHandler] that emits "scanner.issue" events on
     * the [EventBus] whenever Burp reports a new audit issue.
     *
     * Registered once during extension initialization in
     * [RaijinExtension.registerBurpHandlers].
     */
    fun createIssueHandler(): AuditIssueHandler {
        return AuditIssueHandler { issue ->
            val data = serializeIssue(issue)
            eventBus.emit("scanner.issue", data)
            ExchangeArchive.appendIssue(issue)
        }
    }

    // ---------------------------------------------------------------
    // Serialization helpers
    // ---------------------------------------------------------------

    /**
     * Serializes a list of [AuditIssue] objects to a [JsonArray].
     */
    private fun serializeIssues(issues: List<AuditIssue>): JsonArray {
        return buildJsonArray {
            issues.forEach { issue ->
                add(serializeIssue(issue))
            }
        }
    }

    /**
     * Serializes a single [AuditIssue] to a [JsonObject].
     */
    private fun serializeIssue(issue: AuditIssue): JsonObject {
        return buildJsonObject {
            put("name", issue.name())
            put("url", issue.baseUrl())
            put("severity", issue.severity().name)
            put("confidence", issue.confidence().name)
            put("detail", issue.detail() ?: "")
            put("remediation", issue.remediation() ?: "")
            put("type_index", issue.definition()?.typeIndex()?.toLong() ?: 0L)

            // Serialize request/response pairs
            val reqRespPairs = try {
                issue.requestResponses() ?: emptyList()
            } catch (_: Exception) {
                emptyList()
            }

            put("request_responses", buildJsonArray {
                reqRespPairs.forEach { rr ->
                    add(buildJsonObject {
                        try {
                            val req = rr.request()
                            put("request", req?.toString() ?: "")
                            put("request_url", req?.url() ?: "")
                            put("request_method", req?.method() ?: "")
                        } catch (_: Exception) {
                            put("request", "")
                        }
                        try {
                            val resp = rr.response()
                            put("response_status", resp?.statusCode()?.toLong() ?: 0L)
                            put("response_length", resp?.body()?.length()?.toLong() ?: 0L)
                        } catch (_: Exception) {
                            put("response_status", 0L)
                        }
                    })
                }
            })
        }
    }

    companion object {
        /** Formats a report can be written in; a blank `format` means HTML. */
        private val REPORT_FORMATS = setOf("html", "xml")

        /** Severities an issue can be created with; `info` is accepted for `information`. */
        private val CREATE_SEVERITIES = ScanCheckLogic.SEVERITIES + "info"

        /** Severities an issue can be filtered by. */
        private val FILTER_SEVERITIES = CREATE_SEVERITIES + "false_positive"

        /** The [AuditIssueSeverity] constant name for a validated severity value. */
        private fun severityName(value: String): String =
            value.trim().uppercase().let { if (it == "INFO") "INFORMATION" else it }

        /** The [ReportFormat] a validated `format` value names: XML, or the default HTML, blank included. */
        fun reportFormat(format: String): ReportFormat =
            if (format.trim().equals("xml", ignoreCase = true)) ReportFormat.XML else ReportFormat.HTML

        /**
         * Decodes an HTTP message payload supplied to [createCustomIssue].
         *
         * The `scanner_create_issue` schema documents `request`/`response` as
         * plain HTTP messages, so plain HTTP text is the primary supported form.
         * A payload is only treated as base64 when it is *unambiguously* base64:
         * it must consist solely of base64 alphabet characters (no spaces, CR,
         * LF, or other whitespace — all of which appear in any real HTTP message
         * but never in base64) and must decode cleanly. Anything else is encoded
         * as plain HTTP text with CRLF line endings, byte-accurate under an
         * explicit charset.
         */
        fun decodeMessagePayload(payload: String): ByteArray {
            if (looksLikeBase64(payload)) {
                try {
                    return Base64.getDecoder().decode(payload)
                } catch (_: IllegalArgumentException) {
                    // Not valid base64 after all; fall through to plain-text handling.
                }
            }
            // Treat as plain HTTP text. Normalize line endings to CRLF (Burp
            // parses on \r\n) using the repo's 3-step normalization, then encode
            // byte-accurately with an explicit charset.
            val normalized = RequestHygiene.normalizeCrlf(payload)
            return normalized.toByteArray(Charsets.ISO_8859_1)
        }

        /**
         * True only when [s] is a non-empty string drawn purely from the base64
         * alphabet (with optional '=' padding). Any whitespace — space, tab, CR,
         * or LF — disqualifies it, which cleanly excludes every real HTTP message
         * (all contain spaces in the request/status line and CRLF separators).
         */
        fun looksLikeBase64(s: String): Boolean {
            if (s.isEmpty() || s.length % 4 != 0) return false
            var sawPad = false
            for (c in s) {
                when {
                    c == '=' -> sawPad = true
                    sawPad -> return false // padding only allowed at the end
                    c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c == '+' || c == '/' -> {}
                    else -> return false
                }
            }
            return true
        }
    }
}
