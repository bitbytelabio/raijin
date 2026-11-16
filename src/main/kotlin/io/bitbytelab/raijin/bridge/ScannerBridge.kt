package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.core.EnumValidation
import io.bitbytelab.raijin.core.ServiceParts
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import burp.api.montoya.scanner.Crawl
import burp.api.montoya.scanner.CrawlConfiguration
import burp.api.montoya.scanner.audit.Audit
import burp.api.montoya.scanner.audit.AuditIssueHandler
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.http.HttpService
import burp.api.montoya.sitemap.SiteMapFilter
import burp.api.montoya.core.ByteArray as BurpByteArray
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.safety.RequestHygiene
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.state.ScanTask
import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

/**
 * Bridge wrapping the Montoya Scanner API (Pro only).
 *
 * All methods guard against [UnsupportedOperationException] thrown when
 * running on Burp Suite Community Edition, returning meaningful error
 * JSON instead of crashing.
 */
class ScannerBridge(
    private val api: MontoyaApi,
    private val eventBus: EventBus,
    private val stateManager: StateManager
) {
    private val checks = CustomScanCheckManager(api, stateManager)

    private val authRules = AuditAuthRules(stateManager, observe = { task ->
        val audit = task.taskObject as? Audit
        AuditAuthRules.Observation(
            status = try { audit?.statusMessage() } catch (_: Throwable) { null },
            requestCount = try { audit?.requestCount() } catch (_: Throwable) { null },
        )
    })

    /** Audit task id -> site map URL prefixes of its targets, for [getTaskIssues] when Burp cannot list a task's issues. */
    private val auditTargets = ConcurrentHashMap<String, Set<String>>()

    /**
     * Starts a crawl task against the given URLs.
     *
     * Montoya's [CrawlConfiguration] only accepts seed URLs — there is no depth or scope
     * control anywhere in the Scanner API, so [maxDepth] cannot be enforced; it is accepted
     * for schema compatibility but always reported back as ignored. [inScopeOnly] *can* be
     * enforced: seeds outside Burp's target scope are filtered out before the crawl starts,
     * instead of being silently accepted and merely echoed back as before.
     *
     * @param urls Seed URLs for the crawler.
     * @param maxDepth Accepted but not enforced — see above.
     * @param inScopeOnly When true, out-of-scope seeds are dropped before crawling.
     * @return JSON object with the task ID, status, and which parameters were actually applied.
     */
    fun startCrawl(urls: List<String>, maxDepth: Int?, inScopeOnly: Boolean): JsonObject {
        val seeds = if (inScopeOnly) {
            urls.filter { try { api.scope().isInScope(it) } catch (_: Exception) { false } }
        } else {
            urls
        }
        val droppedCount = urls.size - seeds.size
        if (seeds.isEmpty()) {
            return buildJsonObject {
                put(
                    "error",
                    if (droppedCount > 0)
                        "All ${urls.size} seed URL(s) are out of scope; nothing to crawl. " +
                            "Pass in_scope_only=false, or add the target(s) to scope first."
                    else "No seed URLs provided."
                )
            }
        }

        val crawlTask: Crawl
        try {
            val crawlConfig = CrawlConfiguration.crawlConfiguration(*seeds.toTypedArray())
            crawlTask = api.scanner().startCrawl(crawlConfig)
        } catch (e: UnsupportedOperationException) {
            return buildJsonObject {
                put("error", "Scanner API is not available in Burp Suite Community Edition")
            }
        } catch (e: Exception) {
            return buildJsonObject {
                put("error", "Failed to start crawl: ${e.message}")
            }
        }

        val taskId = stateManager.generateId("scan")
        val baseline = sitemapResponseCount(seeds)
        stateManager.scanTasks[taskId] = ScanTask(
            taskId = taskId,
            type = "crawl",
            taskObject = crawlTask,
            createdAt = Instant.now().toString(),
            sitemapSeeds = seeds,
            sitemapBaselineCount = baseline
        )

        val statusMsg = try { crawlTask.statusMessage() } catch (_: Exception) { "started" }

        return buildJsonObject {
            put("task_id", taskId)
            put("type", "crawl")
            put("status", statusMsg)
            put("urls", buildJsonArray { seeds.forEach { add(it) } })
            put("in_scope_only", inScopeOnly)
            if (droppedCount > 0) put("seeds_dropped_out_of_scope", droppedCount)
            put("applied", buildJsonArray { add("urls"); if (inScopeOnly) add("in_scope_only") })
            put("ignored", buildJsonArray { if (maxDepth != null) add("max_depth") })
            if (maxDepth != null) {
                put(
                    "note",
                    "max_depth is not supported by Burp's Montoya Scanner API " +
                        "(CrawlConfiguration has no depth control) and was ignored."
                )
            }
            put("created_at", stateManager.scanTasks[taskId]!!.createdAt)
        }
    }

    /**
     * Starts an audit task.
     *
     * Montoya's [BuiltInAuditConfiguration] has exactly two values (legacy passive / legacy
     * active) — there is no "thorough" preset, so `thorough` and `normal` currently run the
     * identical configuration; this is reported back rather than left implicit.
     * [insertionPointTypes] cannot restrict the built-in audit (no such Montoya API exists)
     * and is reported as ignored when supplied. [urls] are now actually added to the audit
     * (previously accepted but never used — only [requests] reached the task). [crawlFirst]
     * now actually starts a real crawl when [urls] are given — Montoya has no crawl-then-audit
     * pipe, so the crawl's discoveries are not auto-added to this audit; the response says so.
     *
     * [authHeaderName] / [authHeaderValue] put one header on the audit's requests through traffic
     * rules that only apply to Scanner traffic to the audited hosts ([AuditAuthRules]). The rules
     * are removed when the audit ends or is deleted, and a start that fails leaves none behind.
     *
     * @param urls Target URLs to audit directly.
     * @param requests Optional base64-encoded HTTP requests to audit directly.
     * @param auditMode Audit mode: "light" (passive), "normal" or "thorough" (both active). Defaults to "normal".
     * @param crawlFirst When true and [urls] is non-empty, starts a real crawl on those URLs alongside the audit.
     * @param insertionPointTypes Accepted but not enforced — see above.
     * @param authHeaderName Name of a header to set on the audit's requests; needs [authHeaderValue].
     * @param authHeaderValue Value of that header.
     * @return JSON object with task ID, status, and which parameters were actually applied.
     */
    fun startAudit(
        urls: List<String>?,
        requests: List<String>?,
        auditMode: String?,
        crawlFirst: Boolean,
        insertionPointTypes: List<String>?,
        authHeaderName: String? = null,
        authHeaderValue: String? = null
    ): JsonObject {
        EnumValidation.error(auditMode, AUDIT_MODES, "audit_mode")?.let { return it }
        val mode = auditMode?.trim()?.lowercase().takeUnless { it.isNullOrEmpty() } ?: "normal"
        // Decoded once: the auth scope, the site map prefixes and the audit itself all read them.
        val rawRequests = requests.orEmpty().map { runCatching { Base64.getDecoder().decode(it) }.getOrNull() }
        val requestTexts = rawRequests.filterNotNull().map { String(it, Charsets.ISO_8859_1) }

        // Clients often send "" for a parameter they mean to leave out: a blank name with a blank
        // value is no auth header. An empty value under a real name is a header with an empty value.
        val headerName = authHeaderName?.takeIf { it.isNotBlank() }
        val headerValue = authHeaderValue.takeIf { headerName != null || !it.isNullOrBlank() }
        val auth = when {
            headerName == null && headerValue == null -> null
            headerName == null || headerValue == null ->
                return errorJson("auth_header_name and auth_header_value must be given together")
            else -> try {
                AuditAuthRules.plan(headerName, headerValue, urls.orEmpty(), requestTexts)
            } catch (e: IllegalArgumentException) {
                return errorJson(e.message ?: "Invalid auth header")
            }
        }

        var authRuleId: String? = null
        var started: Audit? = null
        var registered = false
        try {
            val builtInConfig =
                if (mode == "light") BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS
                else BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS
            val auditConfig = AuditConfiguration.auditConfiguration(builtInConfig)

            // The rules have to be in place before the audit sends its first request.
            if (auth != null) authRuleId = authRules.install(auth)
            val auditTask: Audit = api.scanner().startAudit(auditConfig)
            started = auditTask

            // Raw requests are added directly.
            var requestsAdded = 0
            var requestsFailed = 0
            rawRequests.forEach { decoded ->
                try {
                    if (decoded == null) throw IllegalArgumentException("not base64")
                    auditTask.addRequest(HttpRequest.httpRequest(BurpByteArray.byteArray(*decoded)))
                    requestsAdded++
                } catch (_: Exception) {
                    requestsFailed++
                }
            }

            // URLs are resolved to requests and added the same way (previously ignored entirely).
            var urlsAdded = 0
            val urlsFailed = mutableListOf<String>()
            urls?.forEach { url ->
                try {
                    auditTask.addRequest(HttpRequest.httpRequestFromUrl(url))
                    urlsAdded++
                } catch (_: Exception) {
                    urlsFailed.add(url)
                }
            }

            // crawl_first now actually crawls when there's something to seed it with. Montoya
            // has no API to chain a crawl's discoveries into this audit automatically, so the
            // two tasks run independently and the response says so explicitly.
            var crawlTaskId: String? = null
            var crawlSkipped: String? = null
            if (crawlFirst) {
                if (!urls.isNullOrEmpty()) {
                    val crawlResult = startCrawl(urls, null, false)
                    crawlTaskId = crawlResult["task_id"]?.jsonPrimitive?.contentOrNull
                    if (crawlTaskId == null) {
                        crawlSkipped = "crawl_first was requested but the crawl failed to start: " +
                            (crawlResult["error"]?.jsonPrimitive?.contentOrNull ?: "unknown error")
                    }
                } else {
                    crawlSkipped = "crawl_first was requested but no 'urls' were given to seed a crawl from"
                }
            }

            val taskId = stateManager.generateId("scan")
            val scanTask = ScanTask(
                taskId = taskId,
                type = "audit",
                taskObject = auditTask,
                createdAt = Instant.now().toString(),
                authRuleId = authRuleId
            )
            stateManager.scanTasks[taskId] = scanTask
            auditTargets[taskId] = targetPrefixes(urls.orEmpty(), requestTexts)
            authRuleId?.let { authRules.track(taskId, it) }
            registered = true

            val statusMsg = try { auditTask.statusMessage() } catch (_: Throwable) { "started" }

            return buildJsonObject {
                put("task_id", taskId)
                put("type", "audit")
                put("status", statusMsg)
                put("audit_mode", mode)
                put(
                    "audit_mode_effective",
                    if (builtInConfig == BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS) "passive" else "active"
                )
                put("requests_added", requestsAdded)
                if (requestsFailed > 0) put("requests_failed", requestsFailed)
                put("urls_added", urlsAdded)
                if (urlsFailed.isNotEmpty()) put("urls_failed", buildJsonArray { urlsFailed.forEach { add(it) } })
                put("crawl_first", crawlFirst)
                if (crawlTaskId != null) {
                    put("crawl_task_id", crawlTaskId)
                    put(
                        "crawl_note",
                        "The crawl runs independently; its newly discovered pages are NOT " +
                            "automatically added to this audit. Poll sitemap_query after it " +
                            "finishes and start a new audit with the URLs you want covered."
                    )
                }
                if (crawlSkipped != null) put("crawl_skipped", crawlSkipped)
                val ignored = buildList {
                    if (!insertionPointTypes.isNullOrEmpty()) add("insertion_point_types")
                    if (mode == "thorough") add("thorough (runs identically to normal)")
                }
                if (ignored.isNotEmpty()) {
                    put("ignored", buildJsonArray { ignored.forEach { add(it) } })
                    put(
                        "ignored_note",
                        "Burp's Montoya Scanner API cannot restrict the built-in audit by " +
                            "insertion point type, and BuiltInAuditConfiguration only has two " +
                            "values (passive/active) — there is no distinct 'thorough' preset."
                    )
                }
                put("created_at", scanTask.createdAt)
                if (auth != null) {
                    put("auth_rule_id", authRuleId)
                    put("auth_hosts", buildJsonArray { auth.hosts.forEach { add(it) } })
                    put(
                        "auth_note",
                        "'${auth.headerName}' is set on Scanner requests to auth_hosts only, replacing any " +
                            "value the request already has. The rule is removed when the audit ends or is deleted."
                    )
                }
            }
        } catch (e: UnsupportedOperationException) {
            return errorJson("Scanner API is not available in Burp Suite Community Edition")
        } catch (e: Exception) {
            return errorJson("Failed to start audit: ${e.message}")
        } finally {
            // However the start failed, an Error from an older Burp included: no rule and no
            // untracked audit is left behind.
            if (!registered) {
                authRuleId?.let { authRules.remove(it) }
                started?.let { audit -> runCatching { audit.delete() } }
            }
        }
    }

    /**
     * Returns the current status of a scan task.
     *
     * @param taskId The task identifier.
     * @return JSON object with status, request count, and error count.
     */
    fun getTaskStatus(taskId: String): JsonObject {
        val scanTask = stateManager.scanTasks[taskId]
            ?: return buildJsonObject { put("error", "Task not found: $taskId") }

        val task = scanTask.taskObject
        if (scanTask.authRuleId != null) authRules.sweep()
        val statusMsg = safeStatusMessage(task)
        val reqCount = safeRequestCount(task)
        val errCount = try { when (task) { is Crawl -> task.errorCount(); is Audit -> task.errorCount(); else -> -1 } } catch (_: Throwable) { -1 }
        val issueCount = try { if (task is Audit) task.issues().size else 0 } catch (_: Throwable) { -1 }

        return buildJsonObject {
            put("task_id", taskId)
            put("type", scanTask.type)
            put("status", statusMsg)
            if (reqCount >= 0) put("request_count", reqCount)
            if (errCount >= 0) put("error_count", errCount)
            if (task is Audit && issueCount >= 0) put("issue_count", issueCount)
            if (scanTask.type == "crawl" && scanTask.sitemapBaselineCount != null && !scanTask.sitemapSeeds.isNullOrEmpty()) {
                val current = sitemapResponseCount(scanTask.sitemapSeeds)
                put("sitemap_new_entries", current - scanTask.sitemapBaselineCount)
                put(
                    "sitemap_progress_note",
                    "Heuristic: site map entries with a response under the crawl's seed URL(s), " +
                        "now vs. at crawl start. Burp's own status/request_count above can be " +
                        "unreliable (e.g. stuck at 0) on some Burp versions — poll this twice and " +
                        "watch for it to stop growing instead."
                )
            }
            scanTask.authRuleId?.let { ruleId ->
                put("auth_rule_id", ruleId)
                put("auth_rule_active", authRules.isActive(taskId))
                authRules.releasedReason(taskId)?.let { put("auth_rule_released", it) }
            }
            put("created_at", scanTask.createdAt)
        }
    }

    /**
     * Counts distinct site map entries with a response under any of [seeds]' URL prefixes.
     * Used as the crawl-progress baseline/current-count in [startCrawl] / [getTaskStatus] —
     * see [io.bitbytelab.raijin.state.ScanTask.sitemapBaselineCount].
     */
    private fun sitemapResponseCount(seeds: List<String>): Int = try {
        seeds.flatMap { seed -> api.siteMap().requestResponses(SiteMapFilter.prefixFilter(seed)) }
            .distinctBy { it.request()?.url() }
            .count { it.hasResponse() }
    } catch (_: Exception) {
        0
    }

    /**
     * Lists all scan tasks, optionally filtered by status substring.
     *
     * @param status Optional status filter (case-insensitive substring match).
     * @return JSON array of task status objects.
     */
    fun listTasks(status: String?): JsonArray {
        // Pre-extract all task data outside the JSON builder to ensure
        // exceptions from unimplemented Montoya methods are caught cleanly.
        data class TaskEntry(val id: String, val type: String, val statusMsg: String, val reqCount: Int, val createdAt: String)

        authRules.sweep()
        val entries = stateManager.scanTasks.values.map { scanTask ->
            val msg = safeStatusMessage(scanTask.taskObject)
            val cnt = safeRequestCount(scanTask.taskObject)
            TaskEntry(scanTask.taskId, scanTask.type, msg, cnt, scanTask.createdAt)
        }

        return buildJsonArray {
            entries.filter { status == null || it.statusMsg.contains(status, ignoreCase = true) }
                .forEach { entry ->
                    add(buildJsonObject {
                        put("task_id", entry.id)
                        put("type", entry.type)
                        put("status", entry.statusMsg)
                        if (entry.reqCount >= 0) put("request_count", entry.reqCount)
                        put("created_at", entry.createdAt)
                    })
                }
        }
    }

    /** Safely get status message — Burp 2026.1.5 throws "Not yet implemented". */
    private fun safeStatusMessage(task: Any): String {
        return try {
            when (task) {
                is Crawl -> task.statusMessage()
                is Audit -> task.statusMessage()
                else -> "unknown"
            }
        } catch (_: Throwable) { "running" }
    }

    /** Safely get request count — may throw on some Burp versions. */
    private fun safeRequestCount(task: Any): Int {
        return try {
            when (task) {
                is Crawl -> task.requestCount()
                is Audit -> task.requestCount()
                else -> -1
            }
        } catch (_: Throwable) { -1 }
    }

    /**
     * Deletes (cancels) a scan task and removes it from state.
     *
     * @param taskId The task identifier.
     * @return JSON object confirming deletion or reporting an error.
     */
    fun deleteTask(taskId: String): JsonObject {
        val scanTask = stateManager.scanTasks[taskId]
            ?: return buildJsonObject { put("error", "Task not found: $taskId") }

        return try {
            when (val task = scanTask.taskObject) {
                is Crawl -> task.delete()
                is Audit -> task.delete()
            }
            stateManager.scanTasks.remove(taskId)
            authRules.forget(taskId)
            scanTask.authRuleId?.let { authRules.remove(it) }
            auditTargets.remove(taskId)
            buildJsonObject {
                put("task_id", taskId)
                put("deleted", true)
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("task_id", taskId)
                put("error", "Failed to delete task: ${e.message}")
            }
        }
    }

    /**
     * Adds an HTTP request to an existing audit task.
     *
     * @param taskId The audit task identifier.
     * @param request Base64-encoded HTTP request.
     * @param host Target host.
     * @param port Target port.
     * @param useTls Whether to use TLS.
     * @return JSON object confirming the request was added.
     */
    fun addRequestToTask(
        taskId: String,
        request: String,
        host: String?,
        port: Int?,
        useTls: Boolean?
    ): JsonObject {
        val scanTask = stateManager.scanTasks[taskId]
            ?: return buildJsonObject { put("error", "Task not found: $taskId") }

        val task = scanTask.taskObject
        if (task !is Audit) {
            return buildJsonObject { put("error", "Task $taskId is not an audit task") }
        }

        return try {
            val decoded = Base64.getDecoder().decode(request)
            var httpRequest = HttpRequest.httpRequest(BurpByteArray.byteArray(*decoded))
            val requestText = String(decoded, Charsets.ISO_8859_1)

            val prefixes = if (host != null) {
                val tls = useTls ?: false
                val servicePort = port ?: if (tls) 443 else 80
                httpRequest = httpRequest.withService(HttpService.httpService(host, servicePort, tls))
                setOf(origin(if (tls) "https" else "http", "$host:$servicePort"))
            } else {
                targetPrefixes(emptyList(), listOf(requestText))
            }

            task.addRequest(httpRequest)
            auditTargets.merge(taskId, prefixes) { known, added -> known + added }

            val targetHost = host ?: AuditAuthRules.authorityOfRawRequest(requestText)?.let { AuditAuthRules.hostOf(it) }
            buildJsonObject {
                put("task_id", taskId)
                put("request_added", true)
                authScopeNote(scanTask, targetHost)?.let { put("auth_note", it) }
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to add request: ${e.message}")
            }
        }
    }

    /**
     * Returns issues found by a specific audit task.
     *
     * Some Burp versions cannot list a task's issues. The response then carries the site map's
     * issues under the task's targets, marked `"source": "site_map"`: scans other than this task
     * may have reported some of them.
     *
     * @param taskId The audit task identifier.
     * @return JSON object with the issues.
     */
    fun getTaskIssues(taskId: String): JsonObject {
        val scanTask = stateManager.scanTasks[taskId]
            ?: return buildJsonObject { put("error", "Task not found: $taskId") }

        val task = scanTask.taskObject
        if (task !is Audit) {
            return buildJsonObject { put("error", "Task $taskId is not an audit task") }
        }

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
        val prefixes = auditTargets[taskId].orEmpty()
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
     * @param format Report format: "HTML" or "XML".
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
        EnumValidation.error(format, REPORT_FORMATS, "format", required = true)?.let { return it }
        severityFilter?.forEachIndexed { i, value ->
            EnumValidation.error(value, FILTER_SEVERITIES, "severity_filter[$i]", required = true)?.let { return it }
        }
        val xml = format.trim().equals("xml", ignoreCase = true)
        val wantedSeverities = severityFilter.orEmpty().map { severityName(it) }.toSet()
        return try {
            val allIssues = if (urlPrefix != null) {
                api.siteMap().issues(SiteMapFilter.prefixFilter(urlPrefix))
            } else {
                api.siteMap().issues()
            }

            val filteredIssues =
                if (wantedSeverities.isEmpty()) allIssues else allIssues.filter { it.severity().name in wantedSeverities }

            val reportFormat =
                if (xml) burp.api.montoya.scanner.ReportFormat.XML else burp.api.montoya.scanner.ReportFormat.HTML

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
     * Imports a BCheck script into the scanner.
     *
     * @param script The BCheck script content.
     * @return JSON object confirming import.
     */
    fun importBCheck(script: String): JsonObject {
        return try {
            val result = api.scanner().bChecks().importBCheck(script)
            when (result.status()) {
                burp.api.montoya.scanner.bchecks.BCheckImportResult.Status.LOADED_WITHOUT_ERRORS ->
                    buildJsonObject {
                        put("imported", true)
                        put("script_length", script.length)
                    }
                else ->
                    // LOADED_WITH_ERRORS: Burp parsed the script but rejected it.
                    // Report the import errors instead of a fake success.
                    buildJsonObject {
                        put("imported", false)
                        put("status", "error")
                        put("errors", buildJsonArray { result.importErrors().forEach { add(it) } })
                        put("hint", "Fix the reported BCheck errors and re-import.")
                    }
            }
        } catch (e: UnsupportedOperationException) {
            buildJsonObject {
                put("error", "BCheck import is not available in Burp Suite Community Edition")
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to import BCheck: ${e.message}")
            }
        }
    }

    /**
     * Registers a scan check that pattern-matches responses and, when active, the responses to
     * its payloads. It runs on the same engine as the `scancheck_*` checks
     * ([CustomScanCheckManager]): a passive check reports when the body regex or the header regex
     * matches; an active check reports when a payload makes the body regex match and the response
     * to the unmodified request does not.
     *
     * @param checkName Name of the registration; registering it again replaces the check.
     * @param checkType "passive", "active" or "both".
     * @param issueName Name of the issue to report when a match is found.
     * @param severity Issue severity: high, medium, low, information.
     * @param confidence Issue confidence: certain, firm, tentative.
     * @param detail Issue detail text.
     * @param remediation Issue remediation text.
     * @param passiveResponseMatch Regex to match against response body (passive checks).
     * @param passiveHeaderMatch Regex to match against response headers (passive checks).
     * @param activePayloads List of payload strings to inject (active checks).
     * @param activeResponseMatch Regex to match in the response after payload injection (active checks).
     * @return JSON object confirming registration.
     */
    fun registerScanCheck(
        checkName: String,
        checkType: String,
        issueName: String,
        severity: String,
        confidence: String,
        detail: String,
        remediation: String,
        passiveResponseMatch: String?,
        passiveHeaderMatch: String?,
        activePayloads: List<String>?,
        activeResponseMatch: String?
    ): JsonObject {
        return try {
            val definition = legacyCheckDefinition(
                checkName, checkType, issueName, severity, confidence, detail, remediation,
                passiveResponseMatch, passiveHeaderMatch, activePayloads, activeResponseMatch
            )
            val (check, replaced) = checks.register(definition)
            buildJsonObject {
                put("registered", true)
                put("id", check.id)
                put("check_name", definition.name)
                put("check_type", definition.mode)
                put("issue_name", definition.issueName)
                if (replaced != null) put("replaced", replaced.id)
            }
        } catch (e: InvalidCheckException) {
            errorJson(e.message ?: "Invalid scan check")
        } catch (e: UnsupportedOperationException) {
            errorJson("Scanner API is not available in Burp Suite Community Edition")
        } catch (e: Exception) {
            errorJson("Failed to register scan check: ${e.message}")
        }
    }

    /**
     * Deregisters a custom scan check by the name it was registered under, or by its id. Checks
     * created with the `scancheck_*` tools can be removed here too.
     *
     * @param checkName The name used when the check was registered.
     * @return JSON object confirming removal or reporting an error.
     */
    fun unregisterScanCheck(checkName: String): JsonObject {
        val check = checks.find(checkName)
            ?: return errorJson("Scan check not found: $checkName")

        return try {
            checks.remove(check)
            buildJsonObject {
                put("check_name", check.definition.name)
                put("id", check.id)
                put("unregistered", true)
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("check_name", checkName)
                put("error", "Failed to unregister scan check: ${e.message}")
            }
        }
    }

    /** Removes every audit auth rule and stops watching audits. Called on extension unload. */
    fun shutdown() {
        authRules.shutdown()
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

    private fun errorJson(message: String): JsonObject = buildJsonObject { put("error", message) }

    /** Says so when [host] lies outside the hosts the audit's auth header is limited to. */
    private fun authScopeNote(scanTask: ScanTask, host: String?): String? {
        val rule = stateManager.trafficRules.firstOrNull { it.ruleId == scanTask.authRuleId } ?: return null
        val scope = rule.matchHost ?: return null
        if (host == null || SafeRegex.matchesHostPattern(scope, host)) return null
        return "The audit's auth header is limited to the hosts the audit was started with and is not sent to '$host'."
    }

    companion object {
        internal val AUDIT_MODES = setOf("light", "normal", "thorough")
        internal val CHECK_TYPES = setOf("passive", "active", "both")
        internal val REPORT_FORMATS = setOf("html", "xml")

        /** Severities an issue can be created with; `info` is accepted for `information`. */
        private val CREATE_SEVERITIES = ScanCheckLogic.SEVERITIES + "info"

        /** Severities an issue can be filtered by. */
        private val FILTER_SEVERITIES = CREATE_SEVERITIES + "false_positive"

        /** The [AuditIssueSeverity] constant name for a validated severity value. */
        private fun severityName(value: String): String =
            value.trim().uppercase().let { if (it == "INFO") "INFORMATION" else it }

        /**
         * Site map URL prefixes (`scheme://host[:port]/`) covering what an audit of [urls] and
         * [rawRequests] targets. A raw request does not say which scheme it is for, so it yields both.
         */
        internal fun targetPrefixes(urls: List<String>, rawRequests: List<String>): Set<String> {
            val prefixes = LinkedHashSet<String>()
            urls.forEach { url ->
                val authority = AuditAuthRules.authorityOfUrl(url) ?: return@forEach
                prefixes += origin(url.substringBefore("://").lowercase(), authority)
            }
            rawRequests.forEach { raw ->
                val authority = AuditAuthRules.authorityOfRawRequest(raw) ?: return@forEach
                prefixes += origin("https", authority)
                prefixes += origin("http", authority)
            }
            return prefixes
        }

        /** `scheme://host[:port]/` the way Burp writes site map URLs: lower case, default port left out. */
        internal fun origin(scheme: String, authority: String): String {
            val defaultPort = if (scheme == "https") ":443" else ":80"
            return "$scheme://${authority.lowercase().removeSuffix(defaultPort)}/"
        }

        /**
         * The `scanner_register_check` parameters as a [CheckDefinition]: the passive regexes become
         * conditions joined by OR, and each payload an optional step whose response body must match.
         *
         * @throws InvalidCheckException when a value is invalid or the chosen type lacks its parameters.
         */
        internal fun legacyCheckDefinition(
            checkName: String,
            checkType: String,
            issueName: String,
            severity: String,
            confidence: String,
            detail: String,
            remediation: String,
            passiveResponseMatch: String?,
            passiveHeaderMatch: String?,
            activePayloads: List<String>?,
            activeResponseMatch: String?,
        ): CheckDefinition {
            if (checkName.isBlank()) throw InvalidCheckException("check_name must not be blank")
            if (issueName.isBlank()) throw InvalidCheckException("issue_name must not be blank")
            EnumValidation.error(checkType, CHECK_TYPES, "check_type", required = true)?.let {
                throw InvalidCheckException(it.getValue("error").jsonPrimitive.content)
            }
            val type = checkType.trim().lowercase()

            fun regexOn(location: String, param: String, pattern: String?): CheckCondition? {
                if (pattern == null) return null
                if (pattern.isEmpty()) throw InvalidCheckException("$param is empty; an empty regex matches every response")
                SafeRegex.validate(pattern, ignoreCase = true)?.let {
                    throw InvalidCheckException("Invalid $param regex: $it")
                }
                return CheckCondition(location, pattern, "matches")
            }

            val passiveConditions = if (type == "active") emptyList<CheckCondition>() else listOfNotNull(
                regexOn("response_body", "passive_response_match", passiveResponseMatch),
                regexOn("response_headers", "passive_header_match", passiveHeaderMatch),
            )
            val activeMatch =
                if (type == "passive") null else regexOn("response_body", "active_response_match", activeResponseMatch)
            val payloads = if (type == "passive") emptyList<String>() else activePayloads.orEmpty()
            val activeSteps = if (activeMatch == null || payloads.isEmpty()) null else payloads.map {
                ActiveStep(it, listOf(activeMatch), stopIfNoMatch = false)
            }

            if (type == "passive" && passiveConditions.isEmpty()) {
                throw InvalidCheckException("A passive check needs passive_response_match and/or passive_header_match")
            }
            if (type == "active" && activeSteps == null) {
                throw InvalidCheckException("An active check needs active_payloads and active_response_match")
            }
            if (passiveConditions.isEmpty() && activeSteps == null) {
                throw InvalidCheckException(
                    "check_type 'both' needs passive_response_match / passive_header_match, " +
                        "or active_payloads with active_response_match"
                )
            }

            return CheckDefinition(
                name = checkName,
                issueName = issueName,
                description = "",
                detail = detail,
                remediation = remediation,
                severity = ScanCheckLogic.severity(severity, "issue_severity"),
                confidence = ScanCheckLogic.confidence(confidence, "issue_confidence"),
                passive = passiveConditions.takeIf { it.isNotEmpty() }?.let { PassiveRule(it, MatchMode.ANY) },
                active = activeSteps,
            )
        }

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
        internal fun decodeMessagePayload(payload: String): ByteArray {
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
        internal fun looksLikeBase64(s: String): Boolean {
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
