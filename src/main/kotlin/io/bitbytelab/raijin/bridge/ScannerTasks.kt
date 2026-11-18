package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import burp.api.montoya.scanner.Crawl
import burp.api.montoya.scanner.CrawlConfiguration
import burp.api.montoya.scanner.audit.Audit
import burp.api.montoya.sitemap.SiteMapFilter
import io.bitbytelab.raijin.core.EnumValidation
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.safety.ScopeGate
import io.bitbytelab.raijin.state.ScanTask
import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

/**
 * The crawl and audit tasks of [ScannerBridge]: starting them, reporting their status, adding
 * requests to an audit, listing an audit's issues (read by [ScannerIssues]) and deleting tasks.
 * Tasks are registered in [StateManager.scanTasks].
 *
 * The traffic rules that put an audit's auth header on its requests ([AuditAuthRules]) live as long
 * as the audit: they go when it ends or is deleted, when its start fails, and on [shutdown].
 */
internal class ScannerTasks(
    private val api: MontoyaApi,
    private val stateManager: StateManager,
    private val issues: ScannerIssues
) {
    private val authRules = AuditAuthRules(stateManager, observe = { task ->
        val audit = task.taskObject as? Audit
        AuditAuthRules.Observation(
            status = try { audit?.statusMessage() } catch (_: Throwable) { null },
            requestCount = try { audit?.requestCount() } catch (_: Throwable) { null },
        )
    })

    /** Advisory only: Scanner targets outside scope are flagged, never dropped. */
    private val scopeGate = ScopeGate(api)

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

        return withScopeAdvice(seeds, buildJsonObject {
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
        })
    }

    /**
     * [result] plus `scope_warnings` (distinct, at most [MAX_SCOPE_WARNINGS]) and `sent_out_of_scope`
     * for the [targets] outside Burp's scope. Advisory only: no target is dropped for it.
     */
    private fun withScopeAdvice(targets: List<String>, result: JsonObject): JsonObject {
        val warnings = targets.mapNotNull { scopeGate.advise(it, "scanner").warning }
        if (warnings.isEmpty()) return result
        return JsonObject(
            result + mapOf(
                "scope_warnings" to JsonArray(warnings.distinct().take(MAX_SCOPE_WARNINGS).map { JsonPrimitive(it) }),
                ScopeGate.SENT to JsonPrimitive(warnings.size),
            )
        )
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
        authHeaderName: String?,
        authHeaderValue: String?
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
            val targets = urls.orEmpty() + rawRequests.mapNotNull { decoded ->
                decoded?.let { runCatching { HttpRequest.httpRequest(BurpByteArray.byteArray(*it)).url() }.getOrNull() }
            }

            return withScopeAdvice(targets, buildJsonObject {
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
            })
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
            withScopeAdvice(listOfNotNull(runCatching { httpRequest.url() }.getOrNull()), buildJsonObject {
                put("task_id", taskId)
                put("request_added", true)
                authScopeNote(scanTask, targetHost)?.let { put("auth_note", it) }
            })
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to add request: ${e.message}")
            }
        }
    }

    /**
     * Returns issues found by a specific audit task; see [ScannerIssues.taskIssues].
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
        return issues.taskIssues(taskId, task, auditTargets[taskId].orEmpty())
    }

    /** Removes every audit auth rule and stops watching audits. Called on extension unload. */
    fun shutdown() {
        authRules.shutdown()
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
        val AUDIT_MODES = setOf("light", "normal", "thorough")

        private const val MAX_SCOPE_WARNINGS = 20

        /**
         * Site map URL prefixes (`scheme://host[:port]/`) covering what an audit of [urls] and
         * [rawRequests] targets. A raw request does not say which scheme it is for, so it yields both.
         */
        fun targetPrefixes(urls: List<String>, rawRequests: List<String>): Set<String> {
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
        fun origin(scheme: String, authority: String): String {
            val defaultPort = if (scheme == "https") ":443" else ":80"
            return "$scheme://${authority.lowercase().removeSuffix(defaultPort)}/"
        }
    }
}
