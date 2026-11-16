package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.scanner.audit.AuditIssueHandler
import io.bitbytelab.raijin.core.EnumValidation
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.*

/**
 * Bridge wrapping the Montoya Scanner API (Pro only).
 *
 * All methods guard against [UnsupportedOperationException] thrown when
 * running on Burp Suite Community Edition, returning meaningful error
 * JSON instead of crashing.
 *
 * Crawl and audit tasks are handled by [ScannerTasks], issues and reports by [ScannerIssues].
 * Scan checks are registered here, through the [CustomScanCheckManager] the `scancheck_*` tools share.
 */
class ScannerBridge(
    private val api: MontoyaApi,
    eventBus: EventBus,
    stateManager: StateManager
) {
    private val checks = CustomScanCheckManager(api, stateManager)
    private val issues = ScannerIssues(api, eventBus)
    private val tasks = ScannerTasks(api, stateManager, issues)

    // ---- crawl and audit tasks ----------------------------------------------

    /** Starts a crawl from seed URLs; see [ScannerTasks.startCrawl]. */
    fun startCrawl(urls: List<String>, maxDepth: Int?, inScopeOnly: Boolean): JsonObject =
        tasks.startCrawl(urls, maxDepth, inScopeOnly)

    /** Starts an audit, optionally putting an auth header on its requests; see [ScannerTasks.startAudit]. */
    fun startAudit(
        urls: List<String>?,
        requests: List<String>?,
        auditMode: String?,
        crawlFirst: Boolean,
        insertionPointTypes: List<String>?,
        authHeaderName: String? = null,
        authHeaderValue: String? = null
    ): JsonObject =
        tasks.startAudit(urls, requests, auditMode, crawlFirst, insertionPointTypes, authHeaderName, authHeaderValue)

    /** The current status of a scan task; see [ScannerTasks.getTaskStatus]. */
    fun getTaskStatus(taskId: String): JsonObject = tasks.getTaskStatus(taskId)

    /** All scan tasks, optionally filtered by status substring; see [ScannerTasks.listTasks]. */
    fun listTasks(status: String?): JsonArray = tasks.listTasks(status)

    /** Deletes (cancels) a scan task; see [ScannerTasks.deleteTask]. */
    fun deleteTask(taskId: String): JsonObject = tasks.deleteTask(taskId)

    /** Adds a base64-encoded HTTP request to an audit task; see [ScannerTasks.addRequestToTask]. */
    fun addRequestToTask(
        taskId: String,
        request: String,
        host: String?,
        port: Int?,
        useTls: Boolean?
    ): JsonObject = tasks.addRequestToTask(taskId, request, host, port, useTls)

    /** Issues found by an audit task; see [ScannerTasks.getTaskIssues]. */
    fun getTaskIssues(taskId: String): JsonObject = tasks.getTaskIssues(taskId)

    // ---- issues and reports -------------------------------------------------

    /** The site map's issues, optionally filtered; see [ScannerIssues.getAllIssues]. */
    fun getAllIssues(
        urlPrefix: String?,
        severity: String?,
        confidence: String?,
        maxResults: Int?
    ): JsonObject = issues.getAllIssues(urlPrefix, severity, confidence, maxResults)

    /** Writes an HTML or XML report under the reports directory; see [ScannerIssues.generateReport]. */
    fun generateReport(
        format: String,
        urlPrefix: String?,
        severityFilter: List<String>?,
        outputPath: String
    ): JsonObject = issues.generateReport(format, urlPrefix, severityFilter, outputPath)

    /** Files a custom issue in the site map; see [ScannerIssues.createCustomIssue]. */
    fun createCustomIssue(
        name: String,
        detail: String?,
        remediation: String?,
        severity: String,
        confidence: String,
        url: String,
        request: String?,
        response: String?
    ): JsonObject = issues.createCustomIssue(name, detail, remediation, severity, confidence, url, request, response)

    /** The handler that emits "scanner.issue" events; see [ScannerIssues.createIssueHandler]. */
    fun createIssueHandler(): AuditIssueHandler = issues.createIssueHandler()

    // ---- scan checks --------------------------------------------------------

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
        tasks.shutdown()
    }

    private fun errorJson(message: String): JsonObject = buildJsonObject { put("error", message) }

    companion object {
        internal val AUDIT_MODES = ScannerTasks.AUDIT_MODES
        internal val CHECK_TYPES = setOf("passive", "active", "both")

        /** See [ScannerTasks.targetPrefixes]. */
        internal fun targetPrefixes(urls: List<String>, rawRequests: List<String>): Set<String> =
            ScannerTasks.targetPrefixes(urls, rawRequests)

        /** See [ScannerTasks.origin]. */
        internal fun origin(scheme: String, authority: String): String = ScannerTasks.origin(scheme, authority)

        /** See [ScannerIssues.decodeMessagePayload]. */
        internal fun decodeMessagePayload(payload: String): ByteArray = ScannerIssues.decodeMessagePayload(payload)

        /** See [ScannerIssues.looksLikeBase64]. */
        internal fun looksLikeBase64(s: String): Boolean = ScannerIssues.looksLikeBase64(s)

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
    }
}
