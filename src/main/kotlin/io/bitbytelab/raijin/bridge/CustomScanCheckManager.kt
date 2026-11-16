package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.core.Registration
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.scanner.AuditResult
import burp.api.montoya.scanner.ConsolidationAction
import burp.api.montoya.scanner.ScanCheck
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import io.bitbytelab.raijin.safety.BoundedHttp
import io.bitbytelab.raijin.state.StateManager
import java.time.Instant

/**
 * A custom scan check Burp is running, with the handle that removes it. It is stored in
 * [StateManager.scanCheckRegistrations] as that handle, so [StateManager.cleanup] deregisters it on
 * unload even if no bridge does.
 */
internal class TrackedScanCheck(
    val id: String,
    val definition: CheckDefinition,
    val deployedAt: Instant,
    private val handle: Registration,
) : Registration by handle

/**
 * Registers custom scan checks with Burp and keeps track of them. `scancheck_*` ([ScanCheckBridge])
 * and `scanner_register_check` ([ScannerBridge]) both go through here, so they share one check
 * engine and one list: a check made by either tool can be listed and removed by the other.
 *
 * The list lives in [StateManager.scanCheckRegistrations], keyed by check id, so every instance of
 * this class built on the same [StateManager] is a view of the same checks.
 */
internal class CustomScanCheckManager(
    private val api: MontoyaApi,
    private val stateManager: StateManager,
) {
    /** Registered checks, oldest first. */
    fun list(): List<TrackedScanCheck> =
        stateManager.scanCheckRegistrations.values.filterIsInstance<TrackedScanCheck>()
            .sortedWith(compareBy<TrackedScanCheck> { it.deployedAt }.thenBy { it.id })

    /** The check with this id, else the one registered under this name. */
    fun find(idOrName: String): TrackedScanCheck? =
        stateManager.scanCheckRegistrations[idOrName] as? TrackedScanCheck
            ?: list().lastOrNull { it.definition.name == idOrName }

    /**
     * Registers [definition] with Burp. A check already registered under the same name is replaced,
     * so re-creating a check while tuning it never leaves the old version running.
     *
     * @return the new check and the one it replaced, if any.
     */
    fun register(definition: CheckDefinition): Pair<TrackedScanCheck, TrackedScanCheck?> =
        synchronized(stateManager.scanCheckRegistrations) {
            val handle = api.scanner().registerScanCheck(Check(definition))
            val replaced = list().lastOrNull { it.definition.name == definition.name }
            if (replaced != null) {
                runCatching { replaced.deregister() }
                forget(replaced)
            }
            val check = TrackedScanCheck(stateManager.generateId("scheck"), definition, Instant.now(), handle)
            stateManager.scanCheckRegistrations[check.id] = check
            stateManager.registeredScanChecks.add(definition.name)
            check to replaced
        }

    /** Deregisters [check] from Burp. It stays tracked when Burp refuses, so the removal can be retried. */
    fun remove(check: TrackedScanCheck) = synchronized(stateManager.scanCheckRegistrations) {
        check.deregister()
        forget(check)
    }

    /** Deregisters every check on extension unload. */
    fun shutdown() = synchronized(stateManager.scanCheckRegistrations) {
        list().forEach { check ->
            runCatching { check.deregister() }
            forget(check)
        }
    }

    private fun forget(check: TrackedScanCheck) {
        stateManager.scanCheckRegistrations.remove(check.id)
        stateManager.registeredScanChecks.remove(check.definition.name)
    }

    /** One [CheckDefinition] as Burp runs it. Nothing here may throw: it is called on scanner threads. */
    private inner class Check(private val definition: CheckDefinition) : ScanCheck {
        private val severity = when (definition.severity) {
            "high" -> AuditIssueSeverity.HIGH
            "medium" -> AuditIssueSeverity.MEDIUM
            "low" -> AuditIssueSeverity.LOW
            else -> AuditIssueSeverity.INFORMATION
        }
        private val confidence = when (definition.confidence) {
            "certain" -> AuditIssueConfidence.CERTAIN
            "firm" -> AuditIssueConfidence.FIRM
            else -> AuditIssueConfidence.TENTATIVE
        }

        // Only the parts of a message the conditions look at are turned into text: a check on
        // headers must not decode every response body the scanner passes it.
        private val passiveParts = ScanCheckLogic.locations(definition.passive?.conditions.orEmpty())
        private val activeParts = ScanCheckLogic.locations(definition.active.orEmpty().flatMap { it.conditions })

        override fun passiveAudit(baseRequestResponse: HttpRequestResponse): AuditResult = issues {
            val rule = definition.passive ?: return@issues emptyList()
            val request = baseRequestResponse.request()
            val exchange = exchangeOf(request, baseRequestResponse.response(), passiveParts)
            if (!ScanCheckLogic.satisfied(rule.conditions, rule.mode, exchange)) return@issues emptyList()
            val url = runCatching { request.url() }.getOrNull().orEmpty()
            listOf(issue(definition.detail, url, listOf(baseRequestResponse)))
        }

        override fun activeAudit(
            baseRequestResponse: HttpRequestResponse,
            insertionPoint: AuditInsertionPoint,
        ): AuditResult = issues {
            val steps = definition.active ?: return@issues emptyList()
            val service = baseRequestResponse.httpService() ?: return@issues emptyList()
            val baseRequest = baseRequestResponse.request()
            val recorded = baseRequestResponse.response()?.let { exchangeOf(baseRequest, it, activeParts) }
            // One unmodified request, which runActive asks for before the first payload: the control,
            // and the baseline as well when the scanner recorded no response.
            val unmodified by lazy(LazyThreadSafetyMode.NONE) { send { baseRequest.withService(service) }?.first }
            val result = ScanCheckLogic.runActive(
                steps,
                baseline = { recorded ?: unmodified },
                send = { payload ->
                    send { insertionPoint.buildHttpRequestWithPayload(BurpByteArray.byteArray(payload)).withService(service) }
                },
                control = { unmodified },
            )
            if (!result.report) return@issues emptyList()
            // type() is newer than the rest of the interface; an older Burp fails with an Error, not an Exception.
            val pointType = try { insertionPoint.type().name } catch (_: Throwable) { "UNKNOWN" }
            val detail = ScanCheckLogic.activeDetail(
                definition.detail, insertionPoint.name().orEmpty(), pointType, result.novelPayloads
            )
            val url = runCatching { baseRequest.url() }.getOrNull().orEmpty()
            listOf(issue(detail, url, listOf(baseRequestResponse) + result.evidence))
        }

        override fun consolidateIssues(existingIssue: AuditIssue, newIssue: AuditIssue): ConsolidationAction = try {
            val duplicate = ScanCheckLogic.isDuplicate(
                existingIssue.name(), existingIssue.baseUrl(), existingIssue.detail(),
                newIssue.name(), newIssue.baseUrl(), newIssue.detail(),
            )
            if (duplicate) ConsolidationAction.KEEP_EXISTING else ConsolidationAction.KEEP_BOTH
        } catch (_: Exception) {
            ConsolidationAction.KEEP_BOTH
        }

        private fun issues(find: () -> List<AuditIssue>): AuditResult =
            AuditResult.auditResult(try { find() } catch (_: Exception) { emptyList<AuditIssue>() })

        /**
         * Sends one probe, bounded, and null when nothing usable came back. The probe leaves Burp as
         * extension traffic, which SCANNER-only audit auth rules skip, so their header is set here.
         */
        private fun send(build: () -> HttpRequest): Pair<CheckExchange, HttpRequestResponse>? = try {
            BoundedHttp.send(api, AuditAuthRules.withAuditAuth(stateManager, build()))
                ?.let { exchangeOf(it.request(), it.response(), activeParts) to it }
        } catch (_: Exception) {
            null
        }

        private fun issue(detail: String, url: String, evidence: List<HttpRequestResponse>): AuditIssue =
            AuditIssue.auditIssue(
                definition.issueName,
                detail,
                definition.remediation,
                url,
                severity,
                confidence,
                null,
                null,
                severity,
                evidence
            )
    }
}

/**
 * The parts of a Burp message a check condition can look at. Only those named in [parts]
 * ([CheckCondition.location] values) are read; the rest stay empty.
 */
internal fun exchangeOf(
    request: HttpRequest?,
    response: HttpResponse?,
    parts: Set<String> = ScanCheckLogic.LOCATIONS,
): CheckExchange {
    fun <T : Any> part(location: String, read: () -> T?): T? =
        if (location in parts) runCatching(read).getOrNull() else null

    return CheckExchange(
        requestUrl = part("request_url") { request?.url() }.orEmpty(),
        requestHeaders = part("request_headers") { request?.headers()?.let(::headerBlock) }.orEmpty(),
        requestBody = part("request_body") { request?.bodyToString() }.orEmpty(),
        hasResponse = response != null,
        statusCode = runCatching { response?.statusCode()?.toInt() }.getOrNull() ?: 0,
        responseHeaders = part("response_headers") { response?.headers()?.let(::headerBlock) }.orEmpty(),
        responseBody = part("response_body") { response?.bodyToString() }.orEmpty(),
        responseLength = part("response_length") { response?.body()?.length() } ?: 0,
    )
}

private fun headerBlock(headers: List<HttpHeader>): String =
    headers.joinToString("\r\n") { "${it.name()}: ${it.value()}" }
