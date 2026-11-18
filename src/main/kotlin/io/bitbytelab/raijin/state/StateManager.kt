package io.bitbytelab.raijin.state

import burp.api.montoya.core.Registration
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import kotlinx.serialization.json.JsonObject
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicLong

/**
 * A proxy interception/modification rule. Applied by the ProxyBridge when
 * matching requests or responses pass through Burp's proxy.
 *
 * @property ruleId Unique identifier (e.g. "prule-001").
 * @property type Whether this rule applies to "request" or "response".
 * @property matchHost Optional hostname glob to match (e.g. "*.example.com").
 * @property matchUrl Optional URL regex to match against the full URL.
 * @property matchMethod Optional HTTP method to match (e.g. "POST").
 * @property matchHeader Optional header name:value pattern to match.
 * @property matchBody Optional body content regex to match.
 * @property matchStatus Optional HTTP status code to match (response rules only).
 * @property action What to do when matched: "modify", "drop", or "tag".
 * @property modifyAddHeader Header to add (format "Name: Value", written as given: CR/LF and any other character included).
 * @property modifyRemoveHeader Header name to remove (every occurrence).
 * @property modifyReplaceHeader Map of header names to replacement values (headers the message already has).
 * @property modifyBodyRegex Regex pattern for body replacement.
 * @property modifyBodyReplacement Replacement string for body regex matches.
 * @property tagComment Comment to set on the proxy history item.
 * @property tagHighlight Highlight color to set on the proxy history item.
 * @property enabled Whether this rule is currently active.
 * @property modifyMethod HTTP method to send instead (request rules).
 * @property modifyPath New path including the query string (request rules); with [modifyPathRegex],
 *   the replacement for each match of that regex in the current path.
 * @property modifyPathRegex Regex searched in the path and query string; its matches are replaced by [modifyPath].
 * @property modifyStatus Status code to answer with instead (response rules).
 * @property modifySetHeader Map of header names to values: each replaces the header when the message has
 *   it (every occurrence, so it is never sent twice) and is added otherwise.
 */
data class ProxyRule(
    val ruleId: String,
    val type: String,
    val matchHost: String? = null,
    val matchUrl: String? = null,
    val matchMethod: String? = null,
    val matchHeader: String? = null,
    val matchBody: String? = null,
    val matchStatus: Int? = null,
    val action: String,
    val modifyAddHeader: String? = null,
    val modifyRemoveHeader: String? = null,
    val modifyReplaceHeader: Map<String, String>? = null,
    val modifyBodyRegex: String? = null,
    val modifyBodyReplacement: String? = null,
    val tagComment: String? = null,
    val tagHighlight: String? = null,
    @Volatile var enabled: Boolean = true,
    val modifyMethod: String? = null,
    val modifyPath: String? = null,
    val modifyPathRegex: String? = null,
    val modifyStatus: Int? = null,
    val modifySetHeader: Map<String, String>? = null,
)

/**
 * Tracks an active scanner crawl or audit task.
 *
 * @property taskId Unique identifier (e.g. "scan-001").
 * @property type "crawl" or "audit".
 * @property taskObject The actual Burp CrawlTask or AuditTask object.
 * @property createdAt ISO-8601 timestamp of task creation.
 */
data class ScanTask(
    val taskId: String,
    val type: String,
    val taskObject: Any,
    val createdAt: String,
    /** Crawl tasks only: the seed URL prefixes the baseline/progress count is scoped to. */
    val sitemapSeeds: List<String>? = null,
    /** Crawl tasks only: site map "has a response" count under [sitemapSeeds] at crawl start.
     *  Burp's own Crawl.requestCount()/statusMessage() can be unreliable (see
     *  ScannerBridge.safeRequestCount's comment), so scanner_task_status diffs the current
     *  count against this as a heuristic for crawl progress. */
    val sitemapBaselineCount: Int? = null,
    /** Audit tasks only: temporary traffic rule ID created for auth header injection, cleaned up when deleted/finished. */
    val authRuleId: String? = null
)

/**
 * Tracks a Burp Collaborator client instance and its associated server.
 *
 * @property clientId Unique identifier (e.g. "collab-001").
 * @property client The actual CollaboratorClient object from the Montoya API.
 * @property server The Collaborator server address.
 * @property createdAt ISO-8601 timestamp of client creation.
 */
data class CollaboratorClientState(
    val clientId: String,
    val client: Any,
    val server: String,
    val createdAt: String
)

/**
 * A record of an MCP tool invocation, stored for UI display and Burp tool integration.
 *
 * @property id Monotonically increasing id for ordering.
 * @property toolName The MCP tool that was called.
 * @property timestamp ISO-8601 timestamp.
 * @property durationMs How long the call took.
 * @property method HTTP method (if applicable).
 * @property url Target URL (if applicable).
 * @property host Target host (if applicable).
 * @property statusCode HTTP response status (if applicable).
 * @property isError Whether the tool call returned an error.
 * @property argsSummary Truncated JSON of the tool arguments.
 * @property resultSummary Truncated JSON of the tool result.
 * @property requestResponse The actual Burp HttpRequestResponse (if this was an HTTP tool).
 */
data class McpActivityEntry(
    val id: Long,
    val toolName: String,
    val timestamp: String,
    val durationMs: Long,
    val method: String,
    val url: String,
    val host: String,
    val statusCode: Int,
    val isError: Boolean,
    val argsSummary: String,
    val resultSummary: String,
    val requestResponse: HttpRequestResponse? = null,
    /** The call's result reported an out-of-scope target (scope_warning, out_of_scope, ...). */
    val outOfScope: Boolean = false,
)

/**
 * A structured, deduplicated finding recorded by the agent — its working memory
 * of confirmed/suspected issues, independent of Burp's native scanner issues.
 *
 * @property location Where the issue lives (e.g. "param:id", "header:X", "body").
 * @property cvssScore Numeric CVSS score as text ("" or "0.0"–"10.0").
 * @property cvssVector CVSS vector string (e.g. "CVSS:3.1/AV:N/AC:L/...").
 * @property owaspCategory OWASP Top 10 2021 category (normalized canonical form).
 * @property stepsToReproduce Ordered reproduction steps.
 * @property request Raw HTTP request evidence.
 * @property response Raw HTTP response evidence.
 */
data class StoredFinding(
    val id: String,
    val type: String,
    val severity: String,
    val url: String,
    val location: String,
    val detail: String,
    val evidence: String,
    val createdAt: String,
    val cvssScore: String = "",
    val cvssVector: String = "",
    val owaspCategory: String = "",
    val stepsToReproduce: String = "",
    val request: String = "",
    val response: String = ""
)

/**
 * Centralized, thread-safe state manager for all mutable runtime state.
 *
 * All collections use concurrent data structures so they can be safely
 * read and written from Burp handler threads, MCP request threads, and
 * the Ktor event loop concurrently.
 */
class StateManager {
    /** Active proxy interception/modification rules. */
    val proxyRules = CopyOnWriteArrayList<ProxyRule>()

    /** Active global HTTP traffic rules. */
    val trafficRules = CopyOnWriteArrayList<TrafficRule>()

    /** Active session handling rules. */
    val sessionRules = CopyOnWriteArrayList<SessionRule>()

    /** Live WebSocket connections keyed by connection id. */
    val websocketConnections = ConcurrentHashMap<String, WebSocketConnection>()

    /** Active scanner tasks keyed by task id. */
    val scanTasks = ConcurrentHashMap<String, ScanTask>()

    /** Active Collaborator clients keyed by client id. */
    val collaboratorClients = ConcurrentHashMap<String, CollaboratorClientState>()

    /** Agent-recorded structured findings (deduplicated working memory). */
    val findings = CopyOnWriteArrayList<StoredFinding>()

    /** Listeners notified when the agent records a finding (durable persistence). */
    val findingsListeners = CopyOnWriteArrayList<(StoredFinding) -> Unit>()

    /** Listeners notified when the agent removes a finding (durable persistence sync). */
    val findingsRemoveListeners = CopyOnWriteArrayList<(String) -> Unit>()

    /** Adds a recorded finding and notifies [findingsListeners] (e.g. the durable store). */
    fun addFinding(f: StoredFinding) {
        findings.add(f)
        findingsListeners.forEach { listener ->
            try { listener(f) } catch (_: Exception) {}
        }
    }

    /** Removes a finding by id. Returns true if one was found and removed. */
    fun removeFinding(id: String): Boolean {
        val removed = findings.removeIf { it.id == id }
        if (removed) {
            findingsRemoveListeners.forEach { listener ->
                try { listener(id) } catch (_: Exception) {}
            }
        }
        return removed
    }

    /**
     * Seeds the findings from the durable store on startup WITHOUT notifying
     * persistence listeners, and continues the shared id counter past the restored
     * numeric suffixes so subsequent generated ids never collide with restored ones.
     */
    fun restoreFindings(list: List<StoredFinding>) {
        findings.addAll(list)
        val maxSuffix = list.maxOfOrNull {
            it.id.substringAfterLast('-').toLongOrNull() ?: 0L
        } ?: 0L
        if (maxSuffix > idCounter.get()) idCounter.set(maxSuffix)
    }

    /** Names of dynamically registered scan check extensions. */
    val registeredScanChecks = CopyOnWriteArrayList<String>()

    /**
     * Montoya [Registration] handles for scan checks registered via
     * [io.bitbytelab.raijin.bridge.ScannerBridge.registerScanCheck], keyed by
     * check name. Retained so the registration is not leaked and the check
     * can be deregistered later (individually or on extension unload).
     */
    val scanCheckRegistrations = ConcurrentHashMap<String, Registration>()

    /** Names of dynamically registered payload processors. */
    val registeredPayloadProcessors = CopyOnWriteArrayList<String>()

    /** Montoya [Registration] handles for Intruder payload processors registered via MCP. */
    val intruderRegistrations = ConcurrentHashMap<String, Registration>()

    /** Rules for WebSocket message interception. */
    val websocketInterceptRules = CopyOnWriteArrayList<WebSocketInterceptRule>()

    /** Live Autorize-style proxy taps (clone + replay matching traffic under a second identity, in the background). */
    val autorizeRules = CopyOnWriteArrayList<AutorizeRule>()

    private val autorizeLog = AutorizeMatchLog()

    /** Flagged mismatches recorded by [autorizeRules] taps, newest first. Change them through [addAutorizeMatch] / [clearAutorizeMatches]. */
    val autorizeMatches: ConcurrentLinkedDeque<AutorizeMatch> get() = autorizeLog.matches

    /** Listeners notified of each recorded match (durable persistence); restored matches are not announced. */
    val autorizeMatchListeners: CopyOnWriteArrayList<(AutorizeMatch) -> Unit> get() = autorizeLog.addListeners

    /** Listeners notified after matches were cleared (durable persistence sync). */
    val autorizeMatchClearListeners: CopyOnWriteArrayList<() -> Unit> get() = autorizeLog.clearListeners

    /** Capacity of the retained match log (for callers restoring it on startup). */
    val autorizeMatchCapacity: Int get() = autorizeLog.capacity

    /** What each rule's tap did with the traffic it saw (replayed, flagged, skipped and why). */
    val autorizeActivity = AutorizeActivity()

    /** Dedup guard so a repeatedly-hit endpoint isn't replayed on every single proxied request; keyed by [autorizeSeenKey]. */
    private val autorizeSeen = AutorizeSeenGuard()

    /**
     * True the first time [key] is seen while its [endpoint] ([autorizeEndpointKey]) has query
     * variants to spare (caller should proceed); false otherwise (caller should skip).
     */
    fun autorizeSeenOnce(key: String, endpoint: String = key.substringBefore('?')): Boolean =
        autorizeSeen.seenOnce(key, endpoint)

    /** The inverse of [autorizeSeenOnce]: a replay that did not happen leaves [key] testable again. */
    fun unmarkAutorizeSeen(key: String, endpoint: String = key.substringBefore('?')) =
        autorizeSeen.unsee(key, endpoint)

    /** Records a flagged [AutorizeRule] mismatch; see [AutorizeMatchLog.add] for the bounds. */
    fun addAutorizeMatch(
        ruleId: String,
        method: String,
        url: String,
        originalStatus: Int,
        findings: List<JsonObject>,
        request: String,
        response: String,
        replays: List<AutorizeReplay> = emptyList(),
        softDenial: Boolean = false,
    ): AutorizeMatch =
        autorizeLog.add(ruleId, method, url, originalStatus, findings, request, response, replays, softDenial)

    /**
     * Seeds the matches from the durable store on startup (newest first) WITHOUT notifying
     * persistence listeners. Match ids continue past the restored ones, and so does the shared id
     * counter past the rule ids they name, so a new rule is never given the id of a rule whose
     * matches were restored.
     */
    fun restoreAutorizeMatches(entries: List<AutorizeMatch>) {
        autorizeLog.restore(entries)
        val maxSuffix = entries.maxOfOrNull { it.ruleId.substringAfterLast('-').toLongOrNull() ?: 0L } ?: 0L
        idCounter.accumulateAndGet(maxSuffix) { current, restored -> maxOf(current, restored) }
    }

    /** Clears seen-request dedup keys (either all or for a specific [ruleId]). */
    fun clearAutorizeSeen(ruleId: String? = null) = autorizeSeen.clear(ruleId)

    /** Clears matches (optionally scoped to one rule) and, when [resetSeen] is true, the dedup guard too. */
    fun clearAutorizeMatches(ruleId: String?, resetSeen: Boolean) {
        autorizeLog.clear(ruleId)
        if (resetSeen) clearAutorizeSeen(ruleId)
    }

    /** Recent MCP tool call activity entries for the native Burp UI tab. */
    val mcpActivity = ConcurrentLinkedDeque<McpActivityEntry>()
    private val mcpActivityIdCounter = AtomicLong(0)
    private val mcpActivityCount = java.util.concurrent.atomic.AtomicInteger(0)

    /** Listeners notified when new MCP activity entries are added. */
    val mcpActivityListeners = CopyOnWriteArrayList<(McpActivityEntry) -> Unit>()

    /** Maximum number of MCP activity entries retained. */
    private val maxMcpActivityEntries = 2000

    /** Clears all in-memory MCP activity (Activity-tab "Delete Saved History"). Issue #8. */
    fun clearMcpActivity() {
        while (mcpActivity.pollFirst() != null) {
            mcpActivityCount.decrementAndGet()
        }
        mcpActivityCount.set(0)
    }

    /**
     * Records a new MCP tool call activity entry and notifies listeners.
     */
    fun addMcpActivity(
        toolName: String,
        timestamp: String,
        durationMs: Long,
        method: String,
        url: String,
        host: String,
        statusCode: Int,
        isError: Boolean,
        argsSummary: String,
        resultSummary: String,
        requestResponse: HttpRequestResponse? = null,
        outOfScope: Boolean = false,
    ): McpActivityEntry {
        val entry = McpActivityEntry(
            id = mcpActivityIdCounter.incrementAndGet(),
            toolName = toolName,
            timestamp = timestamp,
            durationMs = durationMs,
            method = method,
            url = url,
            host = host,
            statusCode = statusCode,
            isError = isError,
            argsSummary = argsSummary,
            resultSummary = resultSummary,
            requestResponse = requestResponse,
            outOfScope = outOfScope,
        )
        mcpActivity.addFirst(entry)
        mcpActivityCount.incrementAndGet()
        while (mcpActivityCount.get() > maxMcpActivityEntries) {
            if (mcpActivity.pollLast() != null) mcpActivityCount.decrementAndGet() else break
        }
        mcpActivityListeners.forEach { listener ->
            try { listener(entry) } catch (_: Exception) {}
        }
        return entry
    }

    /** Capacity of the retained MCP activity buffer (for callers restoring it on startup). */
    val activityCapacity: Int get() = maxMcpActivityEntries

    /**
     * Seeds the activity buffer from persisted [entries] (expected newest-first) WITHOUT
     * notifying persistence listeners — used on extension startup to restore the dashboard
     * across reloads/restarts. Continues the id sequence past the restored ids to avoid
     * collisions with subsequent live entries.
     */
    fun restoreMcpActivity(entries: List<McpActivityEntry>) {
        var room = maxMcpActivityEntries - mcpActivityCount.get()
        for (e in entries) {
            if (room <= 0) break
            mcpActivity.addLast(e)
            mcpActivityCount.incrementAndGet()
            room--
        }
        val maxId = entries.maxOfOrNull { it.id } ?: 0L
        if (maxId > mcpActivityIdCounter.get()) mcpActivityIdCounter.set(maxId)
    }

    private val idCounter = AtomicLong(0)

    /**
     * Generates a unique id with the given [prefix], e.g. "prule-001".
     * The counter is shared across all id types to guarantee global uniqueness.
     */
    fun generateId(prefix: String): String {
        // Not String.format: under an Arabic or Persian default locale it writes non-ASCII digits.
        return "$prefix-${idCounter.incrementAndGet().toString().padStart(3, '0')}"
    }

    /**
     * Clears all state. Called during extension unload to release references
     * and allow garbage collection.
     */
    fun cleanup() {
        // Deregister live Burp registrations before dropping their handles so
        // they don't keep running after the extension unloads.
        scanCheckRegistrations.values.forEach { reg ->
            try { reg.deregister() } catch (_: Exception) {}
        }
        scanCheckRegistrations.clear()
        intruderRegistrations.values.forEach { reg ->
            try { reg.deregister() } catch (_: Exception) {}
        }
        intruderRegistrations.clear()
        registeredScanChecks.clear()
        registeredPayloadProcessors.clear()
        proxyRules.clear()
        trafficRules.clear()
        sessionRules.clear()
        websocketConnections.clear()
        websocketInterceptRules.clear()
        scanTasks.clear()
        collaboratorClients.clear()
        findings.clear()
        findingsListeners.clear()
        findingsRemoveListeners.clear()
        mcpActivity.clear()
        mcpActivityCount.set(0)
        mcpActivityListeners.clear()
        autorizeRules.clear()
        autorizeLog.reset()
        autorizeSeen.clear(null)
        autorizeActivity.clear()
    }

    companion object {
        /** Dedup key for one Autorize replay: rule, method, URL path and query parameters ([AutorizeSeenGuard.key]). */
        fun autorizeSeenKey(ruleId: String, method: String, url: String): String =
            AutorizeSeenGuard.key(ruleId, method, url)

        /** The endpoint a seen key belongs to: rule, method and URL without its query ([AutorizeSeenGuard.endpointKey]). */
        fun autorizeEndpointKey(ruleId: String, method: String, url: String): String =
            AutorizeSeenGuard.endpointKey(ruleId, method, url)
    }
}
