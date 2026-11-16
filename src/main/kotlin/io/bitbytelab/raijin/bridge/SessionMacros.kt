package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ToolType
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.message.params.HttpParameter
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.safety.BoundedHttp
import io.bitbytelab.raijin.safety.HeaderSafety
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.safety.ScopeGate
import io.bitbytelab.raijin.state.SessionMacro
import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import java.time.Instant
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.Collections
import java.util.Locale
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicLong

/**
 * Session login macros ([SessionMacro], the `session_macro_*` tools). When a response shows that
 * the session expired, the macro's stored requests are replayed to log in again, and the request
 * that got the expired response is sent once more with the refreshed session; its response replaces
 * the expired one and carries [HttpExchangeJson.REAUTHENTICATED_HEADER] (the macro's name).
 *
 * How it stays safe on live traffic:
 * - Loop-safe: macro steps and the retry carry [MARKER_HEADER], which [HttpGlobalHandler] strips
 *   before the wire and tracks by message id; their responses never trigger a macro. Steps are sent
 *   as stored (no session-rule value or macro cookie is injected into them), but session rules do
 *   extract from their responses: that is how a new token is captured.
 * - Bounded: one run per macro at a time (a concurrent trigger waits for the running one, then
 *   retries with its result), [SessionMacro.minIntervalMs] between automatic runs, a hard timeout
 *   per step and for the retry, at most [MAX_STEPS] steps and [MAX_RUN_MS] per run, and a circuit
 *   breaker that suspends the macro after [SessionMacro.maxFailures] runs in a row that did not help.
 * - Never logs in a deliberately unauthenticated request: Raijin's internal probes never trigger a
 *   macro nor get its cookies, and by default only a request that carried credentials triggers one.
 * - Sends happen on the caller's thread (Burp's handler thread for an automatic run, as Burp's own
 *   session handling does) and no lock is held while sending, so a nested send's handler callbacks
 *   never wait on this engine.
 *
 * The constructor makes no Burp call: everything touches [api] at use time.
 */
internal class SessionMacroEngine(
    private val api: MontoyaApi,
    private val eventBus: EventBus,
    private val stateManager: StateManager,
    private val chain: HttpRequestChain,
    private val clock: () -> Long = System::nanoTime,
) {

    /** What a request carrying [MARKER_HEADER] is. */
    enum class Traffic(val marker: String) {
        STEP("step"),
        RETRY("retry");

        companion object {
            fun of(marker: String?): Traffic? = entries.firstOrNull { it.marker.equals(marker?.trim(), ignoreCase = true) }
        }
    }

    /** The response that replaces an expired one, obtained by [macro]. */
    class Reauthenticated(val response: HttpResponse, val macro: String)

    private class Entry(val macro: SessionMacro) {
        val state = MacroRunState(macro.minIntervalMs * 1_000_000, macro.maxFailures)
    }

    private class StepReport(val index: Int, val result: HttpRequestChain.StepResult, val cookies: Map<String, String?>)

    private class RunOutcome(
        val success: Boolean,
        val steps: List<StepReport>,
        val variables: Map<String, String>,
        val learned: Map<String, String?>,
        val error: String?,
    )

    @Volatile
    private var entries: List<Entry> = emptyList()
    private val entriesLock = Any()

    /** Session epoch: advanced by every successful run, so a request sent before it is known to be stale. */
    private val epoch = AtomicLong()

    private val scopeGate = ScopeGate(api)

    /** Macro steps and retries on their way, by message id: their responses never trigger a macro. */
    private val macroTraffic: MutableMap<Int, Traffic> = boundedIdMap()

    /** The [epoch] each request a macro covers was sent in, by message id. */
    private val sentEpochs: MutableMap<Int, Long> = boundedIdMap()

    // ---------------------------------------------------------------
    // Definitions (session_macro_set / _list / _remove / _run)
    // ---------------------------------------------------------------

    /** Stores [macro], replacing one of the same name (and its state: counters, suspension, cookies). */
    fun set(macro: SessionMacro): JsonObject {
        validate(macro)?.let { return buildJsonObject { put("error", it) } }
        val replaced: Boolean
        val total: Int
        synchronized(entriesLock) {
            val current = entries
            val index = current.indexOfFirst { it.macro.name == macro.name }
            replaced = index >= 0
            entries = if (replaced) current.toMutableList().also { it[index] = Entry(macro) } else current + Entry(macro)
            total = entries.size
        }
        return buildJsonObject {
            put("status", if (replaced) "replaced" else "created")
            definition(macro).forEach { (k, v) -> put(k, v) }
            put("total_macros", total)
        }
    }

    fun remove(name: String): JsonObject {
        val removed: Boolean
        val remaining: Int
        synchronized(entriesLock) {
            val current = entries
            entries = current.filterNot { it.macro.name == name }
            removed = entries.size != current.size
            remaining = entries.size
        }
        return buildJsonObject {
            if (removed) {
                put("status", "removed")
                put("name", name)
                put("remaining_macros", remaining)
            } else {
                put("error", "No session macro named '$name'")
            }
        }
    }

    fun list(): JsonObject {
        val snapshot = entries
        return buildJsonObject {
            put("count", snapshot.size)
            putJsonArray("macros") {
                snapshot.forEach { entry ->
                    add(JsonObject(definition(entry.macro) + ("state" to entry.state.snapshot())))
                }
            }
        }
    }

    /**
     * Runs [name] now, whatever its trigger, interval or suspension (priming and debugging), and
     * reports every step. A run that completes every step also resumes a suspended macro.
     */
    fun runNow(name: String): JsonObject {
        val entry = entries.firstOrNull { it.macro.name == name }
            ?: return buildJsonObject { put("error", "No session macro named '$name'") }
        var ticket = entry.state.beginManual()
        if (ticket is MacroRunState.Ticket.Wait) {
            awaitRun(ticket.run)
            ticket = entry.state.beginManual()
        }
        if (ticket !is MacroRunState.Ticket.Run) {
            return buildJsonObject { put("error", "Session macro '$name' is already running; try again when it has finished") }
        }
        val before = sessionValues()
        val started = clock()
        val outcome = execute(entry, ticket, manual = true, triggerUrl = null)
        val elapsedMs = (clock() - started) / 1_000_000
        return buildJsonObject {
            put("macro", name)
            put("success", outcome.success)
            outcome.error?.let { put("reason", it) }
            put("elapsed_ms", elapsedMs)
            put("total_steps", entry.macro.steps.size)
            putJsonArray("steps") { outcome.steps.forEach { add(stepJson(it)) } }
            putJsonObject("variables") { outcome.variables.forEach { (k, v) -> put(k, v) } }
            putJsonObject("learned_cookies") { outcome.learned.forEach { (k, v) -> put(k, v) } }
            putJsonArray("session_rules_updated") { changedRules(before).forEach { add(it) } }
            put("state", entry.state.snapshot())
        }
    }

    // ---------------------------------------------------------------
    // Hooks of the global HTTP handler
    // ---------------------------------------------------------------

    /** Whether any macro is enabled and not suspended. */
    fun hasActive(): Boolean = entries.any { it.macro.enabled && !it.state.suspended }

    fun trackMacroTraffic(messageId: Int, traffic: Traffic) {
        macroTraffic[messageId] = traffic
    }

    fun takeMacroTraffic(messageId: Int): Traffic? = macroTraffic.remove(messageId)

    /** Records the session epoch of an outgoing request, when an active macro covers it. */
    fun noteSent(messageId: Int, url: String, toolName: String?, suiteInScope: () -> Boolean) {
        val covered = entries.any {
            it.macro.enabled && !it.state.suspended && SessionMacroTrigger.covers(it.macro, toolName, url, suiteInScope)
        }
        if (covered) sentEpochs[messageId] = epoch.get()
    }

    fun takeSentEpoch(messageId: Int): Long? = sentEpochs.remove(messageId)

    /**
     * [request] with the cookies the enabled macros covering it ([SessionMacro.toolFilter] and
     * scope) learned, each replacing a same-named cookie the request sends. A cookie the request
     * does not send is never added.
     */
    fun applyCookies(request: HttpRequest, url: String, toolName: String?, suiteInScope: () -> Boolean): HttpRequest {
        var current = request
        var present: Map<String, String>? = null
        for (entry in entries) {
            val macro = entry.macro
            if (!macro.enabled || !macro.updateCookies) continue
            val learned = entry.state.cookies
            if (learned.isEmpty() || !SessionMacroTrigger.covers(macro, toolName, url, suiteInScope)) continue
            val have = present ?: requestCookies(current).also { present = it }
            val replacements = SessionMacroCookies.replacements(have, learned)
            if (replacements.isEmpty()) continue
            current = current.withUpdatedParameters(replacements.map { (name, value) -> HttpParameter.cookieParameter(name, value) })
            present = have + replacements
        }
        return current
    }

    /**
     * Re-establishes the session when [response] (to [received]'s request, sent by [toolName] in
     * session epoch [sentEpoch]) shows that it expired and a macro covers it: runs the macro (or
     * waits for its running run) and sends the request once more. Null when no macro triggers or
     * the session could not be refreshed; the caller then keeps [response].
     */
    fun onResponse(received: HttpResponseReceived, response: HttpResponse, toolName: String?, sentEpoch: Long?): Reauthenticated? {
        val active = entries.filter { it.macro.enabled && !it.state.suspended }
        if (active.isEmpty()) return null
        val status = response.statusCode().toInt()
        if (active.none { status in it.macro.triggerStatus || it.macro.triggerRegex != null }) return null
        val initiating = received.initiatingRequest() ?: return null
        val url = initiating.url()
        val suite by lazy { isInSuiteScope(url) }
        val text by lazy { responseText(response) }
        val credentials by lazy { carriesCredentials(initiating, url) { suite } }
        val exchange = SessionMacroTrigger.Exchange(
            url = url,
            toolName = toolName,
            statusCode = status,
            suiteInScope = { suite },
            responseText = { text },
            carriesCredentials = { credentials },
        )
        val entry = active.firstOrNull {
            SessionMacroTrigger.decide(it.macro, it.state.suspended, exchange) == SessionMacroTrigger.Verdict.TRIGGER
        } ?: return null

        val owner = when (val ticket = entry.state.begin(clock(), sentEpoch)) {
            is MacroRunState.Ticket.Run -> {
                if (!execute(entry, ticket, manual = false, triggerUrl = url).success) return null
                true
            }
            is MacroRunState.Ticket.Wait -> {
                if (!awaitRun(ticket.run)) return null
                false
            }
            MacroRunState.Ticket.Retry -> false
            MacroRunState.Ticket.Throttled, MacroRunState.Ticket.Suspended -> return null
        }
        return retry(entry, initiating, url, toolName, { suite }, owner)
    }

    // ---------------------------------------------------------------
    // Running
    // ---------------------------------------------------------------

    /** Runs [entry]'s steps under [ticket]; always ends the run, whatever happens. */
    private fun execute(entry: Entry, ticket: MacroRunState.Ticket.Run, manual: Boolean, triggerUrl: String?): RunOutcome {
        val started = clock()
        var outcome = RunOutcome(false, emptyList(), emptyMap(), emptyMap(), "Run aborted")
        try {
            outcome = runSteps(entry.macro, started)
        } catch (e: Exception) {
            outcome = RunOutcome(false, emptyList(), emptyMap(), emptyMap(), "Run failed: ${e.message ?: e::class.simpleName}")
        } finally {
            val finished = outcome
            val suspendedNow = entry.state.finish(
                ticket, clock(), manual, finished.success,
                if (finished.success) epoch.incrementAndGet() else 0L,
                finished.learned, finished.error, triggerUrl,
            )
            eventBus.emit("session.macro.run", buildJsonObject {
                put("macro", entry.macro.name)
                put("trigger", if (manual) "manual" else "automatic")
                triggerUrl?.let { put("url", it) }
                put("success", finished.success)
                put("steps_completed", finished.steps.count { it.result.success })
                put("total_steps", entry.macro.steps.size)
                finished.error?.let { put("reason", it) }
                put("elapsed_ms", (clock() - started) / 1_000_000)
                putJsonArray("learned_cookies") { finished.learned.keys.forEach { add(it) } }
                put("timestamp", Instant.now().toString())
            })
            if (suspendedNow) emitSuspended(entry)
        }
        return outcome
    }

    private fun runSteps(macro: SessionMacro, started: Long): RunOutcome {
        val deadline = started + MAX_RUN_MS * 1_000_000
        val mode = HttpModes.resolve(macro.httpMode)
        val variables = LinkedHashMap<String, String>()
        val learned = LinkedHashMap<String, String?>()
        val reports = ArrayList<StepReport>()
        for ((index, step) in macro.steps.withIndex()) {
            val remainingMs = (deadline - clock()) / 1_000_000
            if (remainingMs <= 0) {
                return RunOutcome(false, reports, variables, learned, "Stopped before step $index: a run may take at most $MAX_RUN_MS ms")
            }
            val result = chain.run(
                listOf(HttpRequestChain.substituteVariables(step, variables)),
                mode,
                stopOnError = true,
                timeoutMs = minOf(macro.stepTimeoutMs, remainingMs),
                prepare = { it.withHeader(MARKER_HEADER, Traffic.STEP.marker) },
                siteMapNote = null,
            ).steps.single()
            variables.putAll(result.extracted)
            val cookies = result.exchange?.response()?.let { setCookies(it) }.orEmpty()
            if (macro.updateCookies) learned.putAll(cookies)
            reports += StepReport(index, result, cookies)
            if (!result.success) return RunOutcome(false, reports, variables, learned, "Step $index failed: ${result.error ?: "unknown error"}")
        }
        return RunOutcome(true, reports, variables, learned, null)
    }

    /**
     * Sends [initiating] once more with the refreshed session (macro cookies, then session-rule
     * values), marked so it never triggers a macro itself. Only the run's [owner] decides whether the
     * run helped (for the circuit breaker).
     */
    private fun retry(
        entry: Entry,
        initiating: HttpRequest,
        url: String,
        toolName: String?,
        suiteInScope: () -> Boolean,
        owner: Boolean,
    ): Reauthenticated? {
        val macro = entry.macro
        if (scopeGate.deny(url) != null) {
            retried(entry, owner, url, null, "Retry blocked by scope policy (mcp_scope_mode=enforce)")
            return null
        }
        var request = applyCookies(initiating, url, toolName, suiteInScope)
        request = SessionInjection.applyRules(stateManager.sessionRules, request, url, suiteInScope, eventBus)
        val marked = request.withHeader(MARKER_HEADER, Traffic.RETRY.marker)
        val mode = if (initiating.httpVersion().equals("HTTP/2", ignoreCase = true)) HttpMode.HTTP_2 else HttpMode.HTTP_1
        var failure: String? = null
        val exchange = BoundedHttp.runBounded(macro.stepTimeoutMs) {
            try {
                api.http().sendRequest(marked, mode)
            } catch (e: Exception) {
                failure = e.message ?: e::class.simpleName
                null
            }
        }
        val response = exchange?.response()
        if (response == null) {
            val reason = failure ?: if (exchange == null) "Retry timed out after ${macro.stepTimeoutMs} ms" else "Retry got no response"
            retried(entry, owner, url, null, reason)
            return null
        }
        val status = response.statusCode().toInt()
        val helped = !SessionMacroTrigger.expired(macro, status) { responseText(response) }
        retried(entry, owner, url, status, if (helped) null else "The retry still shows an expired session")
        return Reauthenticated(response.withAddedHeader(HttpExchangeJson.REAUTHENTICATED_HEADER, macro.name), macro.name)
    }

    private fun retried(entry: Entry, owner: Boolean, url: String, status: Int?, failure: String?) {
        val suspendedNow = entry.state.retried(helped = failure == null, owner = owner, error = failure)
        eventBus.emit("session.macro.retry", buildJsonObject {
            put("macro", entry.macro.name)
            put("url", url)
            status?.let { put("status_code", it) }
            put("helped", failure == null)
            failure?.let { put("reason", it) }
            put("timestamp", Instant.now().toString())
        })
        if (suspendedNow) emitSuspended(entry)
    }

    private fun emitSuspended(entry: Entry) {
        eventBus.emit("session.macro.suspended", buildJsonObject {
            put("macro", entry.macro.name)
            put("max_failures", entry.macro.maxFailures)
            put("reason", "${entry.macro.maxFailures} runs in a row did not re-establish the session; session_macro_run or session_macro_set resumes it")
            put("timestamp", Instant.now().toString())
        })
    }

    /** Waits for a running run; true when it succeeded. */
    private fun awaitRun(run: CompletableFuture<Boolean>): Boolean = try {
        run.get(MAX_RUN_MS + WAIT_GRACE_MS, TimeUnit.MILLISECONDS)
    } catch (_: InterruptedException) {
        Thread.currentThread().interrupt()
        false
    } catch (_: TimeoutException) {
        false
    } catch (_: ExecutionException) {
        false
    }

    // ---------------------------------------------------------------
    // Reading messages
    // ---------------------------------------------------------------

    private fun isInSuiteScope(url: String): Boolean = try {
        api.scope().isInScope(url)
    } catch (_: Exception) {
        false
    }

    /** Whether [request] carries credentials: an Authorization or Cookie header, or a value a session rule injects. */
    private fun carriesCredentials(request: HttpRequest, url: String, suiteInScope: () -> Boolean): Boolean {
        if (!request.headerValue("Authorization").isNullOrBlank()) return true
        if (!request.headerValue("Cookie").isNullOrBlank()) return true
        return stateManager.sessionRules.any { rule ->
            rule.enabled && rule.lastExtractedValue != null &&
                SessionRuleEngine.inScope(rule.scope, rule.scopePattern, url, suiteInScope) &&
                SessionInjection.carries(rule, request)
        }
    }

    private fun requestCookies(request: HttpRequest): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        for (cookie in request.parameters(HttpParameterType.COOKIE)) out.putIfAbsent(cookie.name(), cookie.value())
        return out
    }

    /** The cookies the `Set-Cookie` headers of [response] set (a null value deletes one), every header read. */
    private fun setCookies(response: HttpResponse): Map<String, String?> {
        val now = Instant.now()
        val out = LinkedHashMap<String, String?>()
        for (header in response.headers()) {
            if (!header.name().equals("Set-Cookie", ignoreCase = true)) continue
            val (name, value) = SessionMacroCookies.parseSetCookie(header.value(), now) ?: continue
            out[name] = value
        }
        return out
    }

    /** What [SessionMacro.triggerRegex] is matched against: status line, headers, blank line, then the body. */
    private fun responseText(response: HttpResponse): String {
        val text = StringBuilder()
        text.append(response.httpVersion()).append(' ').append(response.statusCode().toInt())
        response.reasonPhrase()?.takeIf { it.isNotEmpty() }?.let { text.append(' ').append(it) }
        text.append("\r\n")
        for (header in response.headers()) text.append(header.name()).append(": ").append(header.value()).append("\r\n")
        text.append("\r\n")
        return SessionMacroTrigger.boundedText(text, response.bodyToString())
    }

    private fun sessionValues(): Map<String, String?> = stateManager.sessionRules.associate { it.ruleName to it.lastExtractedValue }

    private fun changedRules(before: Map<String, String?>): List<String> =
        stateManager.sessionRules.filter { it.lastExtractedValue != null && it.lastExtractedValue != before[it.ruleName] }.map { it.ruleName }

    // ---------------------------------------------------------------
    // JSON
    // ---------------------------------------------------------------

    private fun definition(macro: SessionMacro): JsonObject = buildJsonObject {
        put("name", macro.name)
        put("enabled", macro.enabled)
        putJsonArray("steps") { macro.steps.forEach { add(stepSummary(it)) } }
        put("scope", macro.scope)
        macro.scopePattern?.let { put("scope_pattern", it) }
        putJsonArray("trigger_status") { macro.triggerStatus.sorted().forEach { add(it) } }
        macro.triggerRegex?.let { put("trigger_regex", it) }
        putJsonArray("tool_filter") { macro.toolFilter.forEach { add(it) } }
        put("require_credentials", macro.requireCredentials)
        put("update_cookies", macro.updateCookies)
        put("min_interval_ms", macro.minIntervalMs)
        put("max_failures", macro.maxFailures)
        put("step_timeout_ms", macro.stepTimeoutMs)
        put("http_mode", macro.httpMode ?: "AUTO")
    }

    /** `METHOD url`, or the request line of a raw request (its credentials are not echoed). */
    private fun stepSummary(step: JsonObject): String {
        val raw = (step["raw_request"] as? JsonPrimitive)?.contentOrNull
        if (raw != null) return raw.substringBefore('\n').trim()
        val method = (step["method"] as? JsonPrimitive)?.contentOrNull ?: "GET"
        return "$method ${(step["url"] as? JsonPrimitive)?.contentOrNull ?: ""}"
    }

    private fun stepJson(report: StepReport): JsonObject = buildJsonObject {
        val result = report.result
        put("step", report.index)
        put("success", result.success)
        result.exchange?.let { exchange ->
            try {
                exchange.request()?.let {
                    put("method", it.method())
                    put("url", it.url())
                }
                if (exchange.hasResponse()) put("status_code", exchange.response().statusCode().toInt())
            } catch (_: Exception) {
            }
        }
        result.elapsedMs?.let { put("elapsed_ms", it) }
        if (result.extracted.isNotEmpty()) putJsonObject("extracted") { result.extracted.forEach { (k, v) -> put(k, v) } }
        if (report.cookies.isNotEmpty()) putJsonObject("set_cookies") { report.cookies.forEach { (k, v) -> put(k, v) } }
        result.error?.let { put("error", it) }
        if (result.timeout) put("is_timeout", true)
        if (result.outOfScope) put("out_of_scope", true)
    }

    companion object {
        /** Request header marking a macro step or retry; [HttpGlobalHandler] removes it before the wire. */
        const val MARKER_HEADER = "X-Raijin-Session-Macro"

        const val MAX_STEPS = 20

        /** Longest a run may take; a concurrent trigger waits at most this long (plus a grace period). */
        const val MAX_RUN_MS = 60_000L

        private const val WAIT_GRACE_MS = 2_000L
        private const val MAX_NAME_LENGTH = 100
        private const val MAX_TRACKED_MESSAGES = 4096

        private fun <V> boundedIdMap(): MutableMap<Int, V> = Collections.synchronizedMap(
            object : LinkedHashMap<Int, V>(256, 0.75f, false) {
                override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Int, V>): Boolean = size > MAX_TRACKED_MESSAGES
            }
        )

        /** Why [macro] cannot be stored, or null when it can. */
        fun validate(macro: SessionMacro): String? {
            if (macro.name.isBlank()) return "Parameter 'name' must not be blank"
            if (macro.name.length > MAX_NAME_LENGTH || macro.name.any { it.isISOControl() }) {
                return "Parameter 'name' must be at most $MAX_NAME_LENGTH characters without control characters " +
                    "(it becomes the value of the ${HttpExchangeJson.REAUTHENTICATED_HEADER} header)"
            }
            if (macro.steps.isEmpty()) return "'steps' must contain at least one step object"
            if (macro.steps.size > MAX_STEPS) return "'steps' has ${macro.steps.size} steps; a macro takes at most $MAX_STEPS"
            macro.steps.forEachIndexed { i, step ->
                val url = (step["url"] as? JsonPrimitive)?.contentOrNull
                val raw = (step["raw_request"] as? JsonPrimitive)?.contentOrNull
                if (url.isNullOrBlank() && raw.isNullOrBlank()) return "steps[$i] needs a 'url' or a 'raw_request'"
                try {
                    HttpRequestChain.parseExtractRules(step["extract"])
                } catch (e: IllegalArgumentException) {
                    return "steps[$i]: ${e.message}"
                }
            }
            if (macro.scope !in SessionRuleEngine.SCOPES) {
                return "Invalid scope: ${macro.scope}. Must be one of: ${SessionRuleEngine.SCOPES.joinToString(", ")}"
            }
            if (macro.scope == "custom" && macro.scopePattern.isNullOrEmpty()) return "scope 'custom' needs a scope_pattern (URL regex)"
            macro.scopePattern?.let { pattern ->
                SafeRegex.validate(pattern)?.let { return "Parameter 'scope_pattern' is not a valid regex: $it" }
            }
            if (macro.triggerStatus.isEmpty() && macro.triggerRegex.isNullOrEmpty()) {
                return "Give trigger_status or trigger_regex: the macro needs something that means 'session expired'"
            }
            macro.triggerStatus.firstOrNull { it !in 100..599 }?.let { return "trigger_status $it is not an HTTP status code (100-599)" }
            macro.triggerRegex?.let { pattern ->
                SafeRegex.validate(pattern)?.let { return "Parameter 'trigger_regex' is not a valid regex: $it" }
            }
            if (macro.toolFilter.isEmpty()) return "tool_filter must name at least one Burp tool"
            val tools = ToolType.entries.map { it.name }
            macro.toolFilter.firstOrNull { it !in tools }?.let {
                return "tool_filter: unknown tool '$it'. Allowed: ${tools.joinToString(", ")}"
            }
            macro.httpMode?.let { mode ->
                if (mode !in HttpModes.NAMES) return "Invalid http_mode: $mode. Must be one of: ${HttpModes.NAMES.joinToString(", ")}"
            }
            if (macro.minIntervalMs < 0) return "min_interval_ms must not be negative"
            if (macro.maxFailures < 0) return "max_failures must not be negative"
            if (macro.stepTimeoutMs <= 0) return "step_timeout_ms must be positive"
            return null
        }
    }
}

/**
 * Whether a response should start a login macro. Pure: the engine supplies the facts, the
 * expensive ones (Burp's suite scope, the response text, the credentials check) only computed
 * when the decision gets that far.
 */
internal object SessionMacroTrigger {

    enum class Verdict {
        TRIGGER,

        /** Raijin's own unauthenticated probe: never logged in. */
        INTERNAL_PROBE,

        /** A macro step or retry: never triggers (no loops). */
        MACRO_TRAFFIC,
        DISABLED,
        SUSPENDED,
        TOOL_NOT_COVERED,
        OUT_OF_SCOPE,
        NOT_EXPIRED,

        /** The request carried no credentials and the macro requires them. */
        NO_CREDENTIALS,
    }

    class Exchange(
        val url: String,
        val toolName: String?,
        val statusCode: Int,
        val internalProbe: Boolean = false,
        val macroTraffic: Boolean = false,
        val suiteInScope: () -> Boolean = { false },
        val responseText: () -> String = { "" },
        val carriesCredentials: () -> Boolean = { false },
    )

    fun decide(macro: SessionMacro, suspended: Boolean, exchange: Exchange): Verdict = when {
        exchange.internalProbe -> Verdict.INTERNAL_PROBE
        exchange.macroTraffic -> Verdict.MACRO_TRAFFIC
        !macro.enabled -> Verdict.DISABLED
        suspended -> Verdict.SUSPENDED
        !toolCovered(macro, exchange.toolName) -> Verdict.TOOL_NOT_COVERED
        !SessionRuleEngine.inScope(macro.scope, macro.scopePattern, exchange.url, exchange.suiteInScope) -> Verdict.OUT_OF_SCOPE
        !expired(macro, exchange.statusCode, exchange.responseText) -> Verdict.NOT_EXPIRED
        macro.requireCredentials && !exchange.carriesCredentials() -> Verdict.NO_CREDENTIALS
        else -> Verdict.TRIGGER
    }

    /** Whether [macro] covers traffic of [toolName] to [url]: its tool filter and its scope. */
    fun covers(macro: SessionMacro, toolName: String?, url: String, suiteInScope: () -> Boolean): Boolean =
        toolCovered(macro, toolName) && SessionRuleEngine.inScope(macro.scope, macro.scopePattern, url, suiteInScope)

    private fun toolCovered(macro: SessionMacro, toolName: String?): Boolean =
        toolName != null && macro.toolFilter.any { it.equals(toolName, ignoreCase = true) }

    /** Whether a response with [statusCode] and [responseText] shows [macro]'s expired session. */
    fun expired(macro: SessionMacro, statusCode: Int, responseText: () -> String): Boolean =
        statusCode in macro.triggerStatus ||
            (!macro.triggerRegex.isNullOrEmpty() && SafeRegex.containsMatchIn(macro.triggerRegex, responseText()))

    /** [head] (status line and headers) followed by as much of [body] as [SafeRegex] will match over. */
    fun boundedText(head: CharSequence, body: String): String {
        val room = SafeRegex.DEFAULT_MAX_INPUT_LEN - head.length
        return if (room <= 0) head.substring(0, SafeRegex.DEFAULT_MAX_INPUT_LEN) else head.toString() + body.take(room)
    }
}

/** Cookies a login macro learns from `Set-Cookie` headers and puts into later requests. */
internal object SessionMacroCookies {

    private val EXPIRES_FORMATS = listOf(
        DateTimeFormatter.RFC_1123_DATE_TIME,
        DateTimeFormatter.ofPattern("EEE, dd-MMM-yyyy HH:mm:ss zzz", Locale.US),
        DateTimeFormatter.ofPattern("EEE, dd-MMM-yy HH:mm:ss zzz", Locale.US),
    )

    /**
     * (name, value) of one `Set-Cookie` header value; the value is null when the header deletes the
     * cookie (`Max-Age` of 0 or less, else an `Expires` before [now]). Null when it names no cookie.
     */
    fun parseSetCookie(header: String, now: Instant): Pair<String, String?>? {
        val parts = header.split(';')
        val pair = parts[0]
        val eq = pair.indexOf('=')
        if (eq <= 0) return null
        val name = pair.substring(0, eq).trim()
        val value = pair.substring(eq + 1).trim()
        if (name.isEmpty() || name.any { it.isWhitespace() || it == ',' } || HeaderSafety.containsCrlf(value)) return null
        var maxAge: Long? = null
        var expires: Instant? = null
        for (attribute in parts.drop(1)) {
            val key = attribute.substringBefore('=').trim()
            val argument = attribute.substringAfter('=', "").trim()
            when {
                key.equals("Max-Age", ignoreCase = true) -> maxAge = argument.toLongOrNull() ?: maxAge
                key.equals("Expires", ignoreCase = true) -> expires = parseExpires(argument) ?: expires
            }
        }
        val deleted = maxAge?.let { it <= 0 } ?: (expires?.isBefore(now) ?: false)
        return name to (if (deleted) null else value)
    }

    private fun parseExpires(text: String): Instant? = EXPIRES_FORMATS.firstNotNullOfOrNull { format ->
        try {
            ZonedDateTime.parse(text, format).toInstant()
        } catch (_: Exception) {
            null
        }
    }

    /**
     * The cookies to set in a request that sends [present]: every cookie of [learned] the request
     * already sends with another value. A cookie the request does not send is never added.
     */
    fun replacements(present: Map<String, String>, learned: Map<String, String>): Map<String, String> =
        learned.filter { (name, value) -> present[name].let { it != null && it != value } }

    /** [cookies] updated by [learned]: a value replaces, null deletes. */
    fun merge(cookies: Map<String, String>, learned: Map<String, String?>): Map<String, String> {
        if (learned.isEmpty()) return cookies
        val out = LinkedHashMap(cookies)
        learned.forEach { (name, value) -> if (value == null) out.remove(name) else out[name] = value }
        return out
    }
}

/**
 * The run state of one login macro: single flight, minimum interval between automatic runs,
 * consecutive-failure circuit breaker, learned cookies and counters. Times are [System.nanoTime]
 * values from the caller. Its lock is only held to change state, never while sending.
 *
 * @param minIntervalNanos shortest time from the end of one run to the start of an automatic one.
 * @param maxFailures runs in a row that did not help before the macro suspends itself; 0 = never.
 */
internal class MacroRunState(private val minIntervalNanos: Long, private val maxFailures: Int) {

    sealed class Ticket {
        /** Run the macro now, then [finish]. */
        class Run(val run: CompletableFuture<Boolean>) : Ticket()

        /** A run is in progress: wait for [run] (true when it succeeded), then retry. */
        class Wait(val run: CompletableFuture<Boolean>) : Ticket()

        /** The request was sent before the last successful run: retry it with the refreshed session. */
        data object Retry : Ticket()

        /** Too soon after the last run for another automatic one. */
        data object Throttled : Ticket()

        /** The circuit breaker is open. */
        data object Suspended : Ticket()
    }

    private val lock = Any()
    private var running: CompletableFuture<Boolean>? = null
    private var lastRunEnd: Long? = null
    private var lastSuccessEpoch = 0L
    private var runs = 0
    private var automaticRuns = 0
    private var manualRuns = 0
    private var successfulRuns = 0
    private var consecutiveFailures = 0
    private var retries = 0
    private var retriesHelped = 0
    private var lastRunAt: Instant? = null
    private var lastResult: String? = null
    private var lastError: String? = null
    private var lastTriggerUrl: String? = null
    private var suspendedAt: Instant? = null

    @Volatile
    var suspended = false
        private set

    /** Cookies learned by successful runs (name to value). */
    @Volatile
    var cookies: Map<String, String> = emptyMap()
        private set

    /** An automatic trigger for a request sent in session epoch [sentEpoch] (null when unknown). */
    fun begin(now: Long, sentEpoch: Long?): Ticket {
        synchronized(lock) {
            if (suspended) return Ticket.Suspended
            running?.let { return Ticket.Wait(it) }
            if (sentEpoch != null && sentEpoch < lastSuccessEpoch) return Ticket.Retry
            val end = lastRunEnd
            if (end != null && now - end < minIntervalNanos) return Ticket.Throttled
            return start()
        }
    }

    /** A run asked for by the operator: it only waits for a run in progress. */
    fun beginManual(): Ticket {
        synchronized(lock) {
            running?.let { return Ticket.Wait(it) }
            return start()
        }
    }

    private fun start(): Ticket.Run {
        val run = CompletableFuture<Boolean>()
        running = run
        return Ticket.Run(run)
    }

    /**
     * Ends the run of [ticket]. A successful run merges [learned] into [cookies] and becomes the
     * session epoch [epoch]; a successful manual run also closes the circuit breaker; a failed
     * automatic run counts as one that did not help. Waiters are released after the state is updated.
     *
     * @return true when this suspended the macro.
     */
    fun finish(
        ticket: Ticket.Run,
        now: Long,
        manual: Boolean,
        success: Boolean,
        epoch: Long,
        learned: Map<String, String?>,
        error: String?,
        triggerUrl: String?,
    ): Boolean {
        val suspendedNow = synchronized(lock) {
            if (running === ticket.run) running = null
            lastRunEnd = now
            runs++
            if (manual) manualRuns++ else automaticRuns++
            lastRunAt = Instant.now()
            if (triggerUrl != null) lastTriggerUrl = triggerUrl
            lastError = error
            if (success) {
                successfulRuns++
                cookies = SessionMacroCookies.merge(cookies, learned)
                lastSuccessEpoch = epoch
            }
            when {
                manual && success -> {
                    lastResult = "manual_run_succeeded"
                    consecutiveFailures = 0
                    suspended = false
                    suspendedAt = null
                    false
                }
                manual -> {
                    lastResult = "manual_run_failed"
                    false
                }
                success -> {
                    lastResult = "logged_in"
                    false
                }
                else -> {
                    lastResult = "steps_failed"
                    failed()
                }
            }
        }
        ticket.run.complete(success)
        return suspendedNow
    }

    /**
     * Records a retry. Only the run's [owner] judges the run: [helped] resets the failure count,
     * otherwise the run counts as one that did not help.
     *
     * @return true when this suspended the macro.
     */
    fun retried(helped: Boolean, owner: Boolean, error: String?): Boolean {
        synchronized(lock) {
            retries++
            if (helped) retriesHelped++
            if (!owner) return false
            if (helped) {
                consecutiveFailures = 0
                lastResult = "reauthenticated"
                lastError = null
                return false
            }
            lastResult = "did_not_help"
            lastError = error
            return failed()
        }
    }

    /** One more run that did not help; true when that opened the circuit breaker. Under [lock]. */
    private fun failed(): Boolean {
        consecutiveFailures++
        // maxFailures 0 never suspends.
        val open = !suspended && maxFailures in 1..consecutiveFailures
        if (open) {
            suspended = true
            suspendedAt = Instant.now()
        }
        return open
    }

    fun snapshot(): JsonObject = synchronized(lock) {
        buildJsonObject {
            put("running", running != null)
            put("suspended", suspended)
            suspendedAt?.let { put("suspended_at", it.toString()) }
            put("runs", runs)
            put("automatic_runs", automaticRuns)
            put("manual_runs", manualRuns)
            put("successful_runs", successfulRuns)
            put("consecutive_failures", consecutiveFailures)
            put("retries", retries)
            put("retries_helped", retriesHelped)
            put("last_run_at", lastRunAt?.toString())
            put("last_result", lastResult)
            lastError?.let { put("last_error", it) }
            lastTriggerUrl?.let { put("last_trigger_url", it) }
            putJsonArray("learned_cookies") { cookies.keys.forEach { add(it) } }
        }
    }
}
