package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.proxy.http.InterceptedResponse
import io.bitbytelab.raijin.core.BodyText
import io.bitbytelab.raijin.core.RaijinExtension
import io.bitbytelab.raijin.core.TextSimilarity
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.safety.BoundedHttp
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.safety.ScopeGate
import io.bitbytelab.raijin.state.AutorizeMatch
import io.bitbytelab.raijin.state.AutorizeReplay
import io.bitbytelab.raijin.state.AutorizeRule
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.transport.AutorizeFileStore
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.Semaphore
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Pure decisions of the live Autorize tap: which captured traffic is worth replaying, what to send
 * for each identity, and what of a verdict is worth keeping.
 */
internal object AutorizePolicy {

    /** Methods that change state on a conventional API; replayed only for a rule that opts in. */
    val MUTATING_METHODS: Set<String> = setOf("POST", "PUT", "DELETE", "PATCH")

    /** Name of the level that stands for the response the proxy already captured. */
    const val CAPTURED = "captured"

    // What a tap did with one response, counted per rule (StateManager.autorizeActivity).
    const val FILTERED = "filtered"
    const val SKIPPED_MUTATING = "skipped_mutating"
    const val SKIPPED_NOT_FOUND = "skipped_not_found"
    const val SKIPPED_UNAUTHENTICATED = "skipped_unauthenticated"
    const val SKIPPED_SEEN = "skipped_seen"
    const val SKIPPED_BUSY = "skipped_busy"
    const val SKIPPED_OUT_OF_SCOPE = "skipped_out_of_scope"
    /** Replayed although out of scope (mcp_scope_mode=warn); counted next to [SKIPPED_OUT_OF_SCOPE]. */
    const val SENT_OUT_OF_SCOPE = "sent_out_of_scope"
    const val SKIPPED_UNCHANGED = "skipped_unchanged"
    const val REPLAYED = "replayed"
    const val REPLAY_FAILED = "replay_failed"
    const val FLAGGED = "flagged"
    const val SOFT_DENIALS = "soft_denials"

    /** Finding id of the note that says how a soft denial would be judged without the denial wording. */
    const val STATUS_ONLY_ID = "status_only_verdict"

    private val SOFT_DENIAL_IDS = setOf("unauth_soft_denial", "all_identical_soft_denial")

    private val CREDENTIAL_KEYS: Set<String> = AuthIdentityApplier.CREDENTIAL_HEADERS.mapTo(HashSet()) { it.lowercase() }

    /**
     * Why [rule] does not replay a request sent with [method], or null when it does: [FILTERED]
     * when the rule's `methods` leave it out, [SKIPPED_MUTATING] when the method changes state
     * and the rule did not opt in. Naming a state-changing method in `methods` is not opting in.
     */
    fun methodSkip(rule: AutorizeRule, method: String): String? {
        val upper = method.uppercase()
        if (rule.methods != null && upper !in rule.methods) return FILTERED
        if (!rule.includeMutating && upper in MUTATING_METHODS) return SKIPPED_MUTATING
        return null
    }

    /** The state-changing methods in [methods] that a rule will not replay unless [includeMutating]. */
    fun unreplayedMethods(methods: Set<String>?, includeMutating: Boolean): List<String> =
        if (includeMutating) emptyList()
        else methods.orEmpty().map { it.uppercase() }.filter { it in MUTATING_METHODS }.sorted()

    /**
     * Why a captured exchange is not worth replaying, or null when it is:
     *  - [SKIPPED_NOT_FOUND]: a 404 has nothing to compare with;
     *  - [SKIPPED_UNAUTHENTICATED]: the original was itself unauthenticated. Either it was answered
     *    401, or it carried no credentials, so it got what anyone gets and replaying it without
     *    credentials again would "find" that every identity matches.
     *
     * @param headerNames names of the captured request's headers.
     * @param identityHeaders lowercase names of the headers the rule's identities set or remove
     *   ([AuthIdentityApplier.identityHeaders]), so an application-specific credential header counts.
     */
    fun originalSkip(status: Int, headerNames: Collection<String>, identityHeaders: Collection<String>): String? {
        if (status == 404) return SKIPPED_NOT_FOUND
        if (status == 401 || !carriesCredentials(headerNames, identityHeaders)) return SKIPPED_UNAUTHENTICATED
        return null
    }

    /** True when one of [headerNames] is a credential header or one of the rule's [identityHeaders]. */
    fun carriesCredentials(headerNames: Collection<String>, identityHeaders: Collection<String>): Boolean =
        headerNames.any { name ->
            val key = name.trim().lowercase()
            key in CREDENTIAL_KEYS || key in identityHeaders
        }

    /** One request to send: [identity] applied to the captured request. */
    class Replay(val identity: AuthIdentityApplier.Identity, val applied: AuthIdentityApplier.Applied)

    /**
     * What to send for [rawRequest]: one request per identity, leaving out every identity that
     * would send the captured request as it is, because it sets and removes nothing or sets exactly
     * the credentials the request already carries. Such a replay proves nothing, and would be
     * reported as two identities receiving the same answer.
     */
    fun replays(
        rawRequest: String,
        identities: List<AuthIdentityApplier.Identity>,
        identityHeaders: Collection<String> = AuthIdentityApplier.identityHeaders(identities),
    ): List<Replay> {
        val unchanged = canonical(AuthIdentityApplier.apply(rawRequest, AuthIdentityApplier.Identity(CAPTURED)).request)
        return identities.mapNotNull { identity ->
            if (identity.sendsRequestUnchanged) return@mapNotNull null
            val applied = AuthIdentityApplier.apply(rawRequest, identity, identityHeaders)
            if (canonical(applied.request) == unchanged) null else Replay(identity, applied)
        }
    }

    /** [request] with header names lower-cased and values trimmed, so two spellings of one request compare equal. */
    private fun canonical(request: String): String {
        val boundary = request.indexOf("\r\n\r\n")
        val head = if (boundary >= 0) request.substring(0, boundary) else request
        val body = if (boundary >= 0) request.substring(boundary) else ""
        val lines = head.split("\r\n")
        return buildString(request.length) {
            append(lines.first())
            for (line in lines.drop(1)) {
                val colon = line.indexOf(':')
                append("\r\n")
                if (colon <= 0) append(line)
                else append(line.substring(0, colon).trim().lowercase()).append(':').append(line.substring(colon + 1).trim())
            }
            append(body)
        }
    }

    /**
     * What the tap keeps of a verdict.
     *
     * @property findings what is stored on the match.
     * @property actionable the critical and high findings, also recorded as findings.
     * @property softDenial nothing is actionable: the match is kept only because an identity got a
     *   success status whose body reads as a refusal ([AuthDenialHeuristic]), and judged on status
     *   and body similarity alone the replay would have been flagged.
     */
    class Judgement(
        val findings: List<AuthDiffVerdict.Finding>,
        val actionable: List<AuthDiffVerdict.Finding>,
        val softDenial: Boolean,
    )

    /**
     * Judges the captured level and its replays ([AuthDiffVerdict]); null when nothing is worth
     * keeping. A verdict the denial heuristic turned informational is kept and flagged as a soft
     * denial, with a note saying how it reads on status and body similarity alone.
     *
     * @param similarityThreshold the rule's threshold: an unauthenticated body matching an
     *   authenticated one at this percentage is flagged; "all identical" needs 5 points more.
     */
    fun judge(
        levels: List<AuthDiffVerdict.LevelResult>,
        url: String,
        similarityThreshold: Double,
        similarity: (String, String) -> Double = { a, b -> TextSimilarity.dice(a, b) },
    ): Judgement? {
        val allSimilar = (similarityThreshold + 5.0).coerceAtMost(100.0)
        val verdict = AuthDiffVerdict.assess(levels, similarity, url, allSimilar, similarityThreshold)
        val actionable = verdict.filter(::isActionable)
        val softDenials = verdict.filter { it.id in SOFT_DENIAL_IDS }
        if (actionable.isNotEmpty()) return Judgement(actionable + softDenials, actionable, softDenial = false)
        if (softDenials.isEmpty()) return null

        // Kept only when the denial wording is what stood between the replay and a flag.
        val statusOnly = AuthDiffVerdict.assess(levels, similarity, url, allSimilar, similarityThreshold, denied = { false })
            .filter(::isActionable)
        if (statusOnly.isEmpty()) return null
        val note = AuthDiffVerdict.Finding(
            "info", STATUS_ONLY_ID,
            "Judged on status and body similarity alone, ignoring the denial wording, this would be: " +
                statusOnly.joinToString("; ") { "[${it.severity}] ${it.id}" } +
                ". Compare each identity's response with the original to decide.",
        )
        return Judgement(softDenials + note, emptyList(), softDenial = true)
    }

    private fun isActionable(finding: AuthDiffVerdict.Finding): Boolean =
        finding.severity == "critical" || finding.severity == "high"
}

/**
 * The live Autorize tap: clones proxied traffic that matches an [AutorizeRule], replays it under
 * the rule's identities in the background, and diffs each replay against the response the proxy
 * already captured. Rules are managed through [AutorizeBridge]; matches land in
 * [StateManager.autorizeMatches] (persisted per project through [store]), on the [EventBus]
 * (`autorize.match`) and, when critical or high, in the findings memory.
 */
internal class AutorizeTap(
    private val api: MontoyaApi,
    private val eventBus: EventBus,
    private val stateManager: StateManager,
    private val findings: FindingsBridge,
    private val store: AutorizeFileStore?,
) {
    private val scopeGate = ScopeGate(api)

    /**
     * Runs the replays off the proxy handler thread. A dedicated pool (rather than a shared one)
     * keeps this background work from ever competing with other Montoya callback dispatch; its
     * futures are intentionally never awaited.
     */
    private val executor: ExecutorService = Executors.newVirtualThreadPerTaskExecutor()

    /** Admission and send-concurrency bounds for [executor]. */
    private val gate = AutorizeReplayGate(MAX_QUEUED, MAX_CONCURRENT)

    private val started = AtomicBoolean(false)
    private val identityCache = ConcurrentHashMap<String, RuleIdentities>()

    /** A rule's identities parsed once per rule instance, not once per proxied response. */
    private class RuleIdentities(val rule: AutorizeRule) {
        val identities: List<AuthIdentityApplier.Identity> = rule.identities.map { AuthIdentityApplier.parse(it) }
        val headers: Set<String> = AuthIdentityApplier.identityHeaders(identities)
    }

    /**
     * Restores this project's persisted matches and keeps the store in step with the live log from
     * then on. Runs once; does nothing without a store.
     */
    fun start() {
        val store = store ?: return
        if (!started.compareAndSet(false, true)) return
        try {
            val project = RaijinExtension.projectKey(api)
            val restored = store.load(project, stateManager.autorizeMatchCapacity)
            stateManager.restoreAutorizeMatches(restored)
            stateManager.autorizeMatchListeners.add { match -> store.append(match, project) }
            stateManager.autorizeMatchClearListeners.add {
                store.replaceProject(project) { stateManager.autorizeMatches.toList() }
            }
            log("Raijin: restored ${restored.size} Autorize match(es) (project: $project); store → ${store.path()}")
        } catch (e: Exception) {
            log("Raijin: Autorize match restore failed: ${e.message}", error = true)
        }
    }

    /** Stops the background replays on extension unload. */
    fun shutdown() {
        executor.shutdownNow()
    }

    /**
     * Checks [response] against every enabled rule and submits a background replay for each rule
     * that wants one. Runs on Burp's proxy thread for every single response: it never blocks and
     * never throws.
     */
    fun onResponse(response: InterceptedResponse) {
        val rules = stateManager.autorizeRules
        if (rules.none { it.enabled }) return
        // Admissions taken but not yet handed to a submitted task; released in `finally`.
        var admitted = 0
        try {
            val request = response.request() ?: return
            val url = request.url()
            val method = request.method()
            val status = response.statusCode().toInt()
            val contentType = safe { response.headerValue("Content-Type") }
            val headerNames by lazy { request.headers().map { it.name() } }

            // Cheap per-rule checks and the dedup guard run first; the request and response are
            // only stringified when at least one rule will actually replay.
            val replays = ArrayList<RuleIdentities>(1)
            for (rule in rules) {
                if (!rule.enabled) continue
                val identities = identitiesOf(rule)
                val skip = skipReason(identities, request, method, url, status, contentType) { headerNames }
                if (skip != null) {
                    count(rule, skip)
                    continue
                }
                // Queue full: leave the endpoint unmarked so a later hit can still test it.
                if (!gate.tryAdmit()) {
                    count(rule, AutorizePolicy.SKIPPED_BUSY)
                    break
                }
                admitted++
                val key = StateManager.autorizeSeenKey(rule.ruleId, method, url)
                if (stateManager.autorizeSeenOnce(key, StateManager.autorizeEndpointKey(rule.ruleId, method, url))) {
                    replays += identities
                } else {
                    gate.release()
                    admitted--
                    count(rule, AutorizePolicy.SKIPPED_SEEN)
                }
            }
            if (replays.isEmpty()) return

            val captured = AuthDiffVerdict.LevelResult(
                AutorizePolicy.CAPTURED,
                status,
                response.bodyToString(),
                contentType,
                safe { response.headerValue("Location") },
            )
            val service = request.httpService()
            val rawRequest = request.toString()
            val rawResponse = response.toString()

            for (identities in replays) {
                try {
                    executor.execute {
                        try {
                            gate.withSendSlot {
                                replayAndAssess(identities, service, method, url, captured, rawRequest, rawResponse)
                            }
                        } catch (_: Exception) {
                            // Best-effort background check; a failure here must never surface as a proxy error.
                            unmarkSeen(identities.rule, method, url)
                        } finally {
                            gate.release()
                        }
                    }
                } catch (_: RejectedExecutionException) {
                    // Not queued: its admission is released in `finally`, and the endpoint stays testable.
                    unmarkSeen(identities.rule, method, url)
                    continue
                }
                admitted--
            }
        } catch (_: Exception) {
            // Same: tapping must never disrupt the live proxy flow.
        } finally {
            repeat(admitted) { gate.release() }
        }
    }

    /**
     * Why the rule of [identities] does not replay this exchange, as the outcome to count; null
     * when it does. The rule's own filters come first, so the skip counters only count traffic the
     * rule is about.
     */
    private fun skipReason(
        identities: RuleIdentities,
        request: HttpRequest,
        method: String,
        url: String,
        status: Int,
        contentType: String?,
        headerNames: () -> List<String>,
    ): String? {
        val rule = identities.rule
        val byMethod = AutorizePolicy.methodSkip(rule, method)
        if (byMethod == AutorizePolicy.FILTERED) return byMethod
        if (!passesFilters(rule, request, url, contentType)) return AutorizePolicy.FILTERED
        return byMethod ?: AutorizePolicy.originalSkip(status, headerNames(), identities.headers)
    }

    /** The rule's traffic filters besides the method: URL exclude-regex, host include-pattern, scope, static assets. */
    private fun passesFilters(rule: AutorizeRule, request: HttpRequest, url: String, contentType: String?): Boolean {
        if (rule.excludeUrlRegex != null && SafeRegex.containsMatchIn(rule.excludeUrlRegex, url, ignoreCase = true)) return false
        if (rule.includeHostPattern != null) {
            val host = safe { request.httpService().host() } ?: ""
            if (!SafeRegex.matchesHostPattern(rule.includeHostPattern, host)) return false
        }
        if (rule.inScopeOnly) {
            val inScope = safe { api.scope().isInScope(url) } ?: true
            if (!inScope) return false
        }
        if (rule.ignoreStaticAssets && StaticAssetHeuristic.looksStatic(contentType, url)) return false
        return true
    }

    /**
     * Replays the captured request under each identity of the rule ([AuthIdentityApplier], the
     * same application as auth_diff), diffs the answers against the already-captured response
     * (no need to resend the original: it is in hand), and records what [AutorizePolicy.judge] keeps.
     */
    private fun replayAndAssess(
        identities: RuleIdentities,
        service: HttpService,
        method: String,
        url: String,
        captured: AuthDiffVerdict.LevelResult,
        rawRequest: String,
        rawResponse: String,
    ) {
        val rule = identities.rule
        // Hard safety backstop: the operator's global scope policy applies to this outbound replay,
        // independent of rule.inScopeOnly (which only filters which traffic is tapped).
        val scope = scopeGate.check(url)
        if (scope.blocked) {
            count(rule, AutorizePolicy.SKIPPED_OUT_OF_SCOPE)
            unmarkSeen(rule, method, url)
            return
        }
        val planned = AutorizePolicy.replays(rawRequest, identities.identities, identities.headers)
        if (planned.isEmpty()) {
            count(rule, AutorizePolicy.SKIPPED_UNCHANGED)
            return
        }
        // Counted only once something will actually be replayed.
        if (scope.warning != null) count(rule, AutorizePolicy.SENT_OUT_OF_SCOPE)

        // An identity that took the reference level's name would never be compared with it.
        val reference = if (identities.identities.any { it.name.equals(AutorizePolicy.CAPTURED, ignoreCase = true) }) {
            captured.copy(name = "original")
        } else {
            captured
        }
        val levels = mutableListOf(reference)
        val replayed = ArrayList<AutorizeReplay>()
        for (replay in planned) {
            val request = HttpRequest.httpRequest(
                service, BurpByteArray.byteArray(*AuthIdentityApplier.wireBytes(replay.applied.request))
            )
            val response = try {
                BoundedHttp.sendInternal(api, request)?.response()
            } catch (_: Exception) {
                null
            } ?: continue
            // No status: the identity got no usable answer, which is not an answer of "0".
            val status = safe { response.statusCode().toInt() } ?: 0
            if (status == 0) continue
            levels += AuthDiffVerdict.LevelResult(
                replay.identity.name,
                status,
                safe { response.bodyToString() } ?: "",
                safe { response.headerValue("Content-Type") },
                safe { response.headerValue("Location") },
            )
            replayed += AutorizeReplay(replay.identity.name, status, replay.applied.request, safe { response.toString() } ?: "")
        }
        if (levels.size < 2) {
            count(rule, AutorizePolicy.REPLAY_FAILED)
            // Not tested: a later hit on the endpoint may try again.
            unmarkSeen(rule, method, url)
            return
        }
        count(rule, AutorizePolicy.REPLAYED)

        val judgement = AutorizePolicy.judge(levels, url, rule.similarityThreshold) ?: return
        val match = stateManager.addAutorizeMatch(
            ruleId = rule.ruleId,
            method = method,
            url = url,
            originalStatus = captured.status,
            findings = judgement.findings.map { f ->
                buildJsonObject { put("severity", f.severity); put("id", f.id); put("detail", f.detail) }
            },
            request = rawRequest,
            response = rawResponse,
            replays = replayed,
            softDenial = judgement.softDenial,
        )
        emit(match, judgement)
        if (judgement.actionable.isNotEmpty()) {
            val evidence = BodyText.render(rawResponse, 2000, label = "response").text
            for (finding in judgement.actionable) {
                findings.add(
                    type = finding.id,
                    severity = finding.severity,
                    url = url,
                    location = "method:$method",
                    detail = finding.detail,
                    evidence = evidence,
                    request = match.request,
                    response = match.response,
                )
            }
        }
        // Counted last, so a counted match is recorded everywhere it goes.
        count(rule, if (judgement.softDenial) AutorizePolicy.SOFT_DENIALS else AutorizePolicy.FLAGGED)
    }

    private fun emit(match: AutorizeMatch, judgement: AutorizePolicy.Judgement) {
        val severity = when {
            judgement.actionable.any { it.severity == "critical" } -> "critical"
            judgement.actionable.isNotEmpty() -> "high"
            else -> "info"
        }
        eventBus.emit("autorize.match", buildJsonObject {
            put("match_id", match.id)
            put("rule_id", match.ruleId)
            put("method", match.method)
            put("url", match.url)
            put("original_status", match.originalStatus)
            put("severity", severity)
            put("soft_denial", match.softDenial)
            put("findings", buildJsonArray { match.findings.forEach { add(it) } })
            put("identities", buildJsonArray {
                match.replays.forEach { replay ->
                    add(buildJsonObject {
                        put("name", replay.identity)
                        put("status", replay.status)
                    })
                }
            })
            put("timestamp", match.timestamp)
        })
    }

    private fun identitiesOf(rule: AutorizeRule): RuleIdentities {
        val cached = identityCache[rule.ruleId]
        if (cached != null && cached.rule === rule) return cached
        return RuleIdentities(rule).also { identityCache[rule.ruleId] = it }
    }

    private fun count(rule: AutorizeRule, outcome: String) = stateManager.autorizeActivity.count(rule.ruleId, outcome)

    /** Forgets this endpoint's dedup mark for [rule], so a request that was not tested can be later. */
    private fun unmarkSeen(rule: AutorizeRule, method: String, url: String) =
        stateManager.unmarkAutorizeSeen(
            StateManager.autorizeSeenKey(rule.ruleId, method, url),
            StateManager.autorizeEndpointKey(rule.ruleId, method, url),
        )

    private fun log(message: String, error: Boolean = false) {
        try {
            if (error) api.logging().logToError(message) else api.logging().logToOutput(message)
        } catch (_: Exception) {
            // Logging is best-effort.
        }
    }

    /** Runs a Montoya accessor that may throw on malformed data (e.g. MalformedRequestException). */
    private inline fun <T> safe(block: () -> T): T? = try {
        block()
    } catch (_: Exception) {
        null
    }

    private companion object {
        /** Replays admitted at once (queued or running); further matches wait for a later hit. */
        const val MAX_QUEUED = 100

        /** Replays sending at the same time. */
        const val MAX_CONCURRENT = 10
    }
}

/**
 * Bounds background Autorize replays: at most `maxQueued` admitted at once (queued or running;
 * the proxy thread never waits for a slot, it just skips) and at most `maxConcurrent` of them
 * sending at the same time.
 */
internal class AutorizeReplayGate(maxQueued: Int, maxConcurrent: Int) {
    private val admitted = Semaphore(maxQueued)
    private val sending = Semaphore(maxConcurrent)

    /** Non-blocking. Every `true` must be paired with one [release]. */
    fun tryAdmit(): Boolean = admitted.tryAcquire()

    fun release() = admitted.release()

    /** Runs [block] once one of the send slots is free (interruptible while waiting). */
    fun <T> withSendSlot(block: () -> T): T {
        sending.acquire()
        try {
            return block()
        } finally {
            sending.release()
        }
    }
}
