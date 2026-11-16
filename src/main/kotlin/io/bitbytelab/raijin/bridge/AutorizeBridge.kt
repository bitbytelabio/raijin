package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.core.BodyText
import io.bitbytelab.raijin.safety.HeaderSafety
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.state.AutorizeMatch
import io.bitbytelab.raijin.state.AutorizeRule
import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put
import java.time.Instant
import java.util.concurrent.Semaphore

/**
 * CRUD for live Autorize-style proxy taps and their flagged matches. Pure [StateManager]
 * manipulation (no Montoya dependency, unit-testable like [FindingsBridge]) — the actual
 * tap/replay/diff logic lives in [ProxyBridge.maybeAutorize], which reads [StateManager.autorizeRules]
 * on every proxied response and records matches via [StateManager.addAutorizeMatch].
 */
class AutorizeBridge(private val stateManager: StateManager) {

    private val severityRank = mapOf("critical" to 3, "high" to 2, "info" to 1)

    /** Serialises rule writes so concurrent sets of one id cannot both append. */
    private val ruleLock = Any()

    /**
     * Creates a new rule, or — when [ruleId] names an existing rule — updates it. Every parameter
     * besides [ruleId] and [identities] is nullable and PATCH-like: a null means "not specified",
     * which on an update inherits the existing rule's value instead of silently reverting to the
     * hardcoded default (the opposite would mean e.g. updating only `similarity_threshold` without
     * resending `methods` wipes the method filter, or omitting `enabled` re-enables a disabled
     * rule) — only a genuinely new rule (no existing [ruleId] match) falls back to defaults.
     *
     * Either way the rule's dedup guard is reset, so endpoints already tested under the old
     * settings (or under a removed rule that had the same id) are tested again.
     */
    fun setRule(
        ruleId: String?,
        identities: List<JsonObject>?,
        inScopeOnly: Boolean?,
        includeHostPattern: String?,
        excludeUrlRegex: String?,
        methods: List<String>?,
        ignoreStaticAssets: Boolean?,
        similarityThreshold: Double?,
        enabled: Boolean?,
    ): JsonObject {
        validateInput(identities, includeHostPattern, excludeUrlRegex, methods, similarityThreshold)?.let { err ->
            return buildJsonObject { put("error", err) }
        }
        val rule = synchronized(ruleLock) {
            val existing = ruleId?.let { id -> stateManager.autorizeRules.firstOrNull { it.ruleId == id } }
            val resolvedIdentities = identities ?: existing?.identities
            if (resolvedIdentities == null || resolvedIdentities.size < 2) {
                return buildJsonObject {
                    put(
                        "error",
                        "Provide at least 2 'identities' (e.g. an authed level plus a 'none'/'unauth' level), " +
                            "same {name, header_name?, header_value?} shape as auth_diff/access_control_sweep.",
                    )
                }
            }
            val id = ruleId ?: stateManager.generateId("arule")
            val rule = AutorizeRule(
                ruleId = id,
                identities = resolvedIdentities,
                inScopeOnly = inScopeOnly ?: existing?.inScopeOnly ?: true,
                includeHostPattern = includeHostPattern ?: existing?.includeHostPattern,
                excludeUrlRegex = excludeUrlRegex ?: existing?.excludeUrlRegex,
                methods = methods?.map { it.trim().uppercase() }?.toSet() ?: existing?.methods,
                ignoreStaticAssets = ignoreStaticAssets ?: existing?.ignoreStaticAssets ?: true,
                similarityThreshold = similarityThreshold ?: existing?.similarityThreshold ?: 90.0,
                enabled = enabled ?: existing?.enabled ?: true,
                // Preserve the original creation time across updates — AutorizeRule's own default
                // (Instant.now()) would otherwise stamp a fresh value on every single update.
                createdAt = existing?.createdAt ?: Instant.now().toString(),
            )
            if (existing != null) {
                // In place, so the rule keeps its position in the list.
                stateManager.autorizeRules.replaceAll { if (it.ruleId == id) rule else it }
            } else {
                stateManager.autorizeRules.add(rule)
            }
            rule
        }
        // After the swap: keys marked under the previous settings are dropped too.
        stateManager.clearAutorizeSeen(rule.ruleId)
        return buildJsonObject {
            put("rule_id", rule.ruleId)
            put("status", if (rule.enabled) "active" else "disabled")
        }
    }

    fun listRules(): JsonObject = buildJsonObject {
        val rules = stateManager.autorizeRules.toList()
        put("count", rules.size)
        put("rules", buildJsonArray { rules.forEach { add(serializeRule(it)) } })
    }

    fun removeRule(ruleId: String): JsonObject {
        val removed = synchronized(ruleLock) { stateManager.autorizeRules.removeIf { it.ruleId == ruleId } }
        if (removed) stateManager.clearAutorizeSeen(ruleId)
        return buildJsonObject {
            put("rule_id", ruleId)
            put("removed", removed)
            if (!removed) put("error", "Rule not found: $ruleId")
        }
    }

    fun listMatches(ruleId: String?, minSeverity: String?, startIndex: Int, count: Int): JsonObject {
        val minRank = minSeverity?.lowercase()?.let { severityRank[it] } ?: 0
        val all = stateManager.autorizeMatches.filter { m ->
            (ruleId == null || m.ruleId == ruleId) &&
                (minRank == 0 || m.findings.any { f -> rankOf(f) >= minRank })
        }
        val page = all.drop(startIndex.coerceAtLeast(0)).take(count.coerceIn(1, MAX_MATCH_PAGE))
        return buildJsonObject {
            put("total", all.size)
            put("returned", page.size)
            put("matches", buildJsonArray { page.forEach { add(serializeMatch(it)) } })
        }
    }

    fun clearMatches(ruleId: String?, resetSeen: Boolean): JsonObject {
        stateManager.clearAutorizeMatches(ruleId, resetSeen)
        return buildJsonObject {
            put("cleared", true)
            ruleId?.let { put("rule_id", it) }
            put("reset_seen", resetSeen)
        }
    }

    private fun rankOf(finding: JsonObject): Int =
        severityRank[(finding["severity"] as? JsonPrimitive)?.contentOrNull?.lowercase()] ?: 0

    private fun serializeRule(r: AutorizeRule): JsonObject = buildJsonObject {
        put("rule_id", r.ruleId)
        put("enabled", r.enabled)
        put("identities", buildJsonArray { r.identities.forEach { add(it) } })
        put("in_scope_only", r.inScopeOnly)
        r.includeHostPattern?.let { put("include_host_pattern", it) }
        r.excludeUrlRegex?.let { put("exclude_url_regex", it) }
        r.methods?.let { ms -> put("methods", buildJsonArray { ms.forEach { add(it) } }) }
        put("ignore_static_assets", r.ignoreStaticAssets)
        put("similarity_threshold", r.similarityThreshold)
        put("created_at", r.createdAt)
    }

    private fun serializeMatch(m: AutorizeMatch): JsonObject = buildJsonObject {
        put("id", m.id)
        put("rule_id", m.ruleId)
        put("timestamp", m.timestamp)
        put("method", m.method)
        put("url", m.url)
        put("original_status", m.originalStatus)
        put("findings", buildJsonArray { m.findings.forEach { add(it) } })
        put("request", BodyText.render(m.request, EVIDENCE_CHARS, label = "request").text)
        put("response", BodyText.render(m.response, EVIDENCE_CHARS, label = "response").text)
    }

    companion object {
        /** Largest `count` accepted by [listMatches]. */
        const val MAX_MATCH_PAGE = 500

        /** Characters of request/response evidence shown per match. */
        private const val EVIDENCE_CHARS = 4000

        /**
         * Rejects inputs that would make a rule silently never fire or skip identities: invalid
         * patterns, an out-of-range threshold, blank methods, or malformed identities. Null
         * arguments (not provided) are not checked. Returns an error message or null.
         */
        internal fun validateInput(
            identities: List<JsonObject>?,
            includeHostPattern: String?,
            excludeUrlRegex: String?,
            methods: List<String>?,
            similarityThreshold: Double?,
        ): String? {
            identities?.forEachIndexed { i, identity ->
                identityError(identity)?.let { return "identities[$i]: $it" }
            }
            includeHostPattern?.let { p -> ProxyBridge.hostPatternError(p)?.let { return "include_host_pattern: $it" } }
            excludeUrlRegex?.let { p ->
                SafeRegex.validate(p, ignoreCase = true)?.let { return "Invalid exclude_url_regex: $it" }
            }
            methods?.let { ms ->
                if (ms.isEmpty() || ms.any { it.isBlank() }) return "methods must list non-blank HTTP methods (omit it to tap every method)"
            }
            similarityThreshold?.let {
                if (it.isNaN() || it < 0.0 || it > 100.0) return "similarity_threshold must be between 0 and 100 (got $it)"
            }
            return null
        }

        private fun identityError(identity: JsonObject): String? {
            val name = (identity["name"] as? JsonPrimitive)?.contentOrNull
            if (name.isNullOrBlank()) return "'name' is required"
            val headerName = (identity["header_name"] as? JsonPrimitive)?.contentOrNull
            val headerValue = (identity["header_value"] as? JsonPrimitive)?.contentOrNull
            if ((headerName == null) != (headerValue == null)) return "'header_name' and 'header_value' must be given together"
            if (headerName != null && !HeaderSafety.isValidHeaderName(headerName)) {
                return "'header_name' must be a header name without ':' or CR/LF"
            }
            if (headerValue != null && !HeaderSafety.isValidHeaderValue(headerValue)) {
                return "'header_value' must not contain CR/LF"
            }
            return null
        }
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
