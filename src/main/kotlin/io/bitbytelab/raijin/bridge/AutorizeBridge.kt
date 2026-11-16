package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.core.asStringList
import io.bitbytelab.raijin.core.asStringMap
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.state.AutorizeMatch
import io.bitbytelab.raijin.state.AutorizeRule
import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put
import java.time.Instant

/**
 * CRUD for live Autorize-style proxy taps and their flagged matches. Pure [StateManager]
 * manipulation (no Montoya dependency, unit-testable like [FindingsBridge]) — the tap itself is
 * [AutorizeTap], which reads [StateManager.autorizeRules] on every proxied response and records
 * matches via [StateManager.addAutorizeMatch].
 */
class AutorizeBridge(private val stateManager: StateManager) {

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
     *
     * @param includeMutating replay requests whose method changes state (POST, PUT, DELETE, PATCH);
     *   off unless given, also when [methods] names such a method.
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
        includeMutating: Boolean? = null,
    ): JsonObject {
        validateInput(identities, includeHostPattern, excludeUrlRegex, methods, similarityThreshold)?.let { err ->
            return buildJsonObject { put("error", err) }
        }
        val rule = synchronized(ruleLock) {
            val existing = ruleId?.let { id -> stateManager.autorizeRules.firstOrNull { it.ruleId == id } }
            val resolvedIdentities = identities ?: existing?.identities
            if (resolvedIdentities.isNullOrEmpty()) {
                return buildJsonObject {
                    put(
                        "error",
                        "Provide 'identities': at least one that changes the request, e.g. {\"name\":\"none\"} to replay " +
                            "without credentials or {\"name\":\"low_priv\",\"header_name\":\"Cookie\",\"header_value\":\"session=...\"} " +
                            "for a second session (the shape auth_diff/access_control_sweep use).",
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
                includeMutating = includeMutating ?: existing?.includeMutating ?: false,
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
        val notes = ruleNotes(rule)
        return buildJsonObject {
            put("rule_id", rule.ruleId)
            put("status", if (rule.enabled) "active" else "disabled")
            if (notes.isNotEmpty()) put("notes", buildJsonArray { notes.forEach { add(it) } })
        }
    }

    fun listRules(): JsonObject = buildJsonObject {
        val rules = stateManager.autorizeRules.toList()
        put("count", rules.size)
        put("rules", buildJsonArray { rules.forEach { add(serializeRule(it)) } })
    }

    fun removeRule(ruleId: String): JsonObject {
        val removed = synchronized(ruleLock) { stateManager.autorizeRules.removeIf { it.ruleId == ruleId } }
        if (removed) {
            stateManager.clearAutorizeSeen(ruleId)
            stateManager.autorizeActivity.clear(ruleId)
        }
        return buildJsonObject {
            put("rule_id", ruleId)
            put("removed", removed)
            if (!removed) put("error", "Rule not found: $ruleId")
        }
    }

    /**
     * Lists matches newest first. [startIndex] and [count] outside what is supported are clamped
     * and reported in `notes`. [matchId] returns that one match with the original and every
     * identity's replayed request and response at length; otherwise a replay is summarised
     * (identity, status, response length) unless [includeReplays].
     */
    fun listMatches(
        ruleId: String?,
        minSeverity: String?,
        startIndex: Int,
        count: Int,
        matchId: Long? = null,
        includeReplays: Boolean = false,
    ): JsonObject {
        if (matchId != null) {
            val match = stateManager.autorizeMatches.firstOrNull { it.id == matchId }
                ?: return buildJsonObject { put("error", "No Autorize match with id $matchId") }
            return buildJsonObject {
                put("total", 1)
                put("returned", 1)
                put("matches", buildJsonArray { add(serializeMatch(match, DETAIL_CHARS, replayMessages = true)) })
            }
        }
        val notes = mutableListOf<String>()
        val start = ProxyLimits.clamp("start_index", startIndex, 0, Int.MAX_VALUE, notes)
        val size = ProxyLimits.clamp("count", count, 1, MAX_MATCH_PAGE, notes)
        val minRank = minSeverity?.lowercase()?.let { SEVERITY_RANK[it] } ?: 0
        val all = stateManager.autorizeMatches.filter { m ->
            (ruleId == null || m.ruleId == ruleId) &&
                (minRank == 0 || m.findings.any { f -> rankOf(f) >= minRank })
        }
        val page = all.drop(start).take(size)
        return buildJsonObject {
            put("total", all.size)
            put("returned", page.size)
            put("matches", buildJsonArray { page.forEach { add(serializeMatch(it, EVIDENCE_CHARS, includeReplays)) } })
            if (notes.isNotEmpty()) put("notes", buildJsonArray { notes.forEach { add(it) } })
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

    /** What a caller should know about a rule it just set: what the tap will not replay, and why. */
    private fun ruleNotes(rule: AutorizeRule): List<String> = buildList {
        val unreplayed = AutorizePolicy.unreplayedMethods(rule.methods, rule.includeMutating)
        if (unreplayed.isNotEmpty()) {
            add(
                "methods ${unreplayed.joinToString(", ")} change state and are skipped: set include_mutating=true to " +
                    "replay them (each replay repeats the action once per identity)"
            )
        }
        if (rule.includeMutating) {
            add("include_mutating is on: every POST, PUT, DELETE and PATCH the rule taps is sent again once per identity")
        }
        val unchanged = rule.identities.map { AuthIdentityApplier.parse(it) }.filter { it.sendsRequestUnchanged }.map { it.name }
        if (unchanged.isNotEmpty()) {
            add(
                "identities ${unchanged.joinToString(", ") { "'$it'" }} set no header and are not named none/unauth/anonymous: " +
                    "they would resend the captured request as it is, so they are not replayed (the captured response " +
                    "already is the authenticated reference)"
            )
        }
    }

    private fun serializeRule(r: AutorizeRule): JsonObject = buildJsonObject {
        put("rule_id", r.ruleId)
        put("enabled", r.enabled)
        put("identities", buildJsonArray { r.identities.forEach { add(it) } })
        put("in_scope_only", r.inScopeOnly)
        r.includeHostPattern?.let { put("include_host_pattern", it) }
        r.excludeUrlRegex?.let { put("exclude_url_regex", it) }
        r.methods?.let { ms -> put("methods", buildJsonArray { ms.forEach { add(it) } }) }
        put("include_mutating", r.includeMutating)
        put("ignore_static_assets", r.ignoreStaticAssets)
        put("similarity_threshold", r.similarityThreshold)
        put("created_at", r.createdAt)
        val activity = stateManager.autorizeActivity.of(r.ruleId)
        if (activity.isNotEmpty()) put("activity", buildJsonObject { activity.forEach { (outcome, n) -> put(outcome, n) } })
    }

    private fun serializeMatch(m: AutorizeMatch, chars: Int, replayMessages: Boolean): JsonObject = buildJsonObject {
        put("id", m.id)
        put("rule_id", m.ruleId)
        put("timestamp", m.timestamp)
        put("method", m.method)
        put("url", m.url)
        put("original_status", m.originalStatus)
        put("soft_denial", m.softDenial)
        put("findings", buildJsonArray { m.findings.forEach { add(it) } })
        put("request", ProxyLimits.renderMessage(m.request, chars, "request").text)
        put("response", ProxyLimits.renderMessage(m.response, chars, "response").text)
        put("replays", buildJsonArray {
            m.replays.forEach { replay ->
                add(buildJsonObject {
                    put("identity", replay.identity)
                    put("status", replay.status)
                    put("response_length", replay.response.length)
                    if (replayMessages) {
                        put("request", ProxyLimits.renderMessage(replay.request, chars, "request").text)
                        put("response", ProxyLimits.renderMessage(replay.response, chars, "response").text)
                    }
                })
            }
        })
    }

    companion object {
        /** Largest `count` served by [listMatches]. */
        const val MAX_MATCH_PAGE = 500

        /** Characters of request/response body shown per message in a list. */
        private const val EVIDENCE_CHARS = 4000

        /** Characters of body shown per message when one match is asked for by id. */
        private const val DETAIL_CHARS = 30_000

        private val SEVERITY_RANK = mapOf("critical" to 3, "high" to 2, "info" to 1)

        private fun rankOf(finding: JsonObject): Int =
            SEVERITY_RANK[(finding["severity"] as? JsonPrimitive)?.contentOrNull?.lowercase()] ?: 0

        /**
         * Rejects inputs that could never make a rule fire: patterns that do not compile, an
         * out-of-range threshold, blank methods, or identities that cannot be applied or compared.
         * Null arguments (not provided) are not checked. Returns an error message or null.
         *
         * Identity headers are not held to the HTTP grammar: a name or value carrying CR/LF or any
         * other character is replayed as written.
         */
        internal fun validateInput(
            identities: List<JsonObject>?,
            includeHostPattern: String?,
            excludeUrlRegex: String?,
            methods: List<String>?,
            similarityThreshold: Double?,
        ): String? {
            identities?.let { list ->
                list.forEachIndexed { i, identity -> identityError(identity)?.let { return "identities[$i]: $it" } }
                val parsed = list.map { AuthIdentityApplier.parse(it) }
                parsed.groupBy { it.name.lowercase() }.values.firstOrNull { it.size > 1 }?.let { same ->
                    return "Identity names must be unique: '${same.first().name}' appears ${same.size} times " +
                        "(identities with one name are never compared with each other)."
                }
                if (parsed.isNotEmpty() && parsed.all { it.sendsRequestUnchanged }) {
                    return "No identity changes the request: give at least one its credentials (header_name + header_value, " +
                        "or headers), or name one none/unauth/anonymous to replay without credentials."
                }
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
            if (headerName != null && headerName.isBlank()) return "'header_name' must not be blank"
            val headers = identity["headers"]
            if (headers != null && headers !is JsonNull) {
                val map = headers.asStringMap() ?: return "'headers' must be an object of header name to value"
                if (map.keys.any { it.isBlank() }) return "'headers' has an entry without a header name"
            }
            val remove = identity["remove_headers"]
            if (remove != null && remove !is JsonNull) {
                val names = remove.asStringList() ?: return "'remove_headers' must be a list of header names"
                if (names.any { it.isBlank() }) return "'remove_headers' has an empty header name"
            }
            return null
        }
    }
}
