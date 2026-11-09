package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.state.AutorizeMatch
import io.bitbytelab.raijin.state.AutorizeRule
import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.time.Instant

/**
 * CRUD for live Autorize-style proxy taps and their flagged matches. Pure [StateManager]
 * manipulation (no Montoya dependency, unit-testable like [FindingsBridge]) — the actual
 * tap/replay/diff logic lives in [ProxyBridge.maybeAutorize], which reads [StateManager.autorizeRules]
 * on every proxied response and records matches via [StateManager.addAutorizeMatch].
 */
class AutorizeBridge(private val stateManager: StateManager) {

    private val severityRank = mapOf("critical" to 3, "high" to 2, "info" to 1)

    /**
     * Creates a new rule, or — when [ruleId] names an existing rule — updates it. Every parameter
     * besides [ruleId] and [identities] is nullable and PATCH-like: a null means "not specified",
     * which on an update inherits the existing rule's value instead of silently reverting to the
     * hardcoded default (the opposite would mean e.g. updating only `similarity_threshold` without
     * resending `methods` wipes the method filter, or omitting `enabled` re-enables a disabled
     * rule) — only a genuinely new rule (no existing [ruleId] match) falls back to defaults.
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
        val resolvedEnabled = enabled ?: existing?.enabled ?: true
        val rule = AutorizeRule(
            ruleId = id,
            identities = resolvedIdentities,
            inScopeOnly = inScopeOnly ?: existing?.inScopeOnly ?: true,
            includeHostPattern = includeHostPattern ?: existing?.includeHostPattern,
            excludeUrlRegex = excludeUrlRegex ?: existing?.excludeUrlRegex,
            methods = methods?.map { it.uppercase() }?.toSet() ?: existing?.methods,
            ignoreStaticAssets = ignoreStaticAssets ?: existing?.ignoreStaticAssets ?: true,
            similarityThreshold = similarityThreshold ?: existing?.similarityThreshold ?: 90.0,
            enabled = resolvedEnabled,
            // Preserve the original creation time across updates — AutorizeRule's own default
            // (Instant.now()) would otherwise stamp a fresh value on every single update.
            createdAt = existing?.createdAt ?: Instant.now().toString(),
        )
        stateManager.autorizeRules.removeIf { it.ruleId == id }
        stateManager.autorizeRules.add(rule)
        return buildJsonObject {
            put("rule_id", id)
            put("status", if (resolvedEnabled) "active" else "disabled")
        }
    }

    fun listRules(): JsonObject = buildJsonObject {
        put("count", stateManager.autorizeRules.size)
        put("rules", buildJsonArray { stateManager.autorizeRules.forEach { add(serializeRule(it)) } })
    }

    fun removeRule(ruleId: String): JsonObject {
        val removed = stateManager.autorizeRules.removeIf { it.ruleId == ruleId }
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
        val page = all.drop(startIndex.coerceAtLeast(0)).take(count.coerceIn(1, 500))
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
        severityRank[finding["severity"]?.jsonPrimitive?.contentOrNull?.lowercase()] ?: 0

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
        put("request", m.request.take(4000))
        put("response", m.response.take(4000))
    }
}
