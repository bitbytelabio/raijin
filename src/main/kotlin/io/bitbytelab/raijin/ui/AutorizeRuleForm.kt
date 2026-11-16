package io.bitbytelab.raijin.ui

import io.bitbytelab.raijin.bridge.AutorizeBridge
import io.bitbytelab.raijin.safety.HeaderSafety
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.state.AutorizeRule
import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/** One replay identity of an Autorize rule: the `{name, header_name?, header_value?}` shape auth_diff uses. */
internal data class AutorizeIdentity(val name: String, val headerName: String = "", val headerValue: String = "") {
    fun toJson(): JsonObject = buildJsonObject {
        put("name", name)
        if (headerName.isNotEmpty()) {
            put("header_name", headerName)
            put("header_value", headerValue)
        }
    }

    companion object {
        fun from(json: JsonObject): AutorizeIdentity {
            fun text(key: String) = runCatching { json[key]?.jsonPrimitive?.contentOrNull }.getOrNull().orEmpty()
            return AutorizeIdentity(text("name"), text("header_name"), text("header_value"))
        }
    }
}

/**
 * The Autorize tab's rule editor, validated before it reaches [AutorizeBridge.setRule]. A blank
 * optional filter is null ("no filter"): an empty host pattern would match no host, an empty
 * exclude regex every URL.
 */
internal data class AutorizeRuleForm(
    val identities: List<AutorizeIdentity>,
    val inScopeOnly: Boolean = true,
    val includeHostPattern: String? = null,
    val excludeUrlRegex: String? = null,
    val methods: List<String>? = null,
    val ignoreStaticAssets: Boolean = true,
    val similarityThreshold: Double = 90.0,
    val enabled: Boolean = true,
) {
    /** The first problem with this form, or null when it can be saved. */
    fun validate(): String? {
        if (identities.size < 2) {
            return "Add at least 2 identities, e.g. a low-privilege session and 'unauth'. Each one is replayed against the captured request."
        }
        val seen = HashSet<String>()
        for (identity in identities) {
            val name = identity.name
            if (name.isBlank()) return "Every identity needs a name."
            if (!seen.add(name.lowercase())) return "Identity names must be unique: '$name' appears twice."
            if (identity.headerName.isEmpty()) {
                if (identity.headerValue.isNotEmpty()) return "Identity '$name': a header value needs a header name."
                continue
            }
            if (!HeaderSafety.isValidHeaderName(identity.headerName)) {
                return "Identity '$name': '${identity.headerName}' is not a valid header name (no ':' or line breaks)."
            }
            if (identity.headerValue.isEmpty()) {
                return "Identity '$name': enter the ${identity.headerName} value to replay with (e.g. the low-privilege session)."
            }
            if (!HeaderSafety.isValidHeaderValue(identity.headerValue)) {
                return "Identity '$name': the header value must not contain line breaks."
            }
        }
        if (similarityThreshold.isNaN() || similarityThreshold !in 0.0..100.0) {
            return "Similarity threshold must be between 0 and 100."
        }
        excludeUrlRegex?.let { pattern ->
            SafeRegex.validate(pattern, ignoreCase = true)?.let { return "Invalid exclude URL regex: $it" }
        }
        includeHostPattern?.let { pattern -> hostPatternError(pattern)?.let { return it } }
        return null
    }

    fun identitiesJson(): List<JsonObject> = identities.map { it.toJson() }

    /** True when saving over [existing] drops a filter it has; setRule treats a null filter as "keep the current one". */
    fun clearsFilterOf(existing: AutorizeRule): Boolean =
        (includeHostPattern == null && existing.includeHostPattern != null) ||
            (excludeUrlRegex == null && existing.excludeUrlRegex != null) ||
            (methods == null && existing.methods != null)

    /**
     * Creates the rule ([ruleId] null) or updates [ruleId] through [bridge]. Dropping a filter is
     * not expressible through setRule's patch semantics, so that case removes the rule and creates
     * it again under the same id; its matches stay, and its replay dedup cache is reset as an
     * update would. Returns the bridge's result (`rule_id`, or `error`).
     */
    fun save(bridge: AutorizeBridge, stateManager: StateManager, ruleId: String?): JsonObject {
        validate()?.let { message -> return buildJsonObject { put("error", message) } }
        val existing = ruleId?.let { id -> stateManager.autorizeRules.firstOrNull { it.ruleId == id } }
        if (existing != null && clearsFilterOf(existing)) {
            bridge.removeRule(existing.ruleId)
            stateManager.clearAutorizeSeen(existing.ruleId)
        }
        return bridge.setRule(
            ruleId = ruleId,
            identities = identitiesJson(),
            inScopeOnly = inScopeOnly,
            includeHostPattern = includeHostPattern,
            excludeUrlRegex = excludeUrlRegex,
            methods = methods,
            ignoreStaticAssets = ignoreStaticAssets,
            similarityThreshold = similarityThreshold,
            enabled = enabled,
        )
    }

    companion object {
        /** The starting point for a new rule: a low-privilege session to fill in, and no credentials at all. */
        fun newRule() = AutorizeRuleForm(
            identities = listOf(AutorizeIdentity("low-priv", "Cookie", ""), AutorizeIdentity("unauth")),
        )

        fun from(rule: AutorizeRule) = AutorizeRuleForm(
            identities = rule.identities.map(AutorizeIdentity::from),
            inScopeOnly = rule.inScopeOnly,
            includeHostPattern = rule.includeHostPattern,
            excludeUrlRegex = rule.excludeUrlRegex,
            methods = rule.methods?.sorted(),
            ignoreStaticAssets = rule.ignoreStaticAssets,
            similarityThreshold = rule.similarityThreshold,
            enabled = rule.enabled,
        )

        /** "get, Post;PUT" -> [GET, POST, PUT]; blank -> null (every method). */
        fun parseMethods(text: String): List<String>? =
            text.split(',', ';', ' ', '\t').map { it.trim().uppercase() }.filter { it.isNotEmpty() }.distinct().ifEmpty { null }

        /** One-line summary of a rule's traffic filters for the rules table. */
        fun filtersSummary(rule: AutorizeRule): String = buildList {
            if (rule.inScopeOnly) add("in scope")
            rule.includeHostPattern?.let { add("host $it") }
            rule.methods?.let { add(it.sorted().joinToString(",")) }
            rule.excludeUrlRegex?.let { add("skip /$it/") }
            if (rule.ignoreStaticAssets) add("no static")
        }.joinToString(" · ").ifEmpty { "all traffic" }

        fun identityNames(rule: AutorizeRule): String =
            rule.identities.joinToString(", ") { AutorizeIdentity.from(it).name.ifEmpty { "?" } }

        /** "90.0" -> "90%", "87.5" -> "87.5%". */
        fun percent(value: Double): String = if (value % 1.0 == 0.0) "${value.toLong()}%" else "$value%"

        // SafeRegex.matchesHostPattern compiles a pattern with regex syntax as a regex and treats
        // anything else as a '*' glob, so only the former can be invalid.
        private val REGEX_MARKERS = listOf(".*", ".+", "\\", "[", "(", "^", "$", "+", "?")

        private fun hostPatternError(pattern: String): String? {
            if (pattern == "*" || REGEX_MARKERS.none { it in pattern }) return null
            return SafeRegex.validate(pattern, ignoreCase = true)?.let { "Invalid host pattern: $it" }
        }
    }
}
