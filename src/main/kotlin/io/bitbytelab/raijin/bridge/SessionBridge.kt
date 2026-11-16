package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.safety.HeaderSafety
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.state.SessionRule
import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.*

/**
 * Bridge for managing session handling rules that extract dynamic values
 * (e.g. CSRF tokens, session tokens) from responses and inject them into
 * subsequent requests.
 *
 * Rules are stored in [StateManager.sessionRules] and applied by the
 * global HTTP handler ([HttpGlobalHandler]).
 */
class SessionBridge(private val stateManager: StateManager) {

    /**
     * Creates a new session token extraction/injection rule. The value is selected by
     * [extractJsonPath] or [extractXPath] and/or [extractRegex] (at least one); every selector,
     * the scope pattern, the injection target and the template are validated here, so a stored rule
     * can always work.
     */
    fun createTokenRule(
        ruleName: String,
        scope: String,
        scopePattern: String?,
        extractFrom: String,
        extractHeaderName: String?,
        extractRegex: String?,
        extractJsonPath: String?,
        extractXPath: String?,
        injectInto: String,
        injectName: String,
        injectValueTemplate: String,
        injectIfMissing: Boolean,
        enabled: Boolean,
    ): JsonObject {
        fun error(message: String) = buildJsonObject { put("error", message) }

        if (ruleName.isBlank()) return error("Parameter 'rule_name' must not be blank")
        if (stateManager.sessionRules.any { it.ruleName == ruleName }) {
            return error("A session rule named '$ruleName' already exists")
        }

        val ruleScope = scope.trim().lowercase()
        if (ruleScope !in SessionRuleEngine.SCOPES) {
            return error("Invalid scope: $scope. Must be one of: ${SessionRuleEngine.SCOPES.joinToString(", ")}")
        }
        if (ruleScope == "custom" && scopePattern.isNullOrEmpty()) return error("scope 'custom' needs a scope_pattern (URL regex)")
        if (scopePattern != null) {
            SafeRegex.validate(scopePattern)?.let { return error("Parameter 'scope_pattern' is not a valid regex: $it") }
        }

        val source = extractFrom.trim().lowercase()
        if (source !in SessionRuleEngine.EXTRACT_SOURCES) {
            return error("Invalid extract_from: $extractFrom. Must be one of: ${SessionRuleEngine.EXTRACT_SOURCES.joinToString(", ")}")
        }
        if (source == "header" && extractHeaderName.isNullOrBlank()) {
            return error("extract_from 'header' needs extract_header_name (e.g. Set-Cookie)")
        }
        ValueSelector.validate(extractJsonPath, extractXPath, extractRegex, "extract_json_path", "extract_xpath", "extract_regex")
            ?.let { return error(it) }

        val target = injectInto.trim().lowercase()
        if (target !in SessionRuleEngine.INJECT_TARGETS) {
            return error("Invalid inject_into: $injectInto. Must be one of: ${SessionRuleEngine.INJECT_TARGETS.joinToString(", ")}")
        }
        injectNameError(target, injectName)?.let { return error(it) }
        SessionRuleEngine.templateError(injectValueTemplate)?.let { return error(it) }
        if (target != "json" && HeaderSafety.containsCrlf(injectValueTemplate)) {
            return error("inject_value_template must not contain CR/LF: it is written into a header, a cookie or a parameter")
        }

        val rule = SessionRule(
            ruleName = ruleName,
            scope = ruleScope,
            scopePattern = scopePattern,
            extractFrom = source,
            extractHeaderName = extractHeaderName,
            extractRegex = extractRegex.orEmpty(),
            injectInto = target,
            injectName = injectName,
            injectValueTemplate = injectValueTemplate,
            enabled = enabled,
            extractJsonPath = extractJsonPath?.ifEmpty { null },
            extractXPath = extractXPath?.ifEmpty { null },
            injectIfMissing = injectIfMissing,
        )
        stateManager.sessionRules.add(rule)

        return buildJsonObject {
            put("status", "created")
            describe(rule).forEach { (k, v) -> put(k, v) }
            put("total_rules", stateManager.sessionRules.size)
        }
    }

    /** Why [name] cannot name what a rule injecting into [target] sets, or null when it can. */
    private fun injectNameError(target: String, name: String): String? {
        if (name.isEmpty()) return "inject_name must not be empty"
        return when (target) {
            "header" -> if (HeaderSafety.isValidHeaderName(name)) null else "inject_name '$name' is not a header name (no ':', CR or LF)"
            "cookie" -> if (name.any { it == ';' || it == '=' || it == ',' || it.isWhitespace() }) {
                "inject_name '$name' is not a cookie name (no ';', '=', ',' or whitespace)"
            } else {
                null
            }
            "body", "query" -> if (name.any { it == '&' || it == '=' || it == '#' || it == '\r' || it == '\n' }) {
                "inject_name '$name' is not a parameter name (no '&', '=', '#', CR or LF)"
            } else {
                null
            }
            "json" -> SessionInjection.validateJsonTarget(name)?.let { "inject_name: $it" }
            else -> null
        }
    }

    private fun describe(rule: SessionRule): JsonObject = buildJsonObject {
        put("rule_name", rule.ruleName)
        put("scope", rule.scope)
        put("scope_pattern", rule.scopePattern ?: "")
        put("extract_from", rule.extractFrom)
        put("extract_header_name", rule.extractHeaderName ?: "")
        put("extract_regex", rule.extractRegex)
        rule.extractJsonPath?.let { put("extract_json_path", it) }
        rule.extractXPath?.let { put("extract_xpath", it) }
        put("inject_into", rule.injectInto)
        put("inject_name", rule.injectName)
        put("inject_value_template", rule.injectValueTemplate)
        put("inject_if_missing", rule.injectIfMissing)
        put("enabled", rule.enabled)
    }

    /**
     * Lists all session handling rules.
     */
    fun listRules(): JsonObject {
        val rules = buildJsonArray {
            for (rule in stateManager.sessionRules) {
                add(JsonObject(describe(rule) + ("last_extracted_value" to JsonPrimitive(rule.lastExtractedValue ?: "(none)"))))
            }
        }

        return buildJsonObject {
            put("count", stateManager.sessionRules.size)
            put("rules", rules)
        }
    }

    /**
     * Removes a session handling rule by name.
     */
    fun removeRule(ruleName: String): JsonObject {
        val removed = stateManager.sessionRules.removeIf { it.ruleName == ruleName }

        return if (removed) {
            buildJsonObject {
                put("status", "removed")
                put("rule_name", ruleName)
                put("remaining_rules", stateManager.sessionRules.size)
            }
        } else {
            buildJsonObject {
                put("error", "No session rule found with name: $ruleName")
            }
        }
    }
}
