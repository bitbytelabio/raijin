package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.state.SessionRule

/**
 * Pure logic for [SessionRule] evaluation: scope matching, value extraction from a response, and
 * template rendering for injection. Kept free of the Montoya API so it is unit-testable; the bridge
 * supplies the header values, body, and the suite-scope answer.
 */
object SessionRuleEngine {

    val SCOPES: List<String> = listOf("all", "suite", "custom")
    val EXTRACT_SOURCES: List<String> = listOf("header", "body")
    val INJECT_TARGETS: List<String> = listOf("header", "cookie", "body", "query", "json")

    /** `{value}` or `{value|encoder|...}` in an inject template. */
    private val PLACEHOLDER = Regex("""\{value((?:\|[^{}|]*)*)\}""")

    /**
     * Whether this rule applies to [url]. `all` always matches; `custom` matches its
     * [SessionRule.scopePattern] regex; `suite` defers to [suiteInScope] (which the caller computes
     * from `api.scope().isInScope`).
     */
    fun inScope(rule: SessionRule, url: String, suiteInScope: Boolean): Boolean =
        inScope(rule.scope, rule.scopePattern, url) { suiteInScope }

    /**
     * [inScope] for anything scoped the way a session rule is (a rule, a login macro).
     * [suiteInScope] is only called for scope `suite`: it asks Burp.
     */
    fun inScope(scope: String, scopePattern: String?, url: String, suiteInScope: () -> Boolean): Boolean =
        when (scope.lowercase()) {
            "all" -> true
            "suite" -> suiteInScope()
            "custom" -> scopePattern != null && SafeRegex.containsMatchIn(scopePattern, url)
            else -> false
        }

    /**
     * The rule's value in a response, or null when nothing matches. For `extractFrom == "header"`
     * every value of the named header is tried in order ([headerValues]: one entry per header line,
     * so each `Set-Cookie` is read on its own) and the first that yields a value wins; for "body"
     * [body] is read. The value is selected by the rule's JSONPath or XPath when it has one, then by
     * its regex (first capture group, or the whole match) ([ValueSelector]).
     */
    fun extract(rule: SessionRule, headerValues: List<String>, body: String): String? {
        val regex = rule.extractRegex.ifEmpty { null }
        return when (rule.extractFrom.lowercase()) {
            "header" -> headerValues.firstNotNullOfOrNull { ValueSelector.select(it, rule.extractJsonPath, rule.extractXPath, regex) }
            "body" -> ValueSelector.select(body, rule.extractJsonPath, rule.extractXPath, regex)
            else -> null
        }
    }

    /**
     * Renders [template]: `{value}` becomes [value] as is, `{value|url}` the value run through the
     * named [PayloadEncoders] (chained left to right: `{value|base64|url}`). A placeholder naming an
     * unknown encoder is left as written ([templateError] rejects it when the rule is created).
     */
    fun render(template: String, value: String): String {
        if (!template.contains("{value")) return template
        return PLACEHOLDER.replace(template) { match ->
            val encoders = encoderNames(match)
            when {
                encoders.isEmpty() -> value
                encoders.any { it.isEmpty() } || PayloadEncoders.unknown(encoders) != null -> match.value
                else -> PayloadEncoders.chain(encoders)(value)
            }
        }
    }

    /** Why [template] cannot be rendered as written (an empty or unknown encoder), or null when it can. */
    fun templateError(template: String): String? {
        for (match in PLACEHOLDER.findAll(template)) {
            val encoders = encoderNames(match)
            val unknown = if (encoders.any { it.isEmpty() }) "" else PayloadEncoders.unknown(encoders) ?: continue
            return "inject_value_template: unknown encoder '$unknown' in ${match.value}. " +
                "Allowed: ${PayloadEncoders.names.joinToString(", ")}"
        }
        return null
    }

    private fun encoderNames(match: MatchResult): List<String> =
        match.groupValues[1].split('|').drop(1).map { it.trim() }
}
