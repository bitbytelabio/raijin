package io.bitbytelab.raijin.bridge

import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.state.ProxyRule

/**
 * What a proxy rule's `modify` action writes, and the checks on its values.
 *
 * Nothing here is held to the HTTP grammar. A rule may write a header whose name or value carries
 * CR/LF, spaces or any other character: request smuggling, header injection and parser-differential
 * tests need exactly that. Only a value that could never be applied is refused.
 *
 * The edits apply in a fixed order: remove header, add header, replace header, set header, body
 * regex, then the method and the path (request rules) or the status code (response rules). Header
 * names are compared ignoring case, and a remove, replace or set edit reaches every occurrence
 * ([HeaderModifier]).
 */
internal object ProxyRuleEdits {

    /** Largest status code Montoya's `withStatusCode(short)` can carry (`Short.MAX_VALUE`). */
    const val MAX_STATUS = 32767

    /**
     * Splits a `Name: Value` line at its first colon. The name is kept as written, since a space
     * around it is a header obfuscation and not a typo; the value loses the blanks after the colon
     * and a line break that only ends the line. Null without a colon, or with nothing before it.
     */
    fun parseHeaderLine(line: String): Pair<String, String>? {
        val colon = line.indexOf(':')
        if (colon <= 0) return null
        val value = line.substring(colon + 1).trimStart(' ', '\t').trimEnd('\r', '\n')
        return line.substring(0, colon) to value
    }

    /** A header name to look up: the blanks around it and a trailing colon are not part of it. */
    fun headerName(raw: String): String = raw.trim().trimEnd(':').trim()

    /**
     * The path and query string [rule] rewrites [current] to, or null when it leaves them alone:
     * [ProxyRule.modifyPath] as written, or [current] with every match of
     * [ProxyRule.modifyPathRegex] replaced by it (`$1` refers to a group).
     */
    fun rewrittenPath(rule: ProxyRule, current: String): String? {
        val replacement = rule.modifyPath ?: return null
        val regex = rule.modifyPathRegex
        val rewritten = if (regex == null) replacement else SafeRegex.replace(regex, current, replacement, ignoreCase = true)
        return rewritten.takeIf { it != current }
    }

    /** True when [rule] has something for its `modify` action to do. */
    fun modifies(rule: ProxyRule): Boolean =
        rule.modifyAddHeader != null || rule.modifyRemoveHeader != null ||
            !rule.modifyReplaceHeader.isNullOrEmpty() || !rule.modifySetHeader.isNullOrEmpty() ||
            rule.modifyBodyRegex != null || rule.modifyMethod != null || rule.modifyPath != null ||
            rule.modifyStatus != null

    /** The first modification of [rule] that could never be applied, as an error message; null when all can. */
    fun error(rule: ProxyRule): String? {
        val request = rule.type.equals("request", ignoreCase = true)
        rule.modifyAddHeader?.let {
            if (parseHeaderLine(it) == null) return "modify_add_header must be a 'Name: Value' line (got '$it')"
        }
        rule.modifyRemoveHeader?.let {
            if (headerName(it).isEmpty()) return "modify_remove_header must name a header"
        }
        rule.modifyReplaceHeader?.keys?.forEach { name ->
            if (headerName(name).isEmpty()) return "modify_replace_header has an entry without a header name"
        }
        rule.modifySetHeader?.keys?.forEach { name ->
            if (headerName(name).isEmpty()) return "modify_set_header has an entry without a header name"
        }
        if (rule.modifyBodyRegex != null && rule.modifyBodyReplacement == null) {
            return "modify_body_replacement is required with modify_body_regex (use \"\" to delete matches)"
        }
        rule.modifyMethod?.let {
            if (!request) return "modify_method applies to request rules"
            if (it.isBlank()) return "modify_method must not be blank"
        }
        if (rule.modifyPath != null && !request) return "modify_path applies to request rules"
        rule.modifyPathRegex?.let { pattern ->
            if (!request) return "modify_path_regex applies to request rules"
            SafeRegex.validate(pattern, ignoreCase = true)?.let { return "Invalid modify_path_regex regex: $it" }
            if (rule.modifyPath == null) {
                return "modify_path is required with modify_path_regex (the replacement; use \"\" to delete matches)"
            }
        }
        rule.modifyStatus?.let {
            if (request) return "modify_status applies to response rules"
            if (it !in 0..MAX_STATUS) return "modify_status must be between 0 and $MAX_STATUS (got $it)"
        }
        return null
    }

    /** [request] with every modification of [rule]; the original is not changed. */
    fun applyTo(rule: ProxyRule, request: HttpRequest): HttpRequest {
        var modified = request
        rule.modifyRemoveHeader?.let { modified = HeaderModifier.remove(modified, headerName(it)) }
        rule.modifyAddHeader?.let { line ->
            parseHeaderLine(line)?.let { (name, value) -> modified = modified.withAddedHeader(name, value) }
        }
        rule.modifyReplaceHeader?.forEach { (name, value) -> modified = HeaderModifier.replace(modified, headerName(name), value) }
        rule.modifySetHeader?.forEach { (name, value) -> modified = HeaderModifier.set(modified, headerName(name), value) }
        if (rule.modifyBodyRegex != null) replacedBody(rule, modified.bodyToString())?.let { modified = modified.withBody(it) }
        rule.modifyMethod?.let { modified = modified.withMethod(it) }
        if (rule.modifyPath != null) rewrittenPath(rule, modified.path())?.let { modified = modified.withPath(it) }
        return modified
    }

    /** [response] with every modification of [rule]; the original is not changed. */
    fun applyTo(rule: ProxyRule, response: HttpResponse): HttpResponse {
        var modified = response
        rule.modifyRemoveHeader?.let { modified = HeaderModifier.remove(modified, headerName(it)) }
        rule.modifyAddHeader?.let { line ->
            parseHeaderLine(line)?.let { (name, value) -> modified = modified.withAddedHeader(name, value) }
        }
        rule.modifyReplaceHeader?.forEach { (name, value) -> modified = HeaderModifier.replace(modified, headerName(name), value) }
        rule.modifySetHeader?.forEach { (name, value) -> modified = HeaderModifier.set(modified, headerName(name), value) }
        if (rule.modifyBodyRegex != null) replacedBody(rule, modified.bodyToString())?.let { modified = modified.withBody(it) }
        rule.modifyStatus?.let { modified = modified.withStatusCode(it.toShort()) }
        return modified
    }

    /** The body after [rule]'s body regex, or null when the rule has none or it changes nothing. */
    private fun replacedBody(rule: ProxyRule, body: String): String? {
        val regex = rule.modifyBodyRegex ?: return null
        val replacement = rule.modifyBodyReplacement ?: return null
        return SafeRegex.replace(regex, body, replacement, ignoreCase = true).takeIf { it != body }
    }
}
