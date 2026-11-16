package io.bitbytelab.raijin.bridge

import burp.api.montoya.http.message.HttpHeader
import io.bitbytelab.raijin.safety.SafeRegex

/**
 * The host, URL and header conditions shared by HTTP traffic rules ([TrafficRuleApplier]) and proxy
 * rules, so a stored pattern means the same to both. Each check is for a condition the rule sets;
 * a value Burp could not give (null) never satisfies it.
 *
 * WebSocket intercept rules match on their own ([WebSocketInterceptRules]): their URL and content
 * patterns are case-sensitive.
 */
internal object RuleMatcher {

    /** [host] against a host glob (`*.example.com`) or regex, ignoring case ([SafeRegex.matchesHostPattern]). */
    fun host(pattern: String, host: String?): Boolean = host != null && SafeRegex.matchesHostPattern(pattern, host)

    /** The regex [pattern] found anywhere in [url], ignoring case. */
    fun url(pattern: String, url: String?): Boolean = url != null && SafeRegex.containsMatchIn(pattern, url, ignoreCase = true)

    /**
     * The regex [pattern] found, ignoring case, in [headers] written as `Name: value` lines joined
     * by CRLF, with none after the last line; a pattern can span lines.
     */
    fun headers(pattern: String, headers: List<HttpHeader>): Boolean =
        SafeRegex.containsMatchIn(pattern, headerLines(headers), ignoreCase = true)

    private fun headerLines(headers: List<HttpHeader>): String {
        val text = StringBuilder()
        headers.forEachIndexed { i, header ->
            if (i > 0) text.append("\r\n")
            text.append(header.name()).append(": ").append(header.value())
        }
        return text.toString()
    }
}
