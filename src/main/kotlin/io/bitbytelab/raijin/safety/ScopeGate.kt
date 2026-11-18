package io.bitbytelab.raijin.safety

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import io.bitbytelab.raijin.bridge.HttpRequestBuilder
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put

/**
 * Outbound scope gate shared by the send paths. Reads the operator's mode from
 * the `mcp_scope_mode` preference on every check, so a change made in the Server
 * tab, or by an MCP client through `preference_store` (validated and announced
 * by PersistenceBridge), applies to the next request.
 *
 * - [ScopeMode.OFF] checks nothing.
 * - [ScopeMode.WARN] (default) sends and adds `scope_warning` to the result.
 * - [ScopeMode.ENFORCE] blocks the classic send paths ([check]) with [Check.denyJson].
 *
 * Turbo runs, Scanner tasks, WebSocket opens and followed redirects use [advise]:
 * they are flagged under warn and enforce, never blocked. Every warning lands in
 * the tool result, which ToolCallTracker turns into the MCP Activity flag and
 * the audit log's `out_of_scope` field.
 *
 * Fails open: when Burp cannot evaluate scope the request is sent with a
 * `scope_unchecked` warning, so a Burp quirk never blocks legitimate work.
 */
class ScopeGate internal constructor(
    private val readMode: () -> String?,
    private val isInScope: (String) -> Boolean,
) {
    constructor(api: MontoyaApi) : this(
        { api.persistence().preferences().getString(PREF_SCOPE_MODE) },
        { api.scope().isInScope(it) },
    )

    /**
     * One scope decision: [blocked] means nothing may be sent; [warning] annotates a send.
     * [reason] replaces the out-of-scope wording when the target could not be checked at all;
     * [blockedUrls] (at most [MAX_LISTED]) and [blockedCount] describe a multi-request check.
     */
    data class Check(
        val url: String,
        val mode: ScopeMode,
        val blocked: Boolean,
        val warning: String?,
        val reason: String? = null,
        val blockedUrls: List<String> = emptyList(),
        val blockedCount: Int = if (blocked) 1 else 0,
    ) {
        fun denyJson(): JsonObject = buildJsonObject {
            put(
                "error",
                "Not sent: ${reason ?: "$url is outside Burp's target scope"} and the operator's scope mode is enforce. " +
                    "Add the target with scope(action=include), or ask the operator to change mcp_scope_mode (Raijin > Server tab)."
            )
            put(OUT_OF_SCOPE, true)
            put("url", url)
            put("scope_mode", "enforce")
            if (blockedCount > 1) {
                put("blocked_count", blockedCount)
                put("blocked_urls", JsonArray(blockedUrls.map { JsonPrimitive(it) }))
            }
        }

        /** [result] with `scope_warning` as its first key (joined to an existing one), or unchanged without a warning. */
        fun annotate(result: JsonObject): JsonObject = addWarning(result, warning)
    }

    private fun mode(): ScopeMode = ScopeMode.fromString(
        try { readMode() } catch (_: Exception) { null }
    )

    /** Enforcing check: under ENFORCE an out-of-scope [url] is [Check.blocked]. */
    fun check(url: String): Check = evaluate(url, advisoryTool = null)

    /** Advisory check for [tool]: never blocked, flagged under warn and enforce. */
    fun advise(url: String, tool: String): Check = evaluate(url, advisoryTool = tool)

    /** Enforcing check of raw [requestText] sent to [host]:[port] (the connection target, never the request line's host). */
    fun checkRequest(host: String, port: Int, useTls: Boolean, requestText: String): Check =
        checkService(host, port, useTls, requestTarget(requestText))

    /**
     * Enforcing check of several raw requests sent to one [host]:[port]: every distinct target URL
     * is checked, and the call is blocked when any one is (fuzz positions, race payloads and later
     * pipeline items included).
     */
    fun checkRequests(host: String, port: Int, useTls: Boolean, requestTexts: Sequence<String>): Check {
        if (mode() == ScopeMode.OFF) return check(serviceUrl(host, port, useTls, null))
        var first: Check? = null
        val blocked = ArrayList<String>()
        var blockedCount = 0
        val warned = ArrayList<Check>()
        for (url in requestTexts.map { requestTarget(it) }.distinct()) {
            val c = checkService(host, port, useTls, url)
            if (first == null) first = c
            if (c.blocked) {
                blockedCount++
                if (blocked.size < MAX_LISTED) blocked += c.url
                if (blockedCount == 1) first = c
            } else if (c.warning != null) {
                warned += c
            }
        }
        val head = first ?: return checkService(host, port, useTls, null)
        if (blockedCount > 0) return head.copy(blockedUrls = blocked, blockedCount = blockedCount)
        val warning = when (warned.size) {
            0 -> null
            1 -> warned[0].warning
            else -> "${warned[0].warning} (and ${warned.size - 1} more out-of-scope URL(s) in this call)"
        }
        return head.copy(warning = warning)
    }

    /**
     * Enforcing check of a built Montoya [request]: the URL is its service (where the bytes go)
     * plus its path, never what `url()` derives from an absolute-form target or a Host header.
     * [fallbackUrl] is checked only for a request without a service, which cannot be sent.
     */
    fun checkHttpRequest(request: HttpRequest, fallbackUrl: String? = null): Check {
        val service = runCatching { request.httpService() }.getOrNull() ?: return check(fallbackUrl.orEmpty())
        return checkService(service.host(), service.port(), service.secure(), runCatching { request.path() }.getOrNull())
    }

    /**
     * A host that cannot be put into a URL as it is (`/ ? # @ \` or whitespace) could make the
     * checked URL name another host than the socket connects to: such a target is unchecked,
     * refused under enforce.
     */
    private fun checkService(host: String, port: Int, useTls: Boolean, target: String?): Check {
        val url = serviceUrl(host, port, useTls, target)
        if (host.none { it in UNSAFE_HOST_CHARS || it.isWhitespace() }) return check(url)
        return when (val m = mode()) {
            ScopeMode.OFF -> Check(url, m, false, null)
            ScopeMode.ENFORCE -> Check(url, m, true, null, reason = "the host '$host' cannot be checked against Burp's scope")
            ScopeMode.WARN -> Check(url, m, false, "scope_unchecked: the host '$host' cannot be checked against Burp's scope; sent unchecked")
        }
    }

    private fun evaluate(url: String, advisoryTool: String?): Check {
        val m = mode()
        if (m == ScopeMode.OFF) return Check(url, m, false, null)
        val inScope = try {
            isInScope(url)
        } catch (e: Exception) {
            return Check(url, m, false, "scope_unchecked: could not evaluate Burp's scope for $url (${e.message}); sent unchecked")
        }
        return when (ScopePolicy.decide(m, inScope)) {
            ScopeDecision.ALLOW -> Check(url, m, false, null)
            ScopeDecision.WARN -> Check(url, m, false, warnText(url))
            ScopeDecision.DENY -> if (advisoryTool == null) Check(url, m, true, null) else Check(
                url, m, false,
                "out_of_scope: $url is not in Burp's target scope; sent anyway: $advisoryTool is advisory-only and not blocked by mcp_scope_mode=enforce"
            )
        }
    }

    companion object {
        const val PREF_SCOPE_MODE = "mcp_scope_mode"
        const val WARNING = "scope_warning"
        const val OUT_OF_SCOPE = "out_of_scope"
        const val SKIPPED = "skipped_out_of_scope"
        const val SENT = "sent_out_of_scope"
        const val TOOL_NOTE = "Scope: checked against Burp's target scope per the operator's mcp_scope_mode: warn (default) sends and adds scope_warning; enforce refuses (out_of_scope=true, nothing sent); off skips the check."
        const val ADVISORY_NOTE = "Scope: advisory only. An out-of-scope target gets scope_warning under mcp_scope_mode warn and enforce; it is never blocked."

        private fun warnText(url: String) = "out_of_scope: $url is not in Burp's target scope (mcp_scope_mode=warn); sent anyway"

        /** [result] with [warning] as the first `scope_warning` key, joined with "; " to an existing one. */
        fun addWarning(result: JsonObject, warning: String?): JsonObject {
            if (warning == null) return result
            val previous = (result[WARNING] as? JsonPrimitive)?.contentOrNull
            val text = if (previous.isNullOrEmpty()) warning else "$previous; $warning"
            return buildJsonObject {
                put(WARNING, text)
                for ((k, v) in result) if (k != WARNING) put(k, v)
            }
        }

        /** Most URLs a blocked multi-request check lists. */
        const val MAX_LISTED = 20

        private const val UNSAFE_HOST_CHARS = "/?#@\\"
        private val REQUEST_LINE_SEPARATORS = Regex("[ \t]+")

        /**
         * The URL a raw request sent to [host]:[port] reaches: always that connection target, plus
         * the request-line path (the path of an absolute-form target, whose own host is not where
         * the bytes go; `/` when there is none).
         */
        fun requestUrl(host: String, port: Int, useTls: Boolean, requestText: String): String =
            serviceUrl(host, port, useTls, requestTarget(requestText))

        /**
         * The request-target of [requestText]'s request line, read as servers do: leading empty
         * lines skipped, the line split on spaces or tabs. Null when there is none.
         */
        fun requestTarget(requestText: String): String? {
            val start = requestText.indexOfFirst { it != '\r' && it != '\n' }.takeIf { it >= 0 } ?: return null
            val end = requestText.indexOfAny(charArrayOf('\r', '\n'), start).let { if (it < 0) requestText.length else it }
            return requestText.substring(start, end).split(REQUEST_LINE_SEPARATORS).filter { it.isNotEmpty() }.getOrNull(1)
        }

        /** `scheme://host:port` of the connection plus the path of [target] (origin or absolute form). */
        fun serviceUrl(host: String, port: Int, useTls: Boolean, target: String?): String {
            val path = when {
                target == null -> "/"
                target.startsWith("/") -> target
                else -> HttpRequestBuilder.splitUrl(target)?.target ?: "/"
            }
            val hostLit = if (host.contains(':') && !host.startsWith("[")) "[$host]" else host
            return "${if (useTls) "https" else "http"}://$hostLit:$port$path"
        }
    }
}
