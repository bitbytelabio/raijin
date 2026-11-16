package io.bitbytelab.raijin.bridge

import burp.api.montoya.http.message.requests.HttpRequest
import io.bitbytelab.raijin.safety.HeaderSafety
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.state.ScanTask
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.state.TrafficRule
import java.util.concurrent.ConcurrentHashMap

/**
 * The traffic rules that put an audit's auth header on its requests.
 *
 * An audit gets two rules, both limited to Scanner traffic to the audited hosts: one strips the
 * header and the next adds it, so a request that already carries the header leaves with exactly
 * one. A Cookie header is the exception. It gets one rule that sets the cookies it names and
 * leaves the request's other cookies alone, so the Scanner's cookie payloads and the target's CSRF
 * and load balancer cookies still go out. The rules live only as long as the audit: [forget]
 * removes them when it is deleted, [sweep] when it has ended, and a watcher thread sweeps while
 * any audit is tracked, so the cleanup does not depend on anyone polling the task.
 *
 * @param observe reads an audit's state from Burp.
 */
internal class AuditAuthRules(
    private val stateManager: StateManager,
    private val observe: (ScanTask) -> Observation,
    private val pollMs: Long = 5_000,
) {
    /** What Burp says about an audit. A null field means this Burp cannot tell. */
    class Observation(val status: String?, val requestCount: Int?)

    /**
     * A validated auth header and the hosts it may be sent to.
     *
     * @property cookies for a Cookie header, the cookies it sets ([cookiePairs]). Null for any other
     *   header, and for a Cookie value without a single pair, which replaces the header as given.
     */
    class Plan(val headerName: String, val headerValue: String, val hosts: Set<String>) {
        val cookies: Map<String, String>? =
            if (headerName.equals(COOKIE, ignoreCase = true)) cookiePairs(headerValue).takeIf { it.isNotEmpty() } else null
    }

    private class Tracked(val ruleId: String, var lastCount: Int?, var lastChangeAt: Long)

    /** Audit task id -> its live rules. */
    private val tracked = ConcurrentHashMap<String, Tracked>()

    /** Audit task id -> why its rules were removed while the task still exists. */
    private val released = ConcurrentHashMap<String, String>()

    private val watchLock = Any()
    private var watcher: Thread? = null

    /** Adds the rules for [plan]. Returns the id of the rule that sets the header. */
    fun install(plan: Plan): String {
        val ruleId = stateManager.generateId(RULE_PREFIX)
        val scope = hostPattern(plan.hosts)
        val cookies = plan.cookies
        if (cookies != null) {
            stateManager.trafficRules.add(
                TrafficRule(
                    ruleId = ruleId,
                    direction = "request",
                    matchHost = scope,
                    modifySetCookies = cookies,
                    toolFilter = SCANNER_ONLY,
                )
            )
            return ruleId
        }
        // One addAll: no request may see the strip rule without the rule that puts the header back.
        stateManager.trafficRules.addAll(
            listOf(
                TrafficRule(
                    ruleId = ruleId + STRIP_SUFFIX,
                    direction = "request",
                    matchHost = scope,
                    modifyRemoveHeader = plan.headerName,
                    toolFilter = SCANNER_ONLY,
                ),
                TrafficRule(
                    ruleId = ruleId,
                    direction = "request",
                    matchHost = scope,
                    modifyAddHeader = "${plan.headerName}: ${plan.headerValue}",
                    toolFilter = SCANNER_ONLY,
                ),
            )
        )
        return ruleId
    }

    /** Removes the rules [install] returned [ruleId] for. */
    fun remove(ruleId: String) {
        stateManager.trafficRules.removeIf { it.ruleId == ruleId || it.ruleId == ruleId + STRIP_SUFFIX }
    }

    /** Ties the rules [ruleId] to the audit [taskId], so they go when it does. */
    fun track(taskId: String, ruleId: String) {
        tracked[taskId] = Tracked(ruleId, lastCount = null, lastChangeAt = System.currentTimeMillis())
        ensureWatcher()
    }

    /** Removes the rules of [taskId] because the audit is gone. */
    fun forget(taskId: String) {
        tracked.remove(taskId)?.let { remove(it.ruleId) }
        released.remove(taskId)
    }

    fun isActive(taskId: String): Boolean = tracked.containsKey(taskId)

    /** Why the rules of [taskId] were removed, or null while they are in place. */
    fun releasedReason(taskId: String): String? = released[taskId]

    /** Removes the rules of every tracked audit that has ended. */
    @Synchronized
    fun sweep(now: Long = System.currentTimeMillis()) {
        released.keys.removeIf { !stateManager.scanTasks.containsKey(it) }
        for ((taskId, entry) in tracked.entries.toList()) {
            val task = stateManager.scanTasks[taskId]
            val reason = when {
                task == null -> "audit deleted"
                stateManager.trafficRules.none { it.ruleId == entry.ruleId } -> "rule removed"
                else -> {
                    val seen = try { observe(task) } catch (_: Throwable) { Observation(null, null) }
                    if (seen.requestCount != null && seen.requestCount != entry.lastCount) {
                        entry.lastCount = seen.requestCount
                        entry.lastChangeAt = now
                    }
                    releaseReason(seen.status, seen.requestCount, now - entry.lastChangeAt)
                }
            } ?: continue
            tracked.remove(taskId)
            remove(entry.ruleId)
            if (task != null) released[taskId] = reason
        }
    }

    /** Stops the watcher and removes every rule still tracked. */
    fun shutdown() {
        synchronized(watchLock) {
            watcher?.interrupt()
            watcher = null
        }
        tracked.values.toList().forEach { remove(it.ruleId) }
        tracked.clear()
        released.clear()
    }

    private fun ensureWatcher() {
        synchronized(watchLock) {
            if (watcher?.isAlive == true) return
            watcher = Thread({ watch() }, "raijin-audit-auth").apply {
                isDaemon = true
                start()
            }
        }
    }

    /** Sweeps until nothing is tracked. Unload empties the state it reads, so the thread ends by itself. */
    private fun watch() {
        while (true) {
            try {
                Thread.sleep(pollMs)
            } catch (_: InterruptedException) {
                return
            }
            try { sweep() } catch (_: Throwable) {}
            synchronized(watchLock) {
                if (tracked.isEmpty()) {
                    if (watcher === Thread.currentThread()) watcher = null
                    return
                }
            }
        }
    }

    companion object {
        const val RULE_PREFIX = "auth-rule"
        private const val STRIP_SUFFIX = "-strip"
        private val SCANNER_ONLY = setOf("SCANNER")

        /** Without a task status to go by, an audit that sent requests and then none for this long has ended. */
        const val IDLE_LIMIT_MS = 10 * 60_000L

        private val PLAIN_HOST = Regex("[A-Za-z0-9.-]+")
        private val HOST_HEADER = Regex("(?i)host\\s*:(.*)")
        private val WHITESPACE = Regex("\\s+")
        private val PERCENT = Regex("(\\d{1,3})\\s*%")
        private val ENDED = listOf("finished", "cancelled", "canceled", "aborted", "abandoned")
        private const val COOKIE = "Cookie"

        /**
         * Validates the header and works out which hosts it may be sent to.
         *
         * @param rawRequests the audit's raw HTTP requests as text.
         * @throws IllegalArgumentException with a message for the caller when the header cannot be
         *   injected or no host can be derived to scope it to.
         */
        fun plan(headerName: String, headerValue: String, urls: List<String>, rawRequests: List<String>): Plan {
            val name = headerName.trim()
            val value = headerValue.trim()
            // The traffic-rule engine drops a header line it cannot parse, which would run the audit unauthenticated.
            require(HeaderSafety.isValidHeaderName(name) && HeaderSafety.isValidHeaderValue(value)) {
                "auth_header_name must be a header name without ':' and neither it nor auth_header_value may contain a line break"
            }
            val hosts = targetHosts(urls, rawRequests)
            require(hosts.isNotEmpty()) {
                "auth_header_name was given, but no target host could be derived from 'urls' (absolute URLs) or " +
                    "'requests' (Host header), so the header cannot be limited to the audited hosts. Nothing was started."
            }
            return Plan(name, value, hosts)
        }

        /** The hosts an audit of [urls] and [rawRequests] talks to. */
        fun targetHosts(urls: List<String>, rawRequests: List<String>): Set<String> {
            val hosts = LinkedHashSet<String>()
            urls.forEach { url -> authorityOfUrl(url)?.let(::hostOf)?.let { hosts.add(it) } }
            rawRequests.forEach { raw -> authorityOfRawRequest(raw)?.let(::hostOf)?.let { hosts.add(it) } }
            return hosts
        }

        /** `host[:port]` of an absolute URL, or null. Hand-parsed: java.net.URI rejects hosts and paths a target still serves. */
        fun authorityOfUrl(url: String): String? {
            val schemeEnd = url.indexOf("://")
            if (schemeEnd <= 0) return null
            val rest = url.substring(schemeEnd + 3)
            val end = rest.indexOfFirst { it == '/' || it == '?' || it == '#' }
            val authority = if (end < 0) rest else rest.substring(0, end)
            return authority.substringAfterLast('@').trim().takeIf { it.isNotEmpty() }
        }

        /** `host[:port]` a raw HTTP request is for: its Host header, else an absolute-form request line. */
        fun authorityOfRawRequest(raw: String): String? {
            val lines = raw.substringBefore("\r\n\r\n").substringBefore("\n\n").lines()
            val hostHeader = lines.drop(1).firstNotNullOfOrNull { line ->
                HOST_HEADER.matchEntire(line.trim())?.groupValues?.get(1)?.trim()?.takeIf { it.isNotEmpty() }
            }
            if (hostHeader != null) return hostHeader
            val target = lines.firstOrNull()?.trim()?.split(WHITESPACE)?.getOrNull(1) ?: return null
            return authorityOfUrl(target)
        }

        /** The bare lower-case host of `host[:port]` (an IPv6 literal without its brackets), or null. */
        fun hostOf(authority: String): String? {
            val host = when {
                authority.startsWith("[") -> authority.substring(1).substringBefore(']')
                authority.count { it == ':' } > 1 -> authority
                else -> authority.substringBefore(':')
            }.trim().lowercase()
            return host.takeIf { it.isNotEmpty() && it.none(Char::isWhitespace) }
        }

        /** A [TrafficRule.matchHost] value that matches [hosts] and nothing else. */
        fun hostPattern(hosts: Collection<String>): String {
            hosts.singleOrNull()?.takeIf { PLAIN_HOST.matches(it) }?.let { return it }
            // Quoted alternatives; SafeRegex.matchesHostPattern reads the backslashes as "this is a regex"
            // and matches it against the whole host. An IPv6 host is listed with and without brackets.
            return hosts.flatMap { if (':' in it) listOf(it, "[$it]") else listOf(it) }
                .joinToString("|") { Regex.escape(it) }
        }

        /** Whether a task status message says the audit is over. "37% complete" is progress, "100% complete" the end. */
        fun isTerminalStatus(status: String): Boolean {
            val s = status.lowercase()
            if (ENDED.any { it in s }) return true
            if ("complete" !in s) return false
            val percent = PERCENT.find(s)?.groupValues?.get(1)?.toIntOrNull()
            return percent == null || percent >= 100
        }

        /**
         * Why an audit's rules should be removed now, or null to keep them. A status message decides
         * when Burp gives one (a paused audit keeps its rules). Without one, an audit that sent
         * requests and has been silent for [IDLE_LIMIT_MS] counts as ended.
         */
        fun releaseReason(status: String?, requestCount: Int?, idleMs: Long): String? = when {
            !status.isNullOrBlank() -> if (isTerminalStatus(status)) "audit ended (${status.trim()})" else null
            requestCount != null && requestCount > 0 && idleMs >= IDLE_LIMIT_MS ->
                "no audit requests for ${IDLE_LIMIT_MS / 60_000} min, and this Burp does not report task status"
            else -> null
        }

        /**
         * [request] carrying the header of every live audit auth rule that covers its host, or for
         * a Cookie rule its cookies.
         *
         * The rules are SCANNER-only. A custom scan check's probes leave Burp as extension traffic,
         * so the global handler would send them without the header the audit they run in is using,
         * and an unauthenticated probe compared with an authenticated baseline is a false finding.
         */
        fun withAuditAuth(stateManager: StateManager, request: HttpRequest): HttpRequest {
            val rules = stateManager.trafficRules.filter { it.enabled && isAuthRule(it) }
            if (rules.isEmpty()) return request
            val host = runCatching { request.httpService().host() }.getOrNull() ?: return request
            var out = request
            for (rule in rules) {
                if (rule.matchHost != null && !SafeRegex.matchesHostPattern(rule.matchHost, host)) continue
                val cookies = rule.modifySetCookies
                if (cookies != null) {
                    out = withCookies(out, cookies)
                    continue
                }
                val (name, value) = HeaderSafety.parseHeaderLine(rule.modifyAddHeader ?: continue) ?: continue
                out = out.withRemovedHeader(name).withAddedHeader(name, value)
            }
            return out
        }

        /** The rule that sets an audit's header or cookies, not the strip rule that goes with a header. */
        private fun isAuthRule(rule: TrafficRule): Boolean =
            rule.ruleId.startsWith("$RULE_PREFIX-") && !rule.ruleId.endsWith(STRIP_SUFFIX) &&
                (rule.modifyAddHeader != null || rule.modifySetCookies != null)

        /**
         * The pairs of a Cookie header value by name, in order. A pair without `=` is the nameless
         * cookie, kept under "". A name given twice keeps its last value.
         */
        fun cookiePairs(value: String): Map<String, String> {
            val pairs = LinkedHashMap<String, String>()
            for (segment in value.split(';')) {
                val pair = segment.trim()
                if (pair.isNotEmpty()) pairs[cookieName(pair)] = if ('=' in pair) pair.substringAfter('=').trim() else pair
            }
            return pairs
        }

        /**
         * [request] with [cookies] set in its Cookie header ([setCookies]); every other cookie pair it
         * carries stays as it is. A request that already carries exactly these values is returned as is.
         */
        fun withCookies(request: HttpRequest, cookies: Map<String, String>): HttpRequest {
            if (cookies.isEmpty()) return request
            val current = request.headers().filter { it.name().equals(COOKIE, ignoreCase = true) }
            val values = current.map { it.value() }
            val merged = setCookies(values, cookies)
            if (merged == values) return request
            if (current.size == 1 && merged.size == 1) return request.withUpdatedHeader(current[0].name(), merged[0])
            // None yet, or several: written back in order, under the name the first one was written with.
            val name = current.firstOrNull()?.name() ?: COOKIE
            return merged.fold(ProxyRuleEdits.removeHeader(request, COOKIE)) { out, value -> out.withAddedHeader(name, value) }
        }

        /**
         * The values of a request's Cookie headers, [headers] in order, with [cookies] set. A named
         * cookie takes its value where it first appears and is dropped where it appears again, so it
         * goes out once; one the request lacks is appended to the last header, or makes up a header
         * of its own. Every other pair stays as written, separators included, and a header left
         * without a pair is dropped.
         */
        fun setCookies(headers: List<String>, cookies: Map<String, String>): List<String> {
            if (cookies.isEmpty()) return headers
            val placed = HashSet<String>()
            val out = ArrayList<String>(headers.size + 1)
            for (header in headers) {
                val kept = header.split(';').mapNotNull { segment ->
                    val pair = segment.trim()
                    val name = cookieName(pair)
                    when {
                        pair.isEmpty() || name !in cookies -> segment
                        placed.add(name) -> segment.takeWhile(Char::isWhitespace) + cookiePair(name, cookies.getValue(name))
                        else -> null
                    }
                }
                if (kept.any { it.isNotBlank() }) out += kept.joinToString(";").trimStart()
            }
            val missing = cookies.filterKeys { it !in placed }.map { (name, value) -> cookiePair(name, value) }
            if (missing.isEmpty()) return out
            val added = missing.joinToString("; ")
            val last = out.removeLastOrNull()?.trimEnd()
            out += when {
                last.isNullOrEmpty() -> added
                last.endsWith(';') -> "$last $added"
                else -> "$last; $added"
            }
            return out
        }

        private fun cookieName(pair: String): String = if ('=' in pair) pair.substringBefore('=').trim() else ""

        private fun cookiePair(name: String, value: String): String = if (name.isEmpty()) value else "$name=$value"
    }
}
