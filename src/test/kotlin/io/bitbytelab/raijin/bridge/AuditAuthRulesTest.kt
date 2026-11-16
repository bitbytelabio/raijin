package io.bitbytelab.raijin.bridge

import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.state.ScanTask
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.state.TrafficRule
import java.lang.reflect.Proxy
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * An audit's auth header rules (plan P0.3 item 4): limited to the audited hosts and to Scanner
 * traffic, and gone when the audit is.
 */
class AuditAuthRulesTest {

    private val state = StateManager()
    // Read by the watcher thread in one test.
    @Volatile private var status: String? = "Auditing"
    @Volatile private var requestCount: Int? = 0

    /** A poll interval no test waits for, so the watcher never sweeps behind a test's back. */
    private val rules = AuditAuthRules(state, observe = { AuditAuthRules.Observation(status, requestCount) }, pollMs = 3_600_000)

    @AfterTest
    fun stopWatcher() = rules.shutdown()

    private fun plan(vararg hosts: String) = AuditAuthRules.Plan("Authorization", "Bearer abc", hosts.toSet())

    private fun audit(taskId: String, plan: AuditAuthRules.Plan = plan("app.example.com")): String {
        val ruleId = rules.install(plan)
        state.scanTasks[taskId] = ScanTask(taskId, "audit", Any(), "2026-01-01T00:00:00Z", authRuleId = ruleId)
        rules.track(taskId, ruleId)
        return ruleId
    }

    private fun appliesTo(rule: TrafficRule, tool: String, host: String): Boolean =
        HttpBridge.trafficRuleAppliesTo(rule, tool, internalProbe = false) &&
            (rule.matchHost == null || SafeRegex.matchesHostPattern(rule.matchHost, host))

    /** A request whose `toString()` is its headers, one per line; `with*` return modified copies. */
    private fun request(host: String?, headers: List<Pair<String, String>>): HttpRequest =
        Proxy.newProxyInstance(HttpRequest::class.java.classLoader, arrayOf(HttpRequest::class.java)) { _, method, args ->
            when (method.name) {
                "toString" -> headers.joinToString("\n") { "${it.first}: ${it.second}" }
                "httpService" -> host?.let { h ->
                    Proxy.newProxyInstance(HttpService::class.java.classLoader, arrayOf(HttpService::class.java)) { _, m, _ ->
                        if (m.name == "host") h else error("unexpected HttpService.${m.name}")
                    }
                }
                "withRemovedHeader" -> request(host, headers.filterNot { it.first.equals(args[0] as String, ignoreCase = true) })
                "withAddedHeader" -> request(host, headers + (args[0] as String to args[1] as String))
                else -> error("unexpected HttpRequest.${method.name}")
            }
        } as HttpRequest

    // ---- scope -------------------------------------------------------------

    @Test
    fun `the header goes to the audited host from the Scanner and nowhere else`() {
        rules.install(plan("app.example.com"))
        assertEquals(2, state.trafficRules.size)
        for (rule in state.trafficRules) {
            assertEquals("request", rule.direction)
            assertTrue(appliesTo(rule, "SCANNER", "app.example.com"))
            assertTrue(appliesTo(rule, "SCANNER", "APP.example.com"), "host names are case-insensitive")
            // Other targets being tested at the same time must not receive the credential.
            assertFalse(appliesTo(rule, "SCANNER", "other.example.com"))
            assertFalse(appliesTo(rule, "SCANNER", "app.example.com.evil.net"))
            assertFalse(appliesTo(rule, "SCANNER", "notapp.example.com"))
            // Nor traffic of any other tool to the audited host.
            assertFalse(appliesTo(rule, "PROXY", "app.example.com"))
            assertFalse(appliesTo(rule, "REPEATER", "app.example.com"))
            assertFalse(appliesTo(rule, "EXTENSIONS", "app.example.com"))
            // An internal unauthenticated probe must never pick it up.
            assertFalse(HttpBridge.trafficRuleAppliesTo(rule, "EXTENSIONS", internalProbe = true))
        }
    }

    @Test
    fun `the header replaces a value the request already carries`() {
        rules.install(plan("app.example.com"))
        // The global handler applies rules in list order: strip first, then add.
        val (strip, add) = state.trafficRules.toList()
        assertEquals("Authorization", strip.modifyRemoveHeader)
        assertNull(strip.modifyAddHeader)
        assertEquals("Authorization: Bearer abc", add.modifyAddHeader)
        assertNull(add.modifyRemoveHeader)
    }

    @Test
    fun `several audited hosts are all covered and still nothing else`() {
        rules.install(plan("a.example.com", "b.example.org", "::1"))
        val rule = state.trafficRules.last()
        for (host in listOf("a.example.com", "B.EXAMPLE.ORG", "::1", "[::1]")) assertTrue(appliesTo(rule, "SCANNER", host), host)
        for (host in listOf("c.example.com", "a.example.com.b.example.org", "example.com", "a-example.com")) {
            assertFalse(appliesTo(rule, "SCANNER", host), host)
        }
    }

    @Test
    fun `a host with pattern characters is matched as text`() {
        // Not a wildcard, not a regex: exactly this odd name.
        val pattern = AuditAuthRules.hostPattern(listOf("a*b.example.com"))
        assertTrue(SafeRegex.matchesHostPattern(pattern, "a*b.example.com"))
        assertFalse(SafeRegex.matchesHostPattern(pattern, "aXXb.example.com"))
        assertEquals("app.example.com", AuditAuthRules.hostPattern(listOf("app.example.com")), "a plain host stays readable")
    }

    @Test
    fun `target hosts come from URLs and from raw requests`() {
        val hosts = AuditAuthRules.targetHosts(
            urls = listOf(
                "https://App.Example.com:8443/a?b=c",
                "http://user:pw@intra_net.local/x y",   // java.net.URI rejects both the host and the path
                "http://[2001:db8::1]:8080/",
                "not a url",
            ),
            rawRequests = listOf(
                "GET /a HTTP/1.1\r\nHost: api.example.com:9443\r\nAccept: */*\r\n\r\nHost: body.example.com",
                "GET http://absolute.example.com/x HTTP/1.1\nAccept: */*\n\n",
                "GET /nohost HTTP/1.1\r\n\r\n",
            ),
        )
        assertEquals(
            setOf("app.example.com", "intra_net.local", "2001:db8::1", "api.example.com", "absolute.example.com"),
            hosts,
        )
    }

    @Test
    fun `a plan needs an injectable header and a host to limit it to`() {
        val urls = listOf("https://app.example.com/")
        val plan = AuditAuthRules.plan(" Authorization ", " Bearer abc ", urls, emptyList())
        assertEquals("Authorization", plan.headerName)
        assertEquals("Bearer abc", plan.headerValue)
        assertEquals(setOf("app.example.com"), plan.hosts)

        // The rule engine silently drops a header line it cannot parse; the audit would run unauthenticated.
        assertFailsWith<IllegalArgumentException> { AuditAuthRules.plan("X: Y", "v", urls, emptyList()) }
        assertFailsWith<IllegalArgumentException> { AuditAuthRules.plan("X", "a\r\nInjected: 1", urls, emptyList()) }
        assertFailsWith<IllegalArgumentException> { AuditAuthRules.plan("", "v", urls, emptyList()) }

        // No host to scope to: refusing beats a rule that sends the credential to every host.
        val e = assertFailsWith<IllegalArgumentException> { AuditAuthRules.plan("Authorization", "v", listOf("/relative"), emptyList()) }
        assertTrue("no target host" in e.message!!, e.message)
    }

    // ---- lifetime -----------------------------------------------------------

    @Test
    fun `the rules stay while the audit runs or is paused and go when it ends`() {
        audit("scan-1")
        for (running in listOf("Auditing", "Paused", "Waiting to start", "37% complete", "")) {
            status = running
            rules.sweep()
            assertEquals(2, state.trafficRules.size, "must survive status '$running'")
            assertTrue(rules.isActive("scan-1"))
        }

        status = "Audit finished"
        rules.sweep()
        assertTrue(state.trafficRules.isEmpty())
        assertFalse(rules.isActive("scan-1"))
        assertEquals("audit ended (Audit finished)", rules.releasedReason("scan-1"))
    }

    @Test
    fun `every way an audit ends is recognised`() {
        for (ended in listOf("Finished", "100% complete", "Completed", "Cancelled", "canceled by user", "Aborted", "abandoned - too many errors")) {
            assertTrue(AuditAuthRules.isTerminalStatus(ended), ended)
        }
        for (alive in listOf("Auditing", "Paused", "0% complete", "99 % complete", "Waiting to cancel", "Estimating time remaining")) {
            assertFalse(AuditAuthRules.isTerminalStatus(alive), alive)
        }
    }

    @Test
    fun `a Burp without task status releases the rules once the audit has gone quiet`() {
        val limit = AuditAuthRules.IDLE_LIMIT_MS
        assertNull(AuditAuthRules.releaseReason(null, requestCount = 120, idleMs = limit - 1))
        assertTrue("no audit requests" in AuditAuthRules.releaseReason(null, requestCount = 120, idleMs = limit)!!)
        // Never sent anything: it has not started, or has nothing to send. Not "ended".
        assertNull(AuditAuthRules.releaseReason(null, requestCount = 0, idleMs = limit * 10))
        // Nothing observable at all: keep the rules until the task is deleted.
        assertNull(AuditAuthRules.releaseReason(null, requestCount = null, idleMs = limit * 10))
        // A status message, when there is one, decides alone: a paused audit keeps its rules however long.
        assertNull(AuditAuthRules.releaseReason("Paused", requestCount = 120, idleMs = limit * 10))
    }

    @Test
    fun `quiet is measured from the last request the audit made`() {
        status = null
        requestCount = 10
        audit("scan-1")
        val start = System.currentTimeMillis()
        rules.sweep(start)                                       // sees 10 requests
        requestCount = 25
        rules.sweep(start + AuditAuthRules.IDLE_LIMIT_MS)        // still working: the count moved
        assertEquals(2, state.trafficRules.size)
        rules.sweep(start + 2 * AuditAuthRules.IDLE_LIMIT_MS - 1)
        assertEquals(2, state.trafficRules.size)
        rules.sweep(start + 2 * AuditAuthRules.IDLE_LIMIT_MS)    // a full idle period since the count last moved
        assertTrue(state.trafficRules.isEmpty())
    }

    @Test
    fun `deleting the audit removes its rules and nobody else's`() {
        val operatorRule = TrafficRule(ruleId = "trule-1", direction = "request", modifyAddHeader = "X-Test: 1")
        state.trafficRules.add(operatorRule)
        audit("scan-1")
        audit("scan-2", plan("other.example.com"))
        assertEquals(5, state.trafficRules.size)

        rules.forget("scan-1")
        assertEquals(3, state.trafficRules.size)
        assertSame(operatorRule, state.trafficRules.first())
        assertTrue(rules.isActive("scan-2"))

        // A task that vanished from the state without forget() is caught by the next sweep.
        state.scanTasks.remove("scan-2")
        rules.sweep()
        assertEquals(listOf(operatorRule), state.trafficRules.toList())
    }

    @Test
    fun `removing the add rule by hand takes the strip rule with it`() {
        val ruleId = audit("scan-1")
        // What http_rule(traffic_rule_remove) does. The strip rule alone would delete the header from Scanner traffic.
        state.trafficRules.removeIf { it.ruleId == ruleId }
        rules.sweep()
        assertTrue(state.trafficRules.isEmpty())
        assertFalse(rules.isActive("scan-1"))
    }

    @Test
    fun `shutdown removes every audit's rules`() {
        audit("scan-1")
        audit("scan-2", plan("other.example.com"))
        rules.shutdown()
        assertTrue(state.trafficRules.isEmpty())
    }

    @Test
    fun `the rules are removed when the audit ends even if nobody polls the task`() {
        val watched = AuditAuthRules(state, observe = { AuditAuthRules.Observation(status, requestCount) }, pollMs = 20)
        try {
            val ruleId = watched.install(plan("app.example.com"))
            state.scanTasks["scan-9"] = ScanTask("scan-9", "audit", Any(), "2026-01-01T00:00:00Z", authRuleId = ruleId)
            watched.track("scan-9", ruleId)
            Thread.sleep(100)
            assertEquals(2, state.trafficRules.size, "still auditing")

            status = "Finished"
            val deadline = System.currentTimeMillis() + 5_000
            while (state.trafficRules.isNotEmpty() && System.currentTimeMillis() < deadline) Thread.sleep(10)
            assertTrue(state.trafficRules.isEmpty(), "the watcher must have swept the finished audit")
        } finally {
            watched.shutdown()
        }
    }

    // ---- custom scan check probes --------------------------------------------

    @Test
    fun `a custom check's probe to an audited host carries the audit's header exactly once`() {
        rules.install(plan("app.example.com"))
        val probe = request("app.example.com", listOf("Accept" to "*/*", "authorization" to "Bearer stale"))

        val sent = AuditAuthRules.withAuditAuth(state, probe)

        assertEquals("Accept: */*\nAuthorization: Bearer abc", sent.toString())
    }

    @Test
    fun `a probe to another host, or with no audit auth in place, is left alone`() {
        val elsewhere = request("other.example.com", listOf("Accept" to "*/*"))
        assertSame(elsewhere, AuditAuthRules.withAuditAuth(state, elsewhere), "no rule at all")

        rules.install(plan("app.example.com"))
        assertEquals("Accept: */*", AuditAuthRules.withAuditAuth(state, elsewhere).toString())

        // An operator's own rule is the global handler's business, not this function's.
        state.trafficRules.clear()
        state.trafficRules.add(TrafficRule(ruleId = "trule-1", direction = "request", modifyAddHeader = "X-Test: 1"))
        val audited = request("app.example.com", emptyList())
        assertSame(audited, AuditAuthRules.withAuditAuth(state, audited))
    }
}
