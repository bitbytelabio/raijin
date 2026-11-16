package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.ReportFormat
import burp.api.montoya.scanner.Scanner
import burp.api.montoya.scanner.audit.Audit
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import burp.api.montoya.sitemap.SiteMap
import burp.api.montoya.sitemap.SiteMapFilter
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.lang.reflect.Proxy
import java.util.Base64
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** A [T] whose calls go to [handler] (method name, arguments). */
private inline fun <reified T : Any> fake(noinline handler: (String, Array<out Any?>) -> Any?): T =
    Proxy.newProxyInstance(T::class.java.classLoader, arrayOf(T::class.java)) { proxy, method, args ->
        when (method.name) {
            "toString" -> "fake ${T::class.simpleName}"
            "hashCode" -> System.identityHashCode(proxy)
            "equals" -> proxy === args?.firstOrNull()
            else -> handler(method.name, args ?: emptyArray<Any?>())
        }
    } as T

/**
 * `scanner_start_audit` with an auth header, driven through [ScannerBridge] against a stand-in
 * for Burp's scanner (plan P0.3 item 4): where the header may go, how long its rules live, and
 * that no failed start leaves them behind. Also the task-issues fallback (plan P2.5).
 */
class ScannerBridgeAuditTest {

    /** Burp's audit task. Status and issue listing behave as the test sets them. */
    private class FakeAudit {
        var status: String? = "Auditing"
        var deleted = false
        var issues: List<AuditIssue>? = emptyList()
        val added = mutableListOf<Any?>()
        val audit: Audit = fake { method, args ->
            when (method) {
                "statusMessage" -> status ?: throw NotImplementedError("Not yet implemented")
                "requestCount", "errorCount" -> 0
                "issues" -> issues ?: throw UnsupportedOperationException("Currently unsupported")
                "addRequest" -> { added += args[0]; null }
                "delete" -> { deleted = true; null }
                else -> error("unexpected Audit.$method")
            }
        }
    }

    private val state = StateManager()
    private val audit = FakeAudit()
    private var startFailure: Throwable? = null
    private var auditsStarted = 0

    /** Site map issues by URL prefix; asking for the whole site map fails the test. */
    private val siteMapIssues = mutableMapOf<String, List<AuditIssue>>()
    private val prefixOf = mutableMapOf<SiteMapFilter, String>()

    private val api: MontoyaApi = fake { method, _ ->
        when (method) {
            "scanner" -> fake<Scanner> { m, _ ->
                check(m == "startAudit") { "unexpected Scanner.$m" }
                startFailure?.let { throw it }
                auditsStarted++
                audit.audit
            }
            "siteMap" -> fake<SiteMap> { m, a ->
                check(m == "issues" && a.size == 1) { "the task fallback must ask by prefix, got SiteMap.$m(${a.size} args)" }
                siteMapIssues[prefixOf.getValue(a[0] as SiteMapFilter)].orEmpty()
            }
            else -> error("unexpected MontoyaApi.$method")
        }
    }

    /** The few objects Burp's factory has to build for these calls. Everything else is unavailable, as outside Burp. */
    private val factory: MontoyaObjectFactory = fake { method, args ->
        when (method) {
            "auditConfiguration" -> fake<AuditConfiguration> { m, _ -> error("unexpected AuditConfiguration.$m") }
            "prefixFilter" -> fake<SiteMapFilter> { m, _ -> error("unexpected SiteMapFilter.$m") }.also { prefixOf[it] = args[0] as String }
            "byteArray" -> fake<BurpByteArray> { m, _ -> error("unexpected ByteArray.$m") }
            "httpRequest" -> fake<HttpRequest> { m, _ -> error("unexpected HttpRequest.$m") }
            else -> throw IllegalStateException("MontoyaObjectFactory.$method is not available in this test")
        }
    }

    private val bridge = ScannerBridge(api, EventBus(), state)
    private var previousFactory: MontoyaObjectFactory? = null

    @BeforeTest
    fun installFactory() {
        previousFactory = ObjectFactoryLocator.FACTORY
        ObjectFactoryLocator.FACTORY = factory
    }

    @AfterTest
    fun restore() {
        bridge.shutdown()
        ObjectFactoryLocator.FACTORY = previousFactory
    }

    private fun startAuthenticated(
        urls: List<String>? = listOf("https://app.example.com/account"),
        requests: List<String>? = null,
        mode: String? = null,
    ): JsonObject = bridge.startAudit(urls, requests, mode, false, null, "Authorization", "Bearer abc")

    private fun JsonObject.text(key: String): String? = this[key]?.jsonPrimitive?.content

    private fun raw(request: String): String = Base64.getEncoder().encodeToString(request.toByteArray(Charsets.ISO_8859_1))

    private fun issue(name: String, url: String): AuditIssue = fake { method, _ ->
        when (method) {
            "name" -> name
            "baseUrl" -> url
            "severity" -> AuditIssueSeverity.HIGH
            "confidence" -> AuditIssueConfidence.FIRM
            "detail", "remediation", "definition" -> null
            "requestResponses" -> emptyList<Any>()
            else -> error("unexpected AuditIssue.$method")
        }
    }

    // ---- scope and lifetime of the auth rules ----------------------------------

    @Test
    fun `the auth header is limited to the audited hosts and to Scanner traffic`() {
        val started = startAuthenticated(
            urls = listOf("https://app.example.com/account", "https://API.example.com:8443/v1"),
            requests = listOf(raw("GET /x HTTP/1.1\r\nHost: files.example.com\r\n\r\n")),
        )

        assertNotNull(started.text("task_id"), started.toString())
        assertEquals(
            listOf("app.example.com", "api.example.com", "files.example.com"),
            started.getValue("auth_hosts").jsonArray.map { it.jsonPrimitive.content },
        )
        assertEquals(2, state.trafficRules.size)
        for (rule in state.trafficRules) {
            assertEquals(setOf("SCANNER"), rule.toolFilter)
            val scope = assertNotNull(rule.matchHost, "an audit auth rule must never be global")
            for (host in listOf("app.example.com", "api.example.com", "files.example.com")) {
                assertTrue(SafeRegex.matchesHostPattern(scope, host), host)
            }
            assertFalse(SafeRegex.matchesHostPattern(scope, "other-target.example.net"))
            assertFalse(SafeRegex.matchesHostPattern(scope, "example.com"))
        }
        assertEquals(started.text("auth_rule_id"), state.scanTasks.values.single().authRuleId)
    }

    @Test
    fun `deleting the audit removes its auth rules`() {
        val taskId = startAuthenticated().text("task_id")!!
        assertEquals(2, state.trafficRules.size)

        assertEquals(true, bridge.deleteTask(taskId).getValue("deleted").jsonPrimitive.boolean)

        assertTrue(audit.deleted)
        assertTrue(state.trafficRules.isEmpty())
    }

    @Test
    fun `the auth rules go when the audit is seen to have finished`() {
        val taskId = startAuthenticated().text("task_id")!!

        val running = bridge.getTaskStatus(taskId)
        assertEquals(true, running.getValue("auth_rule_active").jsonPrimitive.boolean)
        assertEquals(2, state.trafficRules.size)

        audit.status = "Finished"
        val finished = bridge.getTaskStatus(taskId)
        assertEquals(false, finished.getValue("auth_rule_active").jsonPrimitive.boolean)
        assertEquals("audit ended (Finished)", finished.text("auth_rule_released"))
        assertTrue(state.trafficRules.isEmpty())
    }

    @Test
    fun `listing tasks also releases the rules of a finished audit`() {
        startAuthenticated()
        audit.status = "Cancelled"
        bridge.listTasks(null)
        assertTrue(state.trafficRules.isEmpty())
    }

    // ---- nothing is left behind by a start that fails ---------------------------

    @Test
    fun `a start Burp rejects leaves no auth rule behind`() {
        startFailure = IllegalStateException("scanner is busy")
        val failed = startAuthenticated()
        assertEquals("Failed to start audit: scanner is busy", failed.text("error"))
        assertTrue(state.trafficRules.isEmpty())
        assertTrue(state.scanTasks.isEmpty())
    }

    @Test
    fun `Community Edition leaves no auth rule behind`() {
        startFailure = UnsupportedOperationException()
        val failed = startAuthenticated()
        assertEquals("Scanner API is not available in Burp Suite Community Edition", failed.text("error"))
        assertTrue(state.trafficRules.isEmpty())
    }

    @Test
    fun `an Error from an older Burp leaves no auth rule behind either`() {
        // Not an Exception: the catch blocks do not see it, the cleanup still has to run.
        startFailure = NotImplementedError("Not yet implemented")
        assertFailsWith<NotImplementedError> { startAuthenticated() }
        assertTrue(state.trafficRules.isEmpty())
    }

    @Test
    fun `a Burp that cannot report task status still starts the audit and keeps its rules`() {
        // statusMessage throws an Error there. That must neither fail the start nor undo it.
        audit.status = null
        val started = startAuthenticated()
        assertEquals("started", started.text("status"))
        assertEquals(2, state.trafficRules.size)
        assertFalse(audit.deleted)
    }

    @Test
    fun `an invalid audit_mode is refused before anything is started or installed`() {
        val refused = startAuthenticated(mode = "aggressive")
        assertTrue(refused.text("error")!!.contains("audit_mode"), refused.toString())
        assertEquals(0, auditsStarted)
        assertTrue(state.trafficRules.isEmpty())
    }

    @Test
    fun `an auth header that cannot be limited to a host starts nothing`() {
        val refused = startAuthenticated(urls = listOf("/account"))
        assertTrue(refused.text("error")!!.contains("no target host"), refused.toString())
        assertEquals(0, auditsStarted)
        assertTrue(state.trafficRules.isEmpty())
    }

    @Test
    fun `an auth header needs both its name and its value`() {
        val refused = bridge.startAudit(listOf("https://app.example.com/"), null, null, false, null, "Authorization", null)
        assertEquals("auth_header_name and auth_header_value must be given together", refused.text("error"))
        assertEquals(0, auditsStarted)
    }

    @Test
    fun `an audit without an auth header installs no rule`() {
        val started = bridge.startAudit(listOf("https://app.example.com/"), null, "light", false, null)
        assertNotNull(started.text("task_id"))
        assertEquals("passive", started.text("audit_mode_effective"))
        assertNull(started["auth_rule_id"])
        assertTrue(state.trafficRules.isEmpty())
    }

    @Test
    fun `empty strings for both auth parameters mean no auth header, not an error`() {
        val started = bridge.startAudit(listOf("https://app.example.com/"), null, null, false, null, "", " ")
        assertNotNull(started.text("task_id"), started.toString())
        assertTrue(state.trafficRules.isEmpty())

        // A value without a name is a mistake worth reporting.
        val refused = bridge.startAudit(listOf("https://app.example.com/"), null, null, false, null, "", "Bearer abc")
        assertEquals("auth_header_name and auth_header_value must be given together", refused.text("error"))
    }

    @Test
    fun `a request added for another host is told the auth header does not follow it`() {
        val taskId = startAuthenticated().text("task_id")!!

        val sameHost = bridge.addRequestToTask(taskId, raw("GET /b HTTP/1.1\r\nHost: app.example.com\r\n\r\n"), null, null, null)
        assertEquals(true, sameHost.getValue("request_added").jsonPrimitive.boolean)
        assertNull(sameHost["auth_note"])

        val otherHost = bridge.addRequestToTask(taskId, raw("GET /b HTTP/1.1\r\nHost: partner.example.net\r\n\r\n"), null, null, null)
        assertTrue(otherHost.text("auth_note")!!.contains("partner.example.net"), otherHost.toString())
        assertEquals(2, audit.added.size)
        // The scope did not widen.
        assertFalse(SafeRegex.matchesHostPattern(state.trafficRules.first().matchHost!!, "partner.example.net"))
    }

    // ---- task issues fallback --------------------------------------------------

    @Test
    fun `task issues come from the task when Burp can list them`() {
        val taskId = startAuthenticated().text("task_id")!!
        audit.issues = listOf(issue("SQL injection", "https://app.example.com/account"))

        val result = bridge.getTaskIssues(taskId)

        assertEquals(1, result.getValue("issue_count").jsonPrimitive.int)
        assertNull(result["source"], "no fallback marker when the task itself answered")
    }

    @Test
    fun `the fallback reads the site map under the task's targets only and says so`() {
        val taskId = bridge.startAudit(
            listOf("https://app.example.com/account"), null, null, false, null
        ).text("task_id")!!
        audit.issues = null   // "Currently unsupported"
        siteMapIssues["https://app.example.com/"] = listOf(issue("SQL injection", "https://app.example.com/account"))
        siteMapIssues["https://other-target.example.net/"] = listOf(issue("XSS", "https://other-target.example.net/"))

        val result = bridge.getTaskIssues(taskId)

        assertEquals("site_map", result.text("source"))
        assertEquals(listOf("https://app.example.com/"), result.getValue("url_prefixes").jsonArray.map { it.jsonPrimitive.content })
        assertEquals(1, result.getValue("issue_count").jsonPrimitive.int)
        assertEquals("SQL injection", result.getValue("issues").jsonArray.single().jsonObject.text("name"))
        assertNotNull(result.text("note"))
    }

    @Test
    fun `filters with values that match nothing are errors, not empty results`() {
        assertTrue(bridge.getAllIssues(null, "critical", null, null).text("error")!!.contains("severity"))
        assertTrue(bridge.getAllIssues(null, null, "sure", null).text("error")!!.contains("confidence"))
        assertTrue(bridge.generateReport("pdf", null, null, "r").text("error")!!.contains("format"))
        assertTrue(bridge.generateReport("html", null, listOf("high", "severe"), "r").text("error")!!.contains("severity_filter[1]"))
        assertTrue(bridge.createCustomIssue("n", null, null, "urgent", "firm", "https://t/", null, null).text("error")!!.contains("severity"))
    }

    @Test
    fun `a blank report format means the default, HTML`() {
        // A blank format passes the format check: the error comes from the severity filter checked next.
        assertTrue(bridge.generateReport(" ", null, listOf("severe"), "r").text("error")!!.contains("severity_filter[0]"))
        assertEquals(ReportFormat.HTML, ScannerIssues.reportFormat(""))
        assertEquals(ReportFormat.HTML, ScannerIssues.reportFormat("html"))
        assertEquals(ReportFormat.XML, ScannerIssues.reportFormat(" XML "))
    }
}
