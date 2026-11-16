package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.core.Registration
import burp.api.montoya.http.Http
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import burp.api.montoya.scanner.AuditResult
import burp.api.montoya.scanner.ConsolidationAction
import burp.api.montoya.scanner.ScanCheck
import burp.api.montoya.scanner.Scanner
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointType
import burp.api.montoya.scanner.audit.issues.AuditIssue
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * One manager behind `scancheck_*` and `scanner_register_check` (plan P4.1): every check either
 * tool registers is tracked in one place, replaced by name, removable by the other tool, and
 * deregistered on unload.
 */
class CustomScanCheckManagerTest {

    private class FakeRegistration(private val refuseToDeregister: Boolean = false) : Registration {
        var deregistered = false
        override fun isRegistered(): Boolean = !deregistered
        override fun deregister() {
            if (refuseToDeregister) throw IllegalStateException("Burp says no")
            deregistered = true
        }
    }

    /** Burp's scanner as far as check registration goes: it hands out handles and remembers the checks. */
    private class FakeScanner {
        val checks = mutableListOf<ScanCheck>()
        val handles = mutableListOf<FakeRegistration>()
        var refusal: RuntimeException? = null
        var refuseToDeregister = false

        /** Answers the requests a registered check sends; nothing is answered unless a test says how. */
        var target: (HttpRequest) -> HttpRequestResponse? = { null }

        val api: MontoyaApi = run {
            val scanner = Proxy.newProxyInstance(Scanner::class.java.classLoader, arrayOf(Scanner::class.java)) { _, method, args ->
                check(method.name == "registerScanCheck") { "unexpected Scanner.${method.name}" }
                refusal?.let { throw it }
                checks += args[0] as ScanCheck
                FakeRegistration(refuseToDeregister).also { handles += it }
            } as Scanner
            val http = Proxy.newProxyInstance(Http::class.java.classLoader, arrayOf(Http::class.java)) { _, method, args ->
                check(method.name == "sendRequest" && args?.size == 1) { "unexpected Http.${method.name}" }
                target(args[0] as HttpRequest)
            } as Http
            Proxy.newProxyInstance(MontoyaApi::class.java.classLoader, arrayOf(MontoyaApi::class.java)) { _, method, _ ->
                when (method.name) {
                    "scanner" -> scanner
                    "http" -> http
                    else -> error("unexpected MontoyaApi.${method.name}")
                }
            } as MontoyaApi
        }
    }

    /**
     * A comment board: every request posts the `comment` in its body, and every response lists all
     * the comments posted so far. What one payload stores, every later response shows, the
     * unmodified request's included.
     */
    private class CommentBoard {
        private val comments = mutableListOf("hello")

        /** The comments the check's requests posted, in order; the unmodified request posts "hello". */
        val posted = mutableListOf<String>()

        val insertionPoint: AuditInsertionPoint = stubOf(AuditInsertionPoint::class.java) { m, a ->
            when (m) {
                "name" -> "comment"
                "type" -> AuditInsertionPointType.PARAM_BODY
                "buildHttpRequestWithPayload" -> request(a[0].toString())
                else -> error("unexpected AuditInsertionPoint.$m")
            }
        }

        /** The scanner's base request, with the response it recorded for it, or none when [recorded] is false. */
        fun base(recorded: Boolean): HttpRequestResponse {
            val request = request("hello")
            val response = if (recorded) page() else null
            return stubOf(HttpRequestResponse::class.java) { m, _ ->
                when (m) {
                    "request" -> request
                    "response" -> response
                    "httpService" -> fakeService("board.test")
                    else -> error("unexpected HttpRequestResponse.$m")
                }
            }
        }

        fun answer(request: HttpRequest): HttpRequestResponse {
            val comment = request.bodyToString().substringAfter("comment=")
            posted += comment
            comments += comment
            val response = page()
            return stubOf(HttpRequestResponse::class.java) { m, _ ->
                when (m) {
                    "request" -> request
                    "response" -> response
                    else -> error("unexpected HttpRequestResponse.$m")
                }
            }
        }

        private fun request(comment: String): HttpRequest = stubOf(HttpRequest::class.java) { m, _ ->
            when (m) {
                "withService" -> request(comment)
                "bodyToString" -> "comment=$comment"
                "url" -> "https://board.test/comment"
                "toString" -> "POST /comment comment=$comment"
                else -> error("unexpected HttpRequest.$m")
            }
        }

        private fun page(): HttpResponse {
            val body = comments.joinToString("\n")
            return stubOf(HttpResponse::class.java) { m, _ ->
                when (m) {
                    "bodyToString" -> body
                    "statusCode" -> 200.toShort()
                    else -> error("unexpected HttpResponse.$m")
                }
            }
        }
    }

    /** What Burp's factory builds while a check audits: payload bytes, the issue and the result holding it. */
    private val factory: MontoyaObjectFactory = stubOf(MontoyaObjectFactory::class.java) { m, a ->
        when (m) {
            "byteArray" -> {
                val text = a[0] as String
                stubOf(BurpByteArray::class.java) { bm, _ -> if (bm == "toString") text else error("unexpected ByteArray.$bm") }
            }
            "auditIssue" -> {
                val detail = a[1] as String
                val evidence = a[9] as List<*>
                stubOf(AuditIssue::class.java) { im, _ ->
                    when (im) {
                        "detail" -> detail
                        "requestResponses" -> evidence
                        else -> error("unexpected AuditIssue.$im")
                    }
                }
            }
            "auditResult" -> {
                val issues = a[0] as List<*>
                stubOf(AuditResult::class.java) { rm, _ -> if (rm == "auditIssues") issues else error("unexpected AuditResult.$rm") }
            }
            else -> error("MontoyaObjectFactory.$m is not available in this test")
        }
    }

    private fun <T> withFactory(block: () -> T): T {
        val previous = ObjectFactoryLocator.FACTORY
        ObjectFactoryLocator.FACTORY = factory
        try {
            return block()
        } finally {
            ObjectFactoryLocator.FACTORY = previous
        }
    }

    private fun passive(name: String) = CheckDefinition(
        name = name, issueName = name, description = "", detail = "detail", remediation = "fix",
        severity = "high", confidence = "firm",
        passive = PassiveRule(listOf(CheckCondition("response_body", "secret", "contains"))),
    )

    private fun issue(name: String, url: String, detail: String): AuditIssue =
        Proxy.newProxyInstance(AuditIssue::class.java.classLoader, arrayOf(AuditIssue::class.java)) { _, method, _ ->
            when (method.name) {
                "name" -> name
                "baseUrl" -> url
                "detail" -> detail
                else -> error("unexpected AuditIssue.${method.name}")
            }
        } as AuditIssue

    private fun bodyCondition(pattern: String, type: String = "contains"): JsonObject = buildJsonObject {
        put("location", "response_body")
        put("pattern", pattern)
        put("condition_type", type)
    }

    private fun JsonObject.text(key: String): String? = this[key]?.jsonPrimitive?.content

    // ---- tracking ----------------------------------------------------------

    @Test
    fun `a registered check is tracked where extension unload deregisters it`() {
        val burp = FakeScanner()
        val state = StateManager()
        val (check, replaced) = CustomScanCheckManager(burp.api, state).register(passive("Leak"))

        assertNull(replaced)
        assertTrue(check.id.startsWith("scheck-"), check.id)
        assertSame(check, state.scanCheckRegistrations[check.id])
        assertEquals(listOf("Leak"), state.registeredScanChecks.toList())

        // StateManager.cleanup() runs on unload whether or not any bridge shuts down first.
        state.cleanup()
        assertTrue(burp.handles.single().deregistered)
    }

    @Test
    fun `registering a name again replaces the check instead of running both versions`() {
        val burp = FakeScanner()
        val state = StateManager()
        val manager = CustomScanCheckManager(burp.api, state)

        val (first, _) = manager.register(passive("Leak"))
        val (second, replaced) = manager.register(passive("Leak"))

        assertSame(first, replaced)
        assertTrue(burp.handles[0].deregistered, "the old version must stop running")
        assertFalse(burp.handles[1].deregistered)
        assertEquals(listOf(second.id), manager.list().map { it.id })
        assertEquals(listOf("Leak"), state.registeredScanChecks.toList())
    }

    @Test
    fun `a registration Burp refuses leaves the existing check untouched`() {
        val burp = FakeScanner()
        val manager = CustomScanCheckManager(burp.api, StateManager())
        val (first, _) = manager.register(passive("Leak"))

        burp.refusal = UnsupportedOperationException("Community Edition")
        assertFailsWith<UnsupportedOperationException> { manager.register(passive("Leak")) }

        assertFalse(burp.handles.single().deregistered)
        assertEquals(listOf(first.id), manager.list().map { it.id })
    }

    @Test
    fun `managers built on the same state are one list`() {
        val burp = FakeScanner()
        val state = StateManager()
        val one = CustomScanCheckManager(burp.api, state)
        val other = CustomScanCheckManager(burp.api, state)

        val (check, _) = one.register(passive("Leak"))
        assertSame(check, other.find("Leak"), "found by name")
        assertSame(check, other.find(check.id), "found by id")

        other.remove(check)
        assertTrue(burp.handles.single().deregistered)
        assertTrue(one.list().isEmpty())
        assertTrue(state.scanCheckRegistrations.isEmpty())
        assertTrue(state.registeredScanChecks.isEmpty())
    }

    @Test
    fun `a check Burp will not deregister stays tracked so removal can be retried`() {
        val burp = FakeScanner().apply { refuseToDeregister = true }
        val manager = CustomScanCheckManager(burp.api, StateManager())
        val (check, _) = manager.register(passive("Leak"))

        assertFailsWith<IllegalStateException> { manager.remove(check) }
        assertEquals(listOf(check.id), manager.list().map { it.id })
    }

    @Test
    fun `shutdown deregisters every check and forgets them`() {
        val burp = FakeScanner()
        val state = StateManager()
        val manager = CustomScanCheckManager(burp.api, state)
        manager.register(passive("A"))
        manager.register(passive("B"))

        manager.shutdown()

        assertTrue(burp.handles.all { it.deregistered })
        assertTrue(manager.list().isEmpty())
        assertTrue(state.registeredScanChecks.isEmpty())
    }

    // ---- what Burp is handed ------------------------------------------------

    @Test
    fun `the registered check keeps two insertion points apart and merges a repeat`() {
        val burp = FakeScanner()
        CustomScanCheckManager(burp.api, StateManager()).register(passive("SQLi"))
        val check = burp.checks.single()

        val q = issue("SQLi", "https://t/search?q=1", ScanCheckLogic.activeDetail("d", "q", "PARAM_URL", listOf("'")))
        val id = issue("SQLi", "https://t/search?q=2", ScanCheckLogic.activeDetail("d", "id", "PARAM_URL", listOf("'")))
        val qAgain = issue("SQLi", "https://t/search?q=3", ScanCheckLogic.activeDetail("d", "q", "PARAM_URL", listOf("\"")))

        assertEquals(ConsolidationAction.KEEP_BOTH, check.consolidateIssues(q, id))
        assertEquals(ConsolidationAction.KEEP_EXISTING, check.consolidateIssues(q, qAgain))
    }

    @Test
    fun `an active check reports what the target stores, with one unmodified request sent before the payload`() {
        val stored = CheckDefinition(
            name = "Stored marker", issueName = "Stored marker", description = "", detail = "", remediation = "fix",
            severity = "high", confidence = "firm",
            active = listOf(ActiveStep("<raijin-77>", listOf(CheckCondition("response_body", "<raijin-77>", "contains")))),
        )
        for (recorded in listOf(true, false)) {
            val label = if (recorded) "recorded baseline" else "no recorded baseline"
            val board = CommentBoard()
            val burp = FakeScanner().apply { target = board::answer }
            CustomScanCheckManager(burp.api, StateManager()).register(stored)

            val issues = withFactory { burp.checks.single().activeAudit(board.base(recorded), board.insertionPoint) }.auditIssues()

            // The unmodified request went out once, before the payload was stored: the marker the
            // board shows from then on cannot explain the finding away.
            assertEquals(listOf("hello", "<raijin-77>"), board.posted, label)
            val issue = assertNotNull(issues.singleOrNull(), label)
            assertTrue("<code>&lt;raijin-77&gt;</code>" in issue.detail(), issue.detail())
            assertEquals(2, issue.requestResponses().size, "the base request and the payload's exchange: $label")
        }
    }

    // ---- both tools --------------------------------------------------------

    @Test
    fun `checks from scancheck and scanner_register_check share one list and one removal`() {
        val burp = FakeScanner()
        val state = StateManager()
        val scanCheck = ScanCheckBridge(burp.api, state)
        val scanner = ScannerBridge(burp.api, EventBus(), state)

        val created = scanCheck.createPassive(
            "Leaked key", "finds keys", listOf(bodyCondition("AKIA[0-9A-Z]{16}", "matches")),
            "high", "firm", "A key leaked.", null
        )
        assertEquals("deployed", created.text("status"))
        val registered = scanner.registerScanCheck(
            "legacy", "active", "Error based", "medium", "tentative", "detail", "fix",
            null, null, listOf("'", "\""), "sql syntax"
        )
        assertEquals("true", registered.text("registered"))
        assertEquals("active", registered.text("check_type"))

        val listed = scanCheck.list()
        assertEquals(2, listed.getValue("count").jsonPrimitive.int)
        assertEquals(listOf("Leaked key", "legacy"), listed.getValue("checks").jsonArray.map { it.jsonObject.text("name") })

        // Either tool removes either check.
        assertEquals("true", scanner.unregisterScanCheck("Leaked key").text("unregistered"))
        assertEquals("true", scanCheck.remove("legacy").text("removed"))
        assertTrue(burp.handles.all { it.deregistered })
        assertEquals(0, scanCheck.list().getValue("count").jsonPrimitive.int)
    }

    @Test
    fun `ScanCheckBridge shutdown also deregisters checks registered through the scanner tool`() {
        val burp = FakeScanner()
        val state = StateManager()
        ScannerBridge(burp.api, EventBus(), state).registerScanCheck(
            "legacy", "passive", "Banner", "low", "firm", "", "", "Apache/2", null, null, null
        )

        ScanCheckBridge(burp.api, state).shutdown()

        assertTrue(burp.handles.single().deregistered)
        assertTrue(state.scanCheckRegistrations.isEmpty())
    }

    @Test
    fun `an invalid regex is refused at creation and never reaches Burp`() {
        val burp = FakeScanner()
        val state = StateManager()

        val passive = ScanCheckBridge(burp.api, state).createPassive(
            "bad", "d", listOf(bodyCondition("([unclosed", "matches")), "high", "firm", "detail", null
        )
        assertTrue(passive.text("error")!!.startsWith("Invalid regex in conditions[0].pattern"), passive.toString())

        val active = ScanCheckBridge(burp.api, state).createActive(
            "bad", "d",
            listOf(buildJsonObject {
                put("payload", "'")
                put("response_conditions", buildJsonArray { add(bodyCondition("*oops", "matches")) })
            }),
            "high", "firm", "detail", null
        )
        assertTrue(active.text("error")!!.startsWith("Invalid regex in steps[0].response_conditions[0].pattern"), active.toString())

        val legacy = ScannerBridge(burp.api, EventBus(), state).registerScanCheck(
            "bad", "active", "x", "high", "firm", "", "", null, null, listOf("'"), "(?<broken"
        )
        assertTrue(legacy.text("error")!!.startsWith("Invalid active_response_match regex"), legacy.toString())

        assertTrue(burp.checks.isEmpty(), "nothing invalid may be registered with the scanner")
        assertTrue(state.scanCheckRegistrations.isEmpty())
    }

    @Test
    fun `an active check that could report without evidence is refused at creation`() {
        val burp = FakeScanner()
        val created = ScanCheckBridge(burp.api, StateManager()).createActive(
            "blind", "d", listOf(buildJsonObject { put("payload", "'") }), "high", "firm", "detail", null
        )
        assertNotNull(created.text("error"))
        assertTrue(burp.checks.isEmpty())
    }

    @Test
    fun `Community Edition is reported as such and nothing is tracked`() {
        val burp = FakeScanner().apply { refusal = UnsupportedOperationException() }
        val state = StateManager()
        val created = ScanCheckBridge(burp.api, state).createPassive(
            "Leak", "d", listOf(bodyCondition("secret")), "high", "firm", "detail", null
        )
        assertEquals("Scanner API is not available in Burp Suite Community Edition", created.text("error"))
        assertTrue(state.scanCheckRegistrations.isEmpty())
    }
}
