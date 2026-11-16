package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.Http
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import burp.api.montoya.logging.Logging
import burp.api.montoya.project.Project
import burp.api.montoya.proxy.http.InterceptedResponse
import burp.api.montoya.scope.Scope
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.state.AutorizeMatch
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.transport.AutorizeFileStore
import io.bitbytelab.raijin.transport.AutorizeStore
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.io.File
import java.nio.file.Files
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The live Autorize tap end to end against a fake application: what it replays, what it never
 * replays, what it keeps of each identity's answer, and that its matches survive a reload.
 */
class AutorizeTapTest {

    /** The fake application: answers by the session a request carries, and remembers every request it got. */
    private class App {
        val sent = CopyOnWriteArrayList<String>()

        @Volatile
        var lowPrivSees: Pair<Int, String> = 403 to "{\"error\":\"forbidden\"}"

        @Volatile
        var anonymousSees: Pair<Int, String> = 401 to "{\"error\":\"login required\"}"

        fun answer(raw: String): Pair<Int, String> {
            sent += raw
            return when {
                "session=admin" in raw -> 200 to ADMIN_BODY
                "session=low" in raw -> lowPrivSees
                else -> anonymousSees
            }
        }
    }

    private val app = App()
    private val eventBus = EventBus()
    private val taps = mutableListOf<AutorizeTap>()
    private val dir: File = Files.createTempDirectory("raijin-autorize-tap").toFile()
    private var previousFactory: MontoyaObjectFactory? = null

    /** What Burp's object factory does for the calls a replay makes. */
    private val factory: MontoyaObjectFactory = stubOf(MontoyaObjectFactory::class.java) { m, a ->
        when (m) {
            "byteArray" -> {
                val text = String(a[0] as ByteArray, Charsets.ISO_8859_1)
                stubOf(BurpByteArray::class.java) { bm, _ -> if (bm == "toString") text else error("ByteArray.$bm") }
            }
            "httpRequest" -> replayed(a.last().toString())
            else -> error("MontoyaObjectFactory.$m")
        }
    }

    @BeforeTest
    fun installFactory() {
        previousFactory = ObjectFactoryLocator.FACTORY
        ObjectFactoryLocator.FACTORY = factory
    }

    @AfterTest
    fun tearDown() {
        taps.forEach { it.shutdown() }
        ObjectFactoryLocator.FACTORY = previousFactory
        dir.deleteRecursively()
    }

    // ---- fakes ----------------------------------------------------------

    /** A replay as the tap builds it; Raijin's internal-request marker is accepted and left out. */
    private fun replayed(raw: String): HttpRequest = stubOf(HttpRequest::class.java) { m, _ ->
        when (m) {
            "withHeader" -> replayed(raw)
            "toString" -> raw
            else -> error("HttpRequest.$m")
        }
    }

    private fun answered(status: Int, body: String): HttpRequestResponse {
        val response = stubOf(HttpResponse::class.java) { m, a ->
            when (m) {
                "statusCode" -> status.toShort()
                "bodyToString" -> body
                "headerValue" -> if ((a[0] as String).equals("Content-Type", ignoreCase = true)) "application/json" else null
                "toString" -> "HTTP/1.1 $status X\r\nContent-Type: application/json\r\n\r\n$body"
                else -> error("HttpResponse.$m")
            }
        }
        return stubOf(HttpRequestResponse::class.java) { m, _ -> if (m == "response") response else error("HttpRequestResponse.$m") }
    }

    private val api: MontoyaApi = stubOf(MontoyaApi::class.java) { m, _ ->
        when (m) {
            "http" -> stubOf(Http::class.java) { hm, ha ->
                if (hm != "sendRequest") error("Http.$hm")
                val (status, body) = app.answer((ha[0] as HttpRequest).toString())
                answered(status, body)
            }
            "scope" -> stubOf(Scope::class.java) { sm, _ -> if (sm == "isInScope") true else error("Scope.$sm") }
            "project" -> stubOf(Project::class.java) { pm, _ ->
                when (pm) {
                    "name" -> "shop"
                    "id" -> "p-1"
                    else -> error("Project.$pm")
                }
            }
            "logging" -> stubOf(Logging::class.java) { _, _ -> null }
            else -> error("MontoyaApi.$m")
        }
    }

    /** A response the proxy captured for [method] [path], sent with [headers] besides Host. */
    private fun captured(
        method: String,
        path: String,
        headers: List<Pair<String, String>> = listOf("Cookie" to "session=admin"),
        status: Int = 200,
        body: String = ADMIN_BODY,
    ): InterceptedResponse {
        val request = fakeRequest(
            FakeMessage(method = method, url = "https://shop.test$path", path = path, headers = listOf("Host" to "shop.test") + headers),
            fakeService("shop.test"),
        )
        return stubOf(InterceptedResponse::class.java) { m, a ->
            when (m) {
                "request" -> request
                "statusCode" -> status.toShort()
                "bodyToString" -> body
                "headerValue" -> if ((a[0] as String).equals("Content-Type", ignoreCase = true)) "application/json" else null
                "toString" -> "HTTP/1.1 $status X\r\nContent-Type: application/json\r\n\r\n$body"
                else -> error("InterceptedResponse.$m")
            }
        }
    }

    // ---- helpers --------------------------------------------------------

    private fun tap(state: StateManager, store: AutorizeFileStore? = null): AutorizeTap =
        AutorizeTap(api, eventBus, state, FindingsBridge(state), store).also { taps += it }

    private fun identity(name: String, cookie: String? = null): JsonObject = buildJsonObject {
        put("name", name)
        if (cookie != null) {
            put("header_name", "Cookie")
            put("header_value", cookie)
        }
    }

    private val lowAndNone = listOf(identity("low-priv", "session=low"), identity("none"))

    private fun rule(
        bridge: AutorizeBridge,
        identities: List<JsonObject> = lowAndNone,
        methods: List<String>? = null,
        includeMutating: Boolean? = null,
        ruleId: String? = null,
    ): JsonObject = bridge.setRule(ruleId, identities, null, null, null, methods, null, null, null, includeMutating)

    private fun activity(state: StateManager, ruleId: String): Map<String, Long> = state.autorizeActivity.of(ruleId)

    private fun awaitUntil(what: String, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 5_000
        while (!condition()) {
            check(System.currentTimeMillis() < deadline) { "timed out waiting for $what" }
            Thread.sleep(10)
        }
    }

    private fun JsonObject.text(key: String) = this[key]!!.jsonPrimitive.content

    // ---- tests ----------------------------------------------------------

    @Test
    fun `a low-privilege replay that gets the admin's data is flagged with what each identity received`() {
        app.lowPrivSees = 200 to ADMIN_BODY
        val state = StateManager()
        val ruleId = rule(AutorizeBridge(state)).text("rule_id")

        tap(state).onResponse(captured("GET", "/api/orders?id=1"))
        awaitUntil("the match") { activity(state, ruleId)["flagged"] == 1L }

        val match = state.autorizeMatches.single()
        assertFalse(match.softDenial)
        assertEquals("GET", match.method)
        assertEquals("https://shop.test/api/orders?id=1", match.url)
        assertEquals(200, match.originalStatus)
        assertEquals(listOf("cross_identity_match"), match.findings.map { it.text("id") })
        assertEquals(listOf("low-priv" to 200, "none" to 401), match.replays.map { it.identity to it.status })
        val low = match.replays[0]
        assertTrue("Cookie: session=low" in low.request && "session=admin" !in low.request, low.request)
        assertTrue(ADMIN_BODY in low.response)
        assertFalse("Cookie" in match.replays[1].request, "none is replayed without credentials")
        assertTrue("Cookie: session=admin" in match.request)

        val event = eventBus.getEventsByType(listOf("autorize.match")).single().data
        assertEquals("critical", event.text("severity"))
        assertFalse(event["soft_denial"]!!.jsonPrimitive.boolean)
        assertEquals(
            listOf("low-priv" to 200, "none" to 401),
            event["identities"]!!.jsonArray.map { it.jsonObject.text("name") to it.jsonObject["status"]!!.jsonPrimitive.int },
        )
        awaitUntil("the finding") { state.findings.isNotEmpty() }
        assertEquals("cross_identity_match", state.findings.single().type)
    }

    @Test
    fun `state-changing requests are never replayed unless the rule opts in`() {
        val state = StateManager()
        val bridge = AutorizeBridge(state)
        val created = rule(bridge, methods = listOf("GET", "POST"))
        val ruleId = created.text("rule_id")
        assertTrue(created["notes"]!!.jsonArray.any { "POST" in it.jsonPrimitive.content && "include_mutating" in it.jsonPrimitive.content })
        val tap = tap(state)

        for (method in listOf("POST", "PUT", "DELETE", "PATCH")) tap.onResponse(captured(method, "/api/orders/1"))
        assertEquals(1L, activity(state, ruleId)["skipped_mutating"], "only POST is in the rule's methods; the rest are filtered")
        assertEquals(3L, activity(state, ruleId)["filtered"])
        assertTrue(app.sent.isEmpty(), "nothing was replayed")

        rule(bridge, ruleId = ruleId, identities = listOf(identity("none")), includeMutating = true)
        tap.onResponse(captured("POST", "/api/orders/1"))
        awaitUntil("the opted-in replay") { activity(state, ruleId)["replayed"] == 1L }
        assertTrue(app.sent.single().startsWith("POST /api/orders/1 "))
    }

    @Test
    fun `originals that were not authenticated, or found nothing, are not replayed`() {
        val state = StateManager()
        val ruleId = rule(AutorizeBridge(state)).text("rule_id")
        val tap = tap(state)

        tap.onResponse(captured("GET", "/api/public", headers = emptyList()))
        tap.onResponse(captured("GET", "/api/expired", status = 401, body = "{\"error\":\"login required\"}"))
        tap.onResponse(captured("GET", "/api/missing", status = 404, body = "{}"))

        assertEquals(2L, activity(state, ruleId)["skipped_unauthenticated"])
        assertEquals(1L, activity(state, ruleId)["skipped_not_found"])
        assertTrue(app.sent.isEmpty())
    }

    @Test
    fun `the query string is part of what makes a request new, cache busters aside`() {
        val state = StateManager()
        val ruleId = rule(AutorizeBridge(state), identities = listOf(identity("none"))).text("rule_id")
        val tap = tap(state)

        tap.onResponse(captured("GET", "/api/orders?id=1"))
        tap.onResponse(captured("GET", "/api/orders?id=1"))
        tap.onResponse(captured("GET", "/api/orders?id=2"))
        tap.onResponse(captured("GET", "/api/orders?id=2&_=1731800000001"))
        tap.onResponse(captured("GET", "/api/orders?_=1731800000002&id=2"))

        awaitUntil("three replays") { activity(state, ruleId)["replayed"] == 3L }
        assertEquals(2L, activity(state, ruleId)["skipped_seen"])
        assertEquals(3, app.sent.size)
    }

    @Test
    fun `an identity that would resend the request as it is is not replayed`() {
        val state = StateManager()
        val bridge = AutorizeBridge(state)
        val created = rule(bridge, identities = listOf(identity("admin-again", "session=admin"), identity("none")))
        val ruleId = created.text("rule_id")

        tap(state).onResponse(captured("GET", "/api/orders?id=1"))
        awaitUntil("the replay") { activity(state, ruleId)["replayed"] == 1L }

        assertEquals(1, app.sent.size, "only 'none' changes the request")
        assertFalse("session=admin" in app.sent.single())
        assertTrue(state.autorizeMatches.isEmpty(), "401 for 'none' is no finding")
    }

    @Test
    fun `a soft denial is kept and flagged instead of being dropped`() {
        app.anonymousSees = 200 to "{\"error\":\"unauthorized\"}"
        val state = StateManager()
        val ruleId = rule(AutorizeBridge(state), identities = listOf(identity("none"))).text("rule_id")

        tap(state).onResponse(captured("GET", "/api/profile"))
        awaitUntil("the soft denial") { activity(state, ruleId)["soft_denials"] == 1L }

        val match = state.autorizeMatches.single()
        assertTrue(match.softDenial)
        assertEquals(listOf("unauth_soft_denial", AutorizePolicy.STATUS_ONLY_ID), match.findings.map { it.text("id") })
        assertTrue("unauth_accessible" in match.findings.last().text("detail"))
        assertEquals(listOf("none" to 200), match.replays.map { it.identity to it.status })
        assertTrue(state.findings.isEmpty(), "a soft denial is not recorded as a finding")
        assertTrue(eventBus.getEventsByType(listOf("autorize.match")).single().data["soft_denial"]!!.jsonPrimitive.boolean)
    }

    @Test
    fun `matches survive a reload with each identity's replay, per project`() {
        app.lowPrivSees = 200 to ADMIN_BODY
        val store = AutorizeFileStore(File(dir, "autorize.jsonl"))
        store.append(otherProjectMatch(), "another-project")

        val before = StateManager()
        val running = tap(before, store).also { it.start() }
        val ruleId = rule(AutorizeBridge(before)).text("rule_id")
        running.onResponse(captured("GET", "/api/orders?id=1"))
        awaitUntil("the match") { activity(before, ruleId)["flagged"] == 1L }
        val original = before.autorizeMatches.single()

        val after = StateManager()
        tap(after, store).start()
        val restored = after.autorizeMatches.single()
        assertEquals(original, restored)
        assertEquals(listOf("low-priv" to 200, "none" to 401), restored.replays.map { it.identity to it.status })

        val bridge = AutorizeBridge(after)
        val newRuleId = rule(bridge).text("rule_id")
        assertTrue(newRuleId != ruleId, "a new rule never takes the id of a restored rule's matches")

        bridge.clearMatches(null, resetSeen = false)
        assertTrue(after.autorizeMatches.isEmpty())
        val kept = File(dir, "autorize.jsonl").readLines().mapNotNull { AutorizeStore.parseEntry(it) }
        assertEquals(listOf("another-project"), kept.map { it.second }, "a clear rewrites only this project's matches")
    }

    private fun otherProjectMatch() = AutorizeMatch(
        id = 1, ruleId = "arule-001", timestamp = "2026-11-16T00:00:00Z", method = "GET", url = "https://other.test/",
        originalStatus = 200, findings = emptyList(), request = "GET / HTTP/1.1\r\n\r\n", response = "HTTP/1.1 200 OK\r\n\r\n",
    )

    private companion object {
        const val ADMIN_BODY = "{\"orders\":[{\"id\":1,\"total\":42.5,\"owner\":\"admin@shop.test\"}]}"
    }
}
