package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.state.AutorizeReplay
import io.bitbytelab.raijin.state.AutorizeRule
import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AutorizeBridgeTest {

    private fun identity(name: String): JsonObject = buildJsonObject { put("name", name) }

    private val twoIdentities = listOf(identity("admin"), identity("none"))

    private fun assertError(result: JsonObject, mentions: String) {
        val error = result["error"]?.jsonPrimitive?.contentOrNull
        assertNotNull(error, "expected an error mentioning '$mentions'")
        assertTrue(mentions in error, error)
    }

    private fun notes(result: JsonObject): List<String> = result["notes"]?.jsonArray?.map { it.jsonPrimitive.content }.orEmpty()

    @Test
    fun `setting a rule resets its dedup guard on create and on update`() {
        val state = StateManager()
        val b = AutorizeBridge(state)
        val id = b.setRule(null, twoIdentities, true, null, null, null, true, 90.0, true)["rule_id"]!!.jsonPrimitive.content
        val key = StateManager.autorizeSeenKey(id, "GET", "https://x/a")
        assertTrue(state.autorizeSeenOnce(key))
        assertFalse(state.autorizeSeenOnce(key))

        b.setRule(id, null, null, null, null, null, null, 70.0, null)
        assertTrue(state.autorizeSeenOnce(key), "an updated rule retests endpoints")

        b.removeRule(id)
        state.autorizeSeenOnce(key) // a replay still in flight for the removed rule marks the key
        b.setRule(id, twoIdentities, true, null, null, null, true, 90.0, true)
        assertTrue(state.autorizeSeenOnce(key), "a re-created rule with the same id starts fresh")
    }

    @Test
    fun `invalid filters and identities are rejected instead of silently never matching`() {
        val b = AutorizeBridge(StateManager())
        assertError(b.setRule(null, twoIdentities, true, "[a-", null, null, true, 90.0, true), "include_host_pattern")
        assertError(b.setRule(null, twoIdentities, true, null, "(", null, true, 90.0, true), "exclude_url_regex")
        assertError(b.setRule(null, twoIdentities, true, null, null, listOf(" "), true, 90.0, true), "methods")
        assertError(b.setRule(null, twoIdentities, true, null, null, null, true, 150.0, true), "similarity_threshold")
        assertError(b.setRule(null, twoIdentities, true, null, null, null, true, Double.NaN, true), "similarity_threshold")

        val headerWithoutValue = buildJsonObject { put("name", "low"); put("header_name", "Cookie") }
        val nameless = buildJsonObject { put("header_name", "Cookie"); put("header_value", "a=1") }
        val headersNotAMap = buildJsonObject { put("name", "low"); put("headers", "not a map") }
        val blankRemoval = buildJsonObject { put("name", "low"); putJsonArray("remove_headers") { add(" ") } }
        for (bad in listOf(headerWithoutValue, nameless, headersNotAMap, blankRemoval)) {
            assertError(b.setRule(null, listOf(identity("admin"), bad), true, null, null, null, true, 90.0, true), "identities[1]")
        }
        assertError(b.setRule(null, listOf(identity("none"), identity("NONE")), true, null, null, null, true, 90.0, true), "unique")
        assertEquals(0, b.listRules()["count"]?.jsonPrimitive?.int)

        val ok = b.setRule(null, twoIdentities, true, "*.example.com", "\\.(png|css)$", listOf("get", "post"), true, 0.0, true)
        assertNull(ok["error"])
        assertEquals(
            listOf("GET", "POST"),
            b.listRules()["rules"]!!.jsonArray[0].jsonObject["methods"]!!.jsonArray.map { it.jsonPrimitive.content },
        )
    }

    @Test
    fun `identity headers are replayed as written, CR LF included, and may come as a map with removals`() {
        val b = AutorizeBridge(StateManager())
        val injected = buildJsonObject { put("name", "low"); put("header_name", "Cookie"); put("header_value", "a=1\r\nX-Injected: 1") }
        val mapped = buildJsonObject {
            put("name", "tenant-b")
            putJsonObject("headers") { put("Authorization", "Bearer b"); put("X-Tenant", "b") }
            putJsonArray("remove_headers") { add("X-Csrf-Token") }
        }
        assertNull(b.setRule(null, listOf(injected, mapped), true, null, null, null, true, 90.0, true)["error"])
        val identities = b.listRules()["rules"]!!.jsonArray.single().jsonObject["identities"]!!.jsonArray
        assertEquals("a=1\r\nX-Injected: 1", identities[0].jsonObject["header_value"]!!.jsonPrimitive.content)
        assertEquals("b", identities[1].jsonObject["headers"]!!.jsonObject["X-Tenant"]!!.jsonPrimitive.content)
    }

    @Test
    fun `replay gate skips instead of blocking when full and bounds concurrent sends`() {
        val gate = AutorizeReplayGate(maxQueued = 3, maxConcurrent = 2)
        repeat(3) { assertTrue(gate.tryAdmit()) }
        assertFalse(gate.tryAdmit(), "a full queue skips instead of blocking the proxy thread")
        gate.release()
        assertTrue(gate.tryAdmit())
        repeat(3) { gate.release() }

        val running = AtomicInteger()
        val peak = AtomicInteger()
        val pool = Executors.newFixedThreadPool(8)
        val tasks = (1..16).map {
            pool.submit {
                gate.withSendSlot {
                    val now = running.incrementAndGet()
                    peak.accumulateAndGet(now) { a, b -> maxOf(a, b) }
                    Thread.sleep(20)
                    running.decrementAndGet()
                }
            }
        }
        tasks.forEach { it.get(10, TimeUnit.SECONDS) }
        pool.shutdown()
        assertTrue(peak.get() in 1..2, "at most 2 replays send at once (peak ${peak.get()})")
    }

    @Test
    fun `setRule needs an identity that changes the request`() {
        val b = AutorizeBridge(StateManager())
        assertError(b.setRule(null, emptyList(), true, null, null, null, true, 90.0, true), "identities")
        assertError(b.setRule(null, listOf(identity("admin")), true, null, null, null, true, 90.0, true), "No identity changes the request")
        assertEquals(0, b.listRules()["count"]?.jsonPrimitive?.int)

        // The captured response is the authenticated reference, so one unauthenticated identity is enough.
        assertNull(b.setRule(null, listOf(identity("none")), true, null, null, null, true, 90.0, true)["error"])
        val noted = b.setRule(null, twoIdentities, true, null, null, null, true, 90.0, true)
        assertTrue(notes(noted).any { "'admin'" in it && "not replayed" in it }, notes(noted).toString())
    }

    @Test
    fun `state-changing methods are skipped unless the rule opts in, and the choice survives updates`() {
        val b = AutorizeBridge(StateManager())
        val created = b.setRule(null, twoIdentities, true, null, null, listOf("GET", "POST", "DELETE"), true, 90.0, true)
        val ruleId = created["rule_id"]!!.jsonPrimitive.content
        assertTrue(notes(created).any { "DELETE, POST" in it && "include_mutating" in it }, notes(created).toString())
        assertFalse(b.listRules()["rules"]!!.jsonArray.single().jsonObject["include_mutating"]!!.jsonPrimitive.boolean)

        val optedIn = b.setRule(ruleId, null, null, null, null, null, null, null, null, includeMutating = true)
        assertTrue(notes(optedIn).any { "include_mutating is on" in it })
        b.setRule(ruleId, null, null, null, null, null, null, 80.0, null)
        assertTrue(b.listRules()["rules"]!!.jsonArray.single().jsonObject["include_mutating"]!!.jsonPrimitive.boolean)

        assertEquals(AutorizePolicy.SKIPPED_MUTATING, AutorizePolicy.methodSkip(stateRule(includeMutating = false), "post"))
        assertNull(AutorizePolicy.methodSkip(stateRule(includeMutating = true), "PATCH"))
    }

    private fun stateRule(includeMutating: Boolean) = AutorizeRule("arule-x", twoIdentities, includeMutating = includeMutating)

    @Test
    fun `setRule creates a rule and listRules returns it`() {
        val b = AutorizeBridge(StateManager())
        val r = b.setRule(null, listOf(identity("admin"), identity("none")), true, null, null, null, true, 90.0, true)
        val ruleId = r["rule_id"]?.jsonPrimitive?.contentOrNull
        assertEquals("active", r["status"]?.jsonPrimitive?.contentOrNull)

        val listed = b.listRules()
        assertEquals(1, listed["count"]?.jsonPrimitive?.int)
        assertEquals(ruleId, listed["rules"]!!.jsonArray[0].jsonObject["rule_id"]?.jsonPrimitive?.contentOrNull)
    }

    @Test
    fun `setRule with an existing rule_id replaces it instead of adding a second`() {
        val b = AutorizeBridge(StateManager())
        val r1 = b.setRule(null, listOf(identity("admin"), identity("none")), true, null, null, null, true, 90.0, true)
        val ruleId = r1["rule_id"]!!.jsonPrimitive.content

        b.setRule(ruleId, listOf(identity("admin"), identity("none")), true, null, null, null, true, 50.0, false)
        val listed = b.listRules()
        assertEquals(1, listed["count"]?.jsonPrimitive?.int)
        val rule = listed["rules"]!!.jsonArray[0].jsonObject
        assertEquals(false, rule["enabled"]?.jsonPrimitive?.contentOrNull?.toBoolean())
        assertEquals(50.0, rule["similarity_threshold"]?.jsonPrimitive?.contentOrNull?.toDouble())
    }

    @Test
    fun `updating one field without resending others keeps the rule's existing values`() {
        val b = AutorizeBridge(StateManager())
        val r1 = b.setRule(
            ruleId = null,
            identities = listOf(identity("admin"), identity("none")),
            inScopeOnly = true,
            includeHostPattern = "*.example.com",
            excludeUrlRegex = null,
            methods = listOf("GET"),
            ignoreStaticAssets = true,
            similarityThreshold = 90.0,
            enabled = true,
        )
        val ruleId = r1["rule_id"]!!.jsonPrimitive.content

        // Only similarity_threshold is resent — everything else is omitted (null), as an MCP
        // client would do when it only wants to tune one knob.
        b.setRule(
            ruleId = ruleId,
            identities = null,
            inScopeOnly = null,
            includeHostPattern = null,
            excludeUrlRegex = null,
            methods = null,
            ignoreStaticAssets = null,
            similarityThreshold = 50.0,
            enabled = null,
        )

        val rule = b.listRules()["rules"]!!.jsonArray[0].jsonObject
        assertEquals(50.0, rule["similarity_threshold"]?.jsonPrimitive?.contentOrNull?.toDouble())
        // Everything NOT resent must survive the update unchanged.
        assertEquals(true, rule["enabled"]?.jsonPrimitive?.contentOrNull?.toBoolean())
        assertEquals("*.example.com", rule["include_host_pattern"]?.jsonPrimitive?.contentOrNull)
        assertEquals(listOf("GET"), rule["methods"]?.jsonArray?.map { it.jsonPrimitive.content })
        assertEquals(2, rule["identities"]?.jsonArray?.size)
    }

    @Test
    fun `updating a rule preserves its original created_at instead of stamping a new one`() {
        val b = AutorizeBridge(StateManager())
        val r1 = b.setRule(null, listOf(identity("admin"), identity("none")), true, null, null, null, true, 90.0, true)
        val ruleId = r1["rule_id"]!!.jsonPrimitive.content
        val createdAt = b.listRules()["rules"]!!.jsonArray[0].jsonObject["created_at"]!!.jsonPrimitive.content

        Thread.sleep(5) // guarantee Instant.now() would differ from createdAt if the bug regressed
        b.setRule(ruleId, null, null, null, null, null, null, 70.0, null)

        val updatedCreatedAt = b.listRules()["rules"]!!.jsonArray[0].jsonObject["created_at"]!!.jsonPrimitive.content
        assertEquals(createdAt, updatedCreatedAt)
    }

    @Test
    fun `omitting enabled on an update does not re-enable a disabled rule`() {
        val b = AutorizeBridge(StateManager())
        val r1 = b.setRule(null, listOf(identity("admin"), identity("none")), true, null, null, null, true, 90.0, false)
        val ruleId = r1["rule_id"]!!.jsonPrimitive.content
        assertEquals("disabled", r1["status"]?.jsonPrimitive?.contentOrNull)

        val r2 = b.setRule(ruleId, null, null, null, null, null, null, 75.0, null)
        assertEquals("disabled", r2["status"]?.jsonPrimitive?.contentOrNull)
        assertEquals(false, b.listRules()["rules"]!!.jsonArray[0].jsonObject["enabled"]?.jsonPrimitive?.contentOrNull?.toBoolean())
    }

    @Test
    fun `removeRule removes an existing rule and reports a miss for an unknown id`() {
        val state = StateManager()
        val b = AutorizeBridge(state)
        val r1 = b.setRule(null, listOf(identity("admin"), identity("none")), true, null, null, null, true, 90.0, true)
        val ruleId = r1["rule_id"]!!.jsonPrimitive.content
        state.autorizeActivity.count(ruleId, AutorizePolicy.REPLAYED)
        assertEquals(1L, b.listRules()["rules"]!!.jsonArray[0].jsonObject["activity"]!!.jsonObject["replayed"]!!.jsonPrimitive.long)

        assertEquals(true, b.removeRule(ruleId)["removed"]?.jsonPrimitive?.contentOrNull?.toBoolean())
        assertEquals(0, b.listRules()["count"]?.jsonPrimitive?.int)
        assertTrue(state.autorizeActivity.of(ruleId).isEmpty(), "a removed rule's tallies go with it")

        val miss = b.removeRule("arule-does-not-exist")
        assertEquals(false, miss["removed"]?.jsonPrimitive?.contentOrNull?.toBoolean())
        assertTrue(miss["error"] != null)
    }

    @Test
    fun `listMatches filters by rule_id and min_severity, and pages results`() {
        val stateManager = StateManager()
        val b = AutorizeBridge(stateManager)
        val critical = buildJsonObject { put("severity", "critical"); put("id", "all_identical"); put("detail", "d") }
        val high = buildJsonObject { put("severity", "high"); put("id", "unauth_accessible"); put("detail", "d") }

        stateManager.addAutorizeMatch("arule-1", "GET", "http://x/a", 200, listOf(critical), "req", "resp")
        stateManager.addAutorizeMatch("arule-1", "GET", "http://x/b", 200, listOf(high), "req", "resp")
        stateManager.addAutorizeMatch("arule-2", "GET", "http://x/c", 200, listOf(high), "req", "resp")

        assertEquals(3, b.listMatches(null, null, 0, 50)["total"]?.jsonPrimitive?.int)
        assertEquals(2, b.listMatches("arule-1", null, 0, 50)["total"]?.jsonPrimitive?.int)
        assertEquals(1, b.listMatches(null, "critical", 0, 50)["total"]?.jsonPrimitive?.int)

        val paged = b.listMatches(null, null, 1, 1)
        assertEquals(3, paged["total"]?.jsonPrimitive?.int)
        assertEquals(1, paged["returned"]?.jsonPrimitive?.int)
    }

    @Test
    fun `out-of-range paging is served at the bound with a note instead of an error`() {
        val stateManager = StateManager()
        val b = AutorizeBridge(stateManager)
        repeat(3) { stateManager.addAutorizeMatch("arule-1", "GET", "http://x/$it", 200, emptyList(), "req", "resp") }

        val big = b.listMatches(null, null, -3, 1000)
        assertNull(big["error"])
        assertEquals(3, big["returned"]!!.jsonPrimitive.int)
        assertEquals(
            listOf("start_index -3 is outside 0..2147483647; used 0", "count 1000 is outside 1..${AutorizeBridge.MAX_MATCH_PAGE}; used ${AutorizeBridge.MAX_MATCH_PAGE}"),
            notes(big),
        )
        assertEquals(1, b.listMatches(null, null, 0, 0)["returned"]!!.jsonPrimitive.int)
        assertTrue(notes(b.listMatches(null, null, 0, 50)).isEmpty())
    }

    @Test
    fun `a match shows the original next to each identity's replay, in full when asked for by id`() {
        val stateManager = StateManager()
        val b = AutorizeBridge(stateManager)
        val longBody = "x".repeat(10_000)
        val match = stateManager.addAutorizeMatch(
            "arule-1", "GET", "http://x/a", 200, emptyList(),
            "GET /a HTTP/1.1\r\nCookie: admin\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n$longBody",
            replays = listOf(
                AutorizeReplay("low", 200, "GET /a HTTP/1.1\r\nCookie: low\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n$longBody"),
                AutorizeReplay("none", 302, "GET /a HTTP/1.1\r\n\r\n", "HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n"),
            ),
            softDenial = true,
        )

        val listed = b.listMatches(null, null, 0, 50)["matches"]!!.jsonArray.single().jsonObject
        assertTrue(listed["soft_denial"]!!.jsonPrimitive.boolean)
        val summary = listed["replays"]!!.jsonArray.map { it.jsonObject }
        assertEquals(listOf("low", "none"), summary.map { it["identity"]!!.jsonPrimitive.content })
        assertEquals(listOf(200, 302), summary.map { it["status"]!!.jsonPrimitive.int })
        assertNull(summary[0]["response"], "a list summarises replays unless include_replays")
        assertTrue("[truncated" in listed["response"]!!.jsonPrimitive.content, "a list cuts long bodies")
        assertTrue(listed["response"]!!.jsonPrimitive.content.startsWith("HTTP/1.1 200 OK\r\n\r\n"), "the head is kept whole")

        val withReplays = b.listMatches(null, null, 0, 50, includeReplays = true)["matches"]!!.jsonArray.single().jsonObject
        assertTrue("Cookie: low" in withReplays["replays"]!!.jsonArray[0].jsonObject["request"]!!.jsonPrimitive.content)

        val detail = b.listMatches(null, null, 0, 50, matchId = match.id)["matches"]!!.jsonArray.single().jsonObject
        val lowResponse = detail["replays"]!!.jsonArray[0].jsonObject["response"]!!.jsonPrimitive.content
        assertTrue(lowResponse.endsWith(longBody), "a match asked for by id shows each replay at length")
        assertNotNull(b.listMatches(null, null, 0, 50, matchId = 999)["error"])
    }

    @Test
    fun `clearMatches scoped to a rule only removes that rule's matches`() {
        val stateManager = StateManager()
        val b = AutorizeBridge(stateManager)
        val f = buildJsonObject { put("severity", "critical"); put("id", "all_identical"); put("detail", "d") }
        stateManager.addAutorizeMatch("arule-1", "GET", "http://x/a", 200, listOf(f), "req", "resp")
        stateManager.addAutorizeMatch("arule-2", "GET", "http://x/b", 200, listOf(f), "req", "resp")

        b.clearMatches("arule-1", false)
        val remaining = b.listMatches(null, null, 0, 50)
        assertEquals(1, remaining["total"]?.jsonPrimitive?.int)
        assertEquals("arule-2", remaining["matches"]!!.jsonArray[0].jsonObject["rule_id"]?.jsonPrimitive?.contentOrNull)
    }

    @Test
    fun `setRule rejects an empty or blank exclude_url_regex`() {
        val b = AutorizeBridge(StateManager())
        assertError(b.setRule(null, twoIdentities, true, null, "", null, true, 90.0, true), "exclude_url_regex")
        assertError(b.setRule(null, twoIdentities, true, null, "   ", null, true, 90.0, true), "exclude_url_regex")
    }
}
