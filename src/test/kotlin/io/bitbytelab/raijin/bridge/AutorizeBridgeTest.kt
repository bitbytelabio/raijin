package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AutorizeBridgeTest {

    private fun identity(name: String): JsonObject = buildJsonObject { put("name", name) }

    @Test
    fun `setRule requires at least 2 identities`() {
        val b = AutorizeBridge(StateManager())
        val r = b.setRule(null, listOf(identity("none")), true, null, null, null, true, 90.0, true)
        assertEquals(true, r["error"]?.jsonPrimitive?.contentOrNull?.contains("identities"))
        assertEquals(0, b.listRules()["count"]?.jsonPrimitive?.int)
    }

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
        val b = AutorizeBridge(StateManager())
        val r1 = b.setRule(null, listOf(identity("admin"), identity("none")), true, null, null, null, true, 90.0, true)
        val ruleId = r1["rule_id"]!!.jsonPrimitive.content

        assertEquals(true, b.removeRule(ruleId)["removed"]?.jsonPrimitive?.contentOrNull?.toBoolean())
        assertEquals(0, b.listRules()["count"]?.jsonPrimitive?.int)

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
}
