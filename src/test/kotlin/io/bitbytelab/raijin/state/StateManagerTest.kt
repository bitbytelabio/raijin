package io.bitbytelab.raijin.state

import burp.api.montoya.core.Registration
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class StateManagerTest {

    private class FakeRegistration(private val failOnDeregister: Boolean = false) : Registration {
        var deregistered = false
        override fun isRegistered(): Boolean = !deregistered
        override fun deregister() {
            if (failOnDeregister) throw IllegalStateException("already gone")
            deregistered = true
        }
    }

    private fun entry(id: Long) =
        McpActivityEntry(id, "t", "2026-07-05T00:00:00Z", 1, "GET", "https://x/$id", "x.com", 200, false, "{}", "ok")

    private fun addActivity(sm: StateManager) =
        sm.addMcpActivity("http_send_request", "2026-07-05T00:00:00Z", 1, "GET", "https://x/", "x", 200, false, "{}", "{}")

    @Test
    fun `restored activity counts toward the retention cap`() {
        val sm = StateManager()
        val cap = sm.activityCapacity
        sm.restoreMcpActivity((1..cap + 10L).map { entry(it) })
        assertEquals(cap, sm.mcpActivity.size)

        repeat(5) { addActivity(sm) }
        assertEquals(cap, sm.mcpActivity.size, "live entries evict restored ones instead of growing past the cap")
        assertEquals("http_send_request", sm.mcpActivity.first().toolName)
    }

    @Test
    fun `live activity is capped and newest first`() {
        val sm = StateManager()
        repeat(sm.activityCapacity + 3) { addActivity(sm) }
        assertEquals(sm.activityCapacity, sm.mcpActivity.size)
        assertEquals(sm.activityCapacity + 3L, sm.mcpActivity.first().id)
    }

    @Test
    fun `autorize matches are capped and newest first`() {
        val sm = StateManager()
        repeat(2005) { sm.addAutorizeMatch("arule-1", "GET", "https://x/$it", 200, emptyList(), "", "") }
        assertEquals(2000, sm.autorizeMatches.size)
        assertEquals("https://x/2004", sm.autorizeMatches.first().url)

        sm.clearAutorizeMatches(null, resetSeen = false)
        sm.addAutorizeMatch("arule-1", "GET", "https://x/again", 200, emptyList(), "", "")
        assertEquals(1, sm.autorizeMatches.size)
    }

    @Test
    fun `seen key keeps the query string but not the method case`() {
        assertEquals(
            StateManager.autorizeSeenKey("arule-1", "get", "https://x/a?id=1&sort=asc"),
            StateManager.autorizeSeenKey("arule-1", "GET", "https://x/a?sort=asc&id=1"),
        )
        assertNotEquals(
            StateManager.autorizeSeenKey("arule-1", "GET", "https://x/a?id=1"),
            StateManager.autorizeSeenKey("arule-1", "GET", "https://x/a?id=2"),
        )
        assertEquals(
            "arule-1|GET|https://x/a",
            StateManager.autorizeEndpointKey("arule-1", "get", "https://x/a?id=2"),
        )
    }

    @Test
    fun `query variants of one endpoint stop being replayed past the ceiling`() {
        val sm = StateManager()
        val endpoint = StateManager.autorizeEndpointKey("arule-1", "GET", "https://x/search")
        repeat(AutorizeSeenGuard.MAX_QUERY_VARIANTS) {
            assertTrue(sm.autorizeSeenOnce(StateManager.autorizeSeenKey("arule-1", "GET", "https://x/search?q=term$it"), endpoint))
        }
        assertFalse(sm.autorizeSeenOnce(StateManager.autorizeSeenKey("arule-1", "GET", "https://x/search?q=more"), endpoint))
        sm.clearAutorizeMatches("arule-1", resetSeen = true)
        assertTrue(sm.autorizeSeenOnce(StateManager.autorizeSeenKey("arule-1", "GET", "https://x/search?q=more"), endpoint))
    }

    @Test
    fun `clearing one rule's seen keys leaves other rules alone`() {
        val sm = StateManager()
        val rule1 = StateManager.autorizeSeenKey("arule-1", "GET", "https://x/a")
        val rule10 = StateManager.autorizeSeenKey("arule-10", "GET", "https://x/a")
        assertTrue(sm.autorizeSeenOnce(rule1))
        assertTrue(sm.autorizeSeenOnce(rule10))
        assertFalse(sm.autorizeSeenOnce(rule1))

        sm.clearAutorizeSeen("arule-1")

        assertTrue(sm.autorizeSeenOnce(rule1), "arule-1 is retested")
        assertFalse(sm.autorizeSeenOnce(rule10), "arule-10 keeps its dedup state")
    }

    @Test
    fun `cleanup deregisters every Burp registration even when one fails`() {
        val sm = StateManager()
        val failing = FakeRegistration(failOnDeregister = true)
        val scanCheck = FakeRegistration()
        val payloadProcessor = FakeRegistration()
        sm.scanCheckRegistrations["broken"] = failing
        sm.scanCheckRegistrations["check"] = scanCheck
        sm.intruderRegistrations["processor"] = payloadProcessor

        sm.cleanup()

        assertTrue(scanCheck.deregistered)
        assertTrue(payloadProcessor.deregistered)
        assertTrue(sm.scanCheckRegistrations.isEmpty())
        assertTrue(sm.intruderRegistrations.isEmpty())
    }

    @Test
    fun `cleanup drops listeners, buffers and the dedup guard`() {
        val sm = StateManager()
        sm.mcpActivityListeners.add { }
        sm.findingsListeners.add { }
        sm.findingsRemoveListeners.add { }
        addActivity(sm)
        sm.addAutorizeMatch("arule-1", "GET", "https://x/a", 200, emptyList(), "", "")
        sm.websocketConnections["ws-001"] = WebSocketConnection("ws-001", "wss://x/ws", "2026-11-16T00:00:00Z")
        val key = StateManager.autorizeSeenKey("arule-1", "GET", "https://x/a")
        sm.autorizeSeenOnce(key)

        sm.cleanup()

        assertTrue(sm.mcpActivityListeners.isEmpty())
        assertTrue(sm.findingsListeners.isEmpty())
        assertTrue(sm.findingsRemoveListeners.isEmpty())
        assertTrue(sm.mcpActivity.isEmpty())
        assertTrue(sm.autorizeMatches.isEmpty())
        assertTrue(sm.websocketConnections.isEmpty())
        assertTrue(sm.autorizeSeenOnce(key), "the dedup guard is cleared too")
    }
}
