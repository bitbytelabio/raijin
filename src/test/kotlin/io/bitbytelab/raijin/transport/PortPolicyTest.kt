package io.bitbytelab.raijin.transport

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The ports were hardcoded, so a clash with **PortSwigger's own MCP Server extension — which also
 * defaults to 9876** — was both unfixable and misreported (the old message blamed the build JDK).
 * These pin the resolution ladder and the diagnostic that replaces it.
 */
class PortPolicyTest {

    // ---- resolution ladder: system property > preference > default ---------

    @Test fun `falls back to the default when nothing is configured`() {
        assertEquals(9876, PortPolicy.resolve(null, null, PortPolicy.DEFAULT_SSE))
    }

    @Test fun `a preference overrides the default`() {
        assertEquals(19876, PortPolicy.resolve(null, "19876", PortPolicy.DEFAULT_SSE))
    }

    @Test fun `a system property wins over the preference`() {
        assertEquals(29876, PortPolicy.resolve("29876", "19876", PortPolicy.DEFAULT_SSE))
    }

    @Test fun `whitespace is tolerated`() {
        assertEquals(19876, PortPolicy.resolve(null, "  19876  ", PortPolicy.DEFAULT_SSE))
    }

    @Test fun `a typo degrades to the next source instead of breaking startup`() {
        assertEquals(19876, PortPolicy.resolve("not-a-port", "19876", PortPolicy.DEFAULT_SSE))
        assertEquals(9876, PortPolicy.resolve("", "", PortPolicy.DEFAULT_SSE))
        assertEquals(9876, PortPolicy.resolve(null, "abc", PortPolicy.DEFAULT_SSE))
    }

    @Test fun `out-of-range ports are rejected`() {
        assertEquals(9876, PortPolicy.resolve(null, "0", PortPolicy.DEFAULT_SSE))
        assertEquals(9876, PortPolicy.resolve(null, "65536", PortPolicy.DEFAULT_SSE))
        assertEquals(9876, PortPolicy.resolve(null, "-1", PortPolicy.DEFAULT_SSE))
        assertEquals(65535, PortPolicy.resolve(null, "65535", PortPolicy.DEFAULT_SSE))
        assertEquals(1, PortPolicy.resolve(null, "1", PortPolicy.DEFAULT_SSE))
    }

    // ---- the diagnostic ----------------------------------------------------

    @Test fun `a clash on 9876 names PortSwigger's official MCP Server extension`() {
        val m = PortPolicy.conflictMessage("Primary SSE", "127.0.0.1", 9876, PortPolicy.PREF_SSE_PORT)
        assertTrue(m.contains("ALREADY IN USE"), m)
        assertTrue(m.contains("MCP Server"), "must name the most likely culprit: $m")
        assertTrue(m.contains("9876"), m)
        assertTrue(m.contains(PortPolicy.PREF_SSE_PORT), "must say how to change it: $m")
        // It must actively steer away from the old, wrong diagnosis.
        assertTrue(m.contains("NOT the Java-version problem"), m)
    }

    @Test fun `a clash on another port does not blame PortSwigger`() {
        val m = PortPolicy.conflictMessage("Secondary SSE", "127.0.0.1", 9877, PortPolicy.PREF_HTTP_PORT)
        assertFalse(m.contains("PortSwigger"), "9877 is not their default: $m")
        assertTrue(m.contains("restart Burp"), m)
        assertTrue(m.contains(PortPolicy.PREF_HTTP_PORT), m)
    }

    @Test fun `the message always offers a way to see who owns the port`() {
        val m = PortPolicy.conflictMessage("Dashboard", "127.0.0.1", 9878, PortPolicy.PREF_DASHBOARD_PORT)
        assertTrue(m.contains("9878"), m)
        assertTrue(m.contains("ss -ltnp"), m)
    }

    // ---- clashes between Raijin's own listeners -----------------------------

    @Test fun `distinct ports are kept as configured`() {
        val a = PortPolicy.resolveDistinct(19876, 19877, 19878)
        assertEquals(PortPolicy.Assignment(19876, 19877, 19878, emptyList()), a)
    }

    @Test fun `a clashing listener moves to its default and the move names its preference`() {
        val a = PortPolicy.resolveDistinct(19876, 19876, 9878)
        assertEquals(19876, a.ssePort)
        assertEquals(PortPolicy.DEFAULT_HTTP, a.httpPort)
        assertEquals(9878, a.dashboardPort)
        assertEquals(1, a.messages.size)
        assertTrue(a.messages.single().contains(PortPolicy.PREF_HTTP_PORT), a.messages.single())
    }

    @Test fun `when the default is taken too the listener moves to the next free port`() {
        val a = PortPolicy.resolveDistinct(9877, 9877, 9877)
        assertEquals(listOf(9877, 9878, 9879), listOf(a.ssePort, a.httpPort, a.dashboardPort))
        assertEquals(2, a.messages.size)
    }

    @Test fun `all three on one port still yields three distinct ports`() {
        val a = PortPolicy.resolveDistinct(65535, 65535, 65535)
        assertEquals(3, setOf(a.ssePort, a.httpPort, a.dashboardPort).size, a.toString())
        assertTrue(listOf(a.ssePort, a.httpPort, a.dashboardPort).all { it in 1..65535 })
    }

    @Test fun `a moved listener never takes another listener's configured port`() {
        // mcp_sse_port=9877, the obvious way around PortSwigger's MCP Server on 9876.
        val a = PortPolicy.resolveDistinct(9877, 9877, 9878)
        assertEquals(listOf(9877, 9879, 9878), listOf(a.ssePort, a.httpPort, a.dashboardPort))
        val message = a.messages.single()
        assertTrue(PortPolicy.PREF_HTTP_PORT in message && "uses 9879" in message, message)
        assertFalse(PortPolicy.PREF_DASHBOARD_PORT in message, message)
    }

    @Test fun `a listener whose default is configured for another one skips it`() {
        val a = PortPolicy.resolveDistinct(9876, 9876, 9877)
        assertEquals(listOf(9876, 9878, 9877), listOf(a.ssePort, a.httpPort, a.dashboardPort))
        assertEquals(1, a.messages.size)
    }
}
