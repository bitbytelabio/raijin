package io.bitbytelab.raijin.safety

import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class ScopeGateTest {

    private fun gate(mode: String?, inScope: Boolean) = ScopeGate({ mode }, { inScope })

    @Test
    fun `check follows the mode for in and out of scope targets`() {
        for (mode in listOf("off", "warn", "enforce", null)) {
            val inside = gate(mode, inScope = true).check("https://a/")
            assertFalse(inside.blocked, "$mode in scope")
            assertNull(inside.warning, "$mode in scope")
        }
        val off = gate("off", inScope = false).check("https://a/")
        assertFalse(off.blocked)
        assertNull(off.warning)

        val warn = gate(null, inScope = false).check("https://a/")
        assertFalse(warn.blocked)
        assertEquals("out_of_scope: https://a/ is not in Burp's target scope (mcp_scope_mode=warn); sent anyway", warn.warning)

        val enforce = gate("ENFORCE", inScope = false).check("https://a/")
        assertTrue(enforce.blocked)
        assertNull(enforce.warning)
        val deny = enforce.denyJson()
        assertEquals(true, deny["out_of_scope"]?.jsonPrimitive?.content?.toBoolean())
        assertEquals("enforce", deny["scope_mode"]?.jsonPrimitive?.content)
        assertTrue(deny["error"]!!.jsonPrimitive.content.contains("scope(action=include)"))
    }

    @Test
    fun `a scope evaluation that throws fails open with scope_unchecked`() {
        val check = ScopeGate({ "enforce" }, { throw IllegalStateException("boom") }).check("https://a/")
        assertFalse(check.blocked)
        assertTrue(check.warning!!.startsWith("scope_unchecked: could not evaluate Burp's scope for https://a/ (boom)"))
    }

    @Test
    fun `a mode read that throws counts as warn`() {
        val check = ScopeGate({ throw IllegalStateException() }, { false }).check("https://a/")
        assertFalse(check.blocked)
        assertTrue(check.warning!!.contains("mcp_scope_mode=warn"))
    }

    @Test
    fun `advise never blocks and names the advisory tool under enforce`() {
        val check = gate("enforce", inScope = false).advise("https://a/", "turbo")
        assertFalse(check.blocked)
        assertEquals(
            "out_of_scope: https://a/ is not in Burp's target scope; sent anyway: turbo is advisory-only and not blocked by mcp_scope_mode=enforce",
            check.warning,
        )
        assertTrue(gate("warn", inScope = false).advise("https://a/", "turbo").warning!!.contains("mcp_scope_mode=warn"))
    }

    @Test
    fun `annotate puts scope_warning first and joins an existing one`() {
        val check = gate("warn", inScope = false).check("https://a/")
        val annotated = check.annotate(buildJsonObject { put("status_code", 200) })
        assertEquals(listOf("scope_warning", "status_code"), annotated.keys.toList())

        val joined = check.annotate(buildJsonObject { put("x", 1); put("scope_warning", "earlier") })
        assertEquals(listOf("scope_warning", "x"), joined.keys.toList())
        assertEquals("earlier; ${check.warning}", (joined["scope_warning"] as JsonPrimitive).content)

        val clean = buildJsonObject { put("x", 1) }
        assertSame(clean, gate("warn", inScope = true).check("https://a/").annotate(clean))
    }

    @Test
    fun `requestUrl is the connection target plus the request-line path`() {
        assertEquals("https://[::1]:8443/a?b", ScopeGate.requestUrl("::1", 8443, true, "GET /a?b HTTP/1.1\r\nHost: x\r\n\r\n"))
        assertEquals("http://h:80/", ScopeGate.requestUrl("h", 80, false, "garbage"))
        // An absolute-form target names another host, but the bytes go to h:80.
        assertEquals("http://h:80/x", ScopeGate.requestUrl("h", 80, false, "GET https://in-scope.example/x HTTP/1.1\r\n"))
        // Read as servers do: leading empty lines skipped, tabs separate.
        assertEquals("http://h:80/logout", ScopeGate.requestUrl("h", 80, false, "\r\nGET\t/logout HTTP/1.1\r\n\r\n"))
    }

    @Test
    fun `a multi-request check blocks when any target is out of scope`() {
        val gate = ScopeGate({ "enforce" }, { !it.endsWith("/logout") })
        val check = gate.checkRequests("h", 443, true, sequenceOf("GET / HTTP/1.1\r\n", "GET /logout HTTP/1.1\r\n"))
        assertTrue(check.blocked)
        assertEquals("https://h:443/logout", check.url)
        assertFalse(gate.checkRequests("h", 443, true, sequenceOf("GET /a HTTP/1.1\r\n")).blocked)
    }

    @Test
    fun `a host that cannot be put into a URL is refused under enforce`() {
        val check = ScopeGate({ "enforce" }, { true }).checkRequest("in.example#.evil", 443, true, "GET / HTTP/1.1\r\n")
        assertTrue(check.blocked)
        assertTrue(check.denyJson()["error"]!!.jsonPrimitive.content.contains("cannot be checked"))
        assertTrue(ScopeGate({ "warn" }, { true }).checkRequest("a b", 443, true, "GET / HTTP/1.1\r\n").warning!!.startsWith("scope_unchecked"))
    }
}
