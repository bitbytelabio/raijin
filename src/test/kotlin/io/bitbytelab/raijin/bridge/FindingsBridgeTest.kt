package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals

class FindingsBridgeTest {

    @Test
    fun `adding the same finding twice is deduplicated`() {
        val b = FindingsBridge(StateManager())
        val r1 = b.add("xss", "high", "http://x/p?q=1", "param:q", "reflected", "<script>")
        assertEquals(false, r1["duplicate"]?.jsonPrimitive?.boolean)
        val r2 = b.add("xss", "high", "http://x/p?q=1", "param:q", "reflected again", "<svg>")
        assertEquals(true, r2["duplicate"]?.jsonPrimitive?.boolean)
        assertEquals(1, b.list(null, null)["count"]?.jsonPrimitive?.int)
    }

    @Test
    fun `a different location is a separate finding`() {
        val b = FindingsBridge(StateManager())
        b.add("xss", "high", "http://x/p", "param:q", "", "")
        b.add("xss", "high", "http://x/p", "param:r", "", "")
        assertEquals(2, b.list(null, null)["count"]?.jsonPrimitive?.int)
    }

    @Test
    fun `list filters by severity and type`() {
        val b = FindingsBridge(StateManager())
        b.add("xss", "high", "http://x/1", "", "", "")
        b.add("info_leak", "low", "http://x/2", "", "", "")
        assertEquals(1, b.list("high", null)["count"]?.jsonPrimitive?.int)
        assertEquals(1, b.list(null, "info_leak")["count"]?.jsonPrimitive?.int)
        assertEquals(2, b.list(null, null)["count"]?.jsonPrimitive?.int)
    }

    // --- CVSS validation ---

    @Test
    fun `cvss_score must be a number between 0 and 10`() {
        val b = FindingsBridge(StateManager())
        b.add("xss", "high", "http://x/p", "", "", "", cvssScore = "8.1")
        val bad = b.add("sqli", "high", "http://x/q", "", "", "", cvssScore = "11.0")
        assertEquals(true, bad["error"]?.jsonPrimitive?.contentOrNull?.contains("cvss_score"))
        b.add("idor", "critical", "http://x/r", "", "", "", cvssScore = "not-a-number")
        // only the valid one was recorded
        assertEquals(1, b.list(null, null)["count"]?.jsonPrimitive?.int)
    }

    // --- OWASP Top 10 (2021) normalization ---

    @Test
    fun `owasp category normalizes codes, code+year, names and aliases`() {
        assertEquals("A03:2021 - Injection", Owasp2021.normalize("A03"))
        assertEquals("A03:2021 - Injection", Owasp2021.normalize("a03:2021"))
        assertEquals("A03:2021 - Injection", Owasp2021.normalize("injection"))
        assertEquals("A01:2021 - Broken Access Control", Owasp2021.normalize("Broken Access Control"))
        assertEquals("A10:2021 - Server-Side Request Forgery (SSRF)", Owasp2021.normalize("SSRF"))
        assertEquals("A10:2021 - Server-Side Request Forgery (SSRF)", Owasp2021.normalize("server-side request forgery"))
        assertEquals("A07:2021 - Identification and Authentication Failures", Owasp2021.normalize("A07:2021"))
    }

    @Test
    fun `owasp category passes unrecognized values through and blanks stay blank`() {
        assertEquals("", Owasp2021.normalize(""))
        assertEquals("", Owasp2021.normalize("   "))
        assertEquals("A99 - Something New", Owasp2021.normalize("A99 - Something New"))
    }

    @Test
    fun `add normalizes the owasp category on the stored finding`() {
        val b = FindingsBridge(StateManager())
        val r = b.add("idor", "critical", "http://x/u/2", "param:id", "", "", owaspCategory = "A01")
        assertEquals("A01:2021 - Broken Access Control", r["owasp_category"]?.jsonPrimitive?.contentOrNull)
        assertEquals("A01:2021 - Broken Access Control", b.list(null, null)["findings"]!!
            .jsonArray[0].jsonObject["owasp_category"]?.jsonPrimitive?.contentOrNull)
    }

    @Test
    fun `remove notifies the durable store listeners and drops the finding`() {
        val sm = StateManager()
        val removed = mutableListOf<String>()
        sm.findingsRemoveListeners.add { removed += it }
        val b = FindingsBridge(sm)
        val id = b.add("xss", "high", "http://x/p", "param:q", "", "")["id"]!!.jsonPrimitive.content

        val r = b.remove(id)
        assertEquals(true, r["removed"]?.jsonPrimitive?.boolean)
        assertEquals(listOf(id), removed)
        assertEquals(0, b.list(null, null)["count"]?.jsonPrimitive?.int)

        val missing = b.remove(id)
        assertEquals(false, missing["removed"]?.jsonPrimitive?.boolean)
        assertEquals(true, missing["error"] != null)
        assertEquals(listOf(id), removed, "a failed remove must not touch the store")
    }

    @Test
    fun `cvss_score rejects NaN and infinity`() {
        val b = FindingsBridge(StateManager())
        listOf("NaN", "Infinity", "-0.1").forEach { score ->
            assertEquals(true, b.add("xss", "high", "http://x/$score", "", "", "", cvssScore = score)["error"] != null, score)
        }
        assertEquals(0, b.list(null, null)["count"]?.jsonPrimitive?.int)
    }
}
