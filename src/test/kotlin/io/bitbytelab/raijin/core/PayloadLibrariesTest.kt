package io.bitbytelab.raijin.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PayloadLibrariesTest {

    private val added = listOf("ssrf", "xxe", "crlf", "nosqli", "open_redirect", "prototype_pollution")

    private fun library(name: String): List<String> = PayloadLibraries.get(name) ?: error("no payload library '$name'")

    @Test
    fun `known libraries return non-empty payload sets`() {
        (listOf("xss", "sqli", "traversal", "ssti", "cmdi") + added).forEach {
            assertTrue(PayloadLibraries.get(it)!!.isNotEmpty(), "$it should have payloads")
        }
    }

    @Test
    fun `lookup is case-insensitive`() {
        assertEquals(PayloadLibraries.get("xss"), PayloadLibraries.get("XSS"))
        assertEquals(PayloadLibraries.get("open_redirect"), PayloadLibraries.get(" Open_Redirect "))
    }

    @Test
    fun `unknown library is null`() {
        assertNull(PayloadLibraries.get("definitely-not-a-library"))
    }

    @Test
    fun `representative payloads are present`() {
        assertTrue(PayloadLibraries.get("sqli")!!.any { it.contains("'") })
        assertTrue(PayloadLibraries.get("ssti")!!.contains("{{7*7}}"))
        assertTrue(PayloadLibraries.get("xss")!!.any { it.contains("<script>") })
        assertTrue(PayloadLibraries.get("cmdi")!!.any { it.contains("id") })
    }

    @Test
    fun `names lists the libraries`() {
        assertTrue(PayloadLibraries.names().containsAll(listOf("xss", "sqli", "traversal", "ssti", "cmdi") + added))
        assertEquals(PayloadLibraries.names().size, PayloadLibraries.names().toSet().size)
    }

    @Test
    fun `no library repeats a payload or holds a blank one`() {
        for (name in PayloadLibraries.names()) {
            val payloads = library(name)
            assertEquals(payloads.size, payloads.toSet().size, "$name repeats a payload")
            assertTrue(payloads.none { it.isBlank() }, "$name has a blank payload")
        }
    }

    @Test
    fun `sqli covers an unquoted numeric value`() {
        val numeric = library("sqli").filter { '\'' !in it && '"' !in it && !it.startsWith("1)") }
        assertTrue(numeric.any { it.startsWith("1 AND 1=") }, numeric.toString())
        assertTrue(numeric.any { it.startsWith("1 AND SLEEP(") }, numeric.toString())
    }

    @Test
    fun `ssrf covers loopback, its alternate spellings, cloud metadata and other schemes`() {
        val ssrf = library("ssrf")
        assertTrue("http://127.0.0.1/" in ssrf)
        assertTrue("http://2130706433/" in ssrf, "decimal loopback")
        assertTrue("http://[::1]/" in ssrf)
        assertTrue(ssrf.any { "169.254.169.254" in it })
        assertTrue(ssrf.any { "metadata.google.internal" in it })
        assertTrue(ssrf.any { it.startsWith("file://") } && ssrf.any { it.startsWith("gopher://") })
    }

    @Test
    fun `xxe payloads are complete documents or an XInclude element`() {
        val xxe = library("xxe")
        assertTrue(xxe.all { it.startsWith("<?xml") || "XInclude" in it }, xxe.toString())
        assertTrue(xxe.any { "SYSTEM \"file:///etc/passwd\"" in it })
        assertTrue(xxe.any { "<!ENTITY % " in it }, "parameter entity")
        assertTrue(xxe.filter { it.startsWith("<?xml") }.all { "<!DOCTYPE" in it && it.trimEnd().endsWith(">") })
    }

    @Test
    fun `crlf payloads carry an encoded line break or its JSON escape, never a raw one`() {
        val crlf = library("crlf")
        assertTrue(crlf.none { '\r' in it || '\n' in it }, "a raw line break would split the request it is fuzzed into")
        assertTrue(crlf.all { Regex("(?i)%0a|%0d|%250a|%250d|%E5%98%8A|\\\\n").containsMatchIn(it) }, crlf.toString())
        assertTrue(crlf.none { ' ' in it && it.startsWith("%") }, "URL payloads must not hold a raw space")
    }

    @Test
    fun `nosqli has syntax breakers, script conditions and operators in both syntaxes`() {
        val nosqli = library("nosqli")
        assertTrue("'" in nosqli)
        assertTrue(nosqli.any { "\$ne" in it && it.startsWith("{") }, "JSON operator")
        assertTrue(nosqli.any { it.startsWith("[$") }, "bracket operator")
        assertTrue(nosqli.any { "sleep(" in it })
    }

    @Test
    fun `open_redirect has absolute, scheme-relative and backslash forms`() {
        val redirect = library("open_redirect")
        assertTrue("https://example.com/" in redirect)
        assertTrue("//example.com/" in redirect)
        assertTrue(redirect.any { '\\' in it })
        assertTrue(redirect.all { "example.com" in it || it.startsWith("javascript:") }, redirect.toString())
    }

    @Test
    fun `prototype_pollution has query and JSON forms through __proto__ and constructor`() {
        val pollution = library("prototype_pollution")
        assertTrue(pollution.any { it.startsWith("__proto__[") })
        assertTrue(pollution.any { it.startsWith("constructor[prototype]") })
        assertTrue(pollution.any { it.startsWith("{\"__proto__\"") })
        assertTrue(pollution.any { it.startsWith("{\"constructor\"") })
        assertTrue(pollution.all { "__proto__" in it || "prototype" in it }, pollution.toString())
    }
}
