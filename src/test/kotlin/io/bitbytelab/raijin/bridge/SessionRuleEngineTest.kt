package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.state.SessionRule
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SessionRuleEngineTest {

    private fun rule(
        scope: String = "all",
        scopePattern: String? = null,
        extractFrom: String = "body",
        extractHeaderName: String? = null,
        extractRegex: String = "token=(\\w+)",
        injectInto: String = "header",
        injectName: String = "X-Token",
        injectValueTemplate: String = "Bearer {value}",
        extractJsonPath: String? = null,
        extractXPath: String? = null,
    ) = SessionRule(
        ruleName = "r", scope = scope, scopePattern = scopePattern,
        extractFrom = extractFrom, extractHeaderName = extractHeaderName, extractRegex = extractRegex,
        injectInto = injectInto, injectName = injectName, injectValueTemplate = injectValueTemplate,
        extractJsonPath = extractJsonPath, extractXPath = extractXPath,
    )

    @Test
    fun `extracts the capture group from a body`() {
        assertEquals("abc123", SessionRuleEngine.extract(rule(extractFrom = "body", extractRegex = "token=(\\w+)"), emptyList(), "x token=abc123 y"))
    }

    @Test
    fun `extracts from a header value`() {
        val r = rule(extractFrom = "header", extractHeaderName = "Set-Cookie", extractRegex = "SESSION=([^;]+)")
        assertEquals("xyz", SessionRuleEngine.extract(r, listOf("SESSION=xyz; Path=/; HttpOnly"), ""))
    }

    @Test
    fun `every header line is read and the first that yields a value wins`() {
        val r = rule(extractFrom = "header", extractHeaderName = "Set-Cookie", extractRegex = "SESSION=([^;]+)")
        val setCookies = listOf("theme=dark; Path=/", "SESSION=second; HttpOnly", "SESSION=third")
        assertEquals("second", SessionRuleEngine.extract(r, setCookies, ""))
        assertNull(SessionRuleEngine.extract(r, listOf("theme=dark", "lang=en"), ""))
    }

    @Test
    fun `falls back to the whole match when there is no capture group`() {
        assertEquals("v=1", SessionRuleEngine.extract(rule(extractRegex = "v=\\d"), emptyList(), "a v=1 b"))
    }

    @Test
    fun `returns null when nothing matches or header is absent`() {
        assertNull(SessionRuleEngine.extract(rule(extractRegex = "zzz=(\\d+)"), emptyList(), "nothing here"))
        assertNull(SessionRuleEngine.extract(rule(extractFrom = "header", extractHeaderName = "X"), emptyList(), "body"))
    }

    @Test
    fun `a JSONPath or XPath selects the value and a regex then cuts it`() {
        val json = """{"data":{"token":"Bearer abc.def","ttl":300},"items":[{"id":7}]}"""
        assertEquals("Bearer abc.def", SessionRuleEngine.extract(rule(extractRegex = "", extractJsonPath = "$.data.token"), emptyList(), json))
        assertEquals("abc.def", SessionRuleEngine.extract(rule(extractRegex = "Bearer (.+)", extractJsonPath = "data.token"), emptyList(), json))
        assertEquals("300", SessionRuleEngine.extract(rule(extractRegex = "", extractJsonPath = "$..ttl"), emptyList(), json))
        assertNull(SessionRuleEngine.extract(rule(extractRegex = "", extractJsonPath = "$.data.missing"), emptyList(), json))
        assertNull(SessionRuleEngine.extract(rule(extractRegex = "", extractJsonPath = "$.data.token"), emptyList(), "not json"))

        val xml = """<html><body><form><input name="csrf" value="c5"/></form></body></html>"""
        assertEquals("c5", SessionRuleEngine.extract(rule(extractRegex = "", extractXPath = "//input[@name='csrf']/@value"), emptyList(), xml))
    }

    @Test
    fun `inScope handles all, custom, and suite`() {
        assertTrue(SessionRuleEngine.inScope(rule(scope = "all"), "http://x/", suiteInScope = false))
        assertTrue(SessionRuleEngine.inScope(rule(scope = "custom", scopePattern = "example\\.com"), "http://example.com/a", false))
        assertFalse(SessionRuleEngine.inScope(rule(scope = "custom", scopePattern = "example\\.com"), "http://other.com/", false))
        assertTrue(SessionRuleEngine.inScope(rule(scope = "suite"), "http://x/", suiteInScope = true))
        assertFalse(SessionRuleEngine.inScope(rule(scope = "suite"), "http://x/", suiteInScope = false))
    }

    @Test
    fun `Burp's suite scope is only asked for scope suite`() {
        var asked = 0
        val ask = { asked++; true }
        SessionRuleEngine.inScope("all", null, "http://x/", ask)
        SessionRuleEngine.inScope("custom", "x", "http://x/", ask)
        assertEquals(0, asked)
        assertTrue(SessionRuleEngine.inScope("suite", null, "http://x/", ask))
        assertEquals(1, asked)
    }

    @Test
    fun `render substitutes the value placeholder`() {
        assertEquals("Bearer abc", SessionRuleEngine.render("Bearer {value}", "abc"))
    }

    @Test
    fun `render runs the value through chained encoders`() {
        assertEquals("a%20b%26c", SessionRuleEngine.render("{value|url}", "a b&c"))
        assertEquals("YTpi", SessionRuleEngine.render("{value|base64}", "a:b"))
        assertEquals("YSsvYg%3D%3D", SessionRuleEngine.render("{value|base64|url}", "a+/b"))
        assertEquals("raw=a b; enc=a%20b", SessionRuleEngine.render("raw={value}; enc={value| URL }", "a b"))
        assertEquals("x {value|nope}", SessionRuleEngine.render("x {value|nope}", "v"))
        assertEquals("constant", SessionRuleEngine.render("constant", "v"))
    }

    @Test
    fun `templateError names an unknown or empty encoder`() {
        assertNull(SessionRuleEngine.templateError("Bearer {value}"))
        assertNull(SessionRuleEngine.templateError("{value|url} and {value|base64|url}"))
        val unknown = assertNotNull(SessionRuleEngine.templateError("{value|rot13}"))
        assertTrue("'rot13'" in unknown && "url_all" in unknown, unknown)
        assertNotNull(SessionRuleEngine.templateError("{value|}"))
    }
}
