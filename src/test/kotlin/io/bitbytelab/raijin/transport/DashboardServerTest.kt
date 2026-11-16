package io.bitbytelab.raijin.transport

import io.bitbytelab.raijin.events.BurpEvent
import kotlinx.serialization.json.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class DashboardServerTest {

    // ---- limit clamping ------------------------------------------------------

    private fun limit(raw: String?) = DashboardApi.clampInt(raw, DashboardApi.DEFAULT_LIMIT, 0, DashboardApi.MAX_EVENTS_LIMIT)

    @Test fun `a negative limit is clamped to zero instead of failing`() {
        assertEquals(0, limit("-1"))
        assertEquals(0, limit("-99999999999999999999999"))
    }

    @Test fun `a huge limit is clamped to the maximum`() {
        assertEquals(DashboardApi.MAX_EVENTS_LIMIT, limit("501"))
        assertEquals(DashboardApi.MAX_EVENTS_LIMIT, limit("2147483648"))
        assertEquals(DashboardApi.MAX_EVENTS_LIMIT, limit("99999999999999999999999"))
    }

    @Test fun `missing or non-numeric limits fall back to the default`() {
        assertEquals(DashboardApi.DEFAULT_LIMIT, limit(null))
        assertEquals(DashboardApi.DEFAULT_LIMIT, limit(""))
        assertEquals(DashboardApi.DEFAULT_LIMIT, limit("ten"))
        assertEquals(DashboardApi.DEFAULT_LIMIT, limit("1.5"))
    }

    @Test fun `in-range limits pass through`() {
        assertEquals(0, limit("0"))
        assertEquals(120, limit(" 120 "))
        assertEquals(DashboardApi.MAX_EVENTS_LIMIT, limit("500"))
    }

    @Test fun `the recent window starts at the newest items`() {
        assertEquals(900, DashboardApi.recentStart(total = 1000, limit = 100))
        assertEquals(0, DashboardApi.recentStart(total = 30, limit = 100))
        assertEquals(1000, DashboardApi.recentStart(total = 1000, limit = 0))
    }

    @Test fun `flags are explicit opt-in`() {
        assertTrue(DashboardApi.flag("true"))
        assertTrue(DashboardApi.flag("1"))
        assertTrue(DashboardApi.flag(" YES "))
        assertFalse(DashboardApi.flag(null))
        assertFalse(DashboardApi.flag("false"))
        assertFalse(DashboardApi.flag("on?"))
    }

    // ---- /api/proxy/recent shaping ------------------------------------------

    private val fullItem = buildJsonObject {
        put("index", 7)
        put("host", "example.com")
        put("port", 443)
        put("secure", true)
        put("method", "POST")
        put("url", "https://example.com/login?next=/")
        put("path", "/login?next=/")
        put("mime_type", "HTML")
        put("has_response", true)
        put("time", "2026-11-16T10:00:00.123+07:00[Asia/Ho_Chi_Minh]")
        put("status_code", 302)
        put("response_length", 12)
        put("request_headers", buildJsonArray {
            add(buildJsonObject { put("name", "Cookie"); put("value", "session=abc") })
        })
        put("request", "POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nuser=a")
        put("request_truncated", true)
        put("response", "HTTP/1.1 302 Found\r\n\r\n")
        put("response_binary", false)
        put("some_future_heavy_field", "x".repeat(100))
    }

    private val history = buildJsonObject {
        put("total_filtered", 1000)
        put("start_index", 999)
        put("returned", 1)
        put("items", buildJsonArray { add(fullItem) })
    }

    @Test fun `proxy recent is metadata only by default`() {
        val out = DashboardApi.proxyRecent(history, includeRequest = false, includeResponse = false)
        assertEquals(true, out["metadata_only"]?.jsonPrimitive?.boolean)
        assertEquals(1000, out["total_filtered"]?.jsonPrimitive?.int)
        val item = out["items"]!!.jsonArray.single().jsonObject
        assertEquals("POST", item["method"]?.jsonPrimitive?.content)
        assertEquals("https://example.com/login?next=/", item["url"]?.jsonPrimitive?.content)
        assertEquals(302, item["status_code"]?.jsonPrimitive?.int)
        for (heavy in listOf("request_headers", "request", "request_truncated", "response", "response_binary", "some_future_heavy_field")) {
            assertNull(item[heavy], "$heavy must not be sent by default")
        }
    }

    @Test fun `request and response material are opt-in per side`() {
        val reqOnly = DashboardApi.proxyItem(fullItem, includeRequest = true, includeResponse = false)
        assertNotNull(reqOnly["request"])
        assertNotNull(reqOnly["request_headers"])
        assertNotNull(reqOnly["request_truncated"])
        assertNull(reqOnly["response"])

        val respOnly = DashboardApi.proxyItem(fullItem, includeRequest = false, includeResponse = true)
        assertNotNull(respOnly["response"])
        assertNotNull(respOnly["response_binary"])
        assertNull(respOnly["request"])
        assertNull(respOnly["request_headers"])

        val both = DashboardApi.proxyRecent(history, includeRequest = true, includeResponse = true)
        assertEquals(false, both["metadata_only"]?.jsonPrimitive?.boolean)
    }

    @Test fun `zoned history times become browser-parseable instants`() {
        val item = DashboardApi.proxyItem(fullItem, includeRequest = false, includeResponse = false)
        assertEquals("2026-11-16T03:00:00.123Z", item["time"]?.jsonPrimitive?.content)
        assertEquals("not a time", DashboardApi.isoInstant("not a time"))
    }

    @Test fun `event json carries id, type, timestamp and data`() {
        val evt = BurpEvent(42, "proxy.response", "2026-11-16T03:00:00Z", buildJsonObject { put("status_code", 200) })
        val json = DashboardApi.eventJson(evt)
        assertEquals(42, json["id"]?.jsonPrimitive?.long)
        assertEquals("proxy.response", json["type"]?.jsonPrimitive?.content)
        assertEquals(200, json["data"]?.jsonObject?.get("status_code")?.jsonPrimitive?.int)
    }

    // ---- /api/info -----------------------------------------------------------

    @Test fun `info reports the configured ports, not the defaults`() {
        val info = DashboardApi.info("1.2.3", "127.0.0.1", 19878, 19876, 19877)
        assertEquals("1.2.3", info["version"]?.jsonPrimitive?.content)
        assertEquals(19876, info["ports"]?.jsonObject?.get("primary_mcp")?.jsonPrimitive?.int)
        assertEquals("http://127.0.0.1:19876/mcp", info["primary_mcp_url"]?.jsonPrimitive?.content)
        assertEquals("http://127.0.0.1:19877/mcp", info["secondary_mcp_url"]?.jsonPrimitive?.content)
        assertEquals("http://127.0.0.1:19878", info["dashboard_url"]?.jsonPrimitive?.content)
        val server = info["mcp_client_config"]?.jsonObject?.get("mcpServers")?.jsonObject?.values?.single()?.jsonObject
        assertEquals("http://127.0.0.1:19876/mcp", server?.get("url")?.jsonPrimitive?.content)
        assertTrue(info["claude_code_command"]!!.jsonPrimitive.content.endsWith("http://127.0.0.1:19876/mcp"))
    }

    // ---- static assets -------------------------------------------------------

    @Test fun `static assets are served with their content types`() {
        assertEquals("text/html; charset=utf-8", DashboardAssets.lookup("/")?.contentType)
        assertEquals("text/html; charset=utf-8", DashboardAssets.lookup("/index.html")?.contentType)
        assertEquals("text/css; charset=utf-8", DashboardAssets.lookup("/dashboard.css")?.contentType)
        assertEquals("text/javascript; charset=utf-8", DashboardAssets.lookup("/dashboard.js")?.contentType)
        assertEquals("image/png", DashboardAssets.lookup("/logo.png")?.contentType)
    }

    @Test fun `only listed paths resolve`() {
        assertNull(DashboardAssets.lookup("/../../etc/passwd"))
        assertNull(DashboardAssets.lookup("/dashboard/index.html"))
        assertNull(DashboardAssets.lookup("/api/stats"))
        assertNull(DashboardAssets.lookup("/events"))
    }

    @Test fun `page, stylesheet and script load from the classpath`() {
        val page = assertNotNull(DashboardAssets.load(DashboardAssets.lookup("/")!!))
        val html = page.bytes.decodeToString()
        // The page's own asset references resolve to served paths.
        assertTrue("href=\"dashboard.css\"" in html && "src=\"dashboard.js\"" in html)
        assertNotNull(DashboardAssets.lookup("/dashboard.css")?.let { DashboardAssets.load(it) })
        assertNotNull(DashboardAssets.lookup("/dashboard.js")?.let { DashboardAssets.load(it) })
        assertSame(page, DashboardAssets.load(DashboardAssets.lookup("/index.html")!!), "loaded once, then cached")
    }

    @Test fun `etags revalidate`() {
        val loaded = assertNotNull(DashboardAssets.load(DashboardAssets.lookup("/dashboard.js")!!))
        assertTrue(loaded.etag.startsWith("\"") && loaded.etag.endsWith("\""))
        assertTrue(DashboardAssets.notModified(loaded.etag, loaded.etag))
        assertTrue(DashboardAssets.notModified("\"other\", W/${loaded.etag}", loaded.etag))
        assertTrue(DashboardAssets.notModified("*", loaded.etag))
        assertFalse(DashboardAssets.notModified(null, loaded.etag))
        assertFalse(DashboardAssets.notModified("\"other\"", loaded.etag))
    }
}
