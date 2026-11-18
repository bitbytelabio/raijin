package io.bitbytelab.raijin.bridge

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class HttpRequestBuilderTest {

    // --- Host header parsing ---

    @Test
    fun `parseHostHeader reads host and port including IPv6 literals`() {
        assertEquals("::1" to 8443, HttpRequestBuilder.parseHostHeader("GET / HTTP/1.1\r\nHost: [::1]:8443\r\nX-Port: 9999\r\n\r\n"))
        assertEquals("::1" to null, HttpRequestBuilder.parseHostHeader("GET / HTTP/1.1\r\nHost: [::1]\r\n\r\n"))
        assertEquals("fe80::1" to null, HttpRequestBuilder.parseHostHeader("GET / HTTP/1.1\r\nHost: fe80::1\r\n\r\n"))
        assertEquals("example.com" to 8080, HttpRequestBuilder.parseHostHeader("GET / HTTP/1.1\nhost: example.com:8080\n\n"))
        assertEquals("example.com" to null, HttpRequestBuilder.parseHostHeader("GET / HTTP/1.1\r\nHost: example.com:99999\r\n\r\n"))
        assertEquals("a.example" to null, HttpRequestBuilder.parseHostHeader("GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example:1\r\n\r\n"))
    }

    @Test
    fun `parseHostHeader never crosses a line break or reads the body`() {
        // An empty Host must not borrow the next line's "name:port".
        assertNull(HttpRequestBuilder.parseHostHeader("GET / HTTP/1.1\r\nHost:\r\nfoo:8080\r\n\r\n"))
        // A Host header inside a smuggled request in the body is not the target.
        assertNull(HttpRequestBuilder.parseHostHeader("POST / HTTP/1.1\r\nContent-Length: 40\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal:81\r\n\r\n"))
        // An absolute-form request line is not a Host header.
        assertNull(HttpRequestBuilder.parseHostHeader("GET http://other:81/ HTTP/1.1\r\n\r\n"))
    }

    // --- structured request construction ---

    @Test
    fun `constructRawHttpRequest counts Content-Length in the charset the request is sent with`() {
        val latin1 = HttpRequestBuilder.constructRawHttpRequest("https://h/p?q=1", "POST", emptyMap(), "é", "h", 443, true)
        assertEquals("POST /p?q=1 HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\n\r\né", latin1)
        // A wide char in a header sends the whole request as UTF-8, so "é" in the body is 2 bytes.
        val wide = HttpRequestBuilder.constructRawHttpRequest("https://h/", "POST", mapOf("X-Name" to "日本"), "é", "h", 443, true)
        assertTrue(wide.contains("Content-Length: 2\r\n"), wide)
        // Caller-supplied framing is never second-guessed.
        val declared = HttpRequestBuilder.constructRawHttpRequest("https://h/", "POST", mapOf("Content-Length" to "99"), "abc", "h", 443, true)
        assertEquals("POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 99\r\n\r\nabc", declared)
    }

    @Test
    fun `constructRawHttpRequest brackets an IPv6 host in the Host header`() {
        // Without a URL authority the Host comes from the connection target.
        assertTrue(HttpRequestBuilder.constructRawHttpRequest("/", "GET", emptyMap(), null, "::1", 8080, false).contains("\r\nHost: [::1]:8080\r\n"))
        assertTrue(HttpRequestBuilder.constructRawHttpRequest("https://[::1]/", "GET", emptyMap(), null, "[::1]", 443, true).contains("\r\nHost: [::1]\r\n"))
    }

    @Test
    fun `a host override moves the connection but the Host header stays the URL's`() {
        val raw = HttpRequestBuilder.constructRawHttpRequest("http://t/", "GET", emptyMap(), null, "10.0.0.5", 80, false)
        assertTrue(raw.contains("\r\nHost: t\r\n"), raw)
    }

    @Test
    fun `the URL target is sent exactly as written`() {
        val raw = HttpRequestBuilder.constructRawHttpRequest(
            "https://t/s?q=<script>alert(1)</script>", "GET", emptyMap(), null, "t", 443, true,
        )
        assertTrue(raw.startsWith("GET /s?q=<script>alert(1)</script> HTTP/1.1\r\n"), raw)
    }

    @Test
    fun `splitUrl keeps hosts and targets verbatim`() {
        assertEquals(HttpRequestBuilder.UrlParts("http", "my_host:8080", "/a b|{c}"), HttpRequestBuilder.splitUrl("http://user@my_host:8080/a b|{c}"))
        assertEquals("/?x=1", HttpRequestBuilder.splitUrl("https://h?x=1")?.target)
        assertEquals("/", HttpRequestBuilder.splitUrl("https://h")?.target)
        assertEquals(null, HttpRequestBuilder.splitUrl("/relative"))
    }

    // --- native HTTP/2 requests ---

    @Test
    fun `http2 pseudo-headers are derived and put first when the caller gives none`() {
        val target = HttpRequestBuilder.http2Target("https://h.example:8443/a/b?x=1", null, null, null, emptyList())
        assertEquals(HttpRequestBuilder.Target("h.example", 8443, true), target)
        val fields = HttpRequestBuilder.http2Fields("https://h.example:8443/a/b?x=1", "POST", target, listOf("x-test" to "1"))
        assertEquals(
            listOf(":method" to "POST", ":scheme" to "https", ":authority" to "h.example:8443", ":path" to "/a/b?x=1", "x-test" to "1"),
            fields,
        )
    }

    @Test
    fun `http2 fields with any pseudo-header are sent exactly as given`() {
        val given = listOf(
            ":path" to "/x\r\nInjected: 1",
            ":method" to "GET",
            ":authority" to "a.example",
            ":authority" to "b.example",
            "Transfer-Encoding" to "chunked",
        )
        val target = HttpRequestBuilder.http2Target("https://h.example/", null, null, null, given)
        assertEquals(given, HttpRequestBuilder.http2Fields("https://h.example/", "POST", target, given))
    }

    @Test
    fun `http2 target comes from overrides, then the URL, then the authority and scheme fields`() {
        val fields = listOf(":scheme" to "http", ":authority" to "[::1]:8080", ":path" to "/")
        assertEquals(HttpRequestBuilder.Target("::1", 8080, false), HttpRequestBuilder.http2Target(null, null, null, null, fields))
        assertEquals(HttpRequestBuilder.Target("other", 9443, true), HttpRequestBuilder.http2Target(null, "other", 9443, true, fields))
        assertEquals(HttpRequestBuilder.Target("u.example", 80, false), HttpRequestBuilder.http2Target("http://u.example/", null, null, null, fields))
        assertEquals(HttpRequestBuilder.Target("u.example", 443, true), HttpRequestBuilder.http2Target("https://u.example/", null, null, null, emptyList()))
        assertFailsWith<IllegalArgumentException> { HttpRequestBuilder.http2Target(null, null, null, null, listOf(":path" to "/")) }
    }
}
