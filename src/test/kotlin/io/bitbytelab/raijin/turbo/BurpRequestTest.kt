package io.bitbytelab.raijin.turbo

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import java.net.URI

class BurpRequestTest {

    @Test
    fun `Request does not hold reference to RequestEngine`() {
        val req = Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req.targetUrl = URI("https://example.com:443").toURL()

        // targetUrl should be set, _engine should not exist as a field
        assertEquals("example.com", req.targetUrl!!.host)
        assertEquals(443, req.targetUrl!!.port)
    }

    @Test
    fun `getEffectivePort returns 443 for https URL without explicit port`() {
        val url = URI("https://example.com").toURL()
        assertEquals(-1, url.port) // Verify the raw port is -1
        assertEquals(443, getEffectivePort(url))
    }

    @Test
    fun `getEffectivePort returns 80 for http URL without explicit port`() {
        val url = URI("http://example.com").toURL()
        assertEquals(-1, url.port)
        assertEquals(80, getEffectivePort(url))
    }

    @Test
    fun `getEffectivePort returns explicit port when specified`() {
        val url = URI("https://example.com:8443").toURL()
        assertEquals(8443, url.port)
        assertEquals(8443, getEffectivePort(url))
    }

    @Test
    fun `getEffectivePort returns explicit port 443 for https`() {
        val url = URI("https://example.com:443").toURL()
        assertEquals(443, url.port)
        assertEquals(443, getEffectivePort(url))
    }

    @Test
    fun `getEffectivePort returns explicit port 80 for http`() {
        val url = URI("http://example.com:80").toURL()
        assertEquals(80, url.port)
        assertEquals(80, getEffectivePort(url))
    }

    @Test
    fun `getEffectivePort handles custom ports`() {
        val url = URI("http://localhost:31338").toURL()
        assertEquals(31338, url.port)
        assertEquals(31338, getEffectivePort(url))
    }

    @Test
    fun `materializeAttributes caches code length and wordcount`() {
        val req = Request("GET / HTTP/1.1")
        req.response = "HTTP/1.1 200 OK\r\n\r\nHello World"

        req.materializeAttributes()

        // Null out response to prove values are cached
        req.response = null
        assertEquals(200, req.code)
        assertEquals("HTTP/1.1 200 OK\r\n\r\nHello World".length, req.length)
        assertTrue(req.wordcount > 0)
    }

    @Test
    fun `stripResponseBody nulls response and heavy fields but preserves metadata`() {
        val req = Request("GET / HTTP/1.1", listOf("test"), 0, "my-label")
        req.response = "HTTP/1.1 200 OK\r\n\r\nHello World"
        req.engine = Object()
        req.callback = { _, _ -> false }
        req.gate = null // already null, but explicit
        req.id = 42
        req.ttfb = 100L
        req.ttlb = 200L
        req.anomalyRank = 5

        req.stripResponseBody()

        // Heavy fields nulled
        assertNull(req.response)
        assertNull(req.montoyaReq)
        assertNull(req.engine)
        assertNull(req.callback)
        assertNull(req.gate)

        // Metadata preserved
        assertEquals(200, req.code)
        assertEquals("HTTP/1.1 200 OK\r\n\r\nHello World".length, req.length)
        assertTrue(req.wordcount > 0)
        assertEquals("my-label", req.label)
        assertEquals(42, req.id)
        assertEquals(100L, req.ttfb)
        assertEquals(200L, req.ttlb)
        assertEquals(5, req.anomalyRank)
        assertEquals("GET / HTTP/1.1", req.template)
        assertEquals(listOf("test"), req.words)
    }

    @Test
    fun `stripResponseBody handles null response gracefully`() {
        val req = Request("GET / HTTP/1.1")
        req.response = null

        req.stripResponseBody()

        assertEquals(0, req.code)
        assertEquals(0, req.length)
    }

    @Test
    fun `connectionId field defaults to null`() {
        val req = Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        assertNull(req.connectionId)
    }

    @Test
    fun `connectionId field can be set`() {
        val req = Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req.connectionId = "my-connection"
        assertEquals("my-connection", req.connectionId)
    }
}
