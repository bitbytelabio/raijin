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

    @Test
    fun `fixContentLength keeps bytes 0x80 to 0xFF intact`() {
        val body = "caf\u00e9 \u00ff"
        val req = Request("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\n$body")

        assertEquals("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: ${body.length}\r\n\r\n$body", req.getRequest())
    }

    @Test
    fun `fixContentLength finds the header after one written without a space`() {
        val req = Request("POST / HTTP/1.1\r\nX-A:b\r\nContent-Length: 99\r\n\r\nhello")

        assertEquals("POST / HTTP/1.1\r\nX-A:b\r\nContent-Length: 5\r\n\r\nhello", req.getRequest())
    }

    @Test
    fun `fixContentLength updates Content-Length written without a space`() {
        val req = Request("POST / HTTP/1.1\r\nHost: x\r\nContent-Length:99\r\n\r\nhello")

        assertEquals("POST / HTTP/1.1\r\nHost: x\r\nContent-Length:5\r\n\r\nhello", req.getRequest())
    }

    @Test
    fun `deliberately odd Content-Length headers go out as written`() {
        val leadingSpace = "POST / HTTP/1.1\r\nHost: x\r\n Content-Length: 99\r\n\r\nhello"
        val lowerCase = "POST / HTTP/1.1\r\nHost: x\r\ncontent-length: 99\r\n\r\nhello"

        assertEquals(leadingSpace, Request(leadingSpace).getRequest())
        assertEquals(lowerCase, Request(lowerCase).getRequest())
    }

    @Test
    fun `a request with no blank line after its headers goes out as written`() {
        val unfinished = "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n"

        assertEquals(unfinished, Request(unfinished).getRequest())
    }

    @Test
    fun `getHeaderOffsets finds the value with or without a space after the colon`() {
        val bytes = "GET / HTTP/1.1\r\nA:1\r\nB: 22\r\n\r\n".toByteArray(Charsets.ISO_8859_1)
        val req = Request("GET / HTTP/1.1")

        assertArrayEquals(intArrayOf(16, 18, 19), req.getHeaderOffsets(bytes, "A"))
        assertArrayEquals(intArrayOf(21, 24, 26), req.getHeaderOffsets(bytes, "B"))
        assertThrows(RuntimeException::class.java) { req.getHeaderOffsets(bytes, "C") }
    }

    @Test
    fun `wordcount counts as splitting on non-alphanumerics does`() {
        val samples = listOf("", "abc", "a b", "a  b", "\u00e9", "x\uD83D\uDE00y", "HTTP/1.1 200 OK\r\n\r\n<p>hi</p>")
        for (text in samples) {
            val req = Request("GET / HTTP/1.1").apply { response = text }
            assertEquals(text.split(Regex("[^a-zA-Z0-9]")).size, req.wordcount, text)
        }
    }

    @Test
    fun `the body starts at the end of a message whose headers never end`() {
        val unterminated = "GET / HTTP/1.1\r\nHost: x\r\n".toByteArray(Charsets.ISO_8859_1)

        assertEquals(-1, Utils.findBodyStart(unterminated))
        assertEquals(unterminated.size, Utils.getBodyStart(unterminated))
        assertEquals(5, Utils.getBodyStart("A\r\n\r\nbody".toByteArray(Charsets.ISO_8859_1)))
        assertEquals(3, Utils.getBodyStart("A\n\nbody".toByteArray(Charsets.ISO_8859_1)))
    }
}
