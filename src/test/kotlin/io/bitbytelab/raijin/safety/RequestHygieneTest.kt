package io.bitbytelab.raijin.safety

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Issue #7: a raw CR/LF in an LLM-supplied method/url/header reaches the HTTP/2 :path (or splits a
 * header), so Burp "kettles" the request and the server rejects it (RST_STREAM). [stripControl] is
 * the fix (remove it before sending); [scan] reports what was cleaned. Neither touches raw_request /
 * raw bytes, so intentional CRLF (smuggling research) still works.
 */
class RequestHygieneTest {

    // --- scan(): advisory detection ---

    @Test fun `clean inputs produce no warnings`() {
        assertEquals(emptyList(), RequestHygiene.scan("GET", "https://example.com/api?q=1", mapOf("Accept" to "*/*")))
    }

    @Test fun `null inputs produce no warnings`() {
        assertEquals(emptyList(), RequestHygiene.scan(null, null, null))
    }

    @Test fun `a newline in a header value is flagged and names the header`() {
        val w = RequestHygiene.scan("GET", "https://example.com/", mapOf("X-From-LLM" to "value\nstray"))
        assertEquals(1, w.size)
        assertTrue(w[0].contains("X-From-LLM"), "should name the offending header: ${w[0]}")
    }

    @Test fun `a carriage return in a header value is flagged`() {
        assertEquals(1, RequestHygiene.scan("GET", "https://example.com/", mapOf("X" to "a\r\nInjected: 1")).size)
    }

    @Test fun `a newline in the url is flagged`() {
        assertEquals(1, RequestHygiene.scan("GET", "https://example.com/real/path\n", null).size)
    }

    @Test fun `a newline in the method is flagged`() {
        assertEquals(1, RequestHygiene.scan("GET\r\n", "https://example.com/", null).size)
    }

    @Test fun `a control char in a header name is flagged`() {
        assertTrue(RequestHygiene.scan("GET", "https://example.com/", mapOf("Bad\nName" to "v")).isNotEmpty())
    }

    @Test fun `a tab is not treated as a line break`() {
        assertEquals(emptyList(), RequestHygiene.scan("GET", "https://example.com/", mapOf("X" to "a\tb")))
    }

    // --- stripCrlf(): the actual fix ---

    @Test fun `stripCrlf removes a trailing newline from a url`() {
        assertEquals("https://example.com/api/search", RequestHygiene.stripCrlf("https://example.com/api/search\n"))
    }

    @Test fun `stripCrlf removes embedded CR and LF`() {
        assertEquals("/a/b", RequestHygiene.stripCrlf("/a\r\n/b"))
        assertEquals("GET", RequestHygiene.stripCrlf("GET\r\n"))
    }

    @Test fun `stripCrlf keeps tabs, spaces and normal characters`() {
        assertEquals("a\tb c", RequestHygiene.stripCrlf("a\tb c"))
        assertEquals("/path?q=1&r=2", RequestHygiene.stripCrlf("/path?q=1&r=2"))
    }

    @Test fun `stripCrlf sends every other control char as given`() {
        assertEquals("x\u000By", RequestHygiene.stripCrlf("x\u000By"))  // vertical tab
        assertEquals("c\u0000d", RequestHygiene.stripCrlf("c\u0000d"))  // NUL
        assertEquals("ab", RequestHygiene.stripCrlf("a\r\nb"))
    }

    @Test fun `stripCrlf is a no-op on clean input`() {
        val clean = "https://example.com/normal/path"
        assertEquals(clean, RequestHygiene.stripCrlf(clean))
    }

    // --- normalizeCrlf(): the request-line "kettled :path" fix ---

    @Test fun `normalizeCrlf converts a bare-LF request to CRLF so the request line delimits`() {
        // Regression for the live "kettled" report: a bare-LF WebSocket-upgrade request
        // added to Repeater folded the whole message into the HTTP/2 :path pseudo-header.
        val bareLf = "GET /chat HTTP/1.1\nHost: x.com\nUpgrade: websocket\n\n"
        val fixed = RequestHygiene.normalizeCrlf(bareLf)
        assertTrue(fixed.startsWith("GET /chat HTTP/1.1\r\n"), "request line must be CRLF-delimited: $fixed")
        assertFalse(fixed.contains(Regex("(?<!\r)\n")), "no bare LF may remain: $fixed")
    }

    @Test fun `normalizeCrlf leaves an already-CRLF request byte-identical`() {
        val crlf = "POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc"
        assertEquals(crlf, RequestHygiene.normalizeCrlf(crlf))
    }

    @Test fun `normalizeCrlf canonicalizes escaped JSON-transport line endings`() {
        assertEquals("A\r\nB\r\nC", RequestHygiene.normalizeCrlf("A\\r\\nB\\nC"))
    }

    @Test fun `normalizeCrlf rewrites only the header block and keeps body bytes and Content-Length`() {
        val body = "line1\nline2 {\"msg\":\"a\\nb\"}"
        val raw = "POST /api HTTP/1.1\nHost: x.com\nContent-Length: ${body.length}\n\n$body"
        val normalized = RequestHygiene.normalizeCrlf(raw)
        assertEquals("POST /api HTTP/1.1\r\nHost: x.com\r\nContent-Length: ${body.length}\r\n\r\n$body", normalized)
        assertNull(RequestHygiene.fixContentLength(normalized).rewrittenFrom, "the declared length still matches the untouched body")
    }

    @Test fun `normalizeCrlf keeps a smuggled request in the body exactly as typed`() {
        val smuggled = "0\r\n\r\nGET /admin HTTP/1.1\nX: y"
        val raw = "POST / HTTP/1.1\nHost: x.com\nTransfer-Encoding: chunked\n\n$smuggled"
        assertTrue(RequestHygiene.normalizeCrlf(raw).endsWith("\r\n\r\n$smuggled"))
    }

    @Test fun `normalizeCrlf unescapes a fully escaped single-line request but not its body`() {
        val raw = "POST /api HTTP/1.1\\r\\nHost: x.com\\r\\n\\r\\n{\"msg\":\"a\\nb\"}"
        assertEquals("POST /api HTTP/1.1\r\nHost: x.com\r\n\r\n{\"msg\":\"a\\nb\"}", RequestHygiene.normalizeCrlf(raw))
    }

    // --- fixContentLength() ---

    @Test fun `fixContentLength rewrites only the digits of a wrong Content-Length`() {
        val fix = RequestHygiene.fixContentLength("POST / HTTP/1.1\r\ncontent-length:  1\r\n\r\nabc")
        assertEquals("POST / HTTP/1.1\r\ncontent-length:  3\r\n\r\nabc", fix.request)
        assertEquals(1, fix.rewrittenFrom)
        assertEquals(3, fix.rewrittenTo)
    }

    @Test fun `fixContentLength never reads a value from the next header line`() {
        // An empty Content-Length followed by a digits-only line: the value must not be taken from it.
        val raw = "POST / HTTP/1.1\r\nContent-Length:\r\n12\r\n\r\nabc"
        assertEquals(raw, RequestHygiene.fixContentLength(raw).request)
    }

    @Test fun `fixContentLength counts bytes in the requested charset`() {
        val raw = "POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\né"
        assertEquals(1, RequestHygiene.fixContentLength(raw).rewrittenTo)
        assertEquals(2, RequestHygiene.fixContentLength(raw, utf8Body = true).rewrittenTo)
    }

    // --- wire encoding helpers ---

    @Test fun `wireCharset keeps Latin-1 text single-byte and switches to UTF-8 for wider chars`() {
        assertEquals(Charsets.ISO_8859_1, RequestHygiene.wireCharset("GET /café HTTP/1.1"))
        assertEquals(Charsets.UTF_8, RequestHygiene.wireCharset("GET /日本 HTTP/1.1"))
        assertEquals(Charsets.UTF_8, RequestHygiene.wireCharset("q=\uD83D\uDCA5"))
    }

    @Test fun `unescapeLineEndings decodes a single-line message throughout`() {
        assertEquals(
            "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\n",
            RequestHygiene.unescapeLineEndings("POST / HTTP/1.1\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nGET /admin HTTP/1.1\\n")
        )
    }

    @Test fun `unescapeLineEndings leaves text with real line breaks untouched`() {
        val raw = "POST / HTTP/1.1\r\nHost: x\r\n\r\n{\"a\":\"b\\nc\"}"
        assertEquals(raw, RequestHygiene.unescapeLineEndings(raw))
    }

    @Test fun `decodeHex decodes pairs and ignores whitespace`() {
        assertContentEquals("GET /".toByteArray(), RequestHygiene.decodeHex("47 45 54\n20 2F"))
        assertContentEquals(byteArrayOf(0x00, 0xFF.toByte(), 0x0d, 0x0a), RequestHygiene.decodeHex("00ff0D0A"))
    }

    @Test fun `decodeHex rejects an odd digit count and non-hex characters`() {
        assertTrue(assertFailsWith<IllegalArgumentException> { RequestHygiene.decodeHex("474") }.message!!.contains("odd"))
        assertTrue(assertFailsWith<IllegalArgumentException> { RequestHygiene.decodeHex("47zz") }.message!!.contains("byte 1"))
        // Unicode digits are not hex digits.
        assertFailsWith<IllegalArgumentException> { RequestHygiene.decodeHex("4\u0663") }
    }

    // --- adjustedOffset(): keeps Intruder positions aligned after LF→CRLF expansion ---

    @Test fun `adjustedOffset is identity on an already-CRLF request`() {
        val crlf = "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        assertEquals(10, RequestHygiene.adjustedOffset(crlf, 10))
    }

    @Test fun `adjustedOffset shifts by the count of bare LFs before the offset`() {
        val bareLf = "AB\nCD\nEF" // one LF before index 4, two before index 6
        assertEquals(0, RequestHygiene.adjustedOffset(bareLf, 0))
        assertEquals(5, RequestHygiene.adjustedOffset(bareLf, 4))
        assertEquals(8, RequestHygiene.adjustedOffset(bareLf, 6))
    }

    @Test fun `adjustedOffset clamps out-of-range offsets`() {
        val s = "abc\ndef"
        assertEquals(RequestHygiene.normalizeCrlf(s).length, RequestHygiene.adjustedOffset(s, 999))
        assertEquals(0, RequestHygiene.adjustedOffset(s, -5))
    }
}
