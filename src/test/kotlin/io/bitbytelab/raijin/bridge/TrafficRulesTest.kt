package io.bitbytelab.raijin.bridge

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** Raw header-block edits behind traffic rules whose header lines are not plain `Name: value`. */
class TrafficRulesTest {

    private fun bytes(text: String) = text.toByteArray(Charsets.ISO_8859_1)
    private fun text(bytes: ByteArray) = String(bytes, Charsets.ISO_8859_1)

    @Test
    fun `only a canonical Name colon space value line goes through Montoya's header API`() {
        assertEquals("X-Probe" to "1", RawHeaderEdit.canonical("X-Probe: 1"))
        assertEquals("X-Empty" to "", RawHeaderEdit.canonical("X-Empty: "))
        assertNull(RawHeaderEdit.canonical("no colon"))
        assertNull(RawHeaderEdit.canonical("X-Tight:1"))
        assertNull(RawHeaderEdit.canonical("Transfer-Encoding : chunked"))
        assertNull(RawHeaderEdit.canonical(" X-Lead: 1"))
        assertNull(RawHeaderEdit.canonical("X-A: a\r\nInjected: 1"))
    }

    @Test
    fun `a raw line is added as written at the end of the header block, body untouched`() {
        val request = "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\nab\r\n"
        assertEquals(
            "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\nTransfer-Encoding : chunked\r\n\r\nab\r\n",
            text(RawHeaderEdit.addLine(bytes(request), "Transfer-Encoding : chunked")),
        )
        assertEquals(
            "GET / HTTP/1.1\r\nHost: h\r\nX-A: 1\r\nInjected: yes\r\n\r\n",
            text(RawHeaderEdit.addLine(bytes("GET / HTTP/1.1\r\nHost: h\r\n\r\n"), "X-A: 1\r\nInjected: yes")),
        )
        // A message without a blank line, or without any line break, still gets a well-placed line.
        assertEquals("GET / HTTP/1.1\r\nno colon\r\n", text(RawHeaderEdit.addLine(bytes("GET / HTTP/1.1"), "no colon")))
        assertEquals("GET / HTTP/1.1\r\nHost: h\r\nX: 1\r\n", text(RawHeaderEdit.addLine(bytes("GET / HTTP/1.1\r\nHost: h\r\n"), "X: 1")))
    }

    @Test
    fun `replace removes every same-named header line but never the request line`() {
        val request = "GET /Host: HTTP/1.1\r\nhost: a\r\nX-A: 1\r\nHOST : b\r\n\r\nHost: body"
        assertEquals(
            "GET /Host: HTTP/1.1\r\nX-A: 1\r\nHost: c\r\nd: e\r\n\r\nHost: body",
            text(RawHeaderEdit.replace(bytes(request), "Host", "c\r\nd: e")),
        )
    }

    @Test
    fun `a character above U+00FF in a raw line is written as UTF-8 and the rest keeps its bytes`() {
        val request = byteArrayOf(*bytes("GET / HTTP/1.1\r\nX-Bin: "), 0xFF.toByte(), *bytes("\r\n\r\n"))
        val edited = RawHeaderEdit.addLine(request, "X-Name: 日本 x")
        val expected = byteArrayOf(*bytes("GET / HTTP/1.1\r\nX-Bin: "), 0xFF.toByte(), *bytes("\r\n"), *"X-Name: 日本 x".toByteArray(Charsets.UTF_8), *bytes("\r\n\r\n"))
        assertEquals(expected.toList(), edited.toList())
    }
}
