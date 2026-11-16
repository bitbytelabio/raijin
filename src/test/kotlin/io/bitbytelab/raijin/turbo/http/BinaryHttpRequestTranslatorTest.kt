package io.bitbytelab.raijin.turbo.http

import io.bitbytelab.raijin.turbo.DesyncTechniques
import io.bitbytelab.raijin.turbo.hp3.translate.KettleSyntaxException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class BinaryHttpRequestTranslatorTest {

    private fun fields(raw: String, kettled: Boolean): List<Pair<String, String>> =
        BinaryHttpRequestTranslator.translate(raw, "https", "default.example", kettled).fields.map { it.name() to it.value() }

    @Test
    fun `a header with no space after the colon keeps its value`() {
        assertEquals(
            listOf(":method" to "GET", ":scheme" to "https", ":authority" to "example.com", ":path" to "/", "x-test" to "value"),
            fields("GET / HTTP/1.1\r\nHost:example.com\r\nX-Test:value\r\n\r\n", kettled = false),
        )
    }

    @Test
    fun `an ordinary request trims optional whitespace and drops connection-specific fields`() {
        val request = BinaryHttpRequestTranslator.translate(
            "POST /p HTTP/1.1\nHost: example.com\nX-A: \t spaced \t\nConnection: keep-alive\nTransfer-Encoding: chunked\n\nbody",
            "https", "default.example", kettled = false,
        )
        assertEquals(
            listOf(":method" to "POST", ":scheme" to "https", ":authority" to "example.com", ":path" to "/p", "x-a" to "spaced"),
            request.fields.map { it.name() to it.value() },
        )
        assertContentEquals("body".toByteArray(), request.body)
    }

    @Test
    fun `an ordinary request takes no kettle escapes`() {
        assertEquals(
            listOf(":method" to "GET", ":scheme" to "https", ":authority" to "default.example", ":path" to "/a^sb", "x`y" to "1^~2"),
            fields("GET /a^sb HTTP/1.1\r\nX`Y: 1^~2\r\n\r\n", kettled = false),
        )
    }

    @Test
    fun `a kettled request line decodes escapes in the method and the path`() {
        assertEquals(
            listOf(":method" to "GET X", ":scheme" to "https", ":authority" to "example.com", ":path" to "/a b?c=1"),
            fields("GET^sX /a^sb^x3fc=1 HTTP/1.1\r\nHost: example.com\r\n\r\n", kettled = true),
        )
        assertFailsWith<KettleSyntaxException> { fields("GET /a^q HTTP/1.1\r\nHost: example.com\r\n\r\n", kettled = true) }
    }

    @Test
    fun `kettled fields keep case and deliberate whitespace, and a backtick names a colon`() {
        assertEquals(
            listOf(
                ":method" to "GET", ":scheme" to "https", ":authority" to "example.com", ":path" to "/",
                "X-Padded" to " padded", "X-Tight" to "tight", "X:Y" to "a`b", "X-Crlf" to "one\r\ntransfer-encoding: chunked",
            ),
            fields(
                "GET / HTTP/1.1\r\nHost: example.com\r\nX-Padded:  padded\r\nX-Tight:tight\r\nX`Y: a`b\r\nX-Crlf: one^~transfer-encoding:^schunked\r\n\r\n",
                kettled = true,
            ),
        )
    }

    @Test
    fun `kettled pseudo-headers replace the ones the request line implies`() {
        assertEquals(
            listOf(":method" to "POST", ":path" to "/actual", ":scheme" to "https", ":authority" to "example.com"),
            fields("GET /ignored HTTP/1.1\r\nHost: example.com\r\n:method: POST\r\n:path: /actual\r\n\r\n", kettled = true),
        )
    }

    @Test
    fun `kettled h2colon and h2name put a colon in the field name, not a backtick`() {
        val te = "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"

        val h2colon = fields(DesyncTechniques.apply(te, "Transfer-Encoding", "h2colon")!!, kettled = true)
        assertTrue("Transfer-Encoding:chunked " to "chunked" in h2colon, h2colon.toString())

        val h2name = fields(DesyncTechniques.apply(te, "Transfer-Encoding", "h2name")!!, kettled = true)
        assertTrue("Transfer-Encoding:chunked\r\nxz" to "x" in h2name, h2name.toString())
        assertTrue(h2name.none { (name, _) -> '`' in name })
    }
}
