package io.bitbytelab.raijin.turbo

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DesyncTechniquesTest {

    private val teRequest = "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    private fun clRequest(len: Int = 5) = "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: $len\r\n\r\nhello"
    private fun text(bytes: ByteArray) = String(bytes, Charsets.ISO_8859_1)
    private fun bytes(text: String) = text.toByteArray(Charsets.ISO_8859_1)

    private fun applyTe(technique: String) = DesyncTechniques.apply(bytes(teRequest), "Transfer-Encoding", technique)
    private fun applyCl(technique: String) = DesyncTechniques.apply(bytes(clRequest()), "Content-Length", technique)

    @Test
    fun `every shared, HTTP-1 and HTTP-2 technique mutates both target headers`() {
        val eitherHeader = DesyncTechniques.allTechniques() - "vanilla" -
            DesyncTechniques.TE_TECHNIQUES.toSet() - DesyncTechniques.CL_TECHNIQUES.toSet()
        assertTrue(eitherHeader.containsAll(listOf("quoted", "encode", "accentTE", "qencode", "http2hide", "h2colon", "bodysplit")))
        for (technique in eitherHeader) {
            val te = assertNotNull(applyTe(technique), technique)
            assertFalse(te.contentEquals(bytes(teRequest)), "$technique left the Transfer-Encoding request unchanged")
            val cl = assertNotNull(applyCl(technique), "$technique had no effect on Content-Length")
            assertFalse(cl.contentEquals(bytes(clRequest())), "$technique left the Content-Length request unchanged")
        }
    }

    @Test
    fun `Transfer-Encoding techniques mutate Transfer-Encoding and are a no-op for Content-Length`() {
        for (technique in DesyncTechniques.TE_TECHNIQUES) {
            val te = assertNotNull(applyTe(technique), technique)
            assertFalse(te.contentEquals(bytes(teRequest)), "$technique left the Transfer-Encoding request unchanged")
            assertNull(applyCl(technique), "$technique should not touch Content-Length")
        }
    }

    @Test
    fun `every Content-Length technique mutates a Content-Length request`() {
        for (technique in DesyncTechniques.CL_TECHNIQUES) {
            val cl = assertNotNull(applyCl(technique), technique)
            assertFalse(cl.contentEquals(bytes(clRequest())), "$technique left the Content-Length request unchanged")
        }
    }

    @Test
    fun `shared value and name obfuscations rewrite Content-Length the way they rewrite Transfer-Encoding`() {
        assertTrue(text(applyCl("quoted")!!).contains("Content-Length: \"5\"\r\n"))
        assertTrue(text(applyCl("aposed")!!).contains("Content-Length: '5'\r\n"))
        assertTrue(text(applyCl("encode")!!).contains("\r\nContent-%4Cength: 5\r\n"))
        assertTrue(text(applyCl("qencode")!!).contains("Content-Length: =?iso-8859-1?B?NQ==?=\r\n"))
        assertTrue(text(applyCl("qencodeutf")!!).contains("Content-Length: =?UTF-8?B?NQ==?=\r\n"))
        assertTrue(text(applyCl("h2colon")!!).contains("\r\nContent-Length`5 : 5\r\n"))
        assertTrue(text(applyCl("h2name")!!).contains("\r\nContent-Length`5^~xz: x\r\n"))
        assertTrue(text(applyCl("http2hide")!!).contains("\r\nFoo: b^~Content-Length: 5^~x: x\r\n"))
        assertTrue(text(applyCl("h2prefix")!!).contains("\r\n:content-length: 5\r\n"))
        assertTrue(text(applyCl("h2space")!!).contains("\r\nContent-Length 5 : 5\r\n"))
        assertContentEquals(
            bytes("POST / HTTP/1.1\r\nHost: example.com\r\nCont") + 0x82.toByte() + bytes("nt-Length: 5\r\n\r\nhello"),
            applyCl("accentTE"),
        )
    }

    @Test
    fun `generalised techniques still produce upstream's exact Transfer-Encoding bytes`() {
        assertTrue(text(applyTe("quoted")!!).contains("Transfer-Encoding: \"chunked\"\r\n"))
        assertTrue(text(applyTe("encode")!!).contains("\r\nTransfer-%45ncoding: chunked\r\n"))
        assertTrue(text(applyTe("qencode")!!).contains("Transfer-Encoding: =?iso-8859-1?B?Y2h1bmtlZA==?=\r\n"))
        assertTrue(text(applyTe("h2colon")!!).contains("\r\nTransfer-Encoding`chunked : chunked\r\n"))
        assertTrue(text(applyTe("h2name")!!).contains("\r\nTransfer-Encoding`chunked^~xz: x\r\n"))
        assertTrue(text(applyTe("h2prefix")!!).contains("\r\n:transfer-encoding: chunked\r\n"))
        assertTrue(text(applyTe("nested")!!).contains("Transfer-Encoding: identity, chunked, identity\r\n"))
        assertContentEquals(
            bytes("POST / HTTP/1.1\r\nHost: example.com\r\nTransf") + 0x82.toByte() + bytes("r-Encoding: chunked\r\n\r\n0\r\n\r\n"),
            applyTe("accentTE"),
        )
    }

    @Test
    fun `http2case lower-cases the header names so only the target keeps an upper-case letter`() {
        val withBody = "POST /Path HTTP/1.1\r\nHost: Example.com\r\nX-Token: AbC\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /Admin HTTP/1.1\r\n\r\n"
        val te = text(assertNotNull(DesyncTechniques.apply(bytes(withBody), "Transfer-Encoding", "http2case")))
        assertEquals(
            "POST /Path HTTP/1.1\r\nhost: Example.com\r\nx-token: AbC\r\nx-reject: 1\r\ntransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /Admin HTTP/1.1\r\n\r\n",
            te,
        )

        val cl = text(assertNotNull(applyCl("http2case")))
        assertEquals("POST / HTTP/1.1\r\nhost: example.com\r\nx-reject: 1\r\ncontent-Length: 5\r\n\r\nhello", cl)
    }

    @Test
    fun `http2case is a reported no-op when the target header is missing`() {
        val noCl = "POST / HTTP/1.1\r\nHost: example.com\r\n\r\nhello"
        assertNull(DesyncTechniques.apply(bytes(noCl), "Content-Length", "http2case"))
    }

    @Test
    fun `vanilla returns the request unmodified and is never treated as no-effect`() {
        val result = DesyncTechniques.apply(clRequest().toByteArray(Charsets.ISO_8859_1), "Content-Length", "vanilla")
        requireNotNull(result)
        assertEquals(clRequest(), text(result))
    }

    @Test
    fun `spacejoin1 replaces the hyphen in the header name with a space`() {
        val result = DesyncTechniques.apply(clRequest().toByteArray(Charsets.ISO_8859_1), "Content-Length", "spacejoin1")
        requireNotNull(result)
        assertTrue(text(result).contains("Content Length: 5"))
        assertTrue(!text(result).contains("Content-Length: 5"))
    }

    @Test
    fun `backslash replaces hyphens with a backslash (Amit Klein technique)`() {
        val result = DesyncTechniques.apply(teRequest.toByteArray(Charsets.ISO_8859_1), "Transfer-Encoding", "backslash")
        requireNotNull(result)
        assertTrue(text(result).contains("Transfer\\Encoding: "))
    }

    @Test
    fun `0dsuffix appends a bare CR after the header value`() {
        val result = DesyncTechniques.apply(clRequest().toByteArray(Charsets.ISO_8859_1), "Content-Length", "0dsuffix")
        requireNotNull(result)
        assertTrue(text(result).contains("Content-Length: 5\r\r\n"))
    }

    @Test
    fun `CL-dualCL duplicates the Content-Length header`() {
        val result = DesyncTechniques.apply(clRequest().toByteArray(Charsets.ISO_8859_1), "Content-Length", "CL-dualCL")
        requireNotNull(result)
        assertEquals(2, Regex("Content-Length: 5").findAll(text(result)).count())
    }

    @Test
    fun `CL-plus prefixes the Content-Length value with a plus sign`() {
        val result = DesyncTechniques.apply(clRequest().toByteArray(Charsets.ISO_8859_1), "Content-Length", "CL-plus")
        requireNotNull(result)
        assertTrue(text(result).contains("Content-Length: +5"))
    }

    @Test
    fun `an ineffective Content-Length technique returns null`() {
        // "range" only touches a Range header; it has no Content-Length-specific branch, and the
        // generic add-Range-header mutation still differs from the input — so pick a technique
        // that is genuinely a no-op for this request shape: CL-expect on a request already using it.
        val withExpect = "POST / HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\nhello"
        val result = DesyncTechniques.apply(withExpect.toByteArray(Charsets.ISO_8859_1), "Content-Length", "CL-expect")
        assertNull(result)
    }

    @Test
    fun `commaCow only applies to Transfer-Encoding, not Content-Length`() {
        val result = DesyncTechniques.apply(teRequest.toByteArray(Charsets.ISO_8859_1), "Transfer-Encoding", "commaCow")
        requireNotNull(result)
        assertTrue(text(result).contains("Transfer-Encoding: chunked, identity"))
    }

    @Test
    fun `badwrap reinserts the header's actual value, not a hardcoded one`() {
        // Transfer-Encoding's real value here is "gzip, chunked" (unusual), not the hardcoded
        // "chunked" the technique catalog uses internally for TE — badwrap must round-trip the
        // ACTUAL value it read off the request, exercising the headerValue-vs-value distinction.
        val unusual = "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n"
        val result = DesyncTechniques.apply(unusual.toByteArray(Charsets.ISO_8859_1), "Transfer-Encoding", "badwrap")
        requireNotNull(result)
        assertTrue(text(result).contains("Transfer-Encoding: gzip, chunked"))
        assertTrue(text(result).contains("X-Blah-Ignore: "))
    }

    @Test
    fun `h2CL adds a zero Content-Length header to an HTTP2-style request`() {
        val result = DesyncTechniques.apply(teRequest.toByteArray(Charsets.ISO_8859_1), "Transfer-Encoding", "h2CL")
        requireNotNull(result)
        assertTrue(text(result).contains("Content-Length: 0"))
    }

    @Test
    fun `allTechniques includes every family and the parameterized special-char variants`() {
        val all = DesyncTechniques.allTechniques()
        assertTrue("spacejoin1" in all)
        assertTrue("h2colon" in all)
        assertTrue("lazygrep" in all)
        assertTrue("CL-dualCL" in all)
        assertEquals(all.size, all.toSet().size, "a technique is registered in two families")
        assertTrue("prefix1:0" in all)
        assertTrue("suffix1:127" in all)
    }
}
