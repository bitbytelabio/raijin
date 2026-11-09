package io.bitbytelab.raijin.turbo

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DesyncTechniquesTest {

    private val teRequest = "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    private fun clRequest(len: Int = 5) = "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: $len\r\n\r\nhello"
    private fun text(bytes: ByteArray) = String(bytes, Charsets.ISO_8859_1)

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
        assertTrue("CL-dualCL" in all)
        assertTrue("prefix1:0" in all)
        assertTrue("suffix1:127" in all)
    }
}
