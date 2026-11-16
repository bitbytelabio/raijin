package io.bitbytelab.raijin.bridge

import java.io.ByteArrayOutputStream
import java.util.zip.Deflater
import java.util.zip.DeflaterOutputStream
import java.util.zip.GZIPOutputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class HttpContentDecodingTest {

    private val text = "hello, decoded world ".repeat(20)

    private fun gzip(data: ByteArray): ByteArray =
        ByteArrayOutputStream().also { out -> GZIPOutputStream(out).use { it.write(data) } }.toByteArray()

    private fun zlib(data: ByteArray): ByteArray =
        ByteArrayOutputStream().also { out -> DeflaterOutputStream(out).use { it.write(data) } }.toByteArray()

    private fun rawDeflate(data: ByteArray): ByteArray =
        ByteArrayOutputStream().also { out -> DeflaterOutputStream(out, Deflater(Deflater.DEFAULT_COMPRESSION, true)).use { it.write(data) } }
            .toByteArray()

    @Test
    fun `gzip and x-gzip are undone`() {
        for (coding in listOf("gzip", "x-gzip", " GZIP ")) {
            val decoded = HttpContentDecoding.decode(gzip(text.toByteArray()), coding)
            assertEquals(text, String(decoded.body), coding)
            assertEquals(listOf(coding.trim().lowercase()), decoded.applied)
            assertNull(decoded.error)
        }
    }

    @Test
    fun `deflate is read as zlib and as a raw deflate stream`() {
        for (body in listOf(zlib(text.toByteArray()), rawDeflate(text.toByteArray()))) {
            val decoded = HttpContentDecoding.decode(body, "deflate")
            assertEquals(text, String(decoded.body))
            assertEquals(listOf("deflate"), decoded.applied)
            assertNull(decoded.error)
        }
    }

    @Test
    fun `stacked codings are undone last to first and identity is skipped`() {
        val body = zlib(gzip(text.toByteArray())) // gzip applied first, then deflate
        val decoded = HttpContentDecoding.decode(body, "gzip, identity, deflate")
        assertEquals(text, String(decoded.body))
        assertEquals(listOf("deflate", "gzip"), decoded.applied)
    }

    @Test
    fun `a broken stream keeps what decoded before the break`() {
        val whole = gzip(text.toByteArray())
        val decoded = HttpContentDecoding.decode(whole.copyOf(whole.size - 12), "gzip")
        assertTrue(decoded.error!!.startsWith("gzip stream is broken"), decoded.error)
        assertEquals(listOf("gzip"), decoded.applied)
        assertTrue(decoded.body.isNotEmpty() && text.startsWith(String(decoded.body)), String(decoded.body))

        val garbage = "not compressed".toByteArray()
        val failed = HttpContentDecoding.decode(garbage, "gzip")
        assertContentEquals(garbage, failed.body)
        assertTrue(failed.applied.isEmpty())
        assertTrue(failed.error!!.startsWith("gzip decoding failed"), failed.error)
    }

    @Test
    fun `br goes through the injected decoder and fails cleanly without one`() {
        val body = "brotli bytes".toByteArray()
        val missing = HttpContentDecoding.decode(body, "br")
        assertContentEquals(body, missing.body)
        assertTrue(missing.applied.isEmpty())
        assertEquals("br decoding is not available here", missing.error)

        val decoded = HttpContentDecoding.decode(body, "br", brotli = { "decoded".toByteArray() })
        assertEquals("decoded", String(decoded.body))
        assertEquals(listOf("br"), decoded.applied)

        val throwing = HttpContentDecoding.decode(body, "br", brotli = { error("no brotli here") })
        assertContentEquals(body, throwing.body)
        assertEquals("br decoding failed: no brotli here", throwing.error)
    }

    @Test
    fun `an unknown coding is reported and the body is left as it is`() {
        val body = gzip(text.toByteArray())
        val decoded = HttpContentDecoding.decode(body, "compress, gzip")
        assertEquals(text, String(decoded.body), "gzip, listed last, is undone before compress stops decoding")
        assertEquals(listOf("gzip"), decoded.applied)
        assertEquals("unknown content coding 'compress'", decoded.error)
    }

    @Test
    fun `decoding stops at the size cap`() {
        val decoded = HttpContentDecoding.decode(gzip(text.toByteArray()), "gzip", maxBytes = 10)
        assertEquals(text.take(10), String(decoded.body))
        assertEquals(listOf("gzip"), decoded.applied)
        assertTrue(decoded.error!!.contains("exceeds 10 bytes"), decoded.error)

        val brotli = HttpContentDecoding.decode("x".toByteArray(), "br", brotli = { ByteArray(50) }, maxBytes = 20)
        assertEquals(20, brotli.body.size)
        assertTrue(brotli.error!!.contains("exceeds 20 bytes"), brotli.error)
    }

    @Test
    fun `no coding or an empty body is returned as it is`() {
        val body = "plain".toByteArray()
        assertTrue(HttpContentDecoding.decode(body, null).body === body)
        assertTrue(HttpContentDecoding.decode(body, "identity").applied.isEmpty())
        val empty = HttpContentDecoding.decode(ByteArray(0), "gzip")
        assertTrue(empty.body.isEmpty() && empty.error == null)
    }

    @Test
    fun `text is UTF-8 when valid, else one char per byte`() {
        assertEquals("caf\u00e9 \u20ac", HttpContentDecoding.text("caf\u00e9 \u20ac".toByteArray(Charsets.UTF_8)))
        val latin = byteArrayOf(0x63, 0xE9.toByte(), 0xFF.toByte())
        assertEquals("c\u00e9\u00ff", HttpContentDecoding.text(latin))
    }

    @Test
    fun `hex is lowercase for bytes and for ISO-8859-1 wire text, with a limit`() {
        assertEquals("00ff10ab", HttpContentDecoding.hex(byteArrayOf(0, -1, 0x10, 0xAB.toByte())))
        assertEquals("4100ff", HttpContentDecoding.hex("A\u0000\u00ff"))
        assertEquals("4142", HttpContentDecoding.hex("ABC", limit = 2))
    }
}
