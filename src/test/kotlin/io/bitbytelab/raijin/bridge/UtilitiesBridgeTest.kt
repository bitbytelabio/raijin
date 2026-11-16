package io.bitbytelab.raijin.bridge

import burp.api.montoya.utilities.CompressionType
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Unit tests for the pure, API-free decompression-input validation helpers on
 * [UtilitiesBridge]. These cover the fix for util_decompress silently echoing or
 * truncating malformed / wrong-format input instead of rejecting it.
 */
class UtilitiesBridgeTest {

    // --- validateCompressedInput: empty input guard ---------------------------

    @Test
    fun `validateCompressedInput rejects empty input for GZIP`() {
        val ex = assertFailsWith<IllegalArgumentException> {
            UtilitiesBridge.validateCompressedInput(ByteArray(0), CompressionType.GZIP)
        }
        assertTrue(ex.message!!.contains("empty input"))
    }

    @Test
    fun `validateCompressedInput rejects empty input for DEFLATE`() {
        assertFailsWith<IllegalArgumentException> {
            UtilitiesBridge.validateCompressedInput(ByteArray(0), CompressionType.DEFLATE)
        }
    }

    @Test
    fun `validateCompressedInput rejects empty input for BROTLI`() {
        assertFailsWith<IllegalArgumentException> {
            UtilitiesBridge.validateCompressedInput(ByteArray(0), CompressionType.BROTLI)
        }
    }

    // --- validateCompressedInput: GZIP magic-byte guard -----------------------

    @Test
    fun `validateCompressedInput rejects non-GZIP bytes when GZIP is declared`() {
        // Plain ASCII "hello" is not a GZIP stream.
        val notGzip = "hello".toByteArray()
        val ex = assertFailsWith<IllegalArgumentException> {
            UtilitiesBridge.validateCompressedInput(notGzip, CompressionType.GZIP)
        }
        assertTrue(ex.message!!.contains("GZIP magic bytes"))
    }

    @Test
    fun `validateCompressedInput rejects single-byte input when GZIP is declared`() {
        val oneByte = byteArrayOf(0x1f)
        assertFailsWith<IllegalArgumentException> {
            UtilitiesBridge.validateCompressedInput(oneByte, CompressionType.GZIP)
        }
    }

    @Test
    fun `validateCompressedInput accepts input starting with GZIP magic bytes`() {
        // 0x1f 0x8b is the GZIP magic (RFC 1952); remaining bytes are a plausible header.
        val gzipHeader = byteArrayOf(0x1f.toByte(), 0x8b.toByte(), 0x08, 0x00, 0x00, 0x00)
        // Should not throw.
        UtilitiesBridge.validateCompressedInput(gzipHeader, CompressionType.GZIP)
    }

    @Test
    fun `validateCompressedInput does not magic-check DEFLATE input`() {
        // DEFLATE has no reliable fixed magic; any non-empty input passes the pre-check.
        val arbitrary = "not-really-deflate".toByteArray()
        UtilitiesBridge.validateCompressedInput(arbitrary, CompressionType.DEFLATE)
    }

    @Test
    fun `validateCompressedInput does not magic-check BROTLI input`() {
        val arbitrary = byteArrayOf(0x00, 0x01, 0x02, 0x03)
        UtilitiesBridge.validateCompressedInput(arbitrary, CompressionType.BROTLI)
    }

    // --- isEchoedDecompression: silent-echo failure detection -----------------

    @Test
    fun `isEchoedDecompression flags byte-identical passthrough as failure`() {
        val input = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        val echoed = input.copyOf()
        assertTrue(UtilitiesBridge.isEchoedDecompression(input, echoed))
    }

    @Test
    fun `isEchoedDecompression returns false for genuinely different output`() {
        val input = byteArrayOf(0x1f.toByte(), 0x8b.toByte(), 0x08, 0x00)
        val output = "decompressed payload".toByteArray()
        assertFalse(UtilitiesBridge.isEchoedDecompression(input, output))
    }

    @Test
    fun `isEchoedDecompression returns false when only length differs`() {
        val input = byteArrayOf(0x01, 0x02, 0x03)
        val truncated = byteArrayOf(0x01, 0x02)
        assertFalse(UtilitiesBridge.isEchoedDecompression(input, truncated))
    }

    @Test
    fun `isEchoedDecompression treats two empty arrays as echoed`() {
        // Defensive: empty in / empty out is a degenerate no-op, still an echo.
        assertEquals(true, UtilitiesBridge.isEchoedDecompression(ByteArray(0), ByteArray(0)))
    }

    // --- decodeSmartPure: fully_decoded flag ----------------------------------

    private fun b64(s: String) = Base64.getEncoder().encodeToString(s.toByteArray(Charsets.UTF_8))

    @Test
    fun `decodeSmart reports fully_decoded true once every layer is decoded`() {
        val plain = "{\"q\":\"a b\"}"
        val r = UtilitiesBridge.decodeSmartPure(b64(b64(plain)), maxDepth = 10)
        assertEquals(plain, r["decoded"]?.jsonPrimitive?.content)
        assertEquals(2, r["layers"]?.jsonPrimitive?.int)
        assertEquals(true, r["fully_decoded"]?.jsonPrimitive?.boolean)
        assertEquals(listOf("base64", "base64"),
            r["steps"]!!.jsonArray.map { it.jsonObject["encoding"]!!.jsonPrimitive.content })
    }

    @Test
    fun `decodeSmart reports fully_decoded true for input with nothing to decode`() {
        val r = UtilitiesBridge.decodeSmartPure("plain text!", maxDepth = 10)
        assertEquals(0, r["layers"]?.jsonPrimitive?.int)
        assertEquals(true, r["fully_decoded"]?.jsonPrimitive?.boolean)
    }

    @Test
    fun `decodeSmart reports fully_decoded false when max_depth stops it early`() {
        val r = UtilitiesBridge.decodeSmartPure(b64(b64("hello world")), maxDepth = 1)
        assertEquals(1, r["layers"]?.jsonPrimitive?.int)
        assertEquals(false, r["fully_decoded"]?.jsonPrimitive?.boolean)
    }

    @Test
    fun `decodeSmart handles url encoded quotes, backslashes and newlines`() {
        val r = UtilitiesBridge.decodeSmartPure("%22a%5Cb%0Ac%22", maxDepth = 10)
        assertEquals("\"a\\b\nc\"", r["decoded"]?.jsonPrimitive?.content)
        assertEquals(true, r["fully_decoded"]?.jsonPrimitive?.boolean)
    }
}
