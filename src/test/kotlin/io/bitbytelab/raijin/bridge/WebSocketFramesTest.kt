package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.state.WebSocketMessage
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonPrimitive
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * How the WebSocket tools carry binary frames: base64 in and out, ISO-8859-1 text for regexes,
 * byte lengths, and clipped payloads that stay decodable and JSON-safe.
 */
class WebSocketFramesTest {

    /** Every byte value once. */
    private val allBytes = ByteArray(256) { it.toByte() }

    private fun message(type: String, payload: String, length: Int = payload.length) =
        WebSocketMessage(7, "server_to_client", type, payload, length, "2026-11-17T00:00:00Z")

    @Test
    fun `base64 is accepted in the forms callers send it`() {
        val standard = Base64.getEncoder().encodeToString(allBytes)
        val urlSafeUnpadded = Base64.getUrlEncoder().withoutPadding().encodeToString(allBytes)
        val wrapped = Base64.getMimeEncoder().encodeToString(allBytes)
        assertTrue(wrapped.contains("\r\n"), "the MIME encoder wraps lines")

        for (form in listOf(standard, urlSafeUnpadded, wrapped, " $standard\n")) {
            assertContentEquals(allBytes, WebSocketFrames.decodeBase64(form), form)
        }
        assertContentEquals(ByteArray(0), WebSocketFrames.decodeBase64(""))
        assertContentEquals(byteArrayOf(0x41), WebSocketFrames.decodeBase64("QQ"))
    }

    @Test
    fun `text that is not base64 is refused rather than half decoded`() {
        assertNull(WebSocketFrames.decodeBase64("not base64!"))
        assertNull(WebSocketFrames.decodeBase64("Q"))
        assertNull(WebSocketFrames.decodeBase64("QQ=Q"))
    }

    @Test
    fun `the recorded form of bytes is the canonical base64, whatever form came in`() {
        val urlSafe = Base64.getUrlEncoder().withoutPadding().encodeToString(allBytes)
        val decoded = assertNotNull(WebSocketFrames.decodeBase64(urlSafe))
        assertEquals(Base64.getEncoder().encodeToString(allBytes), WebSocketFrames.encodeBase64(decoded))
    }

    @Test
    fun `ISO-8859-1 text maps every byte to one char and back`() {
        val text = WebSocketFrames.latin1(allBytes)
        assertEquals(256, text.length)
        assertEquals('\u00FF', text[255])
        assertContentEquals(allBytes, WebSocketFrames.latin1Bytes(text))
        // A char with no byte becomes '?'.
        assertContentEquals("a?".toByteArray(), WebSocketFrames.latin1Bytes("a\u20AC"))
    }

    @Test
    fun `a regex sees a binary frame as its bytes and a text frame as its text`() {
        val binary = message("BINARY", Base64.getEncoder().encodeToString(byteArrayOf(0x00, 0x41, 0xFF.toByte())), 3)
        assertEquals("\u0000A\u00FF", WebSocketFrames.matchText(binary))
        assertEquals("\u0000A\u00FF", WebSocketFrames.matchText(binary.copy(type = "BINARY_DROPPED")))
        assertEquals("plain", WebSocketFrames.matchText(message("TEXT", "plain")))
        assertEquals("AAE=", WebSocketFrames.matchText(message("TEXT", "AAE=")))
    }

    @Test
    fun `the UTF-8 length matches what is put on the wire`() {
        for (text in listOf("", "abc", "\u00E9t\u00E9", "\u20AC", "\uD83D\uDE00", "a\uD800b", "\uDC00", "x\uD83D")) {
            assertEquals(text.toByteArray(Charsets.UTF_8).size, WebSocketFrames.utf8Length(text), "length of '$text'")
        }
    }

    @Test
    fun `message types are TEXT and BINARY in any case`() {
        assertNull(WebSocketFrames.messageTypeError(null))
        assertNull(WebSocketFrames.messageTypeError(" binary "))
        assertNull(WebSocketFrames.messageTypeError("Text"))
        assertNotNull(WebSocketFrames.messageTypeError("json"))
        assertEquals("BINARY", WebSocketFrames.normalizeMessageType(" binary "))
        assertNull(WebSocketFrames.normalizeMessageType("  "))
        assertTrue(WebSocketFrames.isBinary("BINARY_UNSENT"))
    }

    @Test
    fun `a clipped base64 payload still decodes, a clipped text never splits a surrogate pair`() {
        val base64 = Base64.getEncoder().encodeToString(allBytes)
        val clipped = WebSocketFrames.clip(base64, 10, base64 = true)
        assertEquals(8, clipped.length)
        assertContentEquals(allBytes.copyOf(6), WebSocketFrames.decodeBase64(clipped))

        assertEquals("ab", WebSocketFrames.clip("ab\uD83D\uDE00cd", 3))
        assertEquals("ab\uD83D\uDE00", WebSocketFrames.clip("ab\uD83D\uDE00cd", 4))
        // A lone surrogate cannot be encoded as JSON text: it is replaced.
        assertEquals("a\uFFFDb", WebSocketFrames.clip("a\uD800b", 0))
    }

    @Test
    fun `a frame in a result keeps its full byte length and says when its payload was cut`() {
        val long = message("TEXT", "x".repeat(50))
        val cut = WebSocketFrames.toJson(long, maxPayloadChars = 10)
        assertEquals(10, cut["payload"]!!.jsonPrimitive.content.length)
        assertTrue(cut["truncated"]!!.jsonPrimitive.boolean)
        assertEquals(50, cut["length"]!!.jsonPrimitive.int)
        assertEquals("server_to_client", cut["direction"]!!.jsonPrimitive.content)

        val whole = WebSocketFrames.toJson(long)
        assertEquals(50, whole["payload"]!!.jsonPrimitive.content.length)
        assertNull(whole["truncated"])

        val brief = WebSocketFrames.toJson(long, brief = true)
        assertNull(brief["direction"])
        assertNull(brief["timestamp"])
        assertEquals(7, brief["index"]!!.jsonPrimitive.int)
    }
}
