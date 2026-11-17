package io.bitbytelab.raijin.turbo

import com.twitter.hpack.Decoder
import java.io.ByteArrayInputStream
import java.io.IOException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class HeaderEncoderTest {

    private fun decode(decoder: Decoder, block: ByteArray): List<Pair<ByteArray, ByteArray>> {
        val fields = mutableListOf<Pair<ByteArray, ByteArray>>()
        decoder.decode(ByteArrayInputStream(block)) { name, value, _ -> fields += name to value }
        decoder.endHeaderBlock()
        return fields
    }

    private fun text(fields: List<Pair<ByteArray, ByteArray>>) =
        fields.map { (name, value) -> String(name, Charsets.ISO_8859_1) to String(value, Charsets.ISO_8859_1) }

    @Test
    fun `characters above 0x7F reach the wire as single ISO-8859-1 bytes`() {
        val block = HeaderEncoder().encode(listOf("x-accent" to "caf\u00e9\u00ff"))
        val (_, value) = decode(Decoder(8192, 4096), block).single()
        assertContentEquals(byteArrayOf(0x63, 0x61, 0x66, 0xE9.toByte(), 0xFF.toByte()), value)
    }

    @Test
    fun `the dynamic table carries over between the header blocks of one connection`() {
        val encoder = HeaderEncoder()
        val decoder = Decoder(8192, 4096)
        val fields = listOf(":path" to "/a", "x-custom" to "some value")
        val first = encoder.encode(fields)
        val second = encoder.encode(fields)
        assertTrue(second.size < first.size, "the second block should reuse indexed entries")
        assertEquals(fields, text(decode(decoder, first)))
        assertEquals(fields, text(decode(decoder, second)))
    }

    @Test
    fun `a smaller table the server asks for is announced before the next block`() {
        val serverDecoder = Decoder(8192, 4096)
        serverDecoder.setMaxHeaderTableSize(256)

        // Without the announcement the server rejects the block outright.
        assertFailsWith<IOException> { decode(serverDecoder, HeaderEncoder().encode(listOf("x-a" to "1"))) }

        val encoder = HeaderEncoder()
        encoder.peerTableSize(256)
        val decoder = Decoder(8192, 4096)
        decoder.setMaxHeaderTableSize(256)
        val block = encoder.encode(listOf("x-a" to "1"))
        assertEquals(0x20, block[0].toInt() and 0xE0, "the block should open with a table size update")
        assertEquals(listOf("x-a" to "1"), text(decode(decoder, block)))
    }

    @Test
    fun `a table the server allows to grow stays at the protocol default`() {
        val encoder = HeaderEncoder()
        encoder.peerTableSize(65536)
        val block = encoder.encode(listOf("x-a" to "1"))
        assertTrue((block[0].toInt() and 0xE0) != 0x20, "no size update is needed when the table does not change")
        assertEquals(listOf("x-a" to "1"), text(decode(Decoder(8192, 4096), block)))
    }

    @Test
    fun `unsigned 32-bit table sizes above 2G keep the protocol default instead of shrinking to zero`() {
        val encoder = HeaderEncoder()
        encoder.peerTableSize(0xFFFF_FFFFL)
        val block = encoder.encode(listOf("x-a" to "1"))
        assertTrue((block[0].toInt() and 0xE0) != 0x20)
        assertEquals(listOf("x-a" to "1"), text(decode(Decoder(8192, 4096), block)))
    }
}
