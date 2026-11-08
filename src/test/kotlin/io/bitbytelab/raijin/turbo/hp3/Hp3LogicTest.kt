package io.bitbytelab.raijin.turbo.hp3

import io.bitbytelab.raijin.turbo.hp3.h3.VarInt
import io.bitbytelab.raijin.turbo.hp3.h3.qpack.FieldLine
import io.bitbytelab.raijin.turbo.hp3.h3.qpack.HuffmanCodec
import io.bitbytelab.raijin.turbo.hp3.h3.qpack.PrefixInteger
import io.bitbytelab.raijin.turbo.hp3.h3.qpack.QpackDecoder
import io.bitbytelab.raijin.turbo.hp3.h3.qpack.QpackEncoder
import io.bitbytelab.raijin.turbo.hp3.translate.KettleEscapes
import io.bitbytelab.raijin.turbo.hp3.translate.KettleSyntaxException
import java.nio.ByteBuffer
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class Hp3LogicTest {

    private fun bytes(vararg values: Int): ByteArray = ByteArray(values.size) { values[it].toByte() }

    // RFC 9000 Appendix A.1 sample varints.
    @Test
    fun varIntDecodesRfc9000Vectors() {
        assertEquals(37L, VarInt.read(ByteBuffer.wrap(bytes(0x25))))
        assertEquals(15293L, VarInt.read(ByteBuffer.wrap(bytes(0x7b, 0xbd))))
        assertEquals(494878333L, VarInt.read(ByteBuffer.wrap(bytes(0x9d, 0x7f, 0x3e, 0x7d))))
        assertEquals(
            151288809941952652L,
            VarInt.read(ByteBuffer.wrap(bytes(0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c))))
    }

    @Test
    fun varIntEncodesMinimalRfc9000Vectors() {
        assertContentEquals(bytes(0x25), VarInt.encode(37L))
        assertContentEquals(bytes(0x7b, 0xbd), VarInt.encode(15293L))
        assertContentEquals(bytes(0x9d, 0x7f, 0x3e, 0x7d), VarInt.encode(494878333L))
        assertContentEquals(
            bytes(0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c),
            VarInt.encode(151288809941952652L))
    }

    @Test
    fun varIntRoundTrips() {
        for (value in longArrayOf(0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, VarInt.MAX_VALUE)) {
            assertEquals(value, VarInt.read(ByteBuffer.wrap(VarInt.encode(value))))
        }
    }

    // RFC 7541 section 5.1: encoding 1337 with a 5-bit prefix is 0x1f 0x9a 0x0a.
    @Test
    fun prefixIntegerRfc7541Example() {
        assertContentEquals(bytes(0x1f, 0x9a, 0x0a), PrefixInteger.encode(1337L, 5, 0))
        assertEquals(1337L, PrefixInteger.read(ByteBuffer.wrap(bytes(0x1f, 0x9a, 0x0a)), 5))
    }

    @Test
    fun prefixIntegerRoundTrips() {
        for (value in longArrayOf(0, 1, 10, 30, 31, 128, 1337, 100000, VarInt.MAX_VALUE)) {
            for (prefixBits in intArrayOf(4, 5, 6, 7, 8)) {
                val encoded = PrefixInteger.encode(value, prefixBits, 0)
                assertEquals(value, PrefixInteger.read(ByteBuffer.wrap(encoded), prefixBits))
            }
        }
    }

    // RFC 7541 Appendix C.6.1: "www.example.com" Huffman-encodes to these 12 octets.
    @Test
    fun huffmanRfc7541Example() {
        val expected = bytes(0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff)
        assertContentEquals(expected, HuffmanCodec.encode("www.example.com"))
        assertEquals(12, HuffmanCodec.encodedLength("www.example.com"))
        assertEquals("www.example.com", HuffmanCodec.decode(expected))
    }

    @Test
    fun huffmanRoundTrips() {
        for (value in listOf("", "a", "no-cache", "/index.html", "HTTP/3 is here", "x".repeat(300))) {
            assertEquals(value, HuffmanCodec.decode(HuffmanCodec.encode(value)))
        }
    }

    @Test
    fun qpackStaticOnlyRoundTrips() {
        val fields = listOf(
            FieldLine.of(":method", "GET"),          // indexed static
            FieldLine.of(":authority", "example.com"), // name reference
            FieldLine.of("x-custom-header", "Value-123"), // literal name
            FieldLine.of(":path", "/index.html"),
        )
        val encoded = QpackEncoder.encodeFieldSection(fields)
        val decoded = QpackDecoder.decodeFieldSection(encoded)
        assertEquals(fields, decoded)
    }

    @Test
    fun kettleEscapes() {
        assertEquals("plain", KettleEscapes.decode("plain"))
        assertEquals("a\r\nb", KettleEscapes.decode("a^~b"))
        assertEquals("\r", KettleEscapes.decode("^r"))
        assertEquals("\n", KettleEscapes.decode("^n"))
        assertEquals("\u0000", KettleEscapes.decode("^0"))
        assertEquals(" ", KettleEscapes.decode("^s"))
        assertEquals("^", KettleEscapes.decode("^^"))
        assertEquals("A", KettleEscapes.decode("^x41"))
        assertEquals("ÿ", KettleEscapes.decode("^xff"))
        assertFailsWith<KettleSyntaxException> { KettleEscapes.decode("^q") }
        assertFailsWith<KettleSyntaxException> { KettleEscapes.decode("trailing^") }
        assertFailsWith<KettleSyntaxException> { KettleEscapes.decode("^x4") }
    }
}
