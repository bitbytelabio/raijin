package io.bitbytelab.raijin.bridge

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DnsQueryDecoderTest {

    private val header = byteArrayOf(
        0x12, 0x34,             // transaction id
        0x01, 0x00,             // flags: standard query, recursion desired
        0x00, 0x01,             // QDCOUNT = 1
        0x00, 0x00,             // ANCOUNT
        0x00, 0x00,             // NSCOUNT
        0x00, 0x00              // ARCOUNT
    )

    /** One label on the wire: its length byte, then its bytes. */
    private fun label(text: String): ByteArray = byteArrayOf(text.length.toByte()) + text.toByteArray(Charsets.ISO_8859_1)

    private fun bytes(vararg values: Int): ByteArray = ByteArray(values.size) { values[it].toByte() }

    /** Builds a minimal DNS query message: 12-byte header + QNAME + QTYPE + QCLASS. */
    private fun dnsQuery(vararg labels: String): ByteArray {
        val qname = labels.fold(ByteArray(0)) { name, text -> name + label(text) } + bytes(0x00) // root terminator
        val footer = bytes(0x00, 0x01, 0x00, 0x01) // QTYPE=A, QCLASS=IN
        return header + qname + footer
    }

    /** The decode error for [query], which must not have produced a name. */
    private fun errorOf(query: ByteArray): String {
        val decoded = DnsQueryDecoder.decode(query)
        assertNull(decoded.name, "decoded a name out of a malformed query")
        assertNull(DnsQueryDecoder.decodeQName(query))
        return assertNotNull(decoded.error)
    }

    @Test
    fun `decodes a standard multi-label qname`() {
        val query = dnsQuery("abc", "example", "com")
        assertEquals("abc.example.com", DnsQueryDecoder.decodeQName(query))
        assertEquals(DnsQueryDecoder.Decoded("abc.example.com", null), DnsQueryDecoder.decode(query))
    }

    @Test
    fun `decodes a long collaborator subdomain`() {
        val query = dnsQuery("rrm5a4gkkzf3k0ax55q0gfuylprffxxe24t5tnxc", "oastify", "com")
        assertEquals("rrm5a4gkkzf3k0ax55q0gfuylprffxxe24t5tnxc.oastify.com", DnsQueryDecoder.decodeQName(query))
    }

    @Test
    fun `returns null for input shorter than the DNS header`() {
        assertNull(DnsQueryDecoder.decodeQName(byteArrayOf(0x00, 0x01, 0x02)))
        assertTrue("too short" in errorOf(byteArrayOf(0x00, 0x01, 0x02)))
        assertTrue("too short" in errorOf(header), "a header without a question")
    }

    @Test
    fun `returns null when a label length runs past the buffer`() {
        // header + a label claiming length 5 but only 2 bytes of data follow
        val malformed = header + bytes(0x05, 0x61, 0x62)
        assertNull(DnsQueryDecoder.decodeQName(malformed))
        assertTrue("runs past the end" in errorOf(malformed))
    }

    @Test
    fun `a name that ends without its root label is an error that still names what was read`() {
        val error = errorOf(header + label("abc") + label("exam"))
        assertTrue("cut off" in error, error)
        assertTrue("abc.exam" in error, error)
    }

    @Test
    fun `reserved label types are rejected instead of being read as long labels`() {
        // 0x40..0xBF as a plain length would swallow the next 64-191 bytes as one "label".
        for (type in listOf(0x40, 0x41, 0x7F, 0x80, 0xA5, 0xBF)) {
            val query = header + bytes(type) + ByteArray(200) { 'a'.code.toByte() } + bytes(0x00)
            val error = errorOf(query)
            assertTrue("reserved label type" in error, error)
            assertTrue("0x%02x".format(type) in error, error)
        }
    }

    @Test
    fun `a reserved label type after valid labels rejects the whole name`() {
        val error = errorOf(header + label("abc") + bytes(0x80) + ByteArray(150) { 'b'.code.toByte() } + bytes(0x00))
        assertTrue("reserved label type" in error, error)
        assertTrue("after 'abc'" in error, error)
    }

    @Test
    fun `63 bytes is the longest label`() {
        val longest = "a".repeat(63)
        assertEquals("$longest.com", DnsQueryDecoder.decodeQName(dnsQuery(longest, "com")))
    }

    @Test
    fun `a name may take 255 octets on the wire and no more`() {
        // 3 * (1 + 63) + (1 + 61) + root = 255
        val atLimit = dnsQuery("a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(61))
        assertEquals(253, DnsQueryDecoder.decodeQName(atLimit)?.length)

        val overLimit = dnsQuery("a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(62))
        assertTrue("longer than 255 octets" in errorOf(overLimit))
    }

    @Test
    fun `the root name decodes as a dot`() {
        assertEquals(".", DnsQueryDecoder.decodeQName(header + bytes(0x00, 0x00, 0x02, 0x00, 0x01)))
    }

    @Test
    fun `bytes that are not printable hostname characters are escaped`() {
        // one label holding: a . b \ space NUL 0xFF
        val odd = header + bytes(7, 'a'.code, '.'.code, 'b'.code, '\\'.code, ' '.code, 0x00, 0xFF) + label("com") + bytes(0x00)
        assertEquals("a\\.b\\\\\\032\\000\\255.com", DnsQueryDecoder.decodeQName(odd))
    }

    @Test
    fun `a compression pointer is followed to the earlier name`() {
        val question = dnsQuery("example", "com") // QNAME at offset 12
        val second = question.size
        val message = question + label("www") + bytes(0xC0, 12)
        assertEquals(DnsQueryDecoder.Decoded("www.example.com", null), DnsQueryDecoder.decodeName(message, second))

        // a pointer may lead to a name that itself ends in a pointer, and into the middle of a name
        val third = message.size
        val chained = message + label("mail") + bytes(0xC0, second) + bytes(0xC0, 12 + 8)
        assertEquals("mail.www.example.com", DnsQueryDecoder.decodeName(chained, third).name)
        assertEquals("com", DnsQueryDecoder.decodeName(chained, third + 5 + 2).name)
    }

    @Test
    fun `a pointer with a 14 bit offset is read from both bytes`() {
        // put the target name at offset 0x0123 so the high bits of the pointer matter
        val target = 0x0123
        val message = header + ByteArray(target - header.size) + label("deep") + bytes(0x00) + bytes(0xC1, 0x23)
        assertEquals("deep", DnsQueryDecoder.decodeName(message, target + 6).name)
    }

    @Test
    fun `a pointer that does not lead back to an earlier name is an error`() {
        // the first name of a message has nothing before it to point to: this one points at itself
        val loop = errorOf(header + label("www") + bytes(0xC0, 12))
        assertTrue("does not lead back" in loop, loop)
        assertTrue("after 'www'" in loop, loop)

        val forward = errorOf(header + bytes(0xC0, 20) + ByteArray(8) + label("abc") + bytes(0x00))
        assertTrue("does not lead back" in forward, forward)
    }

    @Test
    fun `a pointer into the header or cut in half is an error`() {
        val question = dnsQuery("example", "com")
        val intoHeader = DnsQueryDecoder.decodeName(question + bytes(0xC0, 4), question.size)
        assertNull(intoHeader.name)
        assertTrue("DNS header" in assertNotNull(intoHeader.error))

        assertTrue("cut off" in errorOf(header + bytes(0xC0)))
        assertTrue("cut off" in errorOf(header + label("abc") + bytes(0xFF)))
    }

    @Test
    fun `an offset outside the message body is an error`() {
        val question = dnsQuery("example", "com")
        for (offset in listOf(-1, 0, 11, question.size, question.size + 5)) {
            val decoded = DnsQueryDecoder.decodeName(question, offset)
            assertNull(decoded.name, "offset $offset")
            assertTrue("outside" in assertNotNull(decoded.error), "offset $offset")
        }
    }
}
