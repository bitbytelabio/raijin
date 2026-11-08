package io.bitbytelab.raijin.turbo.hp3.h3.qpack

import io.bitbytelab.raijin.turbo.hp3.h3.VarInt
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer

/**
 * N-bit prefix integers, RFC 7541 section 5.1. QPACK inherits the encoding unchanged, and uses it
 * for every index and string length.
 *
 * <p>The first byte carries the low N bits of the value plus whatever representation flags belong
 * in the high bits; larger values continue into subsequent octets with a continuation bit.
 */
object PrefixInteger {

    /**
     * Encodes {@code value} into an {@code prefixBits}-bit prefix, ORing {@code flags} into the
     * high bits of the first byte.
     */
    @JvmStatic
    fun encode(value: Long, prefixBits: Int, flags: Int): ByteArray {
        if (value < 0) {
            throw IllegalArgumentException("prefix integers are unsigned: " + value)
        }
        val max = (1 shl prefixBits) - 1
        val out = ByteArrayOutputStream()
        if (value < max) {
            out.write(flags or value.toInt())
            return out.toByteArray()
        }
        // All prefix bits set means "the value continues in the following octets".
        out.write(flags or max)
        var rest = value - max
        while (rest >= 128) {
            out.write(((rest and 0x7f) or 0x80).toInt())
            rest = rest ushr 7
        }
        out.write(rest.toInt())
        return out.toByteArray()
    }

    /** Reads a prefix integer, consuming the first byte and any continuation octets. */
    @JvmStatic
    @Throws(QpackException::class)
    fun read(buffer: ByteBuffer, prefixBits: Int): Long {
        val max = (1 shl prefixBits) - 1
        var value = (buffer.get().toInt() and max).toLong()
        if (value < max) {
            return value
        }
        var shift = 0
        while (true) {
            val octet = buffer.get().toInt() and 0xff
            value += (octet and 0x7f).toLong() shl shift
            // Checked after every octet, so the accumulator can never wrap into a negative value
            // that a later narrowing cast would turn back into a plausible-looking length.
            if (value < 0 || value > VarInt.MAX_VALUE) {
                throw QpackException(
                    "prefix integer exceeds the maximum QUIC variable-length integer")
            }
            if ((octet and 0x80) == 0) {
                return value
            }
            shift += 7
            if (shift > 56) {
                throw QpackException("prefix integer overflows 64 bits")
            }
        }
    }
}
