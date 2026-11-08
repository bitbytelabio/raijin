package io.bitbytelab.raijin.turbo.hp3.h3

import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.BufferUnderflowException
import java.nio.ByteBuffer

/**
 * QUIC variable-length integers, RFC 9000 section 16. Every length and identifier in HTTP/3 is one
 * of these, so this is the foundation the frame codec and QPACK are built on.
 *
 * <p>The two most significant bits of the first byte select the encoded length; the remaining bits
 * carry the value:
 *
 * <pre>
 *   00  1 byte   6-bit value    0 .. 63
 *   01  2 bytes  14-bit value   0 .. 16383
 *   10  4 bytes  30-bit value   0 .. 1073741823
 *   11  8 bytes  62-bit value   0 .. 4611686018427387903
 * </pre>
 *
 * <p>RFC 9000 permits encodings that are longer than necessary, and a peer must accept them. That
 * is a control seam rather than a curiosity, so {@link #encode(long, int)} exposes it deliberately.
 */
object VarInt {

    /** Largest value a QUIC varint can carry: 2^62 - 1. */
    const val MAX_VALUE: Long = 4611686018427387903L

    private const val MAX_1_BYTE: Long = 63L
    private const val MAX_2_BYTE: Long = 16383L
    private const val MAX_4_BYTE: Long = 1073741823L

    /** Number of bytes the minimal encoding of {@code value} occupies. */
    @JvmStatic
    fun encodedLength(value: Long): Int {
        requireInRange(value)
        if (value <= MAX_1_BYTE) return 1
        if (value <= MAX_2_BYTE) return 2
        if (value <= MAX_4_BYTE) return 4
        return 8
    }

    /** Encodes {@code value} using the fewest bytes possible. */
    @JvmStatic
    fun encode(value: Long): ByteArray {
        return encode(value, encodedLength(value))
    }

    /**
     * Encodes {@code value} into exactly {@code length} bytes, which must be 1, 2, 4 or 8 and large
     * enough to hold the value. Permits the deliberately non-minimal encodings RFC 9000 allows.
     */
    @JvmStatic
    fun encode(value: Long, length: Int): ByteArray {
        requireInRange(value)
        if (length != 1 && length != 2 && length != 4 && length != 8) {
            throw IllegalArgumentException(
                "varint length must be 1, 2, 4 or 8 but was " + length)
        }
        if (length < encodedLength(value)) {
            throw IllegalArgumentException(
                value.toString() + " does not fit in " + length + " byte(s)")
        }

        var v = value
        val out = ByteArray(length)
        for (i in length - 1 downTo 0) {
            out[i] = v.toByte()
            v = v ushr 8
        }
        // Length prefix: 00, 01, 10, 11 for lengths 1, 2, 4, 8.
        out[0] = (out[0].toInt() or (log2(length) shl 6)).toByte()
        return out
    }

    /** Writes the minimal encoding of {@code value} to {@code out}. */
    @JvmStatic
    @Throws(IOException::class)
    fun write(out: OutputStream, value: Long) {
        out.write(encode(value))
    }

    /** Reads one varint from {@code buffer}, advancing its position. */
    @JvmStatic
    fun read(buffer: ByteBuffer): Long {
        if (!buffer.hasRemaining()) {
            throw BufferUnderflowException()
        }
        val first = buffer.get().toInt() and 0xff
        val length = 1 shl (first ushr 6)
        if (buffer.remaining() < length - 1) {
            throw BufferUnderflowException()
        }
        var value = (first and 0x3f).toLong()
        for (i in 1 until length) {
            value = (value shl 8) or (buffer.get().toInt() and 0xff).toLong()
        }
        return value
    }

    /**
     * Reads one varint from {@code in}.
     *
     * @return the value, or -1 if the stream ends cleanly before any byte is read
     * @throws EOFException if the stream ends part-way through a varint
     */
    @JvmStatic
    @Throws(IOException::class)
    fun read(input: InputStream): Long {
        val first = input.read()
        if (first < 0) {
            return -1
        }
        val length = 1 shl (first ushr 6)
        var value = (first and 0x3f).toLong()
        for (i in 1 until length) {
            val next = input.read()
            if (next < 0) {
                throw EOFException(
                    "stream ended " + (length - i) + " byte(s) into a " + length + "-byte varint")
            }
            value = (value shl 8) or next.toLong()
        }
        return value
    }

    private fun requireInRange(value: Long) {
        if (value < 0 || value > MAX_VALUE) {
            throw IllegalArgumentException(
                "varint out of range 0.." + MAX_VALUE + ": " + value)
        }
    }

    /** {@code length} is known to be 1, 2, 4 or 8, so this is 0, 1, 2 or 3. */
    private fun log2(length: Int): Int {
        return Integer.numberOfTrailingZeros(length)
    }
}
