package io.bitbytelab.raijin.turbo.hp3.h3.qpack

import java.io.IOException
import java.io.InputStream
import java.nio.charset.StandardCharsets

/**
 * Reads the instructions a peer sends on its QPACK encoder stream, RFC 9204 section 4.3, and
 * applies them to our copy of its dynamic table.
 *
 * <p>The peer's table and ours only agree if every instruction is applied in order, so this reads
 * one instruction at a time from the stream and never skips one it does not understand: there is no
 * such thing, and guessing would silently desynchronise every later field section.
 */
object QpackEncoderStream {

    /** Set Dynamic Table Capacity, RFC 9204 section 4.3.1: {@code 001 capacity(5+)}. */
    @JvmStatic
    fun encodeSetCapacity(capacity: Long): ByteArray {
        return PrefixInteger.encode(capacity, 5, 0x20)
    }

    /**
     * Insert With Name Reference against the static table, RFC 9204 section 4.3.2:
     * {@code 1 T index(6+)} then the value as a string literal.
     */
    @JvmStatic
    fun encodeInsertWithNameReference(staticIndex: Int, value: String): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.writeBytes(PrefixInteger.encode(staticIndex.toLong(), 6, 0x80 or 0x40))
        QpackEncoder.writeStringLiteral(
            out, value, HuffmanCodec.encodedLength(value) < value.length, 7, 0)
        return out.toByteArray()
    }

    /**
     * Reads and applies one instruction, returning {@code false} once the peer closes the stream.
     */
    @JvmStatic
    @Throws(IOException::class, QpackException::class)
    fun readInstruction(input: InputStream, table: QpackDynamicTable): Boolean {
        val first = input.read()
        if (first < 0) {
            return false
        }

        if ((first and 0x80) != 0) {                       // 1 T index(6+)
            val fromStaticTable = (first and 0x40) != 0
            val index = readPrefixInteger(first, 6, input)
            val name = if (fromStaticTable) {
                staticName(index)
            } else {
                table.get(relativeToAbsolute(table, index)).name()
            }
            table.insert(FieldLine(name, readStringLiteral(input, 7)))
        } else if ((first and 0xc0) == 0x40) {             // 01 H nameLength(5+)
            val huffman = (first and 0x20) != 0
            val length = readPrefixInteger(first, 5, input)
            val name = readString(input, length, huffman)
            table.insert(FieldLine(name, readStringLiteral(input, 7)))
        } else if ((first and 0xe0) == 0x20) {             // 001 capacity(5+)
            table.setCapacity(readPrefixInteger(first, 5, input))
        } else {                                           // 000 index(5+)
            val index = readPrefixInteger(first, 5, input)
            table.insert(table.get(relativeToAbsolute(table, index)))
        }
        return true
    }

    /**
     * RFC 9204 section 3.2.5: on the encoder stream, relative index 0 is the most recent insertion.
     */
    private fun relativeToAbsolute(table: QpackDynamicTable, relativeIndex: Long): Long {
        return table.insertCount() - 1 - relativeIndex
    }

    @Throws(QpackException::class)
    private fun staticName(index: Long): String {
        if (index < 0 || index >= QpackStaticTable.size()) {
            throw QpackException("static table index " + index + " is out of range 0.." +
                (QpackStaticTable.size() - 1))
        }
        return QpackStaticTable.name(index.toInt())
    }

    @Throws(IOException::class, QpackException::class)
    private fun readStringLiteral(input: InputStream, prefixBits: Int): String {
        val first = input.read()
        if (first < 0) {
            throw QpackException("encoder stream ended before a string literal")
        }
        val huffman = (first and (1 shl prefixBits)) != 0
        return readString(input, readPrefixInteger(first, prefixBits, input), huffman)
    }

    @Throws(IOException::class, QpackException::class)
    private fun readString(input: InputStream, length: Long, huffman: Boolean): String {
        if (length > Integer.MAX_VALUE) {
            throw QpackException("string literal declares " + length + " octets")
        }
        val octets = input.readNBytes(length.toInt())
        if (octets.size < length) {
            throw QpackException("encoder stream ended " + (length - octets.size) +
                " octets short of a string literal")
        }
        return if (huffman) {
            HuffmanCodec.decode(octets)
        } else {
            String(octets, StandardCharsets.ISO_8859_1)
        }
    }

    /** RFC 7541 section 5.1, reading onwards from a first byte already taken from the stream. */
    @JvmStatic
    @Throws(IOException::class, QpackException::class)
    internal fun readPrefixInteger(firstByte: Int, prefixBits: Int, input: InputStream): Long {
        val max = (1 shl prefixBits) - 1
        var value = (firstByte and max).toLong()
        if (value < max) {
            return value
        }
        var shift = 0
        while (true) {
            val octet = input.read()
            if (octet < 0) {
                throw QpackException("encoder stream ended part-way through a prefix integer")
            }
            value += (octet and 0x7f).toLong() shl shift
            if (value < 0) {
                throw QpackException("prefix integer overflows 64 bits")
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
