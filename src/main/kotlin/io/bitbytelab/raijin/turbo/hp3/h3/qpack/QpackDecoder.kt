package io.bitbytelab.raijin.turbo.hp3.h3.qpack

import java.nio.BufferUnderflowException
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.ArrayList

/**
 * Decodes QPACK field sections, RFC 9204 section 4.5.
 *
 * <p>With no dynamic table the decoder is static-only: a peer that sends a dynamic or post-base
 * reference anyway must fail loudly here rather than produce quietly wrong headers. Given a
 * {@link QpackDynamicTable} it also resolves references into it, which is what lets a server stop
 * repeating the same response headers in full on every message.
 *
 * <p>Order and duplicates are preserved exactly as received; nothing is normalised on the way in
 * either.
 */
class QpackDecoder private constructor(
    private val buffer: ByteBuffer,
    private val table: QpackDynamicTable.Snapshot?,
) {

    private var base: Long = 0
    private var requiredInsertCount: Long = 0

    /**
     * A decoded field section and the Required Insert Count it carried. A non-zero count means the
     * section leaned on the dynamic table, which RFC 9204 section 4.4.1 requires be acknowledged.
     */
    class FieldSection(private val fields: List<FieldLine>, private val requiredInsertCount: Long) {
        fun fields(): List<FieldLine> = fields
        fun requiredInsertCount(): Long = requiredInsertCount
    }

    /** RFC 9204 section 4.5.1. */
    @Throws(QpackException::class)
    private fun readFieldSectionPrefix() {
        val encodedInsertCount = PrefixInteger.read(buffer, 8)
        val negativeDelta = (peek() and 0x80) != 0
        val deltaBase = PrefixInteger.read(buffer, 7)

        if (table == null) {
            if (encodedInsertCount != 0L) {
                throw QpackException("Required Insert Count is " + encodedInsertCount +
                    " but the dynamic table is disabled (QPACK_MAX_TABLE_CAPACITY=0)")
            }
            if (negativeDelta || deltaBase != 0L) {
                throw QpackException("Base must be 0 when Required Insert Count is 0, got delta " +
                    (if (negativeDelta) "-" else "+") + deltaBase)
            }
            base = 0
            return
        }

        requiredInsertCount = decodeRequiredInsertCount(encodedInsertCount)
        base = if (negativeDelta) {
            requiredInsertCount - deltaBase - 1
        } else {
            requiredInsertCount + deltaBase
        }
        if (base < 0) {
            throw QpackException("field section Base is negative: " + base)
        }
    }

    /**
     * Reverses the wrapped encoding of the Required Insert Count, RFC 9204 section 4.5.1.1. The
     * value is sent modulo twice the table's entry capacity so it fits a small integer, and is
     * recovered here against the insertions actually seen.
     */
    @Throws(QpackException::class)
    private fun decodeRequiredInsertCount(encodedInsertCount: Long): Long {
        if (encodedInsertCount == 0L) {
            return 0
        }
        val table = this.table!!
        val maxEntries = table.maxCapacity() / 32
        val fullRange = 2 * maxEntries
        if (encodedInsertCount > fullRange) {
            throw QpackException("Required Insert Count " + encodedInsertCount +
                " exceeds twice the table's maximum entries (" + fullRange + ")")
        }
        val maxValue = table.insertCount() + maxEntries
        val maxWrapped = (maxValue / fullRange) * fullRange
        var requiredInsertCount = maxWrapped + encodedInsertCount - 1
        if (requiredInsertCount > maxValue) {
            if (requiredInsertCount <= fullRange) {
                throw QpackException(
                    "Required Insert Count " + requiredInsertCount + " wraps below zero")
            }
            requiredInsertCount -= fullRange
        }
        if (requiredInsertCount == 0L) {
            throw QpackException("Required Insert Count decoded to zero from a non-zero value")
        }
        if (requiredInsertCount > table.insertCount()) {
            throw QpackException("field section needs " + requiredInsertCount +
                " insertions but only " + table.insertCount() + " have arrived")
        }
        return requiredInsertCount
    }

    @Throws(QpackException::class)
    private fun readFieldLine(): FieldLine {
        val first = peek()

        if ((first and 0x80) != 0) {                       // 1 T index(6+)
            val fromStaticTable = (first and 0x40) != 0
            val index = PrefixInteger.read(buffer, 6)
            if (fromStaticTable) {
                return staticEntry(index)
            }
            return dynamicEntry(relativeToAbsolute(index), "indexed field line")
        }
        if ((first and 0xc0) == 0x40) {                    // 01 N T index(4+)
            val fromStaticTable = (first and 0x10) != 0
            val index = PrefixInteger.read(buffer, 4)
            val name = if (fromStaticTable) {
                staticName(index)
            } else {
                dynamicEntry(relativeToAbsolute(index),
                    "literal field line with name reference").name()
            }
            return FieldLine(name, readStringLiteral(7))
        }
        if ((first and 0xe0) == 0x20) {                    // 001 N H nameLength(3+)
            val name = readStringLiteral(3)
            return FieldLine(name, readStringLiteral(7))
        }
        if ((first and 0xf0) == 0x10) {                    // 0001 index(4+)
            val index = PrefixInteger.read(buffer, 4)
            return dynamicEntry(postBaseToAbsolute(index),
                "indexed field line with post-base index")
        }
        // 0000 N index(3+)
        val index = PrefixInteger.read(buffer, 3)
        val name = dynamicEntry(postBaseToAbsolute(index),
            "literal field line with post-base name reference").name()
        return FieldLine(name, readStringLiteral(7))
    }

    /** RFC 9204 section 3.2.5: relative indices count back from Base. */
    private fun relativeToAbsolute(relativeIndex: Long): Long {
        return base - 1 - relativeIndex
    }

    /** RFC 9204 section 3.2.6: post-base indices count forward from Base. */
    private fun postBaseToAbsolute(postBaseIndex: Long): Long {
        return base + postBaseIndex
    }

    @Throws(QpackException::class)
    private fun dynamicEntry(absoluteIndex: Long, what: String): FieldLine {
        if (table == null) {
            throw QpackException(what + " references the dynamic table, which is disabled")
        }
        return table.get(absoluteIndex)
    }

    @Throws(QpackException::class)
    private fun readStringLiteral(prefixBits: Int): String {
        val huffman = (peek() and (1 shl prefixBits)) != 0
        val length = PrefixInteger.read(buffer, prefixBits)
        if (length > buffer.remaining()) {
            throw QpackException("string literal declares " + length +
                " octets but only " + buffer.remaining() + " remain")
        }
        val octets = ByteArray(length.toInt())
        buffer.get(octets)
        return if (huffman) {
            HuffmanCodec.decode(octets)
        } else {
            String(octets, StandardCharsets.ISO_8859_1)
        }
    }

    /** Reads the byte at the current position without consuming it. */
    private fun peek(): Int {
        if (!buffer.hasRemaining()) {
            throw BufferUnderflowException()
        }
        return buffer.get(buffer.position()).toInt() and 0xff
    }

    companion object {
        /** Decodes a field section that may reference only the static table. */
        @JvmStatic
        @Throws(QpackException::class)
        fun decodeFieldSection(encoded: ByteArray): List<FieldLine> {
            return decodeFieldSection(encoded, null)
        }

        /**
         * Decodes a complete field section, resolving dynamic references against {@code table} when
         * one is given. Order and duplicates are preserved exactly as received.
         */
        @JvmStatic
        @Throws(QpackException::class)
        fun decodeFieldSection(encoded: ByteArray, table: QpackDynamicTable?): List<FieldLine> {
            return decodeSection(encoded, table).fields()
        }

        /** As {@link #decodeFieldSection(byte[], QpackDynamicTable)}, reporting what it referenced. */
        @JvmStatic
        @Throws(QpackException::class)
        fun decodeSection(encoded: ByteArray, table: QpackDynamicTable?): FieldSection {
            // One snapshot for the whole section: the peer's encoder stream may insert and evict
            // while this runs, and a half-old view would resolve indices against two different
            // tables.
            val decoder = QpackDecoder(ByteBuffer.wrap(encoded),
                if (table == null) null else table.snapshot())
            val fields = ArrayList<FieldLine>()
            try {
                decoder.readFieldSectionPrefix()
                while (decoder.buffer.hasRemaining()) {
                    fields.add(decoder.readFieldLine())
                }
            } catch (e: BufferUnderflowException) {
                throw QpackException("field section ended part-way through a representation")
            }
            return FieldSection(fields, decoder.requiredInsertCount)
        }

        @Throws(QpackException::class)
        private fun staticEntry(index: Long): FieldLine {
            requireStaticIndex(index)
            return FieldLine(QpackStaticTable.name(index.toInt()), QpackStaticTable.value(index.toInt()))
        }

        @Throws(QpackException::class)
        private fun staticName(index: Long): String {
            requireStaticIndex(index)
            return QpackStaticTable.name(index.toInt())
        }

        @Throws(QpackException::class)
        private fun requireStaticIndex(index: Long) {
            if (index < 0 || index >= QpackStaticTable.size()) {
                throw QpackException("static table index " + index + " is out of range 0.." +
                    (QpackStaticTable.size() - 1))
            }
        }
    }
}
