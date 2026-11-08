package io.bitbytelab.raijin.turbo.hp3.h3.qpack

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

/**
 * The RFC 7541 Appendix B Huffman code, which QPACK uses unmodified.
 *
 * <p>Not optional: real servers Huffman-encode their literal values. The phase 1 spike captured
 * quic.tech doing exactly that in a response HEADERS frame.
 *
 * <p>Strings are treated as ISO-8859-1 throughout, which maps every byte value 0-255 to exactly one
 * character and back. UTF-8 would be lossy for header values holding arbitrary bytes, and a tool
 * whose purpose is sending deliberately malformed traffic cannot afford a charset that mangles its
 * input.
 */
object HuffmanCodec {

    /** Decoding trie, flattened: {@code CHILD[2*node + bit]}, or -1 where there is no edge. */
    private val CHILD: IntArray
    /** Symbol at each node, or -1 for an internal node. */
    private val SYMBOL: IntArray

    init {
        val children = ArrayList<IntArray>()   // {zero, one}
        val symbols = ArrayList<Int>()
        children.add(intArrayOf(-1, -1))
        symbols.add(-1)

        for (symbol in HuffmanTable.CODES.indices) {
            val code = HuffmanTable.CODES[symbol]
            val length = HuffmanTable.LENGTHS[symbol].toInt()
            var node = 0
            for (bitIndex in length - 1 downTo 0) {
                val bit = (code ushr bitIndex) and 1
                var next = children[node][bit]
                if (next == -1) {
                    children.add(intArrayOf(-1, -1))
                    symbols.add(-1)
                    next = children.size - 1
                    children[node][bit] = next
                }
                node = next
            }
            symbols[node] = symbol
        }

        CHILD = IntArray(children.size * 2)
        SYMBOL = IntArray(symbols.size)
        for (i in children.indices) {
            CHILD[2 * i] = children[i][0]
            CHILD[2 * i + 1] = children[i][1]
            SYMBOL[i] = symbols[i]
        }
    }

    /** Number of bytes {@code value} occupies once Huffman coded, including padding. */
    @JvmStatic
    fun encodedLength(value: String): Int {
        var bits: Long = 0
        for (b in value.toByteArray(StandardCharsets.ISO_8859_1)) {
            bits += HuffmanTable.LENGTHS[b.toInt() and 0xff].toLong()
        }
        return ((bits + 7) / 8).toInt()
    }

    /** Huffman codes {@code value}, padding to a byte boundary with EOS prefix bits (all ones). */
    @JvmStatic
    fun encode(value: String): ByteArray {
        val out = ByteArrayOutputStream()
        var buffer: Long = 0
        var bits = 0

        for (b in value.toByteArray(StandardCharsets.ISO_8859_1)) {
            val symbol = b.toInt() and 0xff
            buffer = (buffer shl HuffmanTable.LENGTHS[symbol].toInt()) or HuffmanTable.CODES[symbol].toLong()
            bits += HuffmanTable.LENGTHS[symbol].toInt()
            while (bits >= 8) {
                bits -= 8
                out.write((buffer ushr bits).toInt() and 0xff)
            }
            buffer = buffer and ((1L shl bits) - 1)   // drop the bits already emitted
        }

        if (bits > 0) {
            // Pad with the most significant bits of EOS, which are all ones.
            out.write(((buffer shl (8 - bits)) or (((1 shl (8 - bits)) - 1).toLong())).toInt() and 0xff)
        }
        return out.toByteArray()
    }

    @JvmStatic
    @Throws(QpackException::class)
    fun decode(data: ByteArray): String {
        return decode(data, 0, data.size)
    }

    /**
     * Decodes {@code length} bytes from {@code offset}.
     *
     * @throws QpackException on an encoded EOS symbol, over-long padding, or padding that is not
     *                        EOS prefix bits — all three are errors under RFC 7541 section 5.2
     */
    @JvmStatic
    @Throws(QpackException::class)
    fun decode(data: ByteArray, offset: Int, length: Int): String {
        val out = ByteArrayOutputStream()
        var node = 0
        var bitsSinceSymbol = 0
        var paddingIsAllOnes = true

        for (i in offset until offset + length) {
            val octet = data[i].toInt() and 0xff
            for (bitIndex in 7 downTo 0) {
                val bit = (octet ushr bitIndex) and 1
                node = CHILD[2 * node + bit]
                if (node == -1) {
                    throw QpackException("Huffman code walked off the table")
                }
                bitsSinceSymbol++
                if (bit == 0) {
                    paddingIsAllOnes = false
                }

                if (SYMBOL[node] != -1) {
                    if (SYMBOL[node] == HuffmanTable.EOS) {
                        throw QpackException("Huffman string contains an encoded EOS symbol")
                    }
                    out.write(SYMBOL[node])
                    node = 0
                    bitsSinceSymbol = 0
                    paddingIsAllOnes = true
                }
            }
        }

        if (bitsSinceSymbol >= 8) {
            throw QpackException(
                "Huffman padding is " + bitsSinceSymbol + " bits, must be fewer than 8")
        }
        if (bitsSinceSymbol > 0 && !paddingIsAllOnes) {
            throw QpackException("Huffman padding is not the EOS prefix (all ones)")
        }
        return out.toString(StandardCharsets.ISO_8859_1)
    }
}
