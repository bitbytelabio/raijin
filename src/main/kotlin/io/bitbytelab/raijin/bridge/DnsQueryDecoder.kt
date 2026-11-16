package io.bitbytelab.raijin.bridge

/**
 * Decodes the queried hostname (QNAME) out of a raw DNS query message.
 *
 * `DnsDetails.query()` returns the full DNS request packet as raw bytes, so
 * calling `toString()` on it yields binary noise. This extracts the
 * human-readable name (e.g. `abc.oastify.com`) from the question section.
 *
 * Names are read as RFC 1035 §4.1.4 defines them: the two top bits of a length byte say what
 * follows. `00` is a plain label of 1-63 bytes, `11` is a two-byte compression pointer, and
 * `01` / `10` (bytes `0x40..0xBF`) are reserved label types. A reserved type, a bad pointer or a
 * cut-off name is reported as an error rather than read as a 64-191 byte "label" made of
 * whatever bytes happen to follow.
 */
object DnsQueryDecoder {

    /** The fixed DNS header; the first question starts right after it. */
    private const val HEADER_LENGTH = 12

    /** RFC 1035 §2.3.4 limit on the wire length of a name. */
    private const val MAX_NAME_OCTETS = 255

    /**
     * Outcome of decoding a name: exactly one of the two is set.
     *
     * @property name the dotted name. A `.` or `\` inside a label is written `\.` / `\\` and a byte
     *   outside printable ASCII as `\DDD` (decimal), so binary labels stay readable and unambiguous.
     * @property error why the bytes are not a valid name.
     */
    data class Decoded(val name: String?, val error: String?)

    /**
     * @param query the raw DNS query message bytes.
     * @return the dotted hostname from the question section, or `null` if the
     *   message is too short or the QNAME is malformed / truncated ([decode] says which).
     */
    fun decodeQName(query: ByteArray): String? = decode(query).name

    /** Decodes the QNAME of the first question in [query], or reports why it cannot be decoded. */
    fun decode(query: ByteArray): Decoded =
        if (query.size <= HEADER_LENGTH) {
            failure("message is ${query.size} bytes, too short to hold a question", emptyList())
        } else {
            decodeName(query, HEADER_LENGTH)
        }

    /**
     * Decodes the name that starts at [offset] of the DNS [message], following compression pointers.
     *
     * A pointer has to lead to a name that starts earlier in the message, after the header: that is
     * the only form RFC 1035 allows ("a prior occurrence"), and it rules out pointer loops.
     */
    fun decodeName(message: ByteArray, offset: Int): Decoded {
        if (offset < HEADER_LENGTH || offset >= message.size) {
            return failure("name offset $offset is outside the body of a ${message.size}-byte message", emptyList())
        }
        val labels = ArrayList<String>()
        var octets = 1 // the root label that ends every name
        var runStart = offset // where the labels being read started; a pointer must lead before it
        var pos = offset
        while (pos < message.size) {
            val length = message[pos].toInt() and 0xFF
            when (length and 0xC0) {
                0x00 -> {
                    if (length == 0) return Decoded(if (labels.isEmpty()) "." else labels.joinToString("."), null)
                    val end = pos + 1 + length
                    if (end > message.size) {
                        return failure("label of $length bytes at offset $pos runs past the end of the message", labels)
                    }
                    octets += 1 + length
                    if (octets > MAX_NAME_OCTETS) return failure("name is longer than $MAX_NAME_OCTETS octets", labels)
                    labels += presentation(message, pos + 1, length)
                    pos = end
                }
                0xC0 -> {
                    if (pos + 1 >= message.size) return failure("compression pointer at offset $pos is cut off", labels)
                    val target = ((length and 0x3F) shl 8) or (message[pos + 1].toInt() and 0xFF)
                    if (target < HEADER_LENGTH) {
                        return failure("compression pointer at offset $pos leads into the DNS header (offset $target)", labels)
                    }
                    if (target >= runStart) {
                        return failure("compression pointer at offset $pos does not lead back to an earlier name (offset $target)", labels)
                    }
                    runStart = target
                    pos = target
                }
                else -> return failure("reserved label type (length byte 0x%02x) at offset %d".format(length, pos), labels)
            }
        }
        return failure("name is cut off before its terminating root label", labels)
    }

    /** One label in presentation format (RFC 1035 §5.1 escapes). */
    private fun presentation(message: ByteArray, start: Int, length: Int): String {
        val out = StringBuilder(length)
        for (i in start until start + length) {
            when (val b = message[i].toInt() and 0xFF) {
                '.'.code, '\\'.code -> out.append('\\').append(b.toChar())
                in 0x21..0x7E -> out.append(b.toChar())
                else -> out.append('\\').append(b.toString().padStart(3, '0'))
            }
        }
        return out.toString()
    }

    /** A decode error; the labels read before it are named so they are not lost with the name. */
    private fun failure(reason: String, labels: List<String>): Decoded =
        Decoded(null, if (labels.isEmpty()) reason else "$reason (after '${labels.joinToString(".")}')")
}
