package io.bitbytelab.raijin.turbo

import com.twitter.hpack.Encoder
import java.io.ByteArrayOutputStream

/**
 * One connection's HPACK encoder. Its dynamic table has to mirror the server's decoder table for
 * the life of the connection, so every header block on a connection goes through the same instance,
 * in the order the blocks are sent.
 *
 * Names and values are encoded as ISO-8859-1, the model the rest of Turbo uses for request text, so
 * a byte the request carries as U+0080..U+00FF reaches the wire as that single byte.
 */
class HeaderEncoder {

    companion object {
        /** The protocol default for SETTINGS_HEADER_TABLE_SIZE, and the most this encoder uses. */
        const val DEFAULT_TABLE_SIZE = 4096
    }

    private val encoder = Encoder(DEFAULT_TABLE_SIZE)
    private var pendingSize: Int? = null
    private var smallestPendingSize = DEFAULT_TABLE_SIZE

    /**
     * Applies the server's SETTINGS_HEADER_TABLE_SIZE: the table never grows past what the server's
     * decoder keeps. RFC 7541 section 4.2 has a change announced at the start of the next header
     * block, the smallest size first when it changed more than once in between.
     */
    @Synchronized
    fun peerTableSize(size: Int) = peerTableSize(size.toLong())

    @Synchronized
    fun peerTableSize(size: Long) {
        val limit = size.coerceIn(0L, DEFAULT_TABLE_SIZE.toLong()).toInt()
        smallestPendingSize = if (pendingSize == null) limit else minOf(smallestPendingSize, limit)
        pendingSize = limit
    }

    /** Encodes one header block. */
    @Synchronized
    fun encode(fields: List<Pair<String, String>>): ByteArray {
        val out = ByteArrayOutputStream()
        pendingSize?.let { target ->
            if (smallestPendingSize < encoder.maxHeaderTableSize) {
                encoder.setMaxHeaderTableSize(out, smallestPendingSize)
            }
            encoder.setMaxHeaderTableSize(out, target)
            pendingSize = null
        }
        for ((name, value) in fields) {
            encoder.encodeHeader(out, name.toByteArray(Charsets.ISO_8859_1), value.toByteArray(Charsets.ISO_8859_1), false)
        }
        return out.toByteArray()
    }
}
