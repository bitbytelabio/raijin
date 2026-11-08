package io.bitbytelab.raijin.turbo.hp3.h3

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.BufferUnderflowException
import java.nio.ByteBuffer
import java.util.LinkedHashMap

/**
 * A SETTINGS frame payload: a sequence of identifier/value varint pairs, RFC 9114 section 7.2.4.
 *
 * <p>Insertion order is preserved so a caller can control the order settings appear on the wire.
 */
class Http3Settings {

    private val settings: MutableMap<Long, Long> = LinkedHashMap()

    fun with(identifier: Long, value: Long): Http3Settings {
        settings[identifier] = value
        return this
    }

    fun get(identifier: Long, defaultValue: Long): Long {
        return settings.getOrDefault(identifier, defaultValue)
    }

    fun contains(identifier: Long): Boolean {
        return settings.containsKey(identifier)
    }

    fun size(): Int {
        return settings.size
    }

    fun encodePayload(): ByteArray {
        val out = ByteArrayOutputStream()
        try {
            for (entry in settings.entries) {
                VarInt.write(out, entry.key)
                VarInt.write(out, entry.value)
            }
        } catch (e: IOException) {
            throw IllegalStateException("ByteArrayOutputStream does not throw", e)
        }
        return out.toByteArray()
    }

    override fun toString(): String {
        return settings.toString()
    }

    companion object {
        const val QPACK_MAX_TABLE_CAPACITY: Long = 0x01
        const val MAX_FIELD_SECTION_SIZE: Long = 0x06
        const val QPACK_BLOCKED_STREAMS: Long = 0x07
        const val ENABLE_CONNECT_PROTOCOL: Long = 0x08

        /**
         * The dynamic table capacity this client offers a server, in octets.
         *
         * <p>Whatever a server repeats on every response — its {@code server} banner, the
         * {@code content-type} and {@code content-length} of a canned error page, the current
         * {@code date} — costs those bytes once here instead of once per response. A few dozen
         * entries covers that comfortably, and the table only ever holds what the server chooses to
         * put in it.
         */
        const val DEFAULT_QPACK_MAX_TABLE_CAPACITY: Long = 4096

        /**
         * What this client advertises: a dynamic table the server may use, and no blocked streams.
         *
         * <p>Zero blocked streams is the load-bearing half. It lets a server reference an entry only
         * once it knows we have taken that entry in, so a field section can never arrive needing an
         * insertion we have not seen — no request ever waits on the encoder stream, and the decoder
         * needs no machinery for one that does. The cost is that the first few responses on a
         * connection are still literals, which against a run of any length rounds to nothing.
         */
        @JvmStatic
        fun clientDefaults(): Http3Settings {
            return Http3Settings()
                .with(QPACK_MAX_TABLE_CAPACITY, DEFAULT_QPACK_MAX_TABLE_CAPACITY)
                .with(QPACK_BLOCKED_STREAMS, 0)
        }

        @JvmStatic
        fun empty(): Http3Settings {
            return Http3Settings()
        }

        @JvmStatic
        @Throws(Http3Exception::class)
        fun decodePayload(payload: ByteArray): Http3Settings {
            val result = Http3Settings()
            val buffer = ByteBuffer.wrap(payload)
            try {
                while (buffer.hasRemaining()) {
                    val identifier = VarInt.read(buffer)
                    val value = VarInt.read(buffer)
                    if (result.settings.containsKey(identifier)) {
                        throw Http3Exception(Http3Exception.H3_SETTINGS_ERROR,
                            "SETTINGS repeated identifier 0x" + java.lang.Long.toHexString(identifier))
                    }
                    if (identifier >= 0x02 && identifier <= 0x05) {
                        throw Http3Exception(Http3Exception.H3_SETTINGS_ERROR,
                            "SETTINGS used reserved HTTP/2 identifier 0x" +
                                java.lang.Long.toHexString(identifier))
                    }
                    result.settings[identifier] = value
                }
            } catch (e: BufferUnderflowException) {
                throw Http3Exception(Http3Exception.H3_FRAME_ERROR,
                    "SETTINGS payload ended part-way through an identifier/value pair")
            }
            return result
        }
    }
}
