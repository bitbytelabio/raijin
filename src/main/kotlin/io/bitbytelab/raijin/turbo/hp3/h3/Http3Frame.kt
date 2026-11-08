package io.bitbytelab.raijin.turbo.hp3.h3

import java.util.HexFormat

/**
 * One HTTP/3 frame: a varint type, a varint length, and that many payload bytes
 * (RFC 9114 section 7.1).
 *
 * <p>The type is a {@code long} rather than an enum because any 62-bit value is legal on the wire,
 * and both directions matter — we must be able to receive types we do not recognise, and to send
 * them on purpose.
 *
 * @param type    frame type codepoint
 * @param payload frame payload, never null; may be empty
 */
class Http3Frame(private val type: Long, private val payload: ByteArray) {

    init {
        // payload is non-null by Kotlin type; constructor validation preserved for intent.
    }

    fun type(): Long = type

    fun payload(): ByteArray = payload

    fun payloadLength(): Int {
        return payload.size
    }

    /** True if this frame's type is one HTTP/3 requires a receiver to ignore. */
    fun isGrease(): Boolean {
        return Http3FrameType.isGreaseType(type)
    }

    override fun toString(): String {
        return Http3FrameType.name(type) + " len=" + payload.size +
            (if (payload.size == 0) "" else " " + HexFormat.of().formatHex(
                payload, 0, Math.min(payload.size, 32)))
    }

    companion object {
        @JvmStatic
        fun of(type: Long, payload: ByteArray): Http3Frame {
            return Http3Frame(type, payload)
        }
    }
}
