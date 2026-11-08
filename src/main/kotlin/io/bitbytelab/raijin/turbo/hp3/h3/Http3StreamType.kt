package io.bitbytelab.raijin.turbo.hp3.h3

/**
 * Unidirectional stream types, RFC 9114 section 6.2. The type is a varint sent as the first bytes
 * of the stream, before any frames.
 */
object Http3StreamType {

    const val CONTROL: Long = 0x00
    const val PUSH: Long = 0x01
    const val QPACK_ENCODER: Long = 0x02
    const val QPACK_DECODER: Long = 0x03

    @JvmStatic
    fun name(type: Long): String {
        if (type == CONTROL) return "CONTROL"
        if (type == PUSH) return "PUSH"
        if (type == QPACK_ENCODER) return "QPACK_ENCODER"
        if (type == QPACK_DECODER) return "QPACK_DECODER"
        return "UNKNOWN(0x" + java.lang.Long.toHexString(type) + ")"
    }
}
