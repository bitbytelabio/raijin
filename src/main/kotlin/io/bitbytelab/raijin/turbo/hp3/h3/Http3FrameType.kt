package io.bitbytelab.raijin.turbo.hp3.h3

/**
 * HTTP/3 frame type codepoints, from the IANA HTTP/3 Frame Types registry (RFC 9114 section 11.2.1).
 *
 * <p>Frame types are varints, so this is a holder of constants rather than an enum: any 62-bit value
 * is a legal type on the wire, and the codec must be able to emit and receive types that are not
 * listed here.
 */
object Http3FrameType {

    const val DATA: Long = 0x00
    const val HEADERS: Long = 0x01
    const val CANCEL_PUSH: Long = 0x03
    const val SETTINGS: Long = 0x04
    const val PUSH_PROMISE: Long = 0x05
    const val GOAWAY: Long = 0x07
    const val ORIGIN: Long = 0x0c
    const val MAX_PUSH_ID: Long = 0x0d

    /**
     * True for the four codepoints HTTP/2 used that HTTP/3 reserves: 0x02, 0x06, 0x08 and 0x09
     * (PRIORITY, PING, WINDOW_UPDATE, CONTINUATION). RFC 9114 section 7.2.8 requires that receiving
     * one is a connection error of type H3_FRAME_UNEXPECTED.
     *
     * <p>Phase 1 only needs to recognise them. Phase 2 sends them deliberately, to find out whether
     * a target actually enforces the rule.
     */
    @JvmStatic
    fun isReservedHttp2Type(type: Long): Boolean {
        return type == 0x02L || type == 0x06L || type == 0x08L || type == 0x09L
    }

    /**
     * True for the grease codepoints of the form {@code 0x1f * N + 0x21}, which RFC 9114
     * section 7.2.8 reserves to exercise the requirement that unknown types be ignored.
     *
     * <p>Not hypothetical: quic.tech sent two of these ahead of HEADERS on a request stream during
     * the phase 1 spikes.
     */
    @JvmStatic
    fun isGreaseType(type: Long): Boolean {
        return type >= 0x21 && (type - 0x21) % 0x1f == 0L
    }

    /** A human-readable name for logging and test failures. Unknown types render as hex. */
    @JvmStatic
    fun name(type: Long): String {
        if (type == DATA) return "DATA"
        if (type == HEADERS) return "HEADERS"
        if (type == CANCEL_PUSH) return "CANCEL_PUSH"
        if (type == SETTINGS) return "SETTINGS"
        if (type == PUSH_PROMISE) return "PUSH_PROMISE"
        if (type == GOAWAY) return "GOAWAY"
        if (type == ORIGIN) return "ORIGIN"
        if (type == MAX_PUSH_ID) return "MAX_PUSH_ID"
        if (isReservedHttp2Type(type)) return "RESERVED_H2(0x" + java.lang.Long.toHexString(type) + ")"
        if (isGreaseType(type)) return "GREASE(0x" + java.lang.Long.toHexString(type) + ")"
        return "UNKNOWN(0x" + java.lang.Long.toHexString(type) + ")"
    }
}
