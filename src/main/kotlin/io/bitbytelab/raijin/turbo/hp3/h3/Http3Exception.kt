package io.bitbytelab.raijin.turbo.hp3.h3

import java.io.IOException

/**
 * An HTTP/3 protocol error, carrying the error code to close the connection or stream with
 * (RFC 9114 section 8.1).
 *
 * <p>Extends {@link IOException} because every path that raises one is already reading or writing a
 * QUIC stream, and callers should not have to catch two unrelated exception families.
 */
open class Http3Exception(
    private val errorCode: Long,
    message: String?,
) : IOException(message + " [0x" + java.lang.Long.toHexString(errorCode) + "]") {

    fun errorCode(): Long {
        return errorCode
    }

    companion object {
        /** RFC 9114 section 8.1 error codes, as used on the wire. */
        const val H3_GENERAL_PROTOCOL_ERROR: Long = 0x0101
        const val H3_INTERNAL_ERROR: Long = 0x0102
        const val H3_STREAM_CREATION_ERROR: Long = 0x0103
        const val H3_CLOSED_CRITICAL_STREAM: Long = 0x0104
        const val H3_FRAME_UNEXPECTED: Long = 0x0105
        const val H3_FRAME_ERROR: Long = 0x0106
        const val H3_EXCESSIVE_LOAD: Long = 0x0107
        const val H3_ID_ERROR: Long = 0x0108
        const val H3_SETTINGS_ERROR: Long = 0x0109
        const val H3_MISSING_SETTINGS: Long = 0x010a
        const val H3_REQUEST_CANCELLED: Long = 0x010c
        const val H3_MESSAGE_ERROR: Long = 0x010e
        const val QPACK_DECOMPRESSION_FAILED: Long = 0x0200
        const val QPACK_ENCODER_STREAM_ERROR: Long = 0x0201
        const val QPACK_DECODER_STREAM_ERROR: Long = 0x0202
    }
}
