package io.bitbytelab.raijin.turbo.hp3.h3

import java.io.EOFException
import java.io.IOException
import java.io.InputStream

/**
 * Parses a stream of HTTP/3 frames, RFC 9114 section 7.1.
 *
 * <p>Two read modes, because "unknown" and "reserved" are different failures. RFC 9114 section 7.2.8
 * requires that unknown frame types be ignored, and real servers rely on it — quic.tech sent two
 * grease frames ahead of HEADERS during the phase 1 spikes. The four codepoints HTTP/2 used are
 * reserved instead, and receiving one is a connection error, so those must be surfaced rather than
 * quietly dropped.
 */
class Http3FrameReader(
    private val input: InputStream,
    private val maxPayloadLength: Int,
) {

    constructor(input: InputStream) : this(input, DEFAULT_MAX_PAYLOAD_LENGTH)

    /**
     * Reads the next frame verbatim, whatever its type.
     *
     * @return the frame, or null at a clean end of stream
     */
    @Throws(IOException::class)
    fun readFrame(): Http3Frame? {
        val type = VarInt.read(input)
        if (type < 0) {
            return null // clean end of stream between frames
        }

        val length = VarInt.read(input)
        if (length < 0) {
            throw EOFException("stream ended after frame type " + Http3FrameType.name(type) +
                ", before its length")
        }
        if (length > maxPayloadLength) {
            throw Http3Exception(Http3Exception.H3_EXCESSIVE_LOAD,
                Http3FrameType.name(type) + " declares a " + length +
                    " byte payload, over the " + maxPayloadLength + " byte limit")
        }

        val payload = input.readNBytes(length.toInt())
        if (payload.size < length) {
            throw EOFException(Http3FrameType.name(type) + " declares " + length +
                " payload bytes but the stream held " + payload.size)
        }
        return Http3Frame(type, payload)
    }

    /**
     * Reads the next frame, discarding any whose type HTTP/3 requires a receiver to ignore.
     * Reserved HTTP/2 codepoints are returned rather than skipped, so the caller can raise
     * {@code H3_FRAME_UNEXPECTED}.
     *
     * @return the frame, or null at a clean end of stream
     */
    @Throws(IOException::class)
    fun readFrameIgnoringUnknown(): Http3Frame? {
        var frame: Http3Frame?
        while (readFrame().also { frame = it } != null) {
            val f = frame!!
            if (isKnown(f.type()) || Http3FrameType.isReservedHttp2Type(f.type())) {
                return f
            }
            // Unknown type, including grease: discard the whole frame and read the next one.
        }
        return null
    }

    companion object {
        /**
         * Refuse to allocate a payload larger than this. A frame length is a 62-bit varint, so a
         * corrupt or hostile stream can otherwise ask for an unbounded allocation.
         */
        const val DEFAULT_MAX_PAYLOAD_LENGTH: Int = 16 * 1024 * 1024

        /** True for the frame types this implementation understands. */
        @JvmStatic
        internal fun isKnown(type: Long): Boolean {
            return type == Http3FrameType.DATA ||
                type == Http3FrameType.HEADERS ||
                type == Http3FrameType.CANCEL_PUSH ||
                type == Http3FrameType.SETTINGS ||
                type == Http3FrameType.PUSH_PROMISE ||
                type == Http3FrameType.GOAWAY ||
                type == Http3FrameType.ORIGIN ||
                type == Http3FrameType.MAX_PUSH_ID
        }
    }
}
