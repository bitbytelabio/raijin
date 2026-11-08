package io.bitbytelab.raijin.turbo.hp3.h3

import java.io.IOException
import java.io.OutputStream

/**
 * Serialises HTTP/3 frames, RFC 9114 section 7.1.
 *
 * <p>This is the primary control seam of the whole extension. The general
 * {@link #write(OutputStream, long, byte[])} takes an arbitrary type and payload and is what the
 * typed helpers are built from, so emitting a reserved codepoint, a grease type, or a frame whose
 * declared length disagrees with its payload is a matter of calling a different method rather than
 * bypassing the codec.
 *
 * <p>Nothing here validates. That is deliberate: validation belongs to a peer, and the point of this
 * class is to be able to say exactly what we mean.
 */
object Http3FrameWriter {

    /** Writes {@code type}, the payload's length, then the payload. */
    @JvmStatic
    @Throws(IOException::class)
    fun write(out: OutputStream, type: Long, payload: ByteArray) {
        VarInt.write(out, type)
        VarInt.write(out, payload.size.toLong())
        out.write(payload)
    }

    @JvmStatic
    @Throws(IOException::class)
    fun write(out: OutputStream, frame: Http3Frame) {
        write(out, frame.type(), frame.payload())
    }

    /** Returns the frame as bytes rather than writing it to a stream. */
    @JvmStatic
    fun toBytes(type: Long, payload: ByteArray): ByteArray {
        val typeBytes = VarInt.encode(type)
        val lengthBytes = VarInt.encode(payload.size.toLong())
        val out = ByteArray(typeBytes.size + lengthBytes.size + payload.size)
        System.arraycopy(typeBytes, 0, out, 0, typeBytes.size)
        System.arraycopy(lengthBytes, 0, out, typeBytes.size, lengthBytes.size)
        System.arraycopy(payload, 0, out, typeBytes.size + lengthBytes.size, payload.size)
        return out
    }

    /**
     * Writes a frame whose declared length is {@code declaredLength} regardless of how many bytes
     * the payload actually contains. Produces an invalid frame on purpose.
     *
     * <p>Unused in phase 1 and reachable only from a caller that asks for it explicitly. It exists
     * because "the length field and the payload disagree" is a whole class of parser bug, and the
     * design commits to being able to express it.
     */
    @JvmStatic
    @Throws(IOException::class)
    fun writeWithDeclaredLength(out: OutputStream, type: Long, declaredLength: Long,
                               payload: ByteArray) {
        VarInt.write(out, type)
        VarInt.write(out, declaredLength)
        out.write(payload)
    }

    /**
     * Writes the type and length using deliberately non-minimal varint encodings. RFC 9000 permits
     * these and requires peers to accept them; not every implementation does.
     */
    @JvmStatic
    @Throws(IOException::class)
    fun writeWithVarIntWidths(out: OutputStream, type: Long, typeWidth: Int,
                             payload: ByteArray, lengthWidth: Int) {
        out.write(VarInt.encode(type, typeWidth))
        out.write(VarInt.encode(payload.size.toLong(), lengthWidth))
        out.write(payload)
    }

    @JvmStatic
    @Throws(IOException::class)
    fun writeData(out: OutputStream, body: ByteArray) {
        write(out, Http3FrameType.DATA, body)
    }

    @JvmStatic
    @Throws(IOException::class)
    fun writeHeaders(out: OutputStream, encodedFieldSection: ByteArray) {
        write(out, Http3FrameType.HEADERS, encodedFieldSection)
    }
}
