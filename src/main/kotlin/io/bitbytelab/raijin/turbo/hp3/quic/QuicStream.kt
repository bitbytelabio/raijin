package io.bitbytelab.raijin.turbo.hp3.quic

import java.io.InputStream
import java.io.OutputStream

/**
 * A single QUIC stream, exposed as raw bytes in both directions.
 *
 * <p>Deliberately no HTTP/3 knowledge. Everything above this reads and writes frames itself, which
 * is what makes it possible to put arbitrary bytes on a stream.
 */
interface QuicStream {

    fun id(): Long

    fun input(): InputStream

    fun output(): OutputStream

    fun isUnidirectional(): Boolean

    /** Closes our sending half, which is how HTTP/3 signals the end of a message. */
    @Throws(java.io.IOException::class)
    fun finishSending()

    /** Abruptly terminates the sending half with an application error code (RESET_STREAM). */
    fun resetStream(errorCode: Long)

    /** Asks the peer to stop sending, with an application error code (STOP_SENDING). */
    fun stopSending(errorCode: Long)
}
