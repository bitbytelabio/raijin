package io.bitbytelab.raijin.turbo.hp3

import io.bitbytelab.raijin.turbo.hp3.quic.QuicStream
import io.bitbytelab.raijin.turbo.hp3.quic.SdaCapableQuicTransport
import io.bitbytelab.raijin.turbo.hp3.quic.StreamFragment
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
import java.util.function.Consumer

/** An in-memory QUIC stream: records what is written to it and serves [input] as the peer's bytes. */
internal class MemoryStream(
    private val id: Long,
    private val unidirectional: Boolean,
    private val input: InputStream = InputStream.nullInputStream(),
) : QuicStream {
    private val written = ByteArrayOutputStream()

    @Volatile
    var finished = false
        private set

    /** Makes every write and finish fail, the way a stream the peer reset refuses them. */
    @Volatile
    var refuseWrites = false

    @Volatile
    var stopSendingCode: Long? = null
        private set

    override fun id(): Long = id

    override fun input(): InputStream = input

    override fun output(): OutputStream = object : OutputStream() {
        override fun write(b: Int) {
            write(byteArrayOf(b.toByte()), 0, 1)
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            if (refuseWrites) throw IOException("output stream is reset")
            if (finished) throw IOException("output stream already closed")
            synchronized(written) { written.write(b, off, len) }
        }
    }

    override fun isUnidirectional(): Boolean = unidirectional

    override fun finishSending() {
        if (refuseWrites) throw IOException("output stream is reset")
        finished = true
    }

    override fun resetStream(errorCode: Long) {}

    override fun stopSending(errorCode: Long) {
        stopSendingCode = errorCode
    }

    fun writtenBytes(): ByteArray = synchronized(written) { written.toByteArray() }
}

/**
 * Peer bytes that stay open after they have been read, the way a peer's control stream does,
 * until [end] closes them.
 */
internal class HeldOpenInput(private val bytes: ByteArray) : InputStream() {
    private var position = 0
    private val ended = CountDownLatch(1)

    override fun read(): Int {
        if (position < bytes.size) return bytes[position++].toInt() and 0xff
        ended.await()
        return -1
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (len == 0) return 0
        if (position >= bytes.size) {
            ended.await()
            return -1
        }
        val count = minOf(len, bytes.size - position)
        System.arraycopy(bytes, position, b, off, count)
        position += count
        return count
    }

    fun end() = ended.countDown()
}

/** An in-memory transport that records the streams opened on it and how it was closed. */
internal class MemoryTransport : SdaCapableQuicTransport {
    private var nextBidirectionalId = 0L
    private var nextUnidirectionalId = 2L

    val openedStreams = CopyOnWriteArrayList<MemoryStream>()

    /** The application error code the transport was closed with, once it has been. */
    val closedWithError = CompletableFuture<Long>()
    val plainCloses = AtomicInteger()

    @Volatile
    var failUnidirectionalOpens = false

    @Volatile
    private var peerStreamHandler: Consumer<QuicStream>? = null

    @Synchronized
    override fun openBidirectionalStream(): QuicStream =
        MemoryStream(nextBidirectionalId, false).also {
            nextBidirectionalId += 4
            openedStreams += it
        }

    @Synchronized
    override fun openUnidirectionalStream(): QuicStream {
        if (failUnidirectionalOpens) throw IOException("peer allows no more unidirectional streams")
        return MemoryStream(nextUnidirectionalId, true).also {
            nextUnidirectionalId += 4
            openedStreams += it
        }
    }

    override fun onPeerStream(handler: Consumer<QuicStream>) {
        peerStreamHandler = handler
    }

    /** Hands [stream] over as one the peer opened. */
    fun openPeerStream(stream: QuicStream) {
        checkNotNull(peerStreamHandler) { "no peer stream handler registered" }.accept(stream)
    }

    /** The first stream we opened that declared [streamType] as its first byte. */
    fun unidirectionalStreamOfType(streamType: Int): MemoryStream =
        openedStreams.first { it.isUnidirectional() && it.writtenBytes().firstOrNull()?.toInt() == streamType }

    override fun isConnected(): Boolean = !closedWithError.isDone && plainCloses.get() == 0

    override fun close(errorCode: Long, reason: String) {
        closedWithError.complete(errorCode)
    }

    override fun close() {
        plainCloses.incrementAndGet()
    }

    override fun sendSingleDatagram(
        fragments: List<StreamFragment>,
        maximumDatagramSize: Int,
        retransmissions: Int,
    ) {
        throw UnsupportedOperationException("not used by these tests")
    }
}
