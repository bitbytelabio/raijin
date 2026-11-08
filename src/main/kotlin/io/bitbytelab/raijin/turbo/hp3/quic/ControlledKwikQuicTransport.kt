package io.bitbytelab.raijin.turbo.hp3.quic

import tech.kwik.core.DatagramSocketFactory
import tech.kwik.core.QuicClientConnection
import tech.kwik.core.cc.CongestionController
import tech.kwik.core.send.SenderImpl
import tech.kwik.core.frame.QuicFrame
import tech.kwik.core.impl.QuicConnectionImpl
import tech.kwik.core.log.Logger
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.UncheckedIOException
import java.util.concurrent.atomic.AtomicInteger
import java.util.function.Consumer

class ControlledKwikQuicTransport private constructor(
    private val connection: QuicClientConnection?,
    private val bundleSender: AtomicBundleSender,
) : SdaCapableQuicTransport {

    interface AtomicBundleSender {
        fun maxPacketSize(): Int

        fun maxShortHeaderPacketOverhead(): Int

        @Throws(IOException::class)
        fun submit(bundle: AtomicStreamFrameBundle, lostCallback: Consumer<QuicFrame>)

        fun cancelConfirmation(bundle: AtomicStreamFrameBundle) {
        }
    }

    /** Kwik's own count of bytes sent and not yet acknowledged, or null if it could not be found. */
    private val congestionController: CongestionController? = findCongestionController(connection)

    /**
     * The largest packet the active path will carry, which is the ceiling any single-datagram
     * claim has to fit inside. Exposed so a test can assert against the connection's own limit
     * rather than a number copied from it.
     */
    fun maxPacketSize(): Int {
        return bundleSender.maxPacketSize()
    }

    override fun singleDatagramFrameBudget(maximumDatagramSize: Int): Int {
        if (maximumDatagramSize < 1) {
            throw IllegalArgumentException("maximumDatagramSize must be positive")
        }
        return Math.min(maximumDatagramSize, bundleSender.maxPacketSize()) -
            bundleSender.maxShortHeaderPacketOverhead()
    }

    @Throws(IOException::class)
    override fun sendSingleDatagram(
        fragments: List<StreamFragment>,
        maximumDatagramSize: Int,
        retransmissions: Int) {
        prepareSingleDatagram(fragments, maximumDatagramSize, retransmissions).send()
    }

    override fun prepareSingleDatagram(
        fragments: List<StreamFragment>,
        maximumDatagramSize: Int,
        retransmissions: Int): SdaCapableQuicTransport.PreparedDatagram {
        if (retransmissions < 0) {
            throw IllegalArgumentException("retransmissions must be non-negative")
        }

        val bundle = AtomicStreamFrameBundle.from(fragments)
        // The same number a batch reserved against while it was being staged, so a batch that was
        // allowed to grow to the edge is not refused at the edge.
        val frameBudget = singleDatagramFrameBudget(maximumDatagramSize)
        val packetLimit = Math.min(maximumDatagramSize, bundleSender.maxPacketSize())
        val overhead = bundleSender.maxShortHeaderPacketOverhead()
        if (bundle.getFrameLength() > frameBudget) {
            throw IllegalArgumentException(
                "SDA release requires " + (bundle.getFrameLength() + overhead) +
                    " bytes but limit is " + packetLimit +
                    ". This batch is too large for one datagram. Note that a batch costs" +
                    " more on every gate after the first on the same connection: each" +
                    " request carries its stream ID as a varint, and a varint grows at" +
                    " 64 and again at 16384: the first gate's IDs cost a byte each, the" +
                    " next twenty or so cost two, and past stream 16384 they cost four." +
                    " So a batch that fitted a moment ago can stop fitting. Use" +
                    " gateMode='qpack' to release on the QPACK encoder stream instead," +
                    " which is bounded by the server's SETTINGS_QPACK_BLOCKED_STREAMS" +
                    " rather than by a datagram and needs the server to advertise that" +
                    " and QPACK_MAX_TABLE_CAPACITY, or queue a smaller batch.")
        }

        val remainingRetransmissions = AtomicInteger(retransmissions)
        val lostCallback: Consumer<QuicFrame> = object : Consumer<QuicFrame> {
            override fun accept(ignored: QuicFrame) {
                val previous = remainingRetransmissions.getAndUpdate { value -> if (value > 0) value - 1 else 0 }
                if (previous > 0) {
                    try {
                        bundleSender.submit(bundle, this)
                    } catch (exception: IOException) {
                        throw UncheckedIOException(exception)
                    }
                }
            }
        }
        // All that is left for the instant the gate opens.
        return SdaCapableQuicTransport.PreparedDatagram {
            bundleSender.submit(bundle, lostCallback)
            try {
                bundle.awaitSent(RELEASE_SEND_TIMEOUT_MILLIS)
            } catch (failure: IOException) {
                bundleSender.cancelConfirmation(bundle)
                throw failure
            }
        }
    }

    @Throws(IOException::class)
    override fun openBidirectionalStream(): QuicStream {
        return KwikStream(requireConnection().createStream(true))
    }

    @Throws(IOException::class)
    override fun openUnidirectionalStream(): QuicStream {
        return KwikStream(requireConnection().createStream(false))
    }

    override fun onPeerStream(handler: Consumer<QuicStream>) {
        requireConnection().setPeerInitiatedStreamCallback { stream ->
            handler.accept(KwikStream(stream))
        }
    }

    override fun unackedBytes(): Long? {
        return if (congestionController == null) null else congestionController.getBytesInFlight()
    }

    override fun isConnected(): Boolean {
        return connection != null && connection.isConnected()
    }

    override fun close(errorCode: Long, reason: String) {
        requireConnection().close(errorCode, reason)
    }

    override fun close() {
        if (connection != null) {
            connection.close()
        }
    }

    private fun requireConnection(): QuicClientConnection {
        return connection ?: throw IllegalStateException("test transport has no QUIC connection")
    }

    private class KwikStream(private val delegate: tech.kwik.core.QuicStream) : QuicStream {
        override fun id(): Long {
            return delegate.getStreamId().toLong()
        }

        override fun input(): InputStream {
            return delegate.getInputStream()
        }

        override fun output(): OutputStream {
            return delegate.getOutputStream()
        }

        override fun isUnidirectional(): Boolean {
            return delegate.isUnidirectional()
        }

        @Throws(IOException::class)
        override fun finishSending() {
            delegate.getOutputStream().close()
        }

        override fun resetStream(errorCode: Long) {
            delegate.resetStream(errorCode)
        }

        override fun stopSending(errorCode: Long) {
            delegate.abortReading(errorCode)
        }
    }

    companion object {
        private const val RELEASE_SEND_TIMEOUT_MILLIS: Long = 5_000

        /**
         * Reaches Kwik's congestion controller, which counts the bytes in flight.
         *
         * <p>By reflection because the only route to it is {@code QuicConnectionImpl.getSender()},
         * which is protected. The two hops past it are public API on a public class and a public
         * interface, so this is one accessibility check rather than a walk through internals — but
         * it is still coupled to a method name in a dependency, so a failure to find it is not fatal.
         * Without it a gate falls back to the fixed wait it always used to take.
         *
         * <p>The alternative was Statistics.dataBytesSent(), which getStats() hands over publicly.
         * Measured, that is already at the batch's full staged total the instant the last stage()
         * returns — Kwik counts a byte when it packs it, not when the peer has it — so it cannot say
         * whether anything arrived. Bytes in flight can: on a 100-request batch it held at the
         * staged value for 17ms and then dropped to zero.
         */
        private fun findCongestionController(connection: QuicClientConnection?): CongestionController? {
            if (connection == null) {
                return null
            }
            return try {
                val getSender = QuicConnectionImpl::class.java.getDeclaredMethod("getSender")
                getSender.isAccessible = true
                val sender = getSender.invoke(connection) as SenderImpl?
                sender?.getCongestionController()
            } catch (failure: ReflectiveOperationException) {
                null
            } catch (failure: RuntimeException) {
                null
            }
        }

        @JvmStatic
        @Throws(IOException::class)
        fun connect(host: String, port: Int, config: QuicConfig): ControlledKwikQuicTransport {
            return connect(host, port, config, QuicSockets.highThroughput(), null)
        }

        @JvmStatic
        @Throws(IOException::class)
        internal fun connectForTest(
            host: String,
            port: Int,
            config: QuicConfig,
            socketFactory: DatagramSocketFactory?,
            logger: Logger?): ControlledKwikQuicTransport {
            return connect(host, port, config, socketFactory, logger)
        }

        @Throws(IOException::class)
        private fun connect(
            host: String,
            port: Int,
            config: QuicConfig,
            socketFactory: DatagramSocketFactory?,
            logger: Logger?): ControlledKwikQuicTransport {
            val builder = QuicClientConnection.newBuilder()
                .host(host)
                .port(port)
                .applicationProtocol("h3")
                .connectTimeout(config.handshakeTimeout())
                .maxIdleTimeout(config.idleTimeout())
                .maxOpenPeerInitiatedUnidirectionalStreams(16)
            val releaseTracker = ReleaseTrackingLogger()

            if (socketFactory != null) {
                builder.socketFactory(socketFactory)
            }
            builder.logger(releaseTracker.wrap(logger))

            if (!config.verifyCertificates()) {
                builder.noServerCertificateCheck()
            }

            val connection = builder.build()
            connection.connect()
            val implementation = connection as QuicConnectionImpl
            return ControlledKwikQuicTransport(
                connection,
                object : AtomicBundleSender {
                    override fun maxPacketSize(): Int {
                        return implementation.getMaxPacketSize()
                    }

                    override fun maxShortHeaderPacketOverhead(): Int {
                        return implementation.getMaxShortHeaderPacketOverhead()
                    }

                    override fun submit(
                        bundle: AtomicStreamFrameBundle,
                        lostCallback: Consumer<QuicFrame>) {
                        releaseTracker.expect(bundle)
                        try {
                            implementation.send(bundle, lostCallback, true)
                        } catch (failure: RuntimeException) {
                            releaseTracker.cancel(bundle)
                            throw failure
                        } catch (failure: Error) {
                            releaseTracker.cancel(bundle)
                            throw failure
                        }
                    }

                    override fun cancelConfirmation(bundle: AtomicStreamFrameBundle) {
                        releaseTracker.cancel(bundle)
                    }
                })
        }

        @JvmStatic
        internal fun forTest(bundleSender: AtomicBundleSender): ControlledKwikQuicTransport {
            return ControlledKwikQuicTransport(null, bundleSender)
        }
    }
}
