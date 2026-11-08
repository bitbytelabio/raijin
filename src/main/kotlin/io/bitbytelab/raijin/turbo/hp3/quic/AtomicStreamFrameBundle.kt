package io.bitbytelab.raijin.turbo.hp3.quic

import tech.kwik.core.frame.FrameProcessor
import tech.kwik.core.frame.StreamFrame
import tech.kwik.core.packet.PacketMetaData
import tech.kwik.core.packet.QuicPacket
import tech.kwik.core.frame.QuicFrame
import java.io.IOException
import java.nio.ByteBuffer
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

class AtomicStreamFrameBundle private constructor(inputFrames: List<StreamFrame>) : QuicFrame() {

    private val frames: List<StreamFrame>
    private val frameLengthBytes: Int
    private val sentAtNanos = CompletableFuture<Long>()

    init {
        if (inputFrames.isEmpty()) {
            throw IllegalArgumentException("an atomic stream bundle must contain at least one frame")
        }
        this.frames = java.util.List.copyOf(inputFrames)
        this.frameLengthBytes = inputFrames.sumOf { it.getFrameLength() }
    }

    fun streamFrames(): List<StreamFrame> {
        return frames
    }

    /** Called by the transport logger after the datagram carrying this bundle has been sent. */
    internal fun markSent(timestampNanos: Long) {
        sentAtNanos.complete(timestampNanos)
    }

    @Throws(IOException::class)
    internal fun awaitSent(timeoutMillis: Long): Long {
        try {
            return sentAtNanos.get(timeoutMillis, TimeUnit.MILLISECONDS)
        } catch (exception: InterruptedException) {
            Thread.currentThread().interrupt()
            throw IOException("Interrupted while waiting for the release datagram to be sent", exception)
        } catch (exception: ExecutionException) {
            throw IOException("The release datagram could not be sent", exception.cause)
        } catch (exception: TimeoutException) {
            throw IOException("The release datagram was not sent within " + timeoutMillis + "ms", exception)
        }
    }

    override fun accept(frameProcessor: FrameProcessor, packet: QuicPacket, metaData: PacketMetaData) {
        frames.forEach { frame -> frame.accept(frameProcessor, packet, metaData) }
    }

    override fun getFrameLength(): Int {
        return frameLengthBytes
    }

    override fun serialize(buffer: ByteBuffer) {
        if (buffer.remaining() < frameLengthBytes) {
            throw IllegalArgumentException("insufficient buffer space for atomic stream bundle")
        }
        frames.forEach { frame -> frame.serialize(buffer) }
    }

    companion object {
        @JvmStatic
        fun from(fragments: List<StreamFragment>?): AtomicStreamFrameBundle {
            if (fragments == null) {
                throw IllegalArgumentException("fragments must not be null")
            }
            return AtomicStreamFrameBundle(fragments.map { fragment ->
                StreamFrame(
                    fragment.streamId(),
                    fragment.offset(),
                    fragment.data(),
                    fragment.fin())
            })
        }

        /**
         * What one fragment will cost the release it goes into.
         *
         * <p>Measured by building the frame rather than by adding up varint widths, so a batch that
         * reserves budget per request reserves the same number the release later adds up. Two
         * statements of one size drift apart, and the one that drifts is the one no traffic goes
         * through.
         */
        @JvmStatic
        fun frameLengthOf(fragment: StreamFragment): Int {
            return from(listOf(fragment)).getFrameLength()
        }
    }
}
