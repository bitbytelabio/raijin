package io.bitbytelab.raijin.turbo.hp3.quic

import tech.kwik.core.log.Logger
import tech.kwik.core.log.NullLogger
import tech.kwik.core.packet.QuicPacket
import java.lang.reflect.InvocationHandler
import java.lang.reflect.Proxy
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

/** Marks an SDA bundle after Kwik's UDP socket send has returned. */
internal class ReleaseTrackingLogger : NullLogger() {
    private val pending: MutableSet<AtomicStreamFrameBundle> = ConcurrentHashMap.newKeySet()

    fun wrap(delegate: Logger?): Logger {
        if (delegate == null) {
            return this
        }
        return Proxy.newProxyInstance(
            Logger::class.java.classLoader,
            arrayOf<Class<*>>(Logger::class.java),
            InvocationHandler { _, method, arguments ->
                if (method.name == "sent" && arguments != null && arguments.size == 2) {
                    markSentArgument(arguments[1])
                }
                if (arguments != null) method.invoke(delegate, *arguments) else method.invoke(delegate)
            }) as Logger
    }

    fun expect(bundle: AtomicStreamFrameBundle) {
        pending.add(bundle)
    }

    fun cancel(bundle: AtomicStreamFrameBundle) {
        pending.remove(bundle)
    }

    override fun sent(sent: Instant, packet: QuicPacket) {
        markSent(listOf(packet))
    }

    override fun sent(sent: Instant, packets: MutableList<QuicPacket>) {
        markSent(packets)
    }

    private fun markSentArgument(packets: Any?) {
        if (packets is QuicPacket) {
            markSent(listOf(packets))
        } else if (packets is List<*>) {
            markSent(packets.filterIsInstance<QuicPacket>())
        }
    }

    private fun markSent(packets: List<QuicPacket>) {
        if (pending.isEmpty()) {
            return
        }
        val sentAtNanos = System.nanoTime()
        packets.stream()
            .flatMap { packet -> packet.frames.stream() }
            .filter(AtomicStreamFrameBundle::class.java::isInstance)
            .map(AtomicStreamFrameBundle::class.java::cast)
            .filter { pending.remove(it) }
            .forEach { bundle -> bundle.markSent(sentAtNanos) }
    }
}
