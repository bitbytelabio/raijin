package io.bitbytelab.raijin.turbo.hp3.quic

/**
 * Threads for work that blocks inside Kwik: a handshake, a response read, or a peer stream that is
 * read for as long as its connection lives.
 *
 * <p>Kwik waits for stream data inside {@code synchronized (addMonitor)}
 * ({@code tech.kwik.core.stream.StreamInputStreamImpl}). Since JEP 491 (JDK 24) a virtual thread
 * blocked there no longer pins its carrier, and Raijin requires Java 25, so these threads are
 * virtual.
 */
object KwikThreads {

    /** A builder for a thread that will block inside Kwik. */
    @JvmStatic
    fun blockingThread(name: String): Thread.Builder = Thread.ofVirtual().name(name)
}
