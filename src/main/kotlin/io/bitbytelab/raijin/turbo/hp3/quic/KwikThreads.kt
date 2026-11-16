package io.bitbytelab.raijin.turbo.hp3.quic

/**
 * Threads for work that blocks inside Kwik: a handshake, a response read, or a peer stream that is
 * read for as long as its connection lives.
 *
 * <p>Kwik waits for stream data inside {@code synchronized (addMonitor)}
 * ({@code tech.kwik.core.stream.StreamInputStreamImpl}). Before JDK 24 a virtual thread blocked in
 * a synchronized block pins its carrier and the scheduler does not compensate, so every such reader
 * costs a carrier for as long as it waits. A server's control and QPACK streams are read for the
 * life of the connection, so on those JDKs a pool with as many connections as there are carriers
 * would leave none for any other virtual thread in the JVM. There the threads are platform threads,
 * made daemon so one waiting on a peer that never answers cannot hold the JVM open. JEP 491 removed
 * the pinning in JDK 24, and from there virtual threads cost heap rather than OS threads.
 */
object KwikThreads {

    /**
     * The first JDK where a virtual thread no longer pins its carrier while blocked inside a
     * synchronized block (JEP 491).
     */
    private const val FIRST_JDK_WITHOUT_MONITOR_PINNING = 24

    /** Whether [jdkFeatureVersion] carries blocked virtual threads without pinning a carrier. */
    @JvmStatic
    fun prefersVirtualThreads(jdkFeatureVersion: Int): Boolean =
        jdkFeatureVersion >= FIRST_JDK_WITHOUT_MONITOR_PINNING

    /** A builder for a thread that will block inside Kwik on the running JVM. */
    @JvmStatic
    fun blockingThread(name: String): Thread.Builder =
        if (prefersVirtualThreads(Runtime.version().feature())) {
            Thread.ofVirtual().name(name)
        } else {
            Thread.ofPlatform().daemon().name(name)
        }
}
