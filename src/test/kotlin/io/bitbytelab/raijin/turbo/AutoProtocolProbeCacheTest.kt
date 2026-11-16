package io.bitbytelab.raijin.turbo

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.net.URI
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class AutoProtocolProbeCacheTest {

    private fun <T> async(block: () -> T): CompletableFuture<T> {
        val future = CompletableFuture<T>()
        thread(isDaemon = true) {
            try {
                future.complete(block())
            } catch (failure: Throwable) {
                future.completeExceptionally(failure)
            }
        }
        return future
    }

    @Test
    fun `a protocol's result is published without waiting for a slower protocol in the same probe`() {
        val http1Started = CountDownLatch(1)
        val secondCallerStarted = CountDownLatch(1)
        val releaseHttp3 = CountDownLatch(1)
        val prober = AutoProtocolProber(
            mapOf(
                AutoProtocol.HTTP1 to AutoHandshakeProbe { _, _, _ ->
                    http1Started.countDown()
                    secondCallerStarted.await(5, TimeUnit.SECONDS)
                    AutoProbeResult.success(AutoProtocol.HTTP1, 1)
                },
                AutoProtocol.HTTP3 to AutoHandshakeProbe { _, _, _ ->
                    releaseHttp3.await(10, TimeUnit.SECONDS)
                    AutoProbeResult.success(AutoProtocol.HTTP3, 1)
                },
            ),
            timeout = Duration.ofSeconds(10),
        )
        val cache = AutoProtocolProbeCache(Duration.ofSeconds(60))
        val endpoint = URI("https://example.test").toURL()

        val both = async { cache.probe(prober, endpoint, false, setOf(AutoProtocol.HTTP1, AutoProtocol.HTTP3)) }
        assertTrue(http1Started.await(5, TimeUnit.SECONDS))
        // Finds HTTP/1 in flight under the first caller and waits on it.
        val http1Only = async { cache.probe(prober, endpoint, false, setOf(AutoProtocol.HTTP1)) }
        secondCallerStarted.countDown()

        try {
            val results = http1Only.get(3, TimeUnit.SECONDS)
            assertEquals(listOf(AutoProtocol.HTTP1), results.map { it.protocol })
            assertTrue(results.single().succeeded)
            assertFalse(both.isDone, "HTTP/3 is still probing")
        } finally {
            releaseHttp3.countDown()
        }
        assertEquals(
            listOf(AutoProtocol.HTTP1, AutoProtocol.HTTP3),
            both.get(5, TimeUnit.SECONDS).map { it.protocol },
        )
    }
}
