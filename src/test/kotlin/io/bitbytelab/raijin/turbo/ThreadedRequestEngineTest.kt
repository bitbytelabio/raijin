package io.bitbytelab.raijin.turbo

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class ThreadedRequestEngineTest {

    @BeforeEach
    fun liveTurbo() {
        Utils.unloaded = false
    }

    /** A loopback port nothing listens on, so no worker ever connects. */
    private fun closedPort(): Int = ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { it.localPort }

    @Test
    fun `a stop while start waits for connections stands, and start returns at once`() {
        val engine = ThreadedRequestEngine(
            "http://127.0.0.1:${closedPort()}", 1, 10, 1, 1, 0, 0L, { _, _ -> false }, 1, null, 1024, false,
        )
        val starter = thread(name = "turbo-test-start") { engine.start(30) }
        try {
            // start() waits on the connection latch, which no worker can count down.
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (starter.state != Thread.State.TIMED_WAITING && System.nanoTime() < deadline) Thread.sleep(5)
            assertEquals(Thread.State.TIMED_WAITING, starter.state, "start() never got to waiting for connections")

            engine.cancel()
            starter.join(5_000)

            assertFalse(starter.isAlive, "start() kept waiting for connections after the stop")
            // start() used to set the run live once its wait ended, undoing the stop.
            assertEquals(3, engine.runState.get())
            assertThrows<IllegalStateException> { engine.queue("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n") }
        } finally {
            engine.cancel()
            starter.join(1_000)
        }
    }
}
