package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.state.WebSocketConnection
import io.bitbytelab.raijin.state.WebSocketMessage
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * [WebSocketWait.collect] and [WebSocketFrameFilter], behind `websocket_wait_message` and the fuzz
 * windows: frames are found whether they were recorded before or during the wait, each message is
 * examined once, and the window, the idle time and the timeout are honoured.
 */
class WebSocketWaitTest {

    private fun connection() = WebSocketConnection("ws-001", "wss://chat.test/ws", "2026-11-17T00:00:00Z")

    private fun WebSocketConnection.server(text: String) = append("server_to_client", "TEXT", text, text.length)

    private fun message(type: String, payload: String, direction: String = "server_to_client") =
        WebSocketMessage(0, direction, type, payload, payload.length, "2026-11-17T00:00:00Z")

    private fun ms(millis: Long) = TimeUnit.MILLISECONDS.toNanos(millis)

    /** Far longer than any of these tests should take: a wait that runs this long has missed its wake-up. */
    private val longWait = TimeUnit.SECONDS.toNanos(30)

    private val any = WebSocketFrameFilter()

    @Test
    fun `the filter checks direction, frame kind and pattern, and a dropped frame counts as its kind`() {
        val text = message("TEXT", "Hello World")
        val dropped = message("TEXT_DROPPED", "secret", direction = "client_to_server")
        val binary = message("BINARY", Base64.getEncoder().encodeToString(byteArrayOf(0x00, 0xFF.toByte(), 0x41)))

        assertTrue(WebSocketFrameFilter(direction = "server_to_client").matches(text))
        assertFalse(WebSocketFrameFilter(direction = "server_to_client").matches(dropped))
        assertTrue(WebSocketFrameFilter(binary = false).matches(dropped))
        assertFalse(WebSocketFrameFilter(binary = false).matches(binary))
        assertTrue(WebSocketFrameFilter(binary = true).matches(binary))
        assertTrue(WebSocketFrameFilter(pattern = "hello world").matches(text), "patterns ignore case")
        assertFalse(WebSocketFrameFilter(pattern = "(?-i)hello world").matches(text))
        // A binary frame is matched on its bytes, not on its base64.
        assertTrue(WebSocketFrameFilter(pattern = "\\x00\\xFFA").matches(binary))
        assertFalse(WebSocketFrameFilter(pattern = "AP9B").matches(binary))
    }

    @Test
    fun `a matching frame that is already recorded is returned without waiting`() {
        val c = connection()
        c.server("ready")

        val started = System.nanoTime()
        val collected = WebSocketWait.collect(c, -1, any, longWait, maxFrames = 1)

        assertEquals(listOf("ready"), collected.frames.map { it.payload })
        assertEquals(0L, collected.cursor)
        assertTrue(System.nanoTime() - started < longWait / 2)
    }

    @Test
    fun `the wait skips frames the filter rejects and wakes for the one it accepts`() {
        val c = connection()
        val writer = thread {
            Thread.sleep(100)
            c.server("heartbeat")
            c.append("client_to_server", "TEXT", "reply?", 6)
            Thread.sleep(100)
            c.server("reply 42")
        }

        val collected = WebSocketWait.collect(
            c, -1, WebSocketFrameFilter(direction = "server_to_client", pattern = "^reply"), longWait, maxFrames = 1
        )
        writer.join()

        assertEquals(listOf(2L), collected.frames.map { it.index })
        assertEquals(2L, collected.cursor)
        assertEquals(3, collected.scanned, "every message examined once")
        assertFalse(collected.closed)
    }

    @Test
    fun `the window ends at its timeout, and the cursor continues where it stopped`() {
        val c = connection()
        c.server("noise 1")
        c.server("noise 2")
        val filter = WebSocketFrameFilter(pattern = "signal")

        val first = WebSocketWait.collect(c, -1, filter, ms(200), maxFrames = 1)

        assertTrue(first.frames.isEmpty())
        assertTrue(first.elapsedNanos >= ms(200), "returned after ${first.elapsedNanos / 1_000_000} ms")
        assertTrue(first.elapsedNanos < longWait / 2)
        assertEquals(1L, first.cursor)
        assertEquals(2, first.scanned)
        assertFalse(first.closed)

        c.server("signal")
        val second = WebSocketWait.collect(c, first.cursor, filter, longWait, maxFrames = 1)
        assertEquals(listOf("signal"), second.frames.map { it.payload })
        assertEquals(1, second.scanned, "nothing examined twice")
    }

    @Test
    fun `once frames arrived, the window ends after the idle time without another`() {
        val c = connection()
        repeat(3) { c.server("part $it") }

        // The window itself is long: only the idle time can end it this early.
        val collected = WebSocketWait.collect(c, -1, any, longWait, idleNanos = ms(300))

        assertEquals(listOf("part 0", "part 1", "part 2"), collected.frames.map { it.payload })
        assertTrue(collected.elapsedNanos >= ms(300), "returned after ${collected.elapsedNanos / 1_000_000} ms")
        assertTrue(collected.elapsedNanos < longWait / 2, "returned after ${collected.elapsedNanos / 1_000_000} ms")
        assertTrue(collected.firstFrameNanos in 0..collected.elapsedNanos)
    }

    @Test
    fun `without awaiting a first frame, a quiet connection ends the window after the idle time`() {
        val c = connection()

        val collected = WebSocketWait.collect(c, -1, any, longWait, idleNanos = ms(150), awaitFirst = false)

        assertTrue(collected.frames.isEmpty())
        assertTrue(collected.elapsedNanos >= ms(150))
        assertTrue(collected.elapsedNanos < longWait / 2)
        assertEquals(-1L, collected.cursor)
    }

    @Test
    fun `a zero window reads what is recorded, and untilIndex bounds the range`() {
        val c = connection()
        repeat(5) { c.server("m$it") }

        val all = WebSocketWait.collect(c, -1, any, 0)
        assertEquals(5, all.frames.size)

        val bounded = WebSocketWait.collect(c, 0, any, 0, untilIndex = 3)
        assertEquals(listOf(1L, 2L), bounded.frames.map { it.index })
        assertEquals(2L, bounded.cursor)
        assertFalse(bounded.closed)

        assertTrue(WebSocketWait.collect(c, 2, any, 0, untilIndex = 3).frames.isEmpty())
    }

    @Test
    fun `a closed connection ends the wait once its last frame was examined`() {
        val c = connection()
        c.server("bye")
        c.markClosed()

        val started = System.nanoTime()
        val collected = WebSocketWait.collect(c, -1, WebSocketFrameFilter(pattern = "never"), longWait)

        assertTrue(collected.closed)
        assertEquals(1, collected.scanned)
        assertTrue(System.nanoTime() - started < longWait / 2)
    }

    @Test
    fun `a close during the wait releases the waiter`() {
        val c = connection()
        val closer = thread {
            Thread.sleep(150)
            c.markClosed()
        }

        val collected = WebSocketWait.collect(c, -1, any, longWait, maxFrames = 1)
        closer.join()

        assertTrue(collected.frames.isEmpty())
        assertTrue(collected.closed)
        assertTrue(collected.elapsedNanos < longWait / 2)
    }

    @Test
    fun `evicted messages in the range are reported as missed`() {
        val c = connection()
        repeat(WebSocketConnection.MAX_MESSAGES + 10) { c.server("m$it") }

        val collected = WebSocketWait.collect(c, -1, any, 0)

        assertEquals(10L, collected.missed)
        assertEquals(WebSocketConnection.MAX_MESSAGES, collected.frames.size)
        assertEquals(10L, collected.frames.first().index)

        // A range that ends before the oldest retained message is all missed, and the read still ends.
        val gone = WebSocketWait.collect(c, -1, any, 0, untilIndex = 5)
        assertTrue(gone.frames.isEmpty())
        assertEquals(5L, gone.missed)
    }

    @Test
    fun `a filtered waiter never misses a matching frame from concurrent writers`() {
        val c = connection()
        val writers = 4
        val perWriter = 300 // 1200 messages: below MAX_MESSAGES, so nothing is evicted
        val pool = Executors.newFixedThreadPool(writers)
        val start = CountDownLatch(1)
        repeat(writers) { w ->
            pool.execute {
                start.await()
                repeat(perWriter) { i ->
                    c.server(if (i % 2 == 0) "noise w$w-$i" else "hit w$w-$i")
                    if (i % 40 == 0) Thread.sleep(1)
                }
            }
        }

        val hits = ArrayList<WebSocketMessage>()
        val filter = WebSocketFrameFilter(pattern = "^hit ")
        var cursor = -1L
        var scanned = 0
        start.countDown()
        while (hits.size < writers * perWriter / 2) {
            val collected = WebSocketWait.collect(c, cursor, filter, longWait, maxFrames = 1)
            assertEquals(0L, collected.missed)
            val hit = collected.frames.singleOrNull() ?: break
            hits += hit
            cursor = collected.cursor
            scanned += collected.scanned
        }
        pool.shutdown()
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS))

        val expected = (0 until writers).flatMap { w -> (1 until perWriter step 2).map { i -> "hit w$w-$i" } }.toSet()
        assertEquals(expected, hits.map { it.payload }.toSet())
        assertEquals(hits.size, expected.size, "no hit returned twice")
        assertEquals(hits.map { it.index }.sorted(), hits.map { it.index }, "in index order")
        assertTrue(scanned <= writers * perWriter, "no message examined twice")
    }
}
