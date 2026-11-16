package io.bitbytelab.raijin.state

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Indexed message recording behind `websocket(action=get_messages, since_index=...)`: index
 * allocation and storage are one step, so a poller can never skip a frame. `awaitPage` is the same
 * read for a caller that waits (`wait_message`, `fuzz`): it must neither poll nor miss a frame.
 */
class WebSocketConnectionTest {

    private fun connection() = WebSocketConnection("ws-001", "wss://chat.test/ws", "2026-11-16T00:00:00Z")

    @Test
    fun `append assigns consecutive indices from zero`() {
        val c = connection()
        val first = c.append("client_to_server", "TEXT", "hi", 2)
        val second = c.append("server_to_client", "BINARY", "AAE=", 2)
        assertEquals(0L, first.index)
        assertEquals(1L, second.index)
        assertEquals(listOf(0L, 1L), c.page(-1, 100).messages.map { it.index })
        assertEquals(2, c.messageCount())
    }

    @Test
    fun `page returns only messages after since_index and reports the window`() {
        val c = connection()
        repeat(10) { c.append("server_to_client", "TEXT", "m$it", 2) }

        val page = c.page(sinceIndex = 6, limit = 100)
        assertEquals(listOf(7L, 8L, 9L), page.messages.map { it.index })
        assertEquals(0L, page.oldestIndex)
        assertEquals(10L, page.nextIndex)
        assertEquals(10, page.retained)
        assertEquals(0L, page.missed)
        assertFalse(page.hasMore)

        assertTrue(c.page(sinceIndex = 9, limit = 100).messages.isEmpty())
        assertTrue(c.page(sinceIndex = Long.MAX_VALUE, limit = 100).messages.isEmpty())
    }

    @Test
    fun `limit and direction filter page through matching messages without skipping`() {
        val c = connection()
        repeat(10) { i -> c.append(if (i % 2 == 0) "client_to_server" else "server_to_client", "TEXT", "m$i", 2) }

        val first = c.page(-1, 2, "server_to_client")
        assertEquals(listOf(1L, 3L), first.messages.map { it.index })
        assertTrue(first.hasMore)

        val rest = c.page(first.messages.last().index, 10, "server_to_client")
        assertEquals(listOf(5L, 7L, 9L), rest.messages.map { it.index })
        assertFalse(rest.hasMore)
    }

    @Test
    fun `a zero limit returns nothing but says more is waiting`() {
        val c = connection()
        c.append("server_to_client", "TEXT", "x", 1)
        val page = c.page(-1, 0)
        assertTrue(page.messages.isEmpty())
        assertTrue(page.hasMore)
    }

    @Test
    fun `eviction keeps the newest messages and reports what a slow poller missed`() {
        val c = connection()
        val total = WebSocketConnection.MAX_MESSAGES + 500
        repeat(total) { c.append("server_to_client", "TEXT", "m$it", 2) }

        assertEquals(WebSocketConnection.MAX_MESSAGES, c.messageCount())
        val fromStart = c.page(sinceIndex = -1, limit = 1)
        assertEquals(500L, fromStart.oldestIndex)
        assertEquals(total.toLong(), fromStart.nextIndex)
        assertEquals(500L, fromStart.missed)
        assertEquals(500L, fromStart.messages.single().index)

        // A poller that had read up to index 99 lost 100..499; one at 499 lost nothing.
        assertEquals(400L, c.page(sinceIndex = 99, limit = 1).missed)
        assertEquals(0L, c.page(sinceIndex = 499, limit = 1).missed)
        assertEquals(1000L, c.page(sinceIndex = 999, limit = 1).messages.single().index)
    }

    @Test
    fun `concurrent writers never leave a gap for a since_index poller`() {
        val c = connection()
        val writers = 4
        val perWriter = 400 // stays below MAX_MESSAGES, so nothing is evicted
        val total = writers * perWriter
        val pool = Executors.newFixedThreadPool(writers)
        val start = CountDownLatch(1)
        repeat(writers) { w ->
            pool.execute {
                start.await()
                repeat(perWriter) { i -> c.append("server_to_client", "TEXT", "w$w-$i", 4) }
            }
        }

        val seen = ArrayList<Long>(total)
        var since = -1L
        start.countDown()
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20)
        while (seen.size < total && System.nanoTime() < deadline) {
            val page = c.page(since, 7)
            assertEquals(0L, page.missed)
            page.messages.forEach { seen += it.index }
            if (page.messages.isNotEmpty()) since = page.messages.last().index
        }
        pool.shutdown()
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS))

        assertEquals((0L until total.toLong()).toList(), seen, "every index exactly once, in order")
    }

    @Test
    fun `markClosed reports only the first close`() {
        val c = connection()
        assertTrue(c.markClosed())
        assertFalse(c.markClosed())
        assertEquals("closed", c.status)
    }

    @Test
    fun `lastIndex follows the newest message`() {
        val c = connection()
        assertEquals(-1L, c.lastIndex())
        c.append("server_to_client", "TEXT", "a", 1)
        c.append("server_to_client", "TEXT", "b", 1)
        assertEquals(1L, c.lastIndex())
    }

    @Test
    fun `relabel changes the type of a retained message and ignores any other index`() {
        val c = connection()
        c.append("client_to_server", "TEXT", "a", 1)
        c.append("client_to_server", "TEXT", "b", 1)

        c.relabel(1, "TEXT_UNSENT")
        c.relabel(7, "TEXT_UNSENT")
        c.relabel(-1, "TEXT_UNSENT")

        val messages = c.page(-1, 10).messages
        assertEquals(listOf("TEXT", "TEXT_UNSENT"), messages.map { it.type })
        assertEquals(listOf("a", "b"), messages.map { it.payload })
    }

    @Test
    fun `a page says whether the connection was closed`() {
        val c = connection()
        assertFalse(c.page(-1, 10).closed)
        c.markClosed()
        assertTrue(c.page(-1, 10).closed)
    }

    // --- awaitPage: waiting for the next message instead of polling ---

    /** Far longer than any of these tests should take: a wait that runs this long has missed its wake-up. */
    private val longWait = TimeUnit.SECONDS.toNanos(30)

    @Test
    fun `awaitPage returns at once when a later message is already recorded`() {
        val c = connection()
        c.append("server_to_client", "TEXT", "a", 1)
        c.append("server_to_client", "TEXT", "b", 1)

        val started = System.nanoTime()
        val page = c.awaitPage(0, 10, longWait)

        assertEquals(listOf(1L), page.messages.map { it.index })
        assertFalse(page.closed)
        assertTrue(System.nanoTime() - started < longWait / 2, "must not wait when a message is there")
    }

    @Test
    fun `awaitPage blocks until the next message is appended`() {
        val c = connection()
        c.append("client_to_server", "TEXT", "ping", 4)
        val writer = thread {
            Thread.sleep(150)
            c.append("server_to_client", "TEXT", "pong", 4)
        }

        val page = c.awaitPage(0, 10, longWait)
        writer.join()

        assertEquals(listOf("pong"), page.messages.map { it.payload })
    }

    @Test
    fun `awaitPage returns an empty page once its timeout has passed`() {
        val c = connection()
        val timeout = TimeUnit.MILLISECONDS.toNanos(200)

        val started = System.nanoTime()
        val page = c.awaitPage(-1, 10, timeout)
        val waited = System.nanoTime() - started

        assertTrue(page.messages.isEmpty())
        assertFalse(page.closed)
        assertTrue(waited >= timeout, "returned after ${waited / 1_000_000} ms")
        assertTrue(waited < longWait / 2, "returned after ${waited / 1_000_000} ms")
    }

    @Test
    fun `a zero timeout reads what is there without waiting`() {
        val c = connection()
        assertTrue(c.awaitPage(-1, 10, 0).messages.isEmpty())
        c.append("server_to_client", "TEXT", "a", 1)
        assertEquals(1, c.awaitPage(-1, 10, 0).messages.size)
        // An index below -1 means the same as -1.
        assertEquals(1, c.awaitPage(-9, 10, 0).messages.size)
    }

    @Test
    fun `closing the connection releases a waiter`() {
        val c = connection()
        val closer = thread {
            Thread.sleep(150)
            c.markClosed()
        }

        val page = c.awaitPage(-1, 10, longWait)
        closer.join()

        assertTrue(page.messages.isEmpty())
        assertTrue(page.closed)
        // Nothing more arrives on a closed connection, so a later call does not wait either.
        val started = System.nanoTime()
        assertTrue(c.awaitPage(-1, 10, longWait).closed)
        assertTrue(System.nanoTime() - started < longWait / 2)
    }

    @Test
    fun `an interrupted waiter stops waiting`() {
        val c = connection()
        val failure = AtomicReference<Throwable>()
        val waiter = thread {
            try {
                c.awaitPage(-1, 10, longWait)
            } catch (t: Throwable) {
                failure.set(t)
            }
        }
        Thread.sleep(150)
        waiter.interrupt()
        waiter.join(TimeUnit.SECONDS.toMillis(20))

        assertTrue(failure.get() is InterruptedException, "got ${failure.get()}")
    }

    @Test
    fun `a waiter never misses a frame recorded by concurrent writers`() {
        val c = connection()
        val writers = 4
        val perWriter = 400 // stays below MAX_MESSAGES, so nothing is evicted
        val total = writers * perWriter
        val pool = Executors.newFixedThreadPool(writers)
        val start = CountDownLatch(1)
        repeat(writers) { w ->
            pool.execute {
                start.await()
                repeat(perWriter) { i ->
                    c.append("server_to_client", "TEXT", "w$w-$i", 4)
                    // Pauses let the waiter catch up and block, so both "found" and "woken" happen.
                    if (i % 50 == 0) Thread.sleep(1)
                }
            }
        }

        val seen = ArrayList<Long>(total)
        var since = -1L
        start.countDown()
        while (seen.size < total) {
            // One message per call: each of them has to be found, or to wake the waiter.
            val page = c.awaitPage(since, 1, longWait)
            assertEquals(0L, page.missed)
            val message = page.messages.singleOrNull() ?: break
            seen += message.index
            since = message.index
        }
        pool.shutdown()
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS))

        assertEquals((0L until total.toLong()).toList(), seen, "every index exactly once, in order")
    }
}
