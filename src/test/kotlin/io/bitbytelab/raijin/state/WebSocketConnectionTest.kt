package io.bitbytelab.raijin.state

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Indexed message recording behind `websocket(action=get_messages, since_index=...)`: index
 * allocation and storage are one step, so a poller can never skip a frame.
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
}
