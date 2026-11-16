package io.bitbytelab.raijin.events

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Ring-buffer sizing and ordering under concurrency, and leak-free client poll subscriptions. */
class EventBusTest {

    private val data: JsonObject = buildJsonObject {}

    @Test fun `size stays exact and ids stay ordered under concurrent emitters`() {
        val bus = EventBus(maxBufferSize = 500)
        val threads = 8
        val perThread = 2_000
        val pool = Executors.newFixedThreadPool(threads)
        val start = CountDownLatch(1)
        repeat(threads) { pool.submit { start.await(); repeat(perThread) { bus.emit("t", data) } } }
        start.countDown()
        pool.shutdown()
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS))

        assertEquals(500, bus.size())
        assertEquals((threads * perThread).toLong(), bus.lastId())
        val ids = bus.getEvents(0, Int.MAX_VALUE).map { it.id }
        assertEquals(500, ids.size)
        assertEquals((ids.first()..ids.last()).toList(), ids, "the buffer holds the newest events in id order, without gaps")
        assertEquals(bus.lastId(), ids.last())
    }

    @Test fun `clear keeps internal subscribers and resets the size`() {
        val bus = EventBus(maxBufferSize = 10)
        var internalSeen = 0
        bus.subscribeInternal(emptyList()) { internalSeen++ }
        bus.subscribe(emptyList()) { }
        bus.openPollSubscription(emptyList())
        repeat(3) { bus.emit("t", data) }

        bus.clear()
        assertEquals(0, bus.size())
        assertEquals(1, bus.pushSubscriberCount(), "only the internal subscriber survives")
        assertEquals(0, bus.pollSubscriptionCount())
        bus.emit("t", data)
        assertEquals(4, internalSeen)
        assertEquals(1, bus.size())
    }

    @Test fun `a poll subscription registers no callback and reads only new matching events`() {
        val bus = EventBus()
        bus.emit("proxy.request", data)
        val sub = bus.openPollSubscription(listOf("scanner.issue"))
        assertEquals(0, bus.pushSubscriberCount(), "poll subscriptions must not leak push callbacks")

        repeat(3) { bus.emit("proxy.request", data) }
        repeat(2) { bus.emit("scanner.issue", data) }
        val page = assertNotNull(bus.poll(sub.id))
        assertEquals(listOf("scanner.issue", "scanner.issue"), page.events.map { it.type })
        assertEquals(bus.lastId(), page.cursor)
        assertFalse(page.missed)

        assertTrue(assertNotNull(bus.poll(sub.id)).events.isEmpty(), "a second poll returns nothing new")
        bus.emit("scanner.issue", data)
        assertEquals(1, assertNotNull(bus.poll(sub.id)).events.size)
    }

    @Test fun `polling pages through matching events without skipping any`() {
        val bus = EventBus()
        val sub = bus.openPollSubscription(emptyList())
        repeat(5) { bus.emit("t", data) }
        val first = assertNotNull(bus.poll(sub.id, maxEvents = 2))
        val second = assertNotNull(bus.poll(sub.id, maxEvents = 2))
        val third = assertNotNull(bus.poll(sub.id, maxEvents = 2))
        assertEquals(listOf(1L, 2L, 3L, 4L, 5L), (first.events + second.events + third.events).map { it.id })
        assertTrue(assertNotNull(bus.poll(sub.id, maxEvents = 0)).events.isEmpty())
    }

    @Test fun `eviction before a poll is reported as missed`() {
        val bus = EventBus(maxBufferSize = 3)
        val sub = bus.openPollSubscription(emptyList())
        repeat(6) { bus.emit("t", data) }
        val page = assertNotNull(bus.poll(sub.id))
        assertTrue(page.missed)
        assertEquals(listOf(4L, 5L, 6L), page.events.map { it.id })
    }

    @Test fun `open poll subscriptions are capped, dropping the least recently used`() {
        val bus = EventBus()
        val first = bus.openPollSubscription(emptyList())
        val second = bus.openPollSubscription(emptyList())
        assertNotNull(bus.poll(first.id)) // first is now more recently used than second
        repeat(EventBus.MAX_POLL_SUBSCRIPTIONS - 1) { bus.openPollSubscription(emptyList()) }
        assertEquals(EventBus.MAX_POLL_SUBSCRIPTIONS, bus.pollSubscriptionCount())
        assertNull(bus.poll(second.id), "the least recently used subscription is dropped")
        assertNotNull(bus.poll(first.id))
    }

    @Test fun `unsubscribe reports whether something was removed`() {
        val bus = EventBus()
        val poll = bus.openPollSubscription(emptyList())
        val push = bus.subscribe(emptyList()) { }
        assertTrue(bus.unsubscribe(poll.id))
        assertTrue(bus.unsubscribe(push))
        assertFalse(bus.unsubscribe(poll.id))
        assertNull(bus.poll(poll.id))
    }
}
