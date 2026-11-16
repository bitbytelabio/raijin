package io.bitbytelab.raijin.events

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicLong
import java.time.Instant

/**
 * Represents a single event emitted by a Burp Suite handler.
 *
 * @property id Monotonically increasing event identifier used for cursor-based polling.
 * @property type Dot-separated event category (e.g. "proxy.request", "scanner.issue").
 * @property timestamp ISO-8601 timestamp of when the event was created.
 * @property data Arbitrary JSON payload specific to the event type.
 */
@Serializable
data class BurpEvent(
    val id: Long,
    val type: String,
    val timestamp: String,
    val data: JsonObject
)

/**
 * Thread-safe event bus backed by a bounded ring buffer.
 *
 * Events are emitted by Burp handler callbacks and consumed by MCP clients through cursor-based
 * polling (getEvents / getEventsByType, or a [PollSubscription] that keeps its own cursor), and by
 * in-process listeners through push callbacks (subscribe / subscribeInternal).
 *
 * When the buffer reaches [maxBufferSize], the oldest events are evicted to keep memory usage
 * bounded. Events enter the buffer in id order, so a cursor never skips an event still buffered.
 *
 * All public methods are safe to call from any thread.
 *
 * @param maxBufferSize Maximum number of events retained in the ring buffer.
 */
class EventBus(private val maxBufferSize: Int = 10000) {
    private val buffer = ConcurrentLinkedDeque<BurpEvent>()
    /** Guards id assignment, insertion and eviction together; reads iterate [buffer] without it. */
    private val emitLock = Any()
    private var nextId = 0L // guarded by emitLock

    @Volatile
    private var count = 0

    /** Every event with an id up to this one is already in [buffer] (or was evicted). */
    @Volatile
    private var lastCommittedId = 0L

    /** Separate from event ids so subscribing never leaves gaps in event ids. */
    private val subscriptionCounter = AtomicLong(0)
    private val subscribers = CopyOnWriteArrayList<EventSubscriber>()
    /** Access-ordered, so the least recently polled subscription is dropped first. Guarded by itself. */
    private val pollSubscriptions = LinkedHashMap<String, PollSubscription>(16, 0.75f, true)

    companion object {
        /** Cap on open [PollSubscription]s; beyond it the least recently used one is dropped. */
        const val MAX_POLL_SUBSCRIPTIONS = 64
    }

    /**
     * Emits a new event, appending it to the ring buffer and notifying
     * all matching subscribers.
     *
     * @param type Dot-separated event type string.
     * @param data JSON payload for the event.
     */
    fun emit(type: String, data: JsonObject) {
        val event = synchronized(emitLock) {
            val e = BurpEvent(id = ++nextId, type = type, timestamp = Instant.now().toString(), data = data)
            buffer.addLast(e)
            var n = count + 1
            while (n > maxBufferSize && buffer.pollFirst() != null) n--
            count = n
            lastCommittedId = e.id
            e
        }

        // Notify matching subscribers (type filter is empty == wildcard)
        subscribers.forEach { subscriber ->
            if (subscriber.types.isEmpty() || subscriber.types.contains(type)) {
                try {
                    subscriber.callback(event)
                } catch (_: Exception) {
                    // Swallow subscriber exceptions to avoid disrupting emitters
                }
            }
        }
    }

    /**
     * Returns events whose id is strictly greater than [sinceId], up to
     * [maxEvents] results. Used for cursor-based polling by MCP clients.
     */
    fun getEvents(sinceId: Long = 0, maxEvents: Int = 200): List<BurpEvent> {
        // Clamp to a non-negative, bounded ceiling so a hostile/negative
        // maxEvents can never trip Iterable.take()'s require(n >= 0).
        return buffer.filter { it.id > sinceId }.take(maxEvents.coerceIn(0, maxBufferSize))
    }

    /**
     * Returns up to [maxEvents] most-recent events in chronological (oldest-to-newest) order
     * by iterating from the tail in O(maxEvents).
     */
    fun getRecentEvents(maxEvents: Int = 50): List<BurpEvent> {
        val cap = maxEvents.coerceIn(0, maxBufferSize)
        if (cap == 0) return emptyList()
        val recent = ArrayList<BurpEvent>(cap)
        val it = buffer.descendingIterator()
        while (it.hasNext() && recent.size < cap) {
            recent.add(it.next())
        }
        recent.reverse()
        return recent
    }

    /**
     * Returns events matching any of the given [types] whose id is strictly
     * greater than [sinceId], up to [maxEvents] results.
     */
    fun getEventsByType(
        types: List<String>,
        sinceId: Long = 0,
        maxEvents: Int = 200
    ): List<BurpEvent> {
        // Clamp to a non-negative, bounded ceiling so a hostile/negative
        // maxEvents can never trip Iterable.take()'s require(n >= 0).
        return buffer.filter { it.id > sinceId && it.type in types }.take(maxEvents.coerceIn(0, maxBufferSize))
    }

    /**
     * Registers a push-based subscriber. When [types] is empty the subscriber
     * receives all events; otherwise only events whose type is in the list.
     * Removed by [clear]; use [subscribeInternal] for listeners that must outlive it.
     *
     * @return A subscription id that can be passed to [unsubscribe].
     */
    fun subscribe(types: List<String>, callback: (BurpEvent) -> Unit): String {
        val id = "sub-${subscriptionCounter.incrementAndGet()}"
        subscribers.add(EventSubscriber(id, types, callback, internal = false))
        return id
    }

    /**
     * Registers an internal infrastructure subscriber (e.g. Dashboard SSE stream, UI panels)
     * that is preserved across [clear] calls and only removed on [unsubscribe] or [clearAll].
     */
    fun subscribeInternal(types: List<String>, callback: (BurpEvent) -> Unit): String {
        val id = "sub-int-${subscriptionCounter.incrementAndGet()}"
        subscribers.add(EventSubscriber(id, types, callback, internal = true))
        return id
    }

    /**
     * Opens a client poll subscription for [types] (empty = all) starting after the latest event.
     * It holds no events and runs no callback: [poll] reads the ring buffer from its cursor. At most
     * [MAX_POLL_SUBSCRIPTIONS] stay open; the least recently used one is dropped beyond that.
     */
    fun openPollSubscription(types: List<String>): PollSubscription {
        val subscription = PollSubscription("sub-${subscriptionCounter.incrementAndGet()}", types.distinct(), lastCommittedId)
        synchronized(pollSubscriptions) {
            pollSubscriptions[subscription.id] = subscription
            val eldest = pollSubscriptions.keys.iterator()
            while (pollSubscriptions.size > MAX_POLL_SUBSCRIPTIONS && eldest.hasNext()) {
                eldest.next()
                eldest.remove()
            }
        }
        return subscription
    }

    /**
     * Returns up to [maxEvents] events matching subscription [subscriptionId] since its cursor and
     * advances the cursor past everything read or skipped. Null when no such subscription is open.
     */
    fun poll(subscriptionId: String, maxEvents: Int = 200): PollResult? {
        val subscription = synchronized(pollSubscriptions) { pollSubscriptions[subscriptionId] } ?: return null
        val limit = maxEvents.coerceIn(0, maxBufferSize)
        return synchronized(subscription) {
            val from = subscription.cursor
            val head = lastCommittedId
            val oldest = buffer.peekFirst()?.id
            val missed = head > from && (oldest == null || oldest > from + 1)
            val page = ArrayList<BurpEvent>()
            var lastRead = from
            var full = false
            for (event in buffer) {
                if (event.id <= from) continue
                if (event.id > head) break
                if (subscription.types.isEmpty() || event.type in subscription.types) {
                    if (page.size >= limit) {
                        full = true
                        break
                    }
                    page.add(event)
                }
                lastRead = event.id
            }
            subscription.cursor = if (full) lastRead else maxOf(head, from)
            PollResult(subscription, page, subscription.cursor, missed)
        }
    }

    /**
     * Removes a push subscriber or a poll subscription by its [subscriptionId].
     *
     * @return whether anything was removed.
     */
    fun unsubscribe(subscriptionId: String): Boolean {
        val callback = subscribers.removeIf { it.id == subscriptionId }
        val poll = synchronized(pollSubscriptions) { pollSubscriptions.remove(subscriptionId) } != null
        return callback || poll
    }

    /**
     * Clears the buffered events and removes client subscriptions (non-internal push subscribers
     * and poll subscriptions). Internal Dashboard SSE and Burp UI subscribers are preserved.
     */
    fun clear() {
        synchronized(emitLock) {
            buffer.clear()
            count = 0
        }
        subscribers.removeIf { !it.internal }
        synchronized(pollSubscriptions) { pollSubscriptions.clear() }
    }

    /**
     * Clears the entire buffer and removes ALL subscribers including internal ones.
     * Called only during extension unload.
     */
    fun clearAll() {
        synchronized(emitLock) {
            buffer.clear()
            count = 0
        }
        subscribers.clear()
        synchronized(pollSubscriptions) { pollSubscriptions.clear() }
    }

    /** Number of events currently in the buffer. */
    fun size(): Int = count

    /** The id of the most recently emitted event (0 if none). */
    fun lastId(): Long = lastCommittedId

    /** Open push subscribers (internal ones included); for diagnostics and tests. */
    internal fun pushSubscriberCount(): Int = subscribers.size

    /** Open poll subscriptions; for diagnostics and tests. */
    internal fun pollSubscriptionCount(): Int = synchronized(pollSubscriptions) { pollSubscriptions.size }
}

/**
 * A client poll subscription ([EventBus.openPollSubscription]): a type filter and a read cursor.
 * It holds no events; they stay in the ring buffer until read or evicted.
 *
 * @property id Subscription id, accepted by [EventBus.poll] and [EventBus.unsubscribe].
 * @property types Event types read by [EventBus.poll] (empty = all).
 */
class PollSubscription internal constructor(val id: String, val types: List<String>, startCursor: Long) {
    /** Id of the last event this subscription has read or skipped. */
    @Volatile
    var cursor: Long = startCursor
        internal set
}

/**
 * One page read by [EventBus.poll].
 *
 * @property cursor The subscription cursor after this read.
 * @property missed Events after the previous cursor were evicted before this read, so some
 *   matching events may be gone.
 */
data class PollResult(
    val subscription: PollSubscription,
    val events: List<BurpEvent>,
    val cursor: Long,
    val missed: Boolean
)

/**
 * Internal holder for a push-based event subscription.
 *
 * @property id Unique subscription identifier.
 * @property types Event types this subscriber is interested in (empty = all).
 * @property callback Invoked on the emitter's thread for each matching event.
 * @property internal True for infrastructure subscribers (Dashboard SSE, UI) preserved across [EventBus.clear].
 */
data class EventSubscriber(
    val id: String,
    val types: List<String>,
    val callback: (BurpEvent) -> Unit,
    val internal: Boolean = false
)
