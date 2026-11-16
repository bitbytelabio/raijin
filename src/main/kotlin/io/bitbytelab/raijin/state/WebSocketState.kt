package io.bitbytelab.raijin.state

import java.time.Instant
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Tracks a live WebSocket connection created through Burp's proxy or
 * programmatically via the WebSocket bridge.
 *
 * Messages live in a bounded buffer (the newest [MAX_MESSAGES]). [append] allocates the next index
 * and stores the message under one lock, so retained indices are contiguous and in order and a
 * `since_index` poller can never skip a frame that a concurrent writer is still recording.
 * [awaitPage] checks for new messages and starts waiting under that same lock, so a waiter cannot
 * miss a frame recorded in between either.
 *
 * @property connectionId Unique identifier (e.g. "ws-001").
 * @property url The WebSocket URL.
 * @property createdAt ISO-8601 timestamp of connection creation.
 * @property status Current status: "connected" or "closed".
 * @property messagesSent Counter of messages sent through this connection.
 * @property messagesReceived Counter of messages received on this connection.
 */
data class WebSocketConnection(
    val connectionId: String,
    val url: String,
    val createdAt: String,
    @Volatile var status: String = "connected",
    val messagesSent: AtomicLong = AtomicLong(0),
    val messagesReceived: AtomicLong = AtomicLong(0),
) {
    /** Guards [messages] and [nextIndex], and the change of [status] to "closed". */
    private val lock = ReentrantLock()

    /** Signalled under [lock] when a message is recorded or the connection closes. */
    private val changed = lock.newCondition()

    /** Retained messages, oldest first. Guarded by [lock]. */
    private val messages = ArrayDeque<WebSocketMessage>()

    /** Index the next appended message gets. Guarded by [lock]. */
    private var nextIndex = 0L

    /** Records a message under the next index, evicting the oldest beyond [MAX_MESSAGES]. */
    fun append(direction: String, type: String, payload: String, length: Int): WebSocketMessage = lock.withLock {
        val message = WebSocketMessage(nextIndex, direction, type, payload, length, Instant.now().toString())
        nextIndex++
        messages.addLast(message)
        if (messages.size > MAX_MESSAGES) messages.removeFirst()
        changed.signalAll()
        message
    }

    /**
     * Up to [limit] retained messages with an index greater than [sinceIndex], optionally only those
     * in [direction], read under the same lock as [append] so the page and its window agree. Only
     * the returned messages are copied.
     */
    fun page(sinceIndex: Long, limit: Int, direction: String? = null): WebSocketMessagePage =
        lock.withLock { pageLocked(sinceIndex, limit, direction) }

    /**
     * [page] without a direction filter that first waits, when no message with an index greater than
     * [sinceIndex] has been recorded yet, until one is, the connection closes, or [timeoutNanos]
     * pass. The check and the wait happen under the lock [append] takes, so a message recorded in
     * between always wakes the caller. The page is empty after a timeout or a close.
     *
     * @throws InterruptedException when the calling thread is interrupted while waiting.
     */
    fun awaitPage(sinceIndex: Long, limit: Int, timeoutNanos: Long): WebSocketMessagePage {
        val since = maxOf(sinceIndex, -1L)
        lock.lockInterruptibly()
        try {
            var remaining = timeoutNanos
            while (nextIndex - 1 <= since && status != "closed" && remaining > 0) {
                remaining = changed.awaitNanos(remaining)
            }
            return pageLocked(since, limit, null)
        } finally {
            lock.unlock()
        }
    }

    private fun pageLocked(sinceIndex: Long, limit: Int, direction: String?): WebSocketMessagePage {
        val oldest = nextIndex - messages.size
        // Indices are contiguous from `oldest`, so already-seen messages are skipped by position.
        val skip = when {
            sinceIndex < oldest -> 0
            sinceIndex >= nextIndex - 1 -> messages.size
            else -> (sinceIndex - oldest + 1).toInt()
        }
        val out = ArrayList<WebSocketMessage>()
        var hasMore = false
        for (position in skip until messages.size) {
            val message = messages[position]
            if (direction != null && message.direction != direction) continue
            if (out.size >= limit) {
                hasMore = true
                break
            }
            out.add(message)
        }
        val missed = if (sinceIndex < oldest - 1) oldest - 1 - maxOf(sinceIndex, -1L) else 0L
        return WebSocketMessagePage(out, oldest, nextIndex, messages.size, missed, hasMore, status == "closed")
    }

    fun messageCount(): Int = lock.withLock { messages.size }

    /** Index of the newest recorded message, -1 when none has been recorded. */
    fun lastIndex(): Long = lock.withLock { nextIndex - 1 }

    /**
     * Changes the type of the recorded message [index], if it is still retained. A frame is recorded
     * before it is sent (so that no reply can get a lower index); this marks one whose send failed.
     */
    fun relabel(index: Long, type: String): Unit = lock.withLock {
        val position = index - (nextIndex - messages.size)
        if (position >= 0 && position < messages.size) {
            messages[position.toInt()] = messages[position.toInt()].copy(type = type)
        }
    }

    /** Sets [status] to "closed" and wakes [awaitPage] callers; true only for the call that actually closed it. */
    fun markClosed(): Boolean = lock.withLock {
        if (status == "closed") false else {
            status = "closed"
            changed.signalAll()
            true
        }
    }

    companion object { const val MAX_MESSAGES = 2000 }
}

/**
 * One page read by [WebSocketConnection.page].
 *
 * @property oldestIndex Index of the oldest retained message (equals [nextIndex] when none is retained).
 * @property nextIndex Index the next recorded message will get.
 * @property retained Number of messages currently retained.
 * @property missed Messages after the caller's `since_index` that were evicted before this read.
 * @property hasMore True when more messages matching the filter follow the last one returned.
 * @property closed True when the connection was closed at the time of the read.
 */
data class WebSocketMessagePage(
    val messages: List<WebSocketMessage>,
    val oldestIndex: Long,
    val nextIndex: Long,
    val retained: Int,
    val missed: Long,
    val hasMore: Boolean,
    val closed: Boolean = false,
)

/**
 * A single WebSocket message within a [WebSocketConnection].
 *
 * @property index Monotonic index within the connection, assigned by [WebSocketConnection.append].
 * @property direction "client_to_server" or "server_to_client".
 * @property type "TEXT" or "BINARY"; "TEXT_DROPPED"/"BINARY_DROPPED" when an intercept rule dropped a
 *   proxied frame; "TEXT_UNSENT"/"BINARY_UNSENT" when sending it failed.
 * @property payload The message content (binary payloads are base64-encoded).
 * @property length Length of the payload in bytes.
 * @property timestamp ISO-8601 timestamp of when the message was observed.
 */
data class WebSocketMessage(
    val index: Long,
    val direction: String,
    val type: String,
    val payload: String,
    val length: Int,
    val timestamp: String
)

/**
 * A WebSocket message interception rule. Applied by the WebSocket bridge
 * to intercept, modify, or tag messages on matching connections.
 *
 * A binary frame is matched and rewritten as ISO-8859-1 text (one char per byte), so [matchMessage]
 * and [modifyRegex] can address raw bytes with `\xNN`.
 *
 * @property ruleId Unique identifier (e.g. "wsrule-001").
 * @property matchUrl Optional URL regex to match against the WebSocket URL.
 * @property matchMessage Optional regex to match against message content.
 * @property direction Direction filter: "client_to_server", "server_to_client", or "both".
 * @property action What to do when matched: "modify", "drop", or "tag".
 * @property modifyRegex Regex pattern for message content replacement.
 * @property modifyReplacement Replacement string for regex matches.
 * @property tagComment Comment to attach to the matched message.
 * @property enabled Whether this rule is currently active.
 * @property messageType Frame kind the rule is limited to: "TEXT" or "BINARY"; null for both.
 */
data class WebSocketInterceptRule(
    val ruleId: String,
    val matchUrl: String? = null,
    val matchMessage: String? = null,
    val direction: String = "both",
    val action: String = "tag",
    val modifyRegex: String? = null,
    val modifyReplacement: String? = null,
    val tagComment: String? = null,
    @Volatile var enabled: Boolean = true,
    val messageType: String? = null,
)

