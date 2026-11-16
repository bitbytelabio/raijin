package io.bitbytelab.raijin.state

import java.time.Instant
import java.util.concurrent.atomic.AtomicLong

/**
 * Tracks a live WebSocket connection created through Burp's proxy or
 * programmatically via the WebSocket bridge.
 *
 * Messages live in a bounded buffer (the newest [MAX_MESSAGES]). [append] allocates the next index
 * and stores the message under one lock, so retained indices are contiguous and in order and a
 * `since_index` poller can never skip a frame that a concurrent writer is still recording.
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
    /** Retained messages, oldest first. Guarded by `this`. */
    private val messages = java.util.ArrayDeque<WebSocketMessage>()

    /** Index the next appended message gets. Guarded by `this`. */
    private var nextIndex = 0L

    /** Records a message under the next index, evicting the oldest beyond [MAX_MESSAGES]. */
    fun append(direction: String, type: String, payload: String, length: Int): WebSocketMessage = synchronized(this) {
        val message = WebSocketMessage(nextIndex, direction, type, payload, length, Instant.now().toString())
        nextIndex++
        messages.addLast(message)
        if (messages.size > MAX_MESSAGES) messages.removeFirst()
        message
    }

    /**
     * Up to [limit] retained messages with an index greater than [sinceIndex], optionally only those
     * in [direction], read under the same lock as [append] so the page and its window agree. Only
     * the returned messages are copied.
     */
    fun page(sinceIndex: Long, limit: Int, direction: String? = null): WebSocketMessagePage = synchronized(this) {
        val oldest = nextIndex - messages.size
        // Indices are contiguous from `oldest`, so already-seen messages are skipped by position.
        val skip = when {
            sinceIndex < oldest -> 0
            sinceIndex >= nextIndex - 1 -> messages.size
            else -> (sinceIndex - oldest + 1).toInt()
        }
        val out = ArrayList<WebSocketMessage>()
        var hasMore = false
        val iterator = messages.iterator()
        repeat(skip) { iterator.next() }
        while (iterator.hasNext()) {
            val message = iterator.next()
            if (direction != null && message.direction != direction) continue
            if (out.size >= limit) {
                hasMore = true
                break
            }
            out.add(message)
        }
        val missed = if (sinceIndex < oldest - 1) oldest - 1 - maxOf(sinceIndex, -1L) else 0L
        WebSocketMessagePage(out, oldest, nextIndex, messages.size, missed, hasMore)
    }

    fun messageCount(): Int = synchronized(this) { messages.size }

    /** Sets [status] to "closed"; true only for the call that actually closed it. */
    fun markClosed(): Boolean = synchronized(this) {
        if (status == "closed") false else {
            status = "closed"
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
 */
data class WebSocketMessagePage(
    val messages: List<WebSocketMessage>,
    val oldestIndex: Long,
    val nextIndex: Long,
    val retained: Int,
    val missed: Long,
    val hasMore: Boolean,
)

/**
 * A single WebSocket message within a [WebSocketConnection].
 *
 * @property index Monotonic index within the connection, assigned by [WebSocketConnection.append].
 * @property direction "client_to_server" or "server_to_client".
 * @property type "TEXT" or "BINARY"; "TEXT_DROPPED"/"BINARY_DROPPED" when an intercept rule dropped a proxied frame.
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
 * @property ruleId Unique identifier (e.g. "wsrule-001").
 * @property matchUrl Optional URL regex to match against the WebSocket URL.
 * @property matchMessage Optional regex to match against message content.
 * @property direction Direction filter: "client_to_server", "server_to_client", or "both".
 * @property action What to do when matched: "modify", "drop", or "tag".
 * @property modifyRegex Regex pattern for message content replacement.
 * @property modifyReplacement Replacement string for regex matches.
 * @property tagComment Comment to attach to the matched message.
 * @property enabled Whether this rule is currently active.
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
    @Volatile var enabled: Boolean = true
)

