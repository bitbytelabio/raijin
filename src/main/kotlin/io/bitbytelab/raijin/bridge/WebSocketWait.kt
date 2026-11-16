package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.state.WebSocketConnection
import io.bitbytelab.raijin.state.WebSocketMessage

/**
 * Which recorded frames a wait or a fuzz window accepts. Every criterion is optional.
 *
 * @param direction "client_to_server" or "server_to_client"; null for either.
 * @param binary true for binary frames only, false for text frames only, null for either. A frame an
 *   intercept rule dropped ("TEXT_DROPPED", "BINARY_DROPPED") or whose send failed ("*_UNSENT")
 *   counts as its kind.
 * @param pattern case-insensitive regex the frame content must contain (`(?-i)` makes it exact); a
 *   binary frame is matched as ISO-8859-1 text ([WebSocketFrames.matchText]). The caller validates it.
 */
internal class WebSocketFrameFilter(
    private val direction: String? = null,
    private val binary: Boolean? = null,
    private val pattern: String? = null,
) {
    fun matches(message: WebSocketMessage): Boolean {
        if (direction != null && message.direction != direction) return false
        if (binary != null && WebSocketFrames.isBinary(message.type) != binary) return false
        if (pattern == null) return true
        return SafeRegex.containsMatchIn(
            pattern, WebSocketFrames.matchText(message), ignoreCase = true, maxInputLen = MAX_MATCH_CHARS
        )
    }

    private companion object {
        /**
         * Longest frame a pattern is tried on. The match runs on the caller's thread, not on a Burp
         * callback, so it can afford far more than [SafeRegex.DEFAULT_MAX_INPUT_LEN].
         */
        const val MAX_MATCH_CHARS = 4_000_000
    }
}

/** Waiting for frames on a [WebSocketConnection] without polling. */
internal object WebSocketWait {

    /** Messages copied out of the buffer per lock acquisition. */
    private const val PAGE_SIZE = 256

    /**
     * @property frames the accepted frames, in index order.
     * @property cursor index of the last message examined (the start index when none was): pass it
     *   as the next `sinceIndex` to continue without examining a message twice.
     * @property scanned number of messages examined.
     * @property closed the connection is closed and every message recorded on it was examined.
     * @property firstFrameNanos time from the start to the first accepted frame; -1 when none arrived.
     * @property missed messages in the examined range that were evicted from the buffer before they
     *   could be examined.
     * @property elapsedNanos how long the collection took.
     */
    class Collected(
        val frames: List<WebSocketMessage>,
        val cursor: Long,
        val scanned: Int,
        val closed: Boolean,
        val firstFrameNanos: Long,
        val missed: Long,
        val elapsedNanos: Long,
    )

    /**
     * Collects the frames [filter] accepts among the messages recorded on [connection] after
     * [sinceIndex] and before [untilIndex], blocking in [WebSocketConnection.awaitPage] for new ones.
     * Messages are examined in index order and exactly once, whatever concurrent writers do.
     *
     * The collection ends when [maxFrames] frames were accepted, when every message below
     * [untilIndex] was examined, when the connection closes, or when the window runs out:
     * [windowNanos] in total, and [idleNanos] without another accepted frame once the first one
     * arrived (from the start when [awaitFirst] is false). When the window runs out, the messages
     * recorded by then are still examined before returning, so a window of 0 reads what is there
     * without waiting.
     *
     * @throws InterruptedException when the calling thread is interrupted while waiting.
     */
    fun collect(
        connection: WebSocketConnection,
        sinceIndex: Long,
        filter: WebSocketFrameFilter,
        windowNanos: Long,
        idleNanos: Long = windowNanos,
        awaitFirst: Boolean = true,
        maxFrames: Int = Int.MAX_VALUE,
        untilIndex: Long = Long.MAX_VALUE,
    ): Collected {
        val start = System.nanoTime()
        // Deadlines are offsets from `start`, so they compare correctly whatever nanoTime's origin is.
        var deadline = if (awaitFirst) windowNanos else minOf(windowNanos, idleNanos)
        var cursor = maxOf(sinceIndex, -1L)
        // Highest index to examine; lowered to the newest recorded one once the window has run out.
        var last = untilIndex - 1
        var windowOver = false
        var scanned = 0
        var missed = 0L
        var firstFrame = -1L
        var closed = false
        val frames = ArrayList<WebSocketMessage>()

        while (cursor < last && frames.size < maxFrames) {
            val remaining = deadline - (System.nanoTime() - start)
            val page = connection.awaitPage(cursor, PAGE_SIZE, remaining)
            if (remaining <= 0 && !windowOver) {
                windowOver = true
                last = minOf(last, page.nextIndex - 1)
            }
            // Only evictions inside the examined range count; the rest belong to whoever reads on.
            missed += minOf(page.missed, maxOf(0L, last - cursor))

            // An empty page means the wait ended without news: timeout or close.
            var reachedEnd = page.messages.isEmpty()
            var accepted = false
            for (message in page.messages) {
                if (message.index > last) {
                    // Everything up to `last` was examined or evicted.
                    reachedEnd = true
                    break
                }
                cursor = message.index
                scanned++
                if (!filter.matches(message)) continue
                if (firstFrame < 0) firstFrame = System.nanoTime() - start
                frames += message
                accepted = true
                if (frames.size >= maxFrames) break
            }
            closed = page.closed && cursor >= page.nextIndex - 1
            if (reachedEnd || closed) break
            if (accepted) deadline = minOf(windowNanos, System.nanoTime() - start + idleNanos)
        }
        return Collected(frames, cursor, scanned, closed, firstFrame, missed, System.nanoTime() - start)
    }
}
