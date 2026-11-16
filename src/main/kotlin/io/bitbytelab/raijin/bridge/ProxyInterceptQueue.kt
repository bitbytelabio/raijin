package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.safety.SafeRegex
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * The hold queue behind the proxy intercept tools. Montoya has no API for the messages waiting in
 * Burp's own Intercept tab; what it offers is the synchronous proxy handler. So a message is held
 * by parking its handler thread in [hold] until an agent decides ([decide]) or the hold times out.
 *
 * A hold can never stall the proxy for longer than its timeout:
 *  - nothing is held unless the queue is armed, and at most `maxHeld` messages at once; whatever
 *    arrives beyond that passes straight through;
 *  - a hold nobody answers within its timeout forwards the message unchanged;
 *  - after [unansweredLimit] timeouts in a row the queue disarms itself and releases what it
 *    holds, so a forgotten hold stops slowing traffic down;
 *  - [close] (extension unload) releases everything and refuses to hold again.
 *
 * Generic in the message type, so it is tested without Montoya.
 */
internal class InterceptHoldQueue<T : Any>(private val unansweredLimit: Int = UNANSWERED_LIMIT) {

    enum class Verdict { FORWARD, DROP }

    /** Why a hold ended, or why there was none. */
    enum class Reason {
        /** An agent forwarded or dropped the message. */
        DECIDED,

        /** Nobody decided within the timeout: forwarded unchanged. */
        TIMEOUT,

        /** The queue was disarmed or closed while the message was held: forwarded unchanged. */
        RELEASED,

        /** The holding thread was interrupted: forwarded unchanged. */
        INTERRUPTED,

        /** Not held: the queue is not armed. */
        NOT_ARMED,

        /** Not held: `maxHeld` messages are held already. */
        QUEUE_FULL,
    }

    /** @property replacement the edited message of a forward decision; null sends the held one. */
    data class Outcome<T>(val verdict: Verdict, val reason: Reason, val replacement: T? = null) {
        /** The message was parked rather than passed straight through. */
        val wasHeld: Boolean get() = reason != Reason.NOT_ARMED && reason != Reason.QUEUE_FULL
    }

    /** A message currently parked. */
    class Held<T> internal constructor(val id: Long, val message: T, val heldAtMs: Long, val timeoutMs: Long) {
        internal val outcome = CompletableFuture<Outcome<T>>()
    }

    /** How a finished hold ended; kept for a while so a late decision can be explained. */
    data class Released(val id: Long, val verdict: Verdict, val reason: Reason, val modified: Boolean)

    /**
     * @property remainingMessages messages still to be held before the queue disarms; null without such a budget.
     * @property disarmReason why the queue stopped holding; null while armed or never armed.
     */
    data class Status(
        val armed: Boolean,
        val maxHeld: Int,
        val timeoutMs: Long,
        val remainingMessages: Int?,
        val held: Int,
        val disarmReason: String?,
        val totalHeld: Long,
        val decided: Long,
        val timedOut: Long,
        val passedQueueFull: Long,
    )

    private val lock = ReentrantLock()
    private val arrived = lock.newCondition()

    /** Written under [lock]; read without it on the proxy thread's fast path. */
    @Volatile
    var armed = false
        private set

    // Everything below is guarded by lock.
    private val held = LinkedHashMap<Long, Held<T>>()
    private val recent = ArrayDeque<Released>()
    private var maxHeld = 0
    private var timeoutMs = 0L
    private var remaining: Int? = null
    private var disarmReason: String? = null
    private var closed = false
    private var nextId = 0L
    private var unanswered = 0
    private var totalHeld = 0L
    private var decided = 0L
    private var timedOut = 0L
    private var passedQueueFull = 0L

    /**
     * Starts holding: up to [maxHeld] messages at once, each for at most [timeoutMs], and
     * [maxMessages] in total when given. False once the queue is closed.
     */
    fun arm(maxHeld: Int, timeoutMs: Long, maxMessages: Int? = null): Boolean {
        return lock.withLock {
            if (closed) return false
            this.maxHeld = maxHeld
            this.timeoutMs = timeoutMs
            remaining = maxMessages
            disarmReason = null
            unanswered = 0
            armed = true
            true
        }
    }

    /** Stops holding new messages. Those already held keep waiting for a decision or their timeout. */
    fun disarm(reason: String) {
        lock.withLock { disarmLocked(reason) }
    }

    /**
     * Parks the calling thread with [message] until a decision, the timeout or a release. Returns
     * at once when the queue is not armed or already holds its maximum. [onHeld] runs on the
     * calling thread once the message is listed, before the wait.
     */
    fun hold(message: T, onHeld: (Held<T>) -> Unit = {}): Outcome<T> {
        if (!armed) return Outcome(Verdict.FORWARD, Reason.NOT_ARMED)
        val entry = lock.withLock {
            if (!armed) return Outcome(Verdict.FORWARD, Reason.NOT_ARMED)
            if (held.size >= maxHeld) {
                passedQueueFull++
                return Outcome(Verdict.FORWARD, Reason.QUEUE_FULL)
            }
            val parked = Held(++nextId, message, System.currentTimeMillis(), timeoutMs)
            held[parked.id] = parked
            totalHeld++
            remaining?.let { left ->
                remaining = left - 1
                if (left <= 1) disarmLocked("max_messages reached")
            }
            arrived.signalAll()
            parked
        }
        try {
            onHeld(entry)
        } catch (_: Exception) {
            // Announcing the hold is best-effort; the message is held either way.
        }
        val outcome = await(entry)
        lock.withLock { settleLocked(entry, outcome) }
        return outcome
    }

    /** Ends the hold of [id] with an agent's decision. False when [id] is not held (any more). */
    fun decide(id: Long, verdict: Verdict, replacement: T? = null): Boolean {
        return lock.withLock {
            val entry = held[id] ?: return false
            // complete() fails when the hold just timed out: the timeout already forwarded it.
            if (!entry.outcome.complete(Outcome(verdict, Reason.DECIDED, replacement))) return false
            held.remove(id)
            true
        }
    }

    /** Ends every hold with [verdict] for [reason]; returns how many it ended. */
    fun resolveAll(verdict: Verdict, reason: Reason): Int = lock.withLock { resolveAllLocked(verdict, reason) }

    /** The messages held right now, oldest first. */
    fun list(): List<Held<T>> = lock.withLock { held.values.toList() }

    fun find(id: Long): Held<T>? = lock.withLock { held[id] }

    /** How the hold of [id] ended, when it ended recently. */
    fun released(id: Long): Released? = lock.withLock { recent.lastOrNull { it.id == id } }

    /** The last [limit] finished holds, oldest first. */
    fun recentlyReleased(limit: Int): List<Released> = lock.withLock { recent.toList().takeLast(limit.coerceAtLeast(0)) }

    /**
     * Waits up to [timeoutMs] for a message to be held; true when at least one is. Returns early
     * when the queue is not armed, since nothing can arrive then.
     */
    fun awaitHeld(timeoutMs: Long): Boolean {
        var nanos = TimeUnit.MILLISECONDS.toNanos(timeoutMs)
        return lock.withLock {
            while (held.isEmpty() && armed && nanos > 0) nanos = arrived.awaitNanos(nanos)
            held.isNotEmpty()
        }
    }

    fun status(): Status = lock.withLock {
        Status(armed, maxHeld, timeoutMs, remaining, held.size, disarmReason, totalHeld, decided, timedOut, passedQueueFull)
    }

    /** Releases everything held and refuses to hold again (extension unload). */
    fun close() {
        lock.withLock {
            closed = true
            disarmLocked("the extension is unloading")
            resolveAllLocked(Verdict.FORWARD, Reason.RELEASED)
        }
    }

    private fun await(entry: Held<T>): Outcome<T> {
        try {
            return entry.outcome.get(entry.timeoutMs, TimeUnit.MILLISECONDS)
        } catch (_: TimeoutException) {
            entry.outcome.complete(Outcome(Verdict.FORWARD, Reason.TIMEOUT))
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            entry.outcome.complete(Outcome(Verdict.FORWARD, Reason.INTERRUPTED))
        } catch (_: Exception) {
            entry.outcome.complete(Outcome(Verdict.FORWARD, Reason.RELEASED))
        }
        // complete() only takes effect on an undecided hold, so a decision that raced the timeout wins.
        return entry.outcome.getNow(Outcome(Verdict.FORWARD, Reason.RELEASED))
    }

    private fun settleLocked(entry: Held<T>, outcome: Outcome<T>) {
        held.remove(entry.id)
        when (outcome.reason) {
            Reason.DECIDED -> {
                decided++
                unanswered = 0
            }
            Reason.TIMEOUT -> {
                timedOut++
                if (++unanswered >= unansweredLimit && armed) {
                    disarmLocked("$unansweredLimit holds in a row timed out without a decision")
                    resolveAllLocked(Verdict.FORWARD, Reason.RELEASED)
                }
            }
            else -> {}
        }
        recent.addLast(Released(entry.id, outcome.verdict, outcome.reason, outcome.replacement != null))
        while (recent.size > RECENT_KEPT) recent.removeFirst()
    }

    private fun disarmLocked(reason: String) {
        if (!armed) return
        armed = false
        disarmReason = reason
        arrived.signalAll()
    }

    private fun resolveAllLocked(verdict: Verdict, reason: Reason): Int {
        var ended = 0
        for (entry in held.values) {
            if (entry.outcome.complete(Outcome(verdict, reason))) ended++
        }
        held.clear()
        return ended
    }

    companion object {
        /** Timeouts in a row after which an armed queue disarms itself. */
        const val UNANSWERED_LIMIT = 3

        private const val RECENT_KEPT = 50
    }
}

/**
 * Which proxied messages an armed [InterceptHoldQueue] holds. Every condition that is set must match.
 *
 * @property matchHost host glob or regex ([SafeRegex.matchesHostPattern]).
 * @property matchUrl regex searched in the URL, case-insensitive.
 * @property matchMethod HTTP method, compared ignoring case.
 */
internal data class HoldPolicy(
    val requests: Boolean = true,
    val responses: Boolean = false,
    val matchHost: String? = null,
    val matchUrl: String? = null,
    val matchMethod: String? = null,
    val inScopeOnly: Boolean = false,
) {
    /**
     * [host], [url] and [method] describe the request (for a response: the request it answers) and
     * are null when unreadable, which never satisfies a condition on them. [inScope] is only asked
     * when the policy needs it.
     */
    fun matches(isRequest: Boolean, host: String?, url: String?, method: String?, inScope: () -> Boolean): Boolean {
        if (if (isRequest) !requests else !responses) return false
        if (matchHost != null && (host == null || !SafeRegex.matchesHostPattern(matchHost, host))) return false
        if (matchUrl != null && (url == null || !SafeRegex.containsMatchIn(matchUrl, url, ignoreCase = true))) return false
        if (matchMethod != null && (method == null || !method.equals(matchMethod, ignoreCase = true))) return false
        return !inScopeOnly || inScope()
    }

    /** `request`, `response` or `both`. */
    val target: String
        get() = when {
            requests && responses -> "both"
            responses -> "response"
            else -> "request"
        }

    companion object {
        const val DEFAULT_TIMEOUT_SECONDS = 60
        const val MAX_TIMEOUT_SECONDS = 600
        const val DEFAULT_MAX_HELD = 20
        const val MAX_HELD = 200

        /** (hold requests, hold responses) for `request` (also null or blank), `response` or `both`; null for anything else. */
        fun sides(target: String?): Pair<Boolean, Boolean>? = when (target?.trim()?.lowercase()) {
            null, "", "request" -> true to false
            "response" -> false to true
            "both" -> true to true
            else -> null
        }
    }
}
