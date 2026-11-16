package io.bitbytelab.raijin.state

import io.bitbytelab.raijin.core.BodyText
import kotlinx.serialization.json.JsonObject
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.LongAdder
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * A live "replay under a second identity" tap on proxy traffic — Autorize's core idea (replay
 * captured traffic under a lower-privilege session and diff) applied continuously instead of to
 * a caller-supplied request list. Matching proxied responses are cloned, replayed under each of
 * [identities] in the background by [io.bitbytelab.raijin.bridge.AutorizeTap], and diffed via
 * [io.bitbytelab.raijin.bridge.AuthDiffVerdict] against the already-captured response.
 *
 * @property ruleId Unique identifier (e.g. "arule-001").
 * @property identities Replay identities, the `{name, header_name?, header_value?, headers?, remove_headers?}`
 *   shape of auth_diff/access_control_sweep ([io.bitbytelab.raijin.bridge.AuthIdentityApplier]).
 * @property inScopeOnly When true (default), only taps requests Burp's scope considers in scope.
 * @property includeHostPattern Optional hostname glob (e.g. "*.example.com"); null taps every host.
 * @property excludeUrlRegex Optional URL regex; matching requests are skipped.
 * @property methods Optional set of HTTP methods (uppercase) to tap; null taps every method [includeMutating] allows.
 * @property ignoreStaticAssets When true (default), skip responses that look like a static asset.
 * @property similarityThreshold Body-similarity percent (0-100) controlling how strictly a replay must match to be flagged.
 * @property enabled Whether this rule is currently tapping traffic.
 * @property createdAt ISO-8601 timestamp of rule creation.
 * @property includeMutating When false (default), a request whose method changes state (POST, PUT, DELETE, PATCH)
 *   is never replayed, even when [methods] names it: a replay would repeat the action once per identity.
 */
data class AutorizeRule(
    val ruleId: String,
    val identities: List<JsonObject>,
    val inScopeOnly: Boolean = true,
    val includeHostPattern: String? = null,
    val excludeUrlRegex: String? = null,
    val methods: Set<String>? = null,
    val ignoreStaticAssets: Boolean = true,
    val similarityThreshold: Double = 90.0,
    @Volatile var enabled: Boolean = true,
    val createdAt: String = Instant.now().toString(),
    val includeMutating: Boolean = false,
)

/**
 * What one identity of an [AutorizeRule] sent and got back when a captured request was replayed.
 *
 * @property identity Name of the identity.
 * @property status Status code of the response it received.
 * @property request Raw request text sent for the identity.
 * @property response Raw response text it received.
 */
data class AutorizeReplay(
    val identity: String,
    val status: Int,
    val request: String,
    val response: String,
)

/**
 * One flagged mismatch recorded by a live [AutorizeRule] tap.
 *
 * @property id Monotonically increasing id for ordering/paging.
 * @property ruleId The [AutorizeRule] that produced this match.
 * @property timestamp ISO-8601 timestamp of the replay.
 * @property method HTTP method of the original request.
 * @property url URL of the original request.
 * @property originalStatus Status code of the already-captured (original) response.
 * @property findings Serialized [io.bitbytelab.raijin.bridge.AuthDiffVerdict.Finding]s (one per flagged identity comparison).
 * @property request Raw original request text (evidence).
 * @property response Raw original response text (evidence).
 * @property replays What each replayed identity sent and received, in replay order.
 * @property softDenial No finding is critical or high: an identity got a success status whose body reads
 *   as a refusal ([io.bitbytelab.raijin.bridge.AuthDenialHeuristic]), which turned what status and body
 *   similarity alone would flag into an informational verdict. Kept for review instead of being dropped.
 */
data class AutorizeMatch(
    val id: Long,
    val ruleId: String,
    val timestamp: String,
    val method: String,
    val url: String,
    val originalStatus: Int,
    val findings: List<JsonObject>,
    val request: String,
    val response: String,
    val replays: List<AutorizeReplay> = emptyList(),
    val softDenial: Boolean = false,
) {
    /** Characters of message text this match holds: what [AutorizeMatchLog] budgets. */
    val storedChars: Long
        get() = request.length.toLong() + response.length +
            replays.sumOf { it.request.length.toLong() + it.response.length }

    companion object {
        /** Longest request text kept per message; a longer one is cut and marked. */
        const val MAX_REQUEST_CHARS = 64_000

        /** Longest response text kept per message; a longer one is cut and marked. */
        const val MAX_RESPONSE_CHARS = 32_000
    }
}

/**
 * The matches flagged by the live Autorize taps, newest first. Bounded three ways: by count, by the
 * message text held in total, and by a smaller count for soft denials, so unconfirmed matches cannot
 * push confirmed ones out.
 *
 * Listeners run under the same lock as the change they report, so a durable store sees additions
 * and clears in the order they happened.
 */
class AutorizeMatchLog(
    private val maxMatches: Int = MAX_MATCHES,
    private val maxSoftDenials: Int = MAX_SOFT_DENIALS,
    private val maxChars: Long = MAX_CHARS,
) {
    /** Newest first. Read freely; change only through this class. */
    val matches = ConcurrentLinkedDeque<AutorizeMatch>()

    /** Told about each recorded match. Restored matches are not announced. */
    val addListeners = CopyOnWriteArrayList<(AutorizeMatch) -> Unit>()

    /** Told after matches were cleared. */
    val clearListeners = CopyOnWriteArrayList<() -> Unit>()

    private val lock = ReentrantLock()
    private val idCounter = AtomicLong(0)
    private var count = 0 // guarded by lock
    private var softDenials = 0 // guarded by lock
    private var chars = 0L // guarded by lock

    /** Most matches retained. */
    val capacity: Int get() = maxMatches

    /** Records a match, cutting its messages to the per-message caps and evicting beyond the bounds. */
    fun add(
        ruleId: String,
        method: String,
        url: String,
        originalStatus: Int,
        findings: List<JsonObject>,
        request: String,
        response: String,
        replays: List<AutorizeReplay> = emptyList(),
        softDenial: Boolean = false,
    ): AutorizeMatch {
        val entry = AutorizeMatch(
            id = idCounter.incrementAndGet(),
            ruleId = ruleId,
            timestamp = Instant.now().toString(),
            method = method,
            url = url,
            originalStatus = originalStatus,
            findings = findings,
            request = cap(request, AutorizeMatch.MAX_REQUEST_CHARS),
            response = cap(response, AutorizeMatch.MAX_RESPONSE_CHARS),
            replays = replays.map {
                it.copy(
                    request = cap(it.request, AutorizeMatch.MAX_REQUEST_CHARS),
                    response = cap(it.response, AutorizeMatch.MAX_RESPONSE_CHARS),
                )
            },
            softDenial = softDenial,
        )
        lock.withLock {
            matches.addFirst(entry)
            track(entry, 1)
            evictLocked()
            addListeners.forEach { listener ->
                try { listener(entry) } catch (_: Exception) {}
            }
        }
        return entry
    }

    /**
     * Seeds the log with persisted [entries] (newest first) without notifying listeners, within the
     * same bounds as [add], and continues the id sequence past them.
     */
    fun restore(entries: List<AutorizeMatch>) {
        lock.withLock {
            for (entry in entries) {
                if (count >= maxMatches) break
                if (count > 0 && chars + entry.storedChars > maxChars) break
                if (entry.softDenial && softDenials >= maxSoftDenials) continue
                matches.addLast(entry)
                track(entry, 1)
            }
        }
        val maxId = entries.maxOfOrNull { it.id } ?: 0L
        idCounter.accumulateAndGet(maxId) { current, restored -> maxOf(current, restored) }
    }

    /** Removes every match, or only those of [ruleId], then tells [clearListeners]. */
    fun clear(ruleId: String?) {
        lock.withLock {
            if (ruleId == null) matches.clear() else matches.removeIf { it.ruleId == ruleId }
            recountLocked()
            clearListeners.forEach { listener ->
                try { listener() } catch (_: Exception) {}
            }
        }
    }

    /** Empties the log and drops its listeners without notifying them (extension unload). */
    fun reset() {
        lock.withLock {
            addListeners.clear()
            clearListeners.clear()
            matches.clear()
            recountLocked()
        }
    }

    private fun evictLocked() {
        if (softDenials > maxSoftDenials) removeOldestSoftDenialLocked()
        while (count > maxMatches || (chars > maxChars && count > 1)) {
            val oldest = matches.pollLast() ?: break
            track(oldest, -1)
        }
    }

    private fun removeOldestSoftDenialLocked() {
        val oldestFirst = matches.descendingIterator()
        while (oldestFirst.hasNext()) {
            val match = oldestFirst.next()
            if (!match.softDenial) continue
            oldestFirst.remove()
            track(match, -1)
            return
        }
    }

    private fun recountLocked() {
        count = 0
        softDenials = 0
        chars = 0L
        matches.forEach { track(it, 1) }
    }

    private fun track(match: AutorizeMatch, sign: Int) {
        count += sign
        if (match.softDenial) softDenials += sign
        chars += sign * match.storedChars
    }

    private fun cap(text: String, max: Int): String =
        if (text.length <= max) text
        else BodyText.truncate(text, max) + "\n[truncated by Raijin: ${text.length} characters in total]"

    companion object {
        const val MAX_MATCHES = 2000

        /** Soft denials retained; the oldest one goes when a new one exceeds this. */
        const val MAX_SOFT_DENIALS = 500

        /** Message text retained across all matches, in characters. */
        const val MAX_CHARS = 32_000_000L
    }
}

/**
 * Dedup guard of the live Autorize taps, so an endpoint that is hit over and over is replayed once
 * per rule rather than on every proxied request. A crude cap-and-clear (rather than an LRU) is
 * enough: a full reset just means some endpoints get retested, which is harmless.
 *
 * The query string is part of what is remembered ([key]), with a ceiling of [maxVariants] query
 * variants per endpoint, so a search box or an id enumeration cannot be replayed without end.
 */
class AutorizeSeenGuard(
    private val maxEntries: Int = MAX_ENTRIES,
    private val maxVariants: Int = MAX_QUERY_VARIANTS,
) {
    private val seen = ConcurrentHashMap.newKeySet<String>()

    /** Endpoint ([endpointKey]) -> query variants of it replayed so far. */
    private val variants = ConcurrentHashMap<String, AtomicInteger>()

    /**
     * True the first time [key] is offered while its [endpoint] still has query variants to spare
     * (the caller replays); false on a repeat or beyond the ceiling (the caller skips).
     */
    fun seenOnce(key: String, endpoint: String = key.substringBefore('?')): Boolean {
        if (seen.size > maxEntries) clear(null)
        if (!seen.add(key)) return false
        if (endpoint == key) return true
        return variants.computeIfAbsent(endpoint) { AtomicInteger() }.incrementAndGet() <= maxVariants
    }

    /** Forgets every key, or only those of [ruleId]. */
    fun clear(ruleId: String?) {
        if (ruleId == null) {
            seen.clear()
            variants.clear()
            return
        }
        val prefix = "$ruleId|"
        seen.removeIf { it.startsWith(prefix) }
        variants.keys.removeIf { it.startsWith(prefix) }
    }

    companion object {
        const val MAX_ENTRIES = 20_000

        /** Query-string variants of one endpoint replayed per rule. */
        const val MAX_QUERY_VARIANTS = 50

        /** A value at least this long that contains a digit is a token (UUID, hash, signature), not a name. */
        private const val TOKEN_MIN_CHARS = 16

        /** A number, date or time at least this long is a moment or a cache buster, not an object id. */
        private const val MOMENT_MIN_CHARS = 10

        /**
         * Dedup key for one Autorize replay: rule, method, URL path and query parameters. Parameter
         * order does not matter. Each value counts, so `?id=1` and `?id=2` are two keys (each object
         * is its own authorization question) and so are `?action=export` and `?action=delete`; only
         * a value that changes on every request is not told apart: a timestamp or cache buster
         * (`?_=1731800000000`) and a long token with digits (UUID, hash, signature).
         */
        fun key(ruleId: String, method: String, url: String): String {
            val endpoint = endpointKey(ruleId, method, url)
            val query = normalizedQuery(url)
            return if (query.isEmpty()) endpoint else "$endpoint?$query"
        }

        /** [key] without the query: the endpoint whose query variants are counted. */
        fun endpointKey(ruleId: String, method: String, url: String): String =
            "$ruleId|${method.uppercase()}|${url.substringBefore('#').substringBefore('?')}"

        internal fun normalizedQuery(url: String): String {
            val query = url.substringBefore('#').substringAfter('?', "")
            if (query.isEmpty()) return ""
            return query.split('&')
                .filter { it.isNotEmpty() }
                .map { parameter ->
                    val value = parameter.substringAfter('=', "")
                    if (isVolatile(value)) parameter.substringBefore('=') + "=#" else parameter
                }
                .distinct()
                .sorted()
                .joinToString("&")
        }

        private fun isVolatile(value: String): Boolean {
            if (value.none { it.isDigit() }) return false
            if (value.length >= TOKEN_MIN_CHARS) return true
            return value.length >= MOMENT_MIN_CHARS && value.all { it.isDigit() || it == '.' || it == '-' || it == ':' }
        }
    }
}

/** Per-rule tallies of what a live Autorize tap did with the traffic it saw: replayed, flagged, skipped and why. */
class AutorizeActivity {
    private val counters = ConcurrentHashMap<String, ConcurrentHashMap<String, LongAdder>>()

    fun count(ruleId: String, outcome: String) {
        counters.computeIfAbsent(ruleId) { ConcurrentHashMap() }.computeIfAbsent(outcome) { LongAdder() }.increment()
    }

    /** Outcome -> count for [ruleId], sorted by outcome; empty when the rule saw nothing yet. */
    fun of(ruleId: String): Map<String, Long> =
        counters[ruleId]?.entries?.associate { it.key to it.value.sum() }?.toSortedMap().orEmpty()

    /** Forgets every rule's tallies, or only those of [ruleId]. */
    fun clear(ruleId: String? = null) {
        if (ruleId == null) counters.clear() else counters.remove(ruleId)
    }
}
