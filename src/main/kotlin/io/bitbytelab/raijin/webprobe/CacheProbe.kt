package io.bitbytelab.raijin.webprobe

import io.bitbytelab.raijin.core.ProbeResult
import io.bitbytelab.raijin.core.TextSimilarity
import io.bitbytelab.raijin.recon.Canaries
import io.bitbytelab.raijin.recon.ProbeRequest
import io.bitbytelab.raijin.recon.ProbeText
import kotlin.math.abs
import kotlin.math.max
import kotlin.random.Random

/**
 * Probes one URL for web cache poisoning and web cache deception.
 *
 * Poisoning: an input the cache leaves out of its key (a header, a cookie) that still changes the
 * response lets one request plant that response for everyone. Each input is sent under a query
 * parameter with a value used for nothing else, so whatever gets stored is stored under a key no
 * other visitor asks for; the same key is then requested without the input to see whether the
 * changed response comes back. No input is sent at all once the cache is seen to ignore that
 * parameter, and none that works by changing the status, the redirect or the path until a new
 * value of it is seen to get its own cache entry. A changed status counts only while a visitor
 * without the input still gets the normal answer, since a rate limit or a WAF changes it for
 * everyone; a run of 429/503 answers that a visitor gets too stops the run.
 *
 * Deception: a URL the origin treats as the target page but the cache treats as a static file
 * (`/account/x.css`, `/account;x.css`) gets a logged-in user's page stored for anyone. Each
 * variant is requested as the user, then again without any session.
 */
class CacheProbe(
    private val base: ProbeRequest,
    private val identity: List<Pair<String, String>>,
    private val config: Config,
    private val transport: Transport,
) {
    /**
     * Sends one request. An [anonymous] request must leave without any session: neither the
     * identity headers nor anything Burp would add on its own.
     */
    fun interface Transport {
        fun send(request: ProbeRequest, anonymous: Boolean): ProbeResult?
    }

    /**
     * An input a cache may leave out of its key. In [template], `%s` becomes a canary, `%h` the
     * target host and `%p` a random port; an input without `%s` or `%p` shows only through the
     * status or redirect it causes.
     */
    data class Input(val kind: String, val name: String, val template: String = "%s") {
        /**
         * True when the input works by changing the status or the redirect (it carries no value
         * that could come back) or by rewriting the path the origin serves (a 404 or 403 then).
         */
        val changesStatus: Boolean
            get() = ("%s" !in template && "%p" !in template) || (kind == HEADER && name.lowercase() in PATH_OVERRIDES)
    }

    /**
     * @param host target host, for `%h`.
     * @param extraHeaders header inputs to try before the defaults, as `name` or `name~value`.
     * @param extraCookies cookie inputs to try before the defaults, as `name` or `name~value`.
     */
    class Config(
        val host: String,
        val poisoning: Boolean,
        val deception: Boolean,
        val maxRequests: Int,
        val extraHeaders: List<String> = emptyList(),
        val extraCookies: List<String> = emptyList(),
        val random: Random = Random.Default,
    )

    /**
     * @param verdict [CONFIRMED] when a request without the input got the changed response back
     *   from the cache; [UNCONFIRMED] when the input changes the response, which was not seen
     *   cached; [INCONCLUSIVE] when it changes the status or redirect but whether that is stored
     *   could not be judged without risking other visitors, or a visitor without the input then
     *   got that status too.
     * @param cacheKey the cache-buster pair the attempt was isolated under.
     */
    data class PoisonFinding(
        val input: Input,
        val value: String,
        val effects: List<String>,
        val verdict: String,
        val severity: String,
        val detail: String,
        val cacheKey: String,
        val keyedByVary: Boolean,
    )

    /** @param verdict [CONFIRMED], [LIKELY] or [POTENTIAL]. */
    data class DeceptionFinding(
        val technique: String,
        val target: String,
        val verdict: String,
        val severity: String,
        val detail: String,
        val state: CacheSignals.State,
    )

    /**
     * @param first the cache's word on a first request, [repeat] on the same request again.
     * @param cached the target's response is served from a cache.
     * @param busterEffective true when a new cache-buster value was seen to get its own cache
     *   entry, false when it was served an existing one, null when nothing was seen cached.
     * @param poisoningSkipped why poisoning was not run, or which inputs were held back.
     * @param sessionDependent the target answers differently without a session, or null when deception was not probed.
     * @param stopped why the run ended early: [STOP_BUDGET], [STOP_RATE_LIMITED], [STOP_BASELINE_CHANGED] or [STOP_BUSTER_IGNORED].
     */
    class Report(
        val error: String?,
        val busterParam: String,
        val first: CacheSignals.Observation?,
        val repeat: CacheSignals.Observation?,
        val cached: Boolean,
        val busterEffective: Boolean?,
        val poisoning: List<PoisonFinding>,
        val poisoningTested: Int,
        val poisoningSkipped: String?,
        val deception: List<DeceptionFinding>,
        val deceptionTested: Int,
        val deceptionSkipped: String?,
        val sessionDependent: Boolean?,
        val requests: Int,
        val stopped: String?,
    )

    /** A deception URL. [unique]: its path holds a random name, so it needs no cache-buster of its own. */
    data class Variant(val technique: String, val path: String, val unique: Boolean)

    /** A response together with the cache-buster value its request carried. */
    private class Sample(val result: ProbeResult, val buster: String)

    private val canaries = Canaries(config.random)
    private val busterParam = "zqcb" + ProbeText.token(config.random, 4)
    private var requests = 0
    private var stopped: String? = null

    // What a new cache-buster value was seen to get: a cache entry of its own (true), one shared
    // with other values (false), or nothing seen either way (null).
    private var busterEffective: Boolean? = null

    // Rate-limit and overload answers in a row.
    private var throttled = 0

    fun run(): Report {
        // Is there a cache, does it store this response, and does it key on the cache-buster?
        val firstKey = buster()
        val firstResult = send(asUser(busted(base, firstKey)))
            ?: return report(error = "Target did not answer")
        val clean = Sample(firstResult, firstKey)
        val first = CacheSignals.classify(firstResult.headers)
        val repeat = send(asUser(busted(base, firstKey)))?.let { CacheSignals.classify(it.headers) }
        val repeatHit = repeat?.state == CacheSignals.State.HIT
        // A value never used before must not be served from the cache. One that is means the
        // cache does not key on the parameter, and nothing here is isolated from other visitors.
        var freshHit = first.state == CacheSignals.State.HIT
        if (!freshHit && repeatHit) {
            freshHit = send(asUser(busted(base, buster())))?.let { CacheSignals.classify(it.headers).state } == CacheSignals.State.HIT
        }
        val cached = repeatHit || freshHit
        busterEffective = if (freshHit) false else if (repeatHit) true else null

        // What a visitor without a session gets: the yardstick for "served to someone else".
        val visitorKey = buster()
        val visitorResult = send(busted(base, visitorKey), anonymous = true)
        val visitor = if (visitorResult != null) Sample(visitorResult, visitorKey) else clean

        // A rate limit or an overloaded server already answering: there is no normal answer to compare with.
        val throttledStatus = listOfNotNull(firstResult, visitorResult).firstOrNull { it.status in THROTTLED }?.status
        val unhealthy = when {
            throttledStatus != null ->
                "the target answered $throttledStatus before any input was sent (a rate limit or an overloaded server), so its normal " +
                    "answer is unknown; nothing was sent"
            stopped == STOP_RATE_LIMITED -> "the target answered 429 or 503 to every request before any input was sent; nothing was sent"
            else -> null
        }
        if (unhealthy != null && stopped == null) stopped = STOP_RATE_LIMITED

        val poisoning = ArrayList<PoisonFinding>()
        var poisoningTested = 0
        var poisoningSkipped: String? = null
        if (!config.poisoning) {
            poisoningSkipped = "not requested"
        } else if (unhealthy != null) {
            poisoningSkipped = unhealthy
        } else if (busterEffective == false) {
            poisoningSkipped = "the cache serves a stored response for a cache-buster value it has never seen, so it does not key on the " +
                "query string: an attempt could not be kept away from other visitors, and none was sent"
        } else {
            // Cookies the target hands out are inputs too; the session's own cookies are left alone.
            val own = cookieNames(identity.filter { it.first.equals("Cookie", ignoreCase = true) }.joinToString(";") { it.second }, ';')
            val issued = cookieNames(firstResult.header("set-cookie").orEmpty(), '\n').filterNot { it in own }
            // Until a new cache-buster value is seen to get its own entry, the error or redirect an
            // input causes could be stored under the page's real key, for every visitor.
            val isolated = busterEffective == true
            val (sendable, withheld) = inputs(issued, config.extraHeaders, config.extraCookies).partition { isolated || !it.changesStatus }
            for (input in sendable) {
                if (stopped != null) break
                poisoningTested++
                poison(input, clean, visitor, cached)?.let(poisoning::add)
            }
            if (withheld.isNotEmpty()) {
                poisoningSkipped = "${withheld.size} input(s) that work by changing the status, the redirect or the path were not sent " +
                    "(${withheld.joinToString(", ") { it.name }}): no new cache-buster value was seen to get a cache entry of its own, so " +
                    "the response they cause could have been stored for every visitor. Their result is inconclusive; test them on a URL " +
                    "whose repeated request is a cache hit, or by hand."
            }
        }

        val deception = ArrayList<DeceptionFinding>()
        var deceptionTested = 0
        var deceptionSkipped: String? = null
        var sessionDependent: Boolean? = null
        if (!config.deception) {
            deceptionSkipped = "not requested"
        } else if (unhealthy != null) {
            deceptionSkipped = unhealthy
        } else if (cached) {
            deceptionSkipped = "the target's own response is already served from the cache"
        } else if (firstResult.status !in 200..299) {
            deceptionSkipped = "the target answers ${firstResult.status}, not a page worth caching"
        } else if (stopped == null) {
            val dependent = visitorResult != null && !alike(firstResult, visitorResult)
            sessionDependent = dependent
            for (variant in variants(base.path, staticDirectories(firstResult.body), config.random)) {
                if (stopped != null) break
                deceptionTested++
                deceive(variant, firstResult, if (dependent) visitorResult else null)?.let(deception::add)
            }
        }

        return Report(
            error = null, busterParam = busterParam, first = first, repeat = repeat, cached = cached, busterEffective = busterEffective,
            poisoning = poisoning, poisoningTested = poisoningTested, poisoningSkipped = poisoningSkipped,
            deception = deception, deceptionTested = deceptionTested, deceptionSkipped = deceptionSkipped,
            sessionDependent = sessionDependent, requests = requests, stopped = stopped,
        )
    }

    // --- poisoning ------------------------------------------------------------------------

    /**
     * Tries one input under its own cache key. [clean] is the target's normal answer, [visitor]
     * the normal answer to a request without a session.
     */
    private fun poison(input: Input, clean: Sample, visitor: Sample, cached: Boolean): PoisonFinding? {
        val key = buster()
        val canary = canaries.next()
        val port = (40_000 + config.random.nextInt(10_000)).toString()
        val value = input.template.replace("%h", config.host).replace("%p", port).replace("%s", canary)
        val marker = if ("%s" in input.template) canary else if ("%p" in input.template) port else null

        val poisoned = withInput(asUser(busted(base, key)), input, value)
        val response = send(poisoned) ?: return null
        val sample = Sample(response, key)
        val effects = effects(sample, clean, marker)
        if (effects.isEmpty()) return null
        val reflected = effects.any { it.startsWith(REFLECTED) }

        val vary = response.header("vary").orEmpty().split(',', '\n').map { it.trim().lowercase() }
        val keyedByVary = "*" in vary || (if (input.kind == COOKIE) "cookie" else input.name.lowercase()) in vary
        val changed = "Sent with ${input.kind} ${input.name}: $value, the response changed (${effects.joinToString("; ")})"
        fun finding(verdict: String, severity: String, detail: String) =
            PoisonFinding(input, value, effects, verdict, severity, detail, "$busterParam=$key", keyedByVary)

        if (busterEffective != true && !effects.all { it.startsWith(REFLECTED) }) {
            // Nothing showed that the cache keys on the cache-buster, so this error or redirect is
            // not planted again to see whether it sticks. A visitor's request under a new
            // cache-buster shows whether it already reaches everyone.
            val now = freshVisit()
            if (stopped == STOP_RATE_LIMITED) return null
            if (now != null && !sameAnswer(now, visitor)) {
                if (marker != null && holds(now, marker)) {
                    busterEffective = false
                    stopped = STOP_BUSTER_IGNORED
                    return finding(
                        CONFIRMED, "high",
                        "$changed, and a request without it, without a session and under a new cache-buster got that response back: the " +
                            "cache ignores the cache-buster and now serves this response to every visitor. The run was stopped; have the " +
                            "cached page purged.",
                    )
                }
                stopped = STOP_BASELINE_CHANGED
                return finding(
                    INCONCLUSIVE, "info",
                    "$changed, and a request without any input under a new cache-buster then got HTTP ${now.result.status} where a " +
                        "visitor first got ${visitor.result.status}: either the cache ignores the cache-buster and now serves this " +
                        "response to every visitor, or the target changed its answer for everyone. The run was stopped; check the page by hand.",
                )
            }
            return finding(
                INCONCLUSIVE, "info",
                "$changed. No new cache-buster value was seen to get a cache entry of its own, so a changed status or redirect is not " +
                    "sent again to see whether it is stored: a cache that ignores the cache-buster would serve it to every visitor. Test " +
                    "it on a URL whose repeated request is a cache hit, or by hand.",
            )
        }
        if (!reflected) {
            // A status or redirect can change on its own: it counts once it repeats under another key.
            val again = buster()
            val repeated = send(withInput(asUser(busted(base, again)), input, value)) ?: return null
            if (effects(Sample(repeated, again), clean, marker).isEmpty()) return null
        }

        // The same URL the way any other visitor asks for it: without the input, without a session.
        val visit = busted(base, key)
        var confirmed = send(visit, anonymous = true)?.let { shows(Sample(it, key), sample, visitor, marker) } == true
        if (!confirmed && stopped == null) {
            // Some caches store a response only once it has been asked for more than once.
            send(poisoned)
            send(poisoned)
            confirmed = send(visit, anonymous = true)?.let { shows(Sample(it, key), sample, visitor, marker) } == true
        }
        // The target began rate limiting: whatever this input seemed to change says nothing.
        if (stopped == STOP_RATE_LIMITED) return null

        if (confirmed && !reflected) {
            // A rate limit, a WAF or an outage gives this URL another status for everyone too: the
            // change is the input's only while a visitor without it still gets the normal answer.
            val now = freshVisit()
            if (now == null) {
                if (stopped == STOP_RATE_LIMITED) return null
                return finding(
                    UNCONFIRMED, if (cached && !keyedByVary) "low" else "info",
                    "$changed, and the same URL requested without it and without a session got that response back, but no request was " +
                        "left to show that a visitor still gets the normal answer under another cache-buster, so it is not confirmed.",
                )
            }
            if (!sameAnswer(now, visitor)) {
                stopped = STOP_BASELINE_CHANGED
                return finding(
                    INCONCLUSIVE, "info",
                    "$changed, and the same URL requested without it got that response back, but so did a request without any input " +
                        "under a new cache-buster (HTTP ${now.result.status}, where a visitor first got ${visitor.result.status}). The " +
                        "target now answers everyone this way (a rate limit, a WAF, an outage) or its cache serves this response whatever " +
                        "the cache-buster, so the change is not put down to the input; the run was stopped. Check the page by hand.",
                )
            }
        }

        return if (confirmed) {
            finding(
                CONFIRMED, if (reflected || effects.any { it.startsWith(REDIRECT) }) "high" else "medium",
                "$changed, and the same URL requested without it and without a session got that changed response back: the cache " +
                    "stores it under a key that leaves this input out, so one request plants it for every visitor.",
            )
        } else {
            finding(
                UNCONFIRMED, if (cached && !keyedByVary) "low" else "info",
                "$changed, but a request without it did not get the changed response back" +
                    (if (keyedByVary) " (Vary lists this input, so the cache keys on it)" else "") +
                    ". Worth another look on URLs of this site that are cached.",
            )
        }
    }

    /** What the input did to [response], compared with the [clean] response: reflections of [marker], a new status, a new redirect target. */
    private fun effects(response: Sample, clean: Sample, marker: String?): List<String> {
        val out = ArrayList<String>()
        if (marker != null) {
            if (response.result.body.contains(marker, ignoreCase = true) && !clean.result.body.contains(marker, ignoreCase = true)) {
                out.add("$REFLECTED body")
            }
            for ((name, value) in response.result.headers) {
                if (value.contains(marker, ignoreCase = true) && clean.result.headers[name]?.contains(marker, ignoreCase = true) != true) {
                    out.add("$REFLECTED header $name")
                }
            }
        }
        if (response.result.status != clean.result.status) {
            out.add("$STATUS ${clean.result.status} -> ${response.result.status}")
        } else if (location(response) != location(clean)) {
            out.add("$REDIRECT target changed to ${location(response) ?: "none"}")
        }
        return out
    }

    /**
     * True when [served], a visitor's answer to the same URL without the input, carries what the
     * input put into [poisoned]: the marker, or the poisoned status and redirect target where a
     * visitor's [normal] answer has another.
     */
    private fun shows(served: Sample, poisoned: Sample, normal: Sample, marker: String?): Boolean {
        if (marker != null && holds(poisoned, marker)) return holds(served, marker)
        if (served.result.status != poisoned.result.status || location(served) != location(poisoned)) return false
        return served.result.status != normal.result.status || location(served) != location(normal)
    }

    private fun holds(sample: Sample, marker: String): Boolean =
        sample.result.body.contains(marker, ignoreCase = true) || sample.result.headers.values.any { it.contains(marker, ignoreCase = true) }

    /** A visitor's request (no input, no session) under a new cache-buster; null when it got no answer. */
    private fun freshVisit(): Sample? {
        val key = buster()
        return send(busted(base, key), anonymous = true)?.let { Sample(it, key) }
    }

    /** Whether [now] is the answer [visitor] got: the same status and redirect target. */
    private fun sameAnswer(now: Sample, visitor: Sample): Boolean =
        now.result.status == visitor.result.status && location(now) == location(visitor)

    /** The redirect target without the cache-buster value, which differs per request by design. */
    private fun location(sample: Sample): String? = sample.result.header("location")?.replace(sample.buster, "")

    private fun withInput(request: ProbeRequest, input: Input, value: String): ProbeRequest {
        if (input.kind != COOKIE) return request.withHeader(input.name, value)
        // The cookie takes the place of one of the same name: a server reads the first it finds.
        val others = request.header("Cookie").orEmpty().split(';').map { it.trim() }
            .filter { it.isNotEmpty() && it.substringBefore('=').trim() != input.name }
        return request.withHeader("Cookie", (others + ProbeText.pairs(listOf(input.name to value), "; ")).joinToString("; "))
    }

    // --- deception ------------------------------------------------------------------------

    /**
     * Requests [variant] as the user, and when the origin answers it with the target's page, again
     * without a session. [anonymous] is the target's own answer without a session, given only
     * when that differs from the user's.
     */
    private fun deceive(variant: Variant, reference: ProbeResult, anonymous: ProbeResult?): DeceptionFinding? {
        val bare = base.withPath(variant.path)
        val request = if (variant.unique) bare else busted(bare, buster())
        val victim = send(asUser(request)) ?: return null
        if (!alike(victim, reference)) return null
        val attacker = send(request, anonymous = true) ?: return null
        val observed = CacheSignals.classify(attacker.headers)
        val stored = CacheSignals.classify(victim.headers)
        val sameAsVictim = alike(attacker, victim)
        return when {
            anonymous != null && sameAsVictim && !alike(attacker, anonymous) -> DeceptionFinding(
                variant.technique, request.target, CONFIRMED, "high",
                "Requested with the session, this URL returned the target's page; requested again without any session, it returned the " +
                    "same page instead of what the target shows a visitor who is not logged in. The cache stored the user's page under a " +
                    "URL anyone can fetch.",
                observed.state,
            )
            anonymous == null && sameAsVictim && observed.state == CacheSignals.State.HIT -> DeceptionFinding(
                variant.technique, request.target, LIKELY, "low",
                "The origin answers this URL with the target's page and the cache stores it (the second request was a cache hit), while " +
                    "the target itself is not cached. Run it again with the session headers of a logged-in user to see whether their page is stored.",
                observed.state,
            )
            sameAsVictim && observed.state != CacheSignals.State.HIT &&
                (stored.state == CacheSignals.State.MISS || stored.storable == true) && anonymous == null -> DeceptionFinding(
                variant.technique, request.target, POTENTIAL, "info",
                "The origin answers this URL with the target's page and the response passed through a cache that could store it, but the " +
                    "second request was not a cache hit.",
                observed.state,
            )
            else -> null
        }
    }

    /** Whether two responses are the same page: same status, and bodies equal or nearly so. */
    private fun alike(a: ProbeResult, b: ProbeResult): Boolean {
        if (a.status != b.status) return false
        if (a.body == b.body) return true
        if (abs(a.body.length - b.body.length) > max(a.body.length, b.body.length) / 10) return false
        return TextSimilarity.dice(a.body.take(SIMILARITY_CHARS), b.body.take(SIMILARITY_CHARS)) >= ALIKE_SIMILARITY
    }

    // --- requests -------------------------------------------------------------------------

    private fun buster(): String = ProbeText.token(config.random, 12)

    private fun busted(request: ProbeRequest, value: String): ProbeRequest = request.withQuery("$busterParam=$value")

    private fun asUser(request: ProbeRequest): ProbeRequest = request.withHeaders(identity)

    private fun send(request: ProbeRequest, anonymous: Boolean = false): ProbeResult? {
        if (stopped != null) return null
        if (requests >= config.maxRequests) {
            stopped = STOP_BUDGET
            return null
        }
        requests++
        val result = try { transport.send(request, anonymous) } catch (_: Exception) { null }
        if (result == null || result.status <= 0) return null
        if (result.status !in THROTTLED) {
            throttled = 0
            return result
        }
        if (++throttled < THROTTLED_RUN) return result
        // Several in a row: what the inputs did, or a rate limit or an overloaded target answering
        // everyone this way? A visitor's request under a new cache-buster tells them apart.
        throttled = 0
        val check = freshVisit()
        if (check == null || check.result.status in THROTTLED) {
            if (stopped == null) stopped = STOP_RATE_LIMITED
            return null
        }
        return result
    }

    private fun report(error: String): Report = Report(
        error = error, busterParam = busterParam, first = null, repeat = null, cached = false, busterEffective = null,
        poisoning = emptyList(), poisoningTested = 0, poisoningSkipped = null,
        deception = emptyList(), deceptionTested = 0, deceptionSkipped = null,
        sessionDependent = null, requests = requests, stopped = stopped,
    )

    companion object {
        const val HEADER = "header"
        const val COOKIE = "cookie"

        const val CONFIRMED = "confirmed"
        const val UNCONFIRMED = "unconfirmed"
        const val INCONCLUSIVE = "inconclusive"
        const val LIKELY = "likely"
        const val POTENTIAL = "potential"
        const val STOP_BUDGET = "request_budget"
        const val STOP_RATE_LIMITED = "rate_limited"
        const val STOP_BASELINE_CHANGED = "baseline_changed"

        /** A response an input caused came back under a new cache-buster: the cache ignores it, and the run stops. */
        const val STOP_BUSTER_IGNORED = "cache_buster_ignored"

        /** Statuses of a rate limit or an overloaded server, and how many in a row make the run check for one. */
        private val THROTTLED = setOf(429, 503)
        private const val THROTTLED_RUN = 3

        /** Headers that make the origin serve another path than the one requested. */
        private val PATH_OVERRIDES = setOf("x-original-url", "x-rewrite-url")

        private const val REFLECTED = "reflected in"
        private const val STATUS = "status"
        private const val REDIRECT = "redirect"
        private const val ALIKE_SIMILARITY = 90.0
        private const val SIMILARITY_CHARS = 100_000
        private const val STATIC_SCAN_CHARS = 200_000

        /** Domain (reserved, RFC 2606) that host-like values point at. */
        const val PROBE_DOMAIN = "raijin-cache-probe.example"

        /**
         * Headers caches commonly leave out of the key while applications or frameworks act on
         * them: host overrides, scheme and port hints, URL rewrites, method overrides, and two
         * request headers pages often echo.
         */
        val DEFAULT_HEADERS: List<Input> = listOf(
            Input(HEADER, "X-Forwarded-Host", "%s.$PROBE_DOMAIN"),
            Input(HEADER, "X-Host", "%s.$PROBE_DOMAIN"),
            Input(HEADER, "X-Forwarded-Server", "%s.$PROBE_DOMAIN"),
            Input(HEADER, "X-HTTP-Host-Override", "%s.$PROBE_DOMAIN"),
            Input(HEADER, "X-Original-Host", "%s.$PROBE_DOMAIN"),
            Input(HEADER, "Forwarded", "host=%s.$PROBE_DOMAIN"),
            Input(HEADER, "X-Forwarded-Scheme", "http"),
            Input(HEADER, "X-Forwarded-Proto", "http"),
            Input(HEADER, "X-Forwarded-Ssl", "off"),
            Input(HEADER, "Front-End-Https", "off"),
            Input(HEADER, "X-Forwarded-Port", "%p"),
            Input(HEADER, "X-Forwarded-Prefix", "/%s"),
            Input(HEADER, "X-Original-URL", "/%s"),
            Input(HEADER, "X-Rewrite-URL", "/%s"),
            Input(HEADER, "X-HTTP-Method-Override", "POST"),
            Input(HEADER, "X-HTTP-Method", "POST"),
            Input(HEADER, "X-Method-Override", "POST"),
            Input(HEADER, "Origin", "https://%s.$PROBE_DOMAIN"),
            Input(HEADER, "Referer", "https://%s.$PROBE_DOMAIN/"),
            Input(HEADER, "X-Forwarded-For", "%s"),
        )

        /** Cookie names that often select a variant of the page without being part of the cache key. */
        val DEFAULT_COOKIES: List<String> = listOf("lang", "language", "locale", "country", "region", "currency", "theme", "variant")

        private val DELIMITERS = listOf(
            "semicolon" to ";", "encoded_hash" to "%23", "encoded_question" to "%3f",
            "null_byte" to "%00", "newline" to "%0a", "exclamation" to "!",
        )

        private val STATIC_REFERENCE = Regex("""(?:src|href)=["'](/[A-Za-z0-9_\-]{1,40})/[^"'\s>]{1,200}\.(?:js|css|png|jpe?g|gif|svg|ico|woff2?)""")

        /**
         * URLs that an origin may answer with the page at [path] while a cache files them as
         * static: a made-up file under the path, the path cut off by a delimiter the origin
         * honours and the cache does not, a static extension appended, and the path reached
         * through an encoded `..` from a directory ([staticDirectories]) the cache stores wholesale.
         */
        fun variants(path: String, staticDirectories: List<String>, random: Random): List<Variant> {
            val stem = if (path.length > 1) path.trimEnd('/') else ""
            fun file(extension: String) = ProbeText.token(random, 10) + "." + extension
            val out = ArrayList<Variant>()
            out.add(Variant("path_suffix", stem + "/" + file("css"), true))
            out.add(Variant("path_suffix", stem + "/" + file("js"), true))
            for ((label, delimiter) in DELIMITERS) {
                out.add(Variant("delimiter_$label", stem.ifEmpty { "/" } + delimiter + file("css"), true))
            }
            if (stem.isNotEmpty()) {
                out.add(Variant("extension_suffix", "$stem.css", false))
                for (directory in staticDirectories) {
                    out.add(Variant("static_directory_traversal", directory + "/..%2f" + stem.removePrefix("/"), false))
                }
            }
            return out
        }

        /** The top-level directories [body] loads static files from, commonest first (at most two); `/static` and `/assets` when it names none. */
        fun staticDirectories(body: String): List<String> {
            val counts = STATIC_REFERENCE.findAll(body.take(STATIC_SCAN_CHARS)).groupingBy { it.groupValues[1] }.eachCount()
            val found = counts.entries.sortedByDescending { it.value }.map { it.key }.take(2)
            return found.ifEmpty { listOf("/static", "/assets") }
        }

        /**
         * The inputs to try, in order: what the caller adds as `name` or `name~value` (`%s`
         * canary, `%h` host, `%p` port), the default headers, the cookies the target itself
         * sets ([targetCookies]), the default cookies.
         */
        fun inputs(targetCookies: List<String>, extraHeaders: List<String>, extraCookies: List<String>): List<Input> {
            val out = LinkedHashMap<String, Input>()
            fun add(input: Input) {
                val name = if (input.kind == COOKIE) input.name else input.name.lowercase()
                out.putIfAbsent(input.kind + ":" + name + ":" + input.template, input)
            }
            fun custom(kind: String, spec: String) {
                val sep = spec.indexOf('~')
                val name = (if (sep > 0) spec.substring(0, sep) else spec).trim()
                if (name.isNotEmpty()) add(Input(kind, name, if (sep > 0 && sep < spec.length - 1) spec.substring(sep + 1) else "%s"))
            }
            extraHeaders.forEach { custom(HEADER, it) }
            extraCookies.forEach { custom(COOKIE, it) }
            DEFAULT_HEADERS.forEach(::add)
            targetCookies.forEach { add(Input(COOKIE, it)) }
            DEFAULT_COOKIES.forEach { add(Input(COOKIE, it)) }
            return out.values.toList()
        }

        /** Cookie names in a Cookie header value (`;` between cookies) or joined Set-Cookie values (one per line). */
        internal fun cookieNames(text: String, separator: Char): List<String> =
            text.split(separator).map { it.substringBefore('=').trim() }.filter { it.isNotEmpty() }.distinct()
    }
}
