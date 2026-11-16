package io.bitbytelab.raijin.webprobe

/**
 * Reads what a response's headers say about the cache in front of the origin: whether this
 * response came out of it, and which CDN or proxy it is.
 */
object CacheSignals {

    enum class State {
        /** Served from the cache. */
        HIT,

        /** Fetched from the origin by a cache that can store it. */
        MISS,

        /** The cache says it does not store this response (bypass, dynamic, no-store). */
        UNCACHEABLE,

        /** No header says either way. */
        UNKNOWN,
    }

    /**
     * @param vendor the CDN / cache product recognised, or null.
     * @param evidence the `header: value` lines the verdict rests on.
     * @param age the `Age` header in seconds, or null.
     * @param storable what Cache-Control allows a shared cache to do: true (public / max-age),
     *   false (no-store / private), null when it does not say.
     */
    data class Observation(
        val state: State,
        val vendor: String?,
        val evidence: List<String>,
        val age: Int?,
        val storable: Boolean?,
    )

    /** Headers whose value is a hit/miss word, most specific first. */
    private val STATUS_HEADERS = listOf(
        "cf-cache-status", "x-cache", "x-cache-status", "cache-status", "x-vercel-cache", "cdn-cache",
        "x-proxy-cache", "x-cache-remote", "x-cache-lookup", "x-drupal-cache", "x-drupal-dynamic-cache",
        "x-litespeed-cache", "x-sucuri-cache", "x-fastcgi-cache", "x-nginx-cache", "x-rack-cache",
        "x-kinsta-cache", "x-wp-cf-super-cache", "x-cache-info",
    )

    private val UNCACHEABLE_WORDS = listOf("bypass", "pass", "dynamic", "nocache", "no-cache", "nostore", "uncacheable", "denied", "ignored")

    /** [headers]: lower-cased names to values (repeated headers joined by a newline). */
    fun classify(headers: Map<String, String>): Observation {
        val evidence = ArrayList<String>()
        var state = State.UNKNOWN

        for (name in STATUS_HEADERS) {
            val value = headers[name] ?: continue
            val read = statusWord(name, value) ?: continue
            evidence.add("$name: ${value.replace('\n', ',')}")
            if (state == State.UNKNOWN) state = read
        }
        headers["server-timing"]?.lowercase()?.let { timing ->
            val read = when {
                "cdn-cache-hit" in timing || "desc=hit" in timing -> State.HIT
                "cdn-cache-miss" in timing || "desc=miss" in timing -> State.MISS
                else -> null
            }
            if (read != null) {
                evidence.add("server-timing: $timing")
                if (state == State.UNKNOWN) state = read
            }
        }
        // Fastly / Varnish count the hits for this object; the last number is the edge closest to the client.
        headers["x-cache-hits"]?.let { hits ->
            val last = hits.split(',', '\n').last().trim().toIntOrNull()
            if (last != null) {
                evidence.add("x-cache-hits: ${hits.replace('\n', ',')}")
                if (state == State.UNKNOWN) state = if (last > 0) State.HIT else State.MISS
            }
        }
        // Varnish lists two transaction ids for an object it already had, one for a fetch.
        headers["x-varnish"]?.let { ids ->
            val count = ids.trim().split(' ', ',', '\n').count { it.isNotBlank() }
            evidence.add("x-varnish: ${ids.replace('\n', ',')}")
            if (state == State.UNKNOWN) state = if (count >= 2) State.HIT else State.MISS
        }
        val age = headers["age"]?.lineSequence()?.firstOrNull()?.trim()?.toIntOrNull()
        if (age != null && age > 0) {
            evidence.add("age: $age")
            // Only a cache adds Age; a positive one with no other word means the response sat in one.
            if (state == State.UNKNOWN) state = State.HIT
        }

        val cacheControl = headers["cache-control"]?.lowercase()
        val storable = when {
            cacheControl == null -> null
            "no-store" in cacheControl || "private" in cacheControl -> false
            "public" in cacheControl || positive(cacheControl, "s-maxage") || positive(cacheControl, "max-age") -> true
            else -> null
        }
        return Observation(state, vendor(headers), evidence, age, storable)
    }

    /** The state a hit/miss header value names; for a list (one entry per cache tier) the last entry, nearest the client. */
    private fun statusWord(name: String, value: String): State? {
        val text = value.lowercase()
        if (name == "x-rack-cache") {
            // "miss, store" / "fresh" / "stale, valid, store" / "pass"
            return when {
                "fresh" in text || "valid" in text -> State.HIT
                "miss" in text -> State.MISS
                "pass" in text -> State.UNCACHEABLE
                else -> null
            }
        }
        val last = text.split(',', '\n').last().trim()
        return when {
            "miss" in last || "expired" in last -> State.MISS
            "hit" in last || "stale" in last || "revalidated" in last || "updating" in last -> State.HIT
            UNCACHEABLE_WORDS.any { it in last } -> State.UNCACHEABLE
            else -> null
        }
    }

    private fun positive(cacheControl: String, directive: String): Boolean {
        val at = cacheControl.indexOf("$directive=")
        if (at < 0) return false
        val digits = cacheControl.substring(at + directive.length + 1).takeWhile { it.isDigit() }
        return (digits.toLongOrNull() ?: 0L) > 0L
    }

    private fun vendor(headers: Map<String, String>): String? {
        val server = headers["server"].orEmpty().lowercase()
        val via = headers["via"].orEmpty().lowercase()
        val xCache = headers["x-cache"].orEmpty().lowercase()
        return when {
            "cf-ray" in headers || "cf-cache-status" in headers || "cloudflare" in server -> "cloudflare"
            "x-amz-cf-id" in headers || "cloudfront" in via || "cloudfront" in xCache -> "cloudfront"
            "x-akamai-request-id" in headers || "akamai" in server || "akamai" in xCache || headers.keys.any { it.startsWith("x-akamai-") } -> "akamai"
            "x-fastly-request-id" in headers || ("x-served-by" in headers && "x-cache-hits" in headers) || "fastly" in via -> "fastly"
            "x-azure-ref" in headers || "x-msedge-ref" in headers -> "azure"
            "x-vercel-id" in headers || "x-vercel-cache" in headers -> "vercel"
            "x-nf-request-id" in headers -> "netlify"
            "x-sucuri-id" in headers || "x-sucuri-cache" in headers -> "sucuri"
            "x-iinfo" in headers || "imperva" in headers["x-cdn"].orEmpty().lowercase() -> "imperva"
            "cdn-requestid" in headers || "bunnycdn" in server -> "bunnycdn"
            "keycdn" in server -> "keycdn"
            "x-varnish" in headers || "varnish" in via -> "varnish"
            "squid" in via || "squid" in xCache || "squid" in server -> "squid"
            "x-litespeed-cache" in headers -> "litespeed"
            "x-drupal-cache" in headers || "x-drupal-dynamic-cache" in headers -> "drupal"
            "x-cache-status" in headers || "x-proxy-cache" in headers || "x-fastcgi-cache" in headers || "x-nginx-cache" in headers -> "nginx"
            else -> null
        }
    }
}
