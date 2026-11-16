package io.bitbytelab.raijin.graphql

import java.time.Duration
import java.time.Instant

/**
 * Bounded least-recently-used cache with a time-to-live, keyed by an endpoint URL plus the exact
 * header set a fetch used. It holds the schemas `GraphQlBridge` builds from full introspection: a
 * schema fetched under one identity must never answer for another (introspection can depend on the
 * caller's role), so the key carries the headers themselves rather than a `hashCode()` of them,
 * which can collide. Headers are compared in a canonical order with lower-cased names, because
 * neither their order nor the case of their names changes the request's identity.
 */
class SchemaCache<V : Any>(
    private val maxEntries: Int = DEFAULT_MAX_ENTRIES,
    private val ttl: Duration = DEFAULT_TTL,
    private val now: () -> Instant = Instant::now,
) {
    /** Cache identity of one fetch: the URL and its headers as sorted (lower-cased name, value) pairs. */
    data class Key(val url: String, val headers: List<Pair<String, String>>)

    private class Stored<V>(val value: V, val at: Instant)

    // Access-ordered: the eldest entry is the least recently used one.
    private val entries = object : LinkedHashMap<Key, Stored<V>>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Key, Stored<V>>): Boolean = size > maxEntries
    }

    /** The value cached for this URL and header set, or null when there is none or it is older than the TTL. */
    @Synchronized
    fun get(url: String, headers: Map<String, String>): V? {
        val key = keyOf(url, headers)
        val stored = entries[key] ?: return null
        if (Duration.between(stored.at, now()) >= ttl) {
            entries.remove(key)
            return null
        }
        return stored.value
    }

    /** Caches [value], evicting the least recently used entry once more than `maxEntries` are held. */
    @Synchronized
    fun put(url: String, headers: Map<String, String>, value: V) {
        entries[keyOf(url, headers)] = Stored(value, now())
    }

    @Synchronized
    fun size(): Int = entries.size

    companion object {
        const val DEFAULT_MAX_ENTRIES = 16
        val DEFAULT_TTL: Duration = Duration.ofMinutes(10)

        fun keyOf(url: String, headers: Map<String, String>): Key = Key(
            url,
            headers.map { (name, value) -> name.trim().lowercase() to value }
                .sortedWith(compareBy({ it.first }, { it.second })),
        )
    }
}
