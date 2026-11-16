package io.bitbytelab.raijin.graphql

import java.time.Duration
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class SchemaCacheTest {

    private val url = "https://target.example/graphql"

    @Test
    fun `header order and header-name case do not change the key`() {
        val cache = SchemaCache<String>()
        cache.put(url, linkedMapOf("Authorization" to "Bearer a", "Cookie" to "sid=1"), "schema")

        assertEquals("schema", cache.get(url, linkedMapOf("Cookie" to "sid=1", "Authorization" to "Bearer a")))
        assertEquals("schema", cache.get(url, mapOf("authorization" to "Bearer a", "COOKIE" to "sid=1")))
        assertEquals(1, cache.size())
    }

    @Test
    fun `another identity never gets a schema fetched under different headers`() {
        val cache = SchemaCache<String>()
        cache.put(url, mapOf("Authorization" to "Bearer admin"), "admin schema")

        assertNull(cache.get(url, mapOf("Authorization" to "Bearer guest")))
        assertNull(cache.get(url, emptyMap()))
        assertNull(cache.get(url, mapOf("Authorization" to "Bearer admin", "X-Role" to "1")))
        assertNull(cache.get("https://other.example/graphql", mapOf("Authorization" to "Bearer admin")))
    }

    @Test
    fun `headers with colliding hash codes are different keys`() {
        // "Aa" and "BB" hash alike, so do the two maps: a key built from headers.hashCode() served one for the other.
        val first = mapOf("Authorization" to "Aa")
        val second = mapOf("Authorization" to "BB")
        assertEquals(first.hashCode(), second.hashCode())

        val cache = SchemaCache<String>()
        cache.put(url, first, "schema of Aa")

        assertNull(cache.get(url, second))
        assertEquals("schema of Aa", cache.get(url, first))
    }

    @Test
    fun `the least recently used entry is evicted once the cache is full`() {
        val cache = SchemaCache<String>(maxEntries = 2)
        cache.put("a", emptyMap(), "A")
        cache.put("b", emptyMap(), "B")
        assertEquals("A", cache.get("a", emptyMap())) // "b" is now the least recently used
        cache.put("c", emptyMap(), "C")

        assertEquals(2, cache.size())
        assertNull(cache.get("b", emptyMap()))
        assertEquals("A", cache.get("a", emptyMap()))
        assertEquals("C", cache.get("c", emptyMap()))
    }

    @Test
    fun `the cache never grows past its bound`() {
        val cache = SchemaCache<Int>(maxEntries = 3)
        repeat(100) { cache.put("https://t/$it", emptyMap(), it) }

        assertEquals(3, cache.size())
        assertEquals(99, cache.get("https://t/99", emptyMap()))
        assertNull(cache.get("https://t/0", emptyMap()))
    }

    @Test
    fun `an entry older than the time-to-live is dropped`() {
        var now = Instant.parse("2026-01-01T00:00:00Z")
        val cache = SchemaCache<String>(ttl = Duration.ofMinutes(10), now = { now })
        cache.put(url, emptyMap(), "schema")

        now = now.plus(Duration.ofMinutes(9))
        assertEquals("schema", cache.get(url, emptyMap()))

        now = now.plus(Duration.ofMinutes(1))
        assertNull(cache.get(url, emptyMap()))
        assertEquals(0, cache.size())
    }

    @Test
    fun `putting the same key again replaces the value and restarts its lifetime`() {
        var now = Instant.parse("2026-01-01T00:00:00Z")
        val cache = SchemaCache<String>(ttl = Duration.ofMinutes(10), now = { now })
        cache.put(url, emptyMap(), "old")
        now = now.plus(Duration.ofMinutes(8))
        cache.put(url, emptyMap(), "new")
        now = now.plus(Duration.ofMinutes(8))

        assertEquals("new", cache.get(url, emptyMap()))
        assertEquals(1, cache.size())
    }

    @Test
    fun `keyOf sorts the headers and lower-cases their names`() {
        val key = SchemaCache.keyOf(url, linkedMapOf("X-B" to "2", "Cookie" to "c", "Authorization" to "a"))
        assertEquals(listOf("authorization" to "a", "cookie" to "c", "x-b" to "2"), key.headers)
        assertEquals(url, key.url)
    }
}
