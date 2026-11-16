package io.bitbytelab.raijin.state

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** The Autorize state: the query-aware dedup guard, the bounded match log and the per-rule tallies. */
class AutorizeStateTest {

    private fun key(url: String, method: String = "GET") = AutorizeSeenGuard.key("arule-1", method, url)

    @Test
    fun `the dedup key keeps the query, whatever the parameter order and the method's case`() {
        assertEquals(key("https://x/a?b=2&a=1", "get"), key("https://x/a?a=1&b=2"))
        assertNotEquals(key("https://x/a?id=1"), key("https://x/a?id=2"), "each object is its own authorization question")
        assertNotEquals(key("https://x/a?action=export"), key("https://x/a?action=delete"))
        assertNotEquals(key("https://x/a?id=1"), key("https://x/a"))
        assertNotEquals(key("https://x/a", "GET"), key("https://x/a", "HEAD"))
        assertEquals(key("https://x/a#top"), key("https://x/a"))
        assertEquals("arule-1|GET|https://x/a", AutorizeSeenGuard.endpointKey("arule-1", "get", "https://x/a?id=1#top"))
    }

    @Test
    fun `values that change on every request are not told apart`() {
        assertEquals(key("https://x/a?id=1&_=1731800000001"), key("https://x/a?_=1731800000002&id=1"), "cache buster")
        assertEquals(key("https://x/a?at=2026-11-17T10:00"), key("https://x/a?at=2026-11-18T11:30"), "timestamp")
        assertEquals(
            key("https://x/a?sig=3f2a9c0d8e7b6a51"),
            key("https://x/a?sig=9e8d7c6b5a4f3e21"),
            "a long token with digits",
        )
        assertNotEquals(key("https://x/a?q=hello"), key("https://x/a?q=world"), "words stay apart")
        assertEquals("a&b=", AutorizeSeenGuard.normalizedQuery("https://x/p?b=&a&b="))
    }

    @Test
    fun `query variants of one endpoint are capped`() {
        val guard = AutorizeSeenGuard(maxEntries = 100, maxVariants = 2)
        val endpoint = AutorizeSeenGuard.endpointKey("arule-1", "GET", "https://x/search")
        assertTrue(guard.seenOnce(key("https://x/search?q=a"), endpoint))
        assertTrue(guard.seenOnce(key("https://x/search?q=b"), endpoint))
        assertFalse(guard.seenOnce(key("https://x/search?q=c"), endpoint), "beyond the ceiling")
        assertFalse(guard.seenOnce(key("https://x/search?q=a"), endpoint), "a repeat")
        assertTrue(guard.seenOnce(key("https://x/search"), endpoint), "the bare endpoint is not a variant")

        guard.clear("arule-1")
        assertTrue(guard.seenOnce(key("https://x/search?q=c"), endpoint))
    }

    @Test
    fun `the guard empties itself rather than grow without end`() {
        val guard = AutorizeSeenGuard(maxEntries = 3)
        (1..4).forEach { assertTrue(guard.seenOnce(key("https://x/$it"))) }
        assertTrue(guard.seenOnce(key("https://x/5")))
        assertTrue(guard.seenOnce(key("https://x/1")), "forgotten in the reset: tested again, which is harmless")
    }

    private fun AutorizeMatchLog.add(url: String, softDenial: Boolean = false, response: String = "") =
        add("arule-1", "GET", url, 200, emptyList(), "GET / HTTP/1.1\r\n\r\n", response, softDenial = softDenial)

    @Test
    fun `the log keeps the newest matches, newest first`() {
        val log = AutorizeMatchLog(maxMatches = 3)
        (1..5).forEach { log.add("https://x/$it") }
        assertEquals(listOf("https://x/5", "https://x/4", "https://x/3"), log.matches.map { it.url })
        assertEquals(listOf(5L, 4L, 3L), log.matches.map { it.id })
    }

    @Test
    fun `soft denials cannot push confirmed matches out`() {
        val log = AutorizeMatchLog(maxMatches = 10, maxSoftDenials = 2)
        log.add("https://x/confirmed")
        (1..3).forEach { log.add("https://x/soft$it", softDenial = true) }
        assertEquals(listOf("https://x/soft3", "https://x/soft2", "https://x/confirmed"), log.matches.map { it.url })
    }

    @Test
    fun `messages are cut to their caps and the text held in total is bounded`() {
        val log = AutorizeMatchLog(maxMatches = 100, maxChars = 100_000)
        val long = log.add(
            "arule-1", "GET", "https://x/long", 200, emptyList(), "R".repeat(70_000), "S".repeat(10),
            replays = listOf(AutorizeReplay("low", 200, "r", "B".repeat(40_000))),
        )
        assertTrue(long.request.endsWith("[truncated by Raijin: 70000 characters in total]"))
        assertEquals(AutorizeMatch.MAX_REQUEST_CHARS, long.request.substringBefore('\n').length)
        assertTrue(long.replays.single().response.endsWith("[truncated by Raijin: 40000 characters in total]"))

        log.reset()
        (1..4).forEach { log.add("https://x/$it", response = "x".repeat(30_000)) }
        assertEquals(listOf("https://x/4", "https://x/3", "https://x/2"), log.matches.map { it.url }, "the oldest goes beyond 100k characters")

        val tiny = AutorizeMatchLog(maxChars = 10)
        tiny.add("https://x/big", response = "x".repeat(1_000))
        assertEquals(1, tiny.matches.size, "the newest match is kept whatever its size")
    }

    @Test
    fun `restoring announces nothing and continues the id sequence`() {
        val log = AutorizeMatchLog(maxMatches = 2)
        var announced = 0
        log.addListeners += { announced++ }
        fun stored(id: Long) = AutorizeMatch(id, "arule-1", "2026-11-17T00:00:00Z", "GET", "https://x/$id", 200, emptyList(), "", "")

        log.restore(listOf(stored(7), stored(5), stored(3)))
        assertEquals(listOf(7L, 5L), log.matches.map { it.id }, "within the log's bounds")
        assertEquals(0, announced)

        assertEquals(8L, log.add("https://x/new").id)
        assertEquals(1, announced)
    }

    @Test
    fun `clearing tells the listeners and unloading forgets them`() {
        val log = AutorizeMatchLog()
        var cleared = 0
        log.clearListeners += { cleared++ }
        log.add("arule-1", "GET", "https://x/1", 200, emptyList(), "", "")
        log.add("arule-2", "GET", "https://x/2", 200, emptyList(), "", "")

        log.clear("arule-1")
        assertEquals(listOf("arule-2"), log.matches.map { it.ruleId })
        assertEquals(1, cleared)

        log.reset()
        assertTrue(log.matches.isEmpty())
        assertTrue(log.clearListeners.isEmpty() && log.addListeners.isEmpty())
    }

    @Test
    fun `activity is tallied per rule and outcome`() {
        val activity = AutorizeActivity()
        activity.count("arule-1", "replayed")
        activity.count("arule-1", "replayed")
        activity.count("arule-1", "flagged")
        activity.count("arule-2", "filtered")
        assertEquals(mapOf("flagged" to 1L, "replayed" to 2L), activity.of("arule-1"))
        assertEquals(listOf("flagged", "replayed"), activity.of("arule-1").keys.toList())

        activity.clear("arule-1")
        assertTrue(activity.of("arule-1").isEmpty())
        assertEquals(mapOf("filtered" to 1L), activity.of("arule-2"))
    }

    @Test
    fun `restored matches keep a new rule from taking their rule's id`() {
        val sm = StateManager()
        sm.restoreAutorizeMatches(
            listOf(AutorizeMatch(4, "arule-012", "2026-11-17T00:00:00Z", "GET", "https://x/", 200, emptyList(), "", ""))
        )
        assertEquals("arule-013", sm.generateId("arule"))
        assertEquals(5L, sm.addAutorizeMatch("arule-013", "GET", "https://x/b", 200, emptyList(), "", "").id)
    }
}
