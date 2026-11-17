package io.bitbytelab.raijin.safety

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class SafeRegexTest {

    @Test
    fun `compile caches and returns the same instance for the same pattern`() {
        assertSame(SafeRegex.compile("a+b*"), SafeRegex.compile("a+b*"))
    }

    @Test
    fun `containsMatchIn matches and rejects correctly`() {
        assertTrue(SafeRegex.containsMatchIn("a+", "xaaay"))
        assertFalse(SafeRegex.containsMatchIn("a+", "xyz"))
    }

    @Test
    fun `invalid pattern is treated as no-match, never throws`() {
        // unclosed group → PatternSyntaxException must be swallowed
        assertFalse(SafeRegex.containsMatchIn("(", "anything"))
    }

    @Test
    fun `input longer than the cap is treated as no-match`() {
        assertFalse(SafeRegex.containsMatchIn(".*", "x".repeat(50), maxInputLen = 10))
    }

    @Test
    fun `find returns the capture group`() {
        val m = SafeRegex.find("id=(\\d+)", "user id=42 end")
        assertEquals("42", m?.groupValues?.get(1))
    }

    @Test
    fun `find returns null when no match`() {
        assertNull(SafeRegex.find("id=(\\d+)", "no number here"))
    }

    @Test
    fun `matches requires a full match`() {
        assertTrue(SafeRegex.matches("a+", "aaa"))
        assertFalse(SafeRegex.matches("a+", "aaab"))
    }

    @Test
    fun `ignoreCase is honoured`() {
        assertTrue(SafeRegex.containsMatchIn("abc", "xABCy", ignoreCase = true))
        assertFalse(SafeRegex.containsMatchIn("abc", "xABCy", ignoreCase = false))
    }

    @Test
    fun `replace substitutes matches and is safe on invalid patterns`() {
        assertEquals("a#b#", SafeRegex.replace("\\d+", "a1b2", "#"))
        assertEquals("unchanged", SafeRegex.replace("(", "unchanged", "X"))
    }

    @Test
    fun `catastrophic backtracking aborts via the deadline instead of hanging`() {
        // Classic ReDoS pattern + non-matching tail. With a tiny timeout this must
        // return (false) quickly rather than backtrack forever.
        val evil = "(a+)+$"
        val input = "a".repeat(40) + "!"
        assertFalse(SafeRegex.containsMatchIn(evil, input, timeoutMs = 50))
    }

    @Test
    fun `matchesHostPattern treats alternation and braced quantifiers as regex`() {
        assertTrue(SafeRegex.matchesHostPattern("api|staging", "staging"))
        assertTrue(SafeRegex.matchesHostPattern("api|staging", "API"))
        assertFalse(SafeRegex.matchesHostPattern("api|staging", "prod"))
        assertTrue(SafeRegex.matchesHostPattern("node[0-9]{2}", "node07"))
        assertFalse(SafeRegex.matchesHostPattern("node[0-9]{2}", "node7"))
    }

    @Test
    fun `findAll and replaceOrNull bound oversize and timing-out inputs`() {
        assertEquals(emptyList(), SafeRegex.findAll(Regex("a"), "a".repeat(20), maxInputLen = 10))
        assertEquals(listOf("1", "2"), SafeRegex.findAll(Regex("\\d"), "a1b2").map { it.value })
        val slow = object : CharSequence {
            private val backing = "ababababab"
            override val length: Int get() = backing.length
            override fun get(index: Int): Char {
                if (index == 0) Thread.sleep(20)
                return backing[index]
            }
            override fun subSequence(startIndex: Int, endIndex: Int): CharSequence = backing.subSequence(startIndex, endIndex)
        }
        assertEquals(emptyList(), SafeRegex.findAll(Regex("[ab]{2}"), slow, timeoutMs = 5))
        assertNull(SafeRegex.replaceOrNull("[ab]{2}", slow, timeoutMs = 5) { "x" })
        assertNull(SafeRegex.replaceOrNull("a", "aaa", maxInputLen = 2) { "b" })
        assertEquals("b1b2", SafeRegex.replaceOrNull("a", "a1a2") { "b" })
    }
}
