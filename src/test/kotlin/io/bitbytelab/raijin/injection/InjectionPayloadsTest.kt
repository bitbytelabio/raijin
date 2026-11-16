package io.bitbytelab.raijin.injection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class InjectionPayloadsTest {

    /**
     * True when [text] closes every quote and parenthesis it opens. A `-- ` comment swallows the
     * rest, as it does in SQL, so only what precedes it has to balance.
     */
    private fun balanced(text: String): Boolean {
        var depth = 0
        var quote: Char? = null
        var i = 0
        while (i < text.length) {
            val ch = text[i]
            if (quote != null) {
                if (ch == quote) quote = null
            } else if (ch == '\'' || ch == '"') {
                quote = ch
            } else if (ch == '-' && text.startsWith("-- ", i)) {
                return depth == 0
            } else if (ch == '(') {
                depth++
            } else if (ch == ')') {
                depth--
                if (depth < 0) return false
            }
            i++
        }
        return quote == null && depth == 0
    }

    private fun inPlace(payload: InjectionPayloads.Enclosed, text: String): String = payload.before + text + payload.after

    private val rounds = InjectionPayloads.booleanRounds.indices

    @Test
    fun `the balance check rejects the unterminated literal that used to ship`() {
        assertFalse(balanced("'" + "'||('1'='1)||'" + "'"))
        assertTrue(balanced("'" + "'||('1'='1')||'" + "'"))
        assertFalse(balanced("(1) AND (2"))
        assertTrue(balanced("'1' AND SLEEP(5)-- -'"))
    }

    @Test
    fun `boolean pairs are well-formed in the query they assume`() {
        val pairs = InjectionPayloads.sqlBoolean + InjectionPayloads.nosqlBoolean
        assertTrue(pairs.size >= 8)
        for (pair in pairs) for (round in rounds) for (truth in listOf(true, false)) {
            val payload = InjectionPayloads.boolean(pair.text, "1", round, truth)
            assertTrue(balanced(inPlace(pair, payload)), "unbalanced: ${inPlace(pair, payload)}")
            assertFalse('{' in payload, "unfilled placeholder: $payload")
        }
    }

    @Test
    fun `the FALSE payload is the TRUE payload with its two literals swapped`() {
        for (pair in InjectionPayloads.sqlBoolean + InjectionPayloads.nosqlBoolean) for (round in rounds) {
            val literals = InjectionPayloads.booleanRounds[round]
            val whenTrue = InjectionPayloads.boolean(pair.text, "1", round, true)
            val whenFalse = InjectionPayloads.boolean(pair.text, "1", round, false)
            assertNotEquals(whenTrue, whenFalse)
            assertEquals(whenTrue.toList().sorted(), whenFalse.toList().sorted(), "same characters: $whenTrue / $whenFalse")
            assertTrue(Regex("${literals.lo}\\D*<\\D*${literals.hi}").containsMatchIn(whenTrue), whenTrue)
            assertTrue(Regex("${literals.hi}\\D*<\\D*${literals.lo}").containsMatchIn(whenFalse), whenFalse)
        }
    }

    @Test
    fun `round literals order the same as numbers and as strings and are never reused`() {
        val all = InjectionPayloads.booleanRounds.flatMap { listOf(it.lo, it.hi) }
        assertEquals(all.size, all.toSet().size)
        assertTrue(InjectionPayloads.booleanRounds.size >= 3)
        for ((lo, hi) in InjectionPayloads.booleanRounds) {
            assertEquals(lo.length, hi.length)
            assertTrue(lo.toInt() < hi.toInt())
            assertTrue(lo < hi)
        }
    }

    @Test
    fun `timing payloads are well-formed with a delay and as a zero-delay control`() {
        val payloads = listOf(InjectionPayloads.sqlTime, InjectionPayloads.nosqlTime, InjectionPayloads.cmdTime).flatten()
        for (payload in payloads) {
            val delayed = InjectionPayloads.timed(payload.text, "1", 7)
            val control = InjectionPayloads.timed(payload.text, "1", 0)
            assertTrue(balanced(inPlace(payload, delayed)), "unbalanced: ${inPlace(payload, delayed)}")
            assertNotEquals(delayed, control, "the control must ask for a different delay")
            assertFalse("{delay" in delayed || "{pings}" in delayed || "{base}" in delayed, delayed)
            assertTrue(delayed.startsWith("1"), "appended to the base value: $delayed")
            assertEquals(delayed.replace(Regex("[0-9]+"), "N"), control.replace(Regex("[0-9]+"), "N"), "the control differs in the delay only")
        }
        assertEquals("1;sleep(7000);", InjectionPayloads.timed("{base};sleep({delay_ms});", "1", 7))
        assertEquals("1&ping -n 8 127.0.0.1", InjectionPayloads.timed("{base}&ping -n {pings} 127.0.0.1", "1", 7))
    }

    @Test
    fun `an unquoted numeric value has payloads that close no quote or parenthesis`() {
        val boolean = InjectionPayloads.sqlBoolean.filter { it.before.isEmpty() && it.after.isEmpty() }
        assertTrue(boolean.any { '\'' !in it.text && '"' !in it.text && '(' !in it.text }, boolean.toString())
        val timed = InjectionPayloads.sqlTime.filter { it.before.isEmpty() && it.after.isEmpty() }
        assertTrue(timed.any { it.text.startsWith("{base} AND ") }, timed.toString())
        assertTrue(timed.any { it.text.startsWith("{base};WAITFOR") }, timed.toString())
    }

    @Test
    fun `operator probes use the same operators with swapped operands`() {
        for (probe in InjectionPayloads.nosqlOperators) for (round in rounds) {
            val whenTrue = probe.bounds(round, true)
            val whenFalse = probe.bounds(round, false)
            assertNotEquals(whenTrue, whenFalse, probe.label)
            assertEquals(whenTrue.map { it.first }, whenFalse.map { it.first }, probe.label)
            assertEquals(
                whenTrue.joinToString("") { it.second }.toList().sorted(),
                whenFalse.joinToString("") { it.second }.toList().sorted(),
                "${probe.label}: operands carry the same characters",
            )
            if (probe.numeric) (whenTrue + whenFalse).forEach { assertTrue(it.second.toLongOrNull() != null, it.second) }
        }
    }

    @Test
    fun `arithmetic templates take the operands`() {
        assertEquals("{{3*4}}", InjectionPayloads.arithmetic("{{A*B}}", "1", 3, 4))
        assertEquals("1;echo \$((3*4))", InjectionPayloads.arithmetic("{base};echo \$((A*B))", "1", 3, 4))
        for (template in InjectionPayloads.sstiArithmetic + InjectionPayloads.cmdArithmetic) {
            assertTrue("A*B" in template, template)
            assertFalse("12" in InjectionPayloads.arithmetic(template, "x", 3, 4), "the result must not be in the payload")
        }
    }
}
