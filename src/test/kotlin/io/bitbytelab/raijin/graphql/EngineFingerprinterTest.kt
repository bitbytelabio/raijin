package io.bitbytelab.raijin.graphql

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class EngineFingerprinterTest {

    @Test
    fun `detects graphene from a plain substring match (no 'errors' array)`() {
        // graphene's check has no "errors" array at all, so errorContains falls back to a plain
        // substring search over the whole raw body.
        val outcome = EngineFingerprinter.detect { query ->
            if (query == "aaa") """{"error":"Syntax Error GraphQL (1:1): Cannot parse query"}""" else "{}"
        }
        assertEquals("graphene", outcome.engine)
    }

    @Test
    fun `detects dgraph from a structural __typename check, checked before graphene`() {
        val outcome = EngineFingerprinter.detect { query ->
            if (query == "query {\n  __typename @cascade\n}") """{"data":{"__typename":"Query"}}""" else "{}"
        }
        assertEquals("dgraph", outcome.engine)
        // dgraph is earlier in priority order than graphene, caliban, etc.
        assertEquals(10, outcome.checked)
    }

    @Test
    fun `detects apollo from an error whose message contains re-escaped quotes`() {
        // Apollo's match string carries literal backslash-quote sequences, because InQL (and this
        // port) matches against the RE-SERIALIZED error entry, not the decoded message text.
        val outcome = EngineFingerprinter.detect { query ->
            if (query == "query @skip {\n  __typename\n}") {
                """{"errors":[{"message":"Directive \"@skip\" argument \"if\" of type \"Boolean!\" is required, but it was not provided."}]}"""
            } else {
                "{}"
            }
        }
        assertEquals("apollo", outcome.engine)
    }

    @Test
    fun `no match after exhausting every check`() {
        val outcome = EngineFingerprinter.detect { "{}" }
        assertNull(outcome.engine)
        assertEquals(34, outcome.checked) // total number of ported engine checks
    }

    /** A sender like the bridge's: [status] says what came back for a query, 0 meaning nothing did. */
    private fun sender(calls: MutableList<String>, status: (Int, String) -> Int, body: (String) -> String = { "{}" }): (String) -> String {
        val guard = ReachabilityGuard()
        return { query ->
            calls += query
            val code = status(calls.size, query)
            guard.record(code)
            if (code == 0) "" else body(query)
        }
    }

    @Test
    fun `an unreachable target ends the run at the first probe`() {
        val calls = mutableListOf<String>()
        val outcome = EngineFingerprinter.detect(sender(calls, status = { _, _ -> 0 }))

        assertTrue(outcome.unreachable)
        assertNull(outcome.engine)
        assertEquals(0, outcome.checked)
        assertEquals(1, calls.size, "the other checks must not be sent to a target that does not answer")
    }

    @Test
    fun `one dropped probe does not end the run`() {
        // A WAF resetting the connection on a single malformed query: the second probe gets nothing back.
        val calls = mutableListOf<String>()
        val outcome = EngineFingerprinter.detect(
            sender(
                calls,
                status = { n, _ -> if (n == 2) 0 else 200 },
                body = { query -> if (query == "aaa") """{"error":"Syntax Error GraphQL (1:1): Cannot parse query"}""" else "{}" },
            )
        )

        assertFalse(outcome.unreachable)
        assertEquals("graphene", outcome.engine)
    }

    @Test
    fun `a target that stops answering mid-run ends it after a few failures`() {
        val calls = mutableListOf<String>()
        val outcome = EngineFingerprinter.detect(sender(calls, status = { n, _ -> if (n <= 5) 200 else 0 }))

        assertTrue(outcome.unreachable)
        assertNull(outcome.engine)
        // Five answered probes, then the three consecutive failures the guard allows.
        assertEquals(5 + ReachabilityGuard.DEFAULT_MAX_CONSECUTIVE_FAILURES, calls.size)
        assertEquals(7, outcome.checked)
    }

    @Test
    fun `a sender failing for another reason only fails that check`() {
        var calls = 0
        val outcome = EngineFingerprinter.detect { query ->
            calls++
            if (query == "aaa") """{"error":"Syntax Error GraphQL (1:1): Cannot parse query"}""" else throw IllegalStateException("boom")
        }
        assertFalse(outcome.unreachable)
        assertEquals("graphene", outcome.engine)
        assertTrue(calls > 1)
    }
}
