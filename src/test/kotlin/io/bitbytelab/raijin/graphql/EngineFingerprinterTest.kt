package io.bitbytelab.raijin.graphql

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

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
}
