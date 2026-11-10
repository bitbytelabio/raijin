package io.bitbytelab.raijin.graphql.bruteforcer

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SchemaBruteforcerTest {

    @Test
    fun `discovers fields, classifies scalar vs object, dedupes a self-cycle, and respects depth_limit`() {
        // Fake schema: Query { viewer: User, label: String }, User { label: String, self: User, nested: Nested }.
        // "Nested" sits one level past depth_limit=1, so it must be referenced as a type_hint but never scanned.
        val responses = mapOf(
            "query { ____raijin_bruteforce_probe____ }" to
                err("Cannot query field \"____raijin_bruteforce_probe____\" on type \"Query\"."),
            "mutation { ____raijin_bruteforce_probe____ }" to err("Schema is not configured for mutations."),
            "subscription { ____raijin_bruteforce_probe____ }" to err("Schema is not configured for subscriptions."),

            "query { viewer label self nested zzz1 zzz2 }" to errs(
                "Cannot query field \"self\" on type \"Query\".",
                "Cannot query field \"nested\" on type \"Query\".",
                "Cannot query field \"zzz1\" on type \"Query\".",
                "Cannot query field \"zzz2\" on type \"Query\".",
            ),
            "query { viewer { viewer label self nested zzz1 zzz2 } }" to errs(
                "Cannot query field \"viewer\" on type \"User\".",
                "Cannot query field \"zzz1\" on type \"User\".",
                "Cannot query field \"zzz2\" on type \"User\".",
            ),

            "query { label { ____raijin_bruteforce_probe____ } }" to
                err("Field \"label\" must not have a selection since type \"String\" has no subfields."),
            "query { label { __typename } }" to
                err("Field \"label\" must not have a selection since type \"String\" has no subfields."),
            "query { label(____raijin_bruteforce_probe_arg____: null) { __typename } }" to
                err("Field \"label\" must not have a selection since type \"String\" has no subfields."),

            "query { viewer { ____raijin_bruteforce_probe____ } }" to
                err("Cannot query field \"____raijin_bruteforce_probe____\" on type \"User\"."),
            "query { viewer { __typename } }" to ok(),
            "query { viewer(____raijin_bruteforce_probe_arg____: null) { __typename } }" to
                err("Unknown argument \"____raijin_bruteforce_probe_arg____\" on field \"viewer\"."),

            "query { viewer { label { ____raijin_bruteforce_probe____ } } }" to
                err("Field \"label\" must not have a selection since type \"String\" has no subfields."),
            "query { viewer { label { __typename } } }" to
                err("Field \"label\" must not have a selection since type \"String\" has no subfields."),
            "query { viewer { label(____raijin_bruteforce_probe_arg____: null) { __typename } } }" to
                err("Field \"label\" must not have a selection since type \"String\" has no subfields."),

            "query { viewer { nested { ____raijin_bruteforce_probe____ } } }" to
                err("Cannot query field \"____raijin_bruteforce_probe____\" on type \"Nested\"."),
            "query { viewer { nested { __typename } } }" to ok(),
            "query { viewer { nested(____raijin_bruteforce_probe_arg____: null) { __typename } } }" to
                err("Unknown argument \"____raijin_bruteforce_probe_arg____\" on field \"nested\"."),

            "query { viewer { self { ____raijin_bruteforce_probe____ } } }" to
                err("Cannot query field \"____raijin_bruteforce_probe____\" on type \"User\"."),
            "query { viewer { self { __typename } } }" to ok(),
            "query { viewer { self(____raijin_bruteforce_probe_arg____: null) { __typename } } }" to
                err("Unknown argument \"____raijin_bruteforce_probe_arg____\" on field \"self\"."),
        )

        val bruteforcer = SchemaBruteforcer(
            sendQuery = { q -> responses[q] ?: "{}" },
            bucketSize = 10,
            depthLimit = 1,
            bruteforceArguments = true,
            wordlist = listOf("viewer", "label", "self", "nested", "zzz1", "zzz2"),
            argumentWordlist = emptyList(),
        )

        val result = bruteforcer.run()
        val byName = result.types.associateBy { it.name }

        assertEquals(setOf("Query", "User"), byName.keys)

        val query = byName["Query"]!!
        assertEquals("object", query.kind)
        assertEquals(
            setOf("label" to "String", "viewer" to "User"),
            query.fields.map { it.name to it.typeHint }.toSet(),
        )

        val user = byName["User"]!!
        assertEquals("object", user.kind)
        assertEquals(
            setOf("label" to "String", "self" to "User", "nested" to "Nested"),
            user.fields.map { it.name to it.typeHint }.toSet(),
        )

        // "Nested" is referenced as a type_hint but, sitting past depth_limit, was never itself scanned.
        assertTrue("Nested" !in byName)
    }

    @Test
    fun `discovers a required argument via the no-args probe`() {
        val responses = mapOf(
            "query { ____raijin_bruteforce_probe____ }" to
                err("Cannot query field \"____raijin_bruteforce_probe____\" on type \"Query\"."),
            "mutation { ____raijin_bruteforce_probe____ }" to err("Schema is not configured for mutations."),
            "subscription { ____raijin_bruteforce_probe____ }" to err("Schema is not configured for subscriptions."),

            "query { widget zzz1 zzz2 }" to errs(
                "Cannot query field \"zzz1\" on type \"Query\".",
                "Cannot query field \"zzz2\" on type \"Query\".",
            ),
            "query { widget { ____raijin_bruteforce_probe____ } }" to
                err("Cannot query field \"____raijin_bruteforce_probe____\" on type \"Widget\"."),
            "query { widget { __typename } }" to
                err("Field \"widget\" argument \"id\" of type \"ID!\" is required, but it was not provided."),
            "query { widget(____raijin_bruteforce_probe_arg____: null) { __typename } }" to
                err("Unknown argument \"____raijin_bruteforce_probe_arg____\" on field \"widget\"."),
        )

        val bruteforcer = SchemaBruteforcer(
            sendQuery = { q -> responses[q] ?: "{}" },
            bucketSize = 10,
            depthLimit = 0,
            bruteforceArguments = true,
            wordlist = listOf("widget", "zzz1", "zzz2"),
            argumentWordlist = emptyList(),
        )

        val result = bruteforcer.run()
        val query = result.types.single { it.name == "Query" }
        val widget = query.fields.single { it.name == "widget" }

        assertEquals("Widget", widget.typeHint)
        assertEquals(listOf("id"), widget.args)
        assertTrue(result.types.none { it.name == "Widget" }) // past depth_limit=0, never scanned
    }

    @Test
    fun `an endpoint that never leaks a recognizable error yields an empty reconstruction`() {
        // Every probe gets back an error that none of the Clairvoyance regexes recognize — so
        // nothing is confirmed valid or invalid, and no field survives the elimination logic.
        val bruteforcer = SchemaBruteforcer(
            sendQuery = { err("Internal Server Error") },
            bucketSize = 10,
            depthLimit = 2,
            wordlist = listOf("a", "b"),
            argumentWordlist = emptyList(),
        )
        val result = bruteforcer.run()
        // Root type name defaults to "Query" when even that can't be determined.
        assertEquals(listOf("Query"), result.types.map { it.name })
        assertEquals("object", result.types.single().kind)
        assertTrue(result.types.single().fields.isEmpty())
        assertNull(result.types.single().fields.firstOrNull())
    }

    /** JSON-escapes [message] (its embedded quotes are plain `"`) so it's safe as a JSON string value. */
    private fun jsonEscape(message: String): String = message.replace("\\", "\\\\").replace("\"", "\\\"")

    private fun err(message: String) = """{"errors":[{"message":"${jsonEscape(message)}"}]}"""
    private fun errs(vararg messages: String) =
        """{"errors":[${messages.joinToString(",") { """{"message":"${jsonEscape(it)}"}""" }}]}"""
    private fun ok() = """{"data":{}}"""
}
