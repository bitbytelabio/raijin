package io.bitbytelab.raijin.graphql.scanners

import io.bitbytelab.raijin.graphql.GQLSchema
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class POIScannerTest {

    private val sdl = """
        type Query {
            viewer: User
        }
        type User {
            id: ID!
            address: String
            account: Account
            uninteresting: String
        }
        type Account {
            owner: User
        }
    """.trimIndent()

    @Test
    fun `flags a pii-category field by name`() {
        val schema = GQLSchema(sdl)
        val found = POIScanner(schema).scan()
        assertEquals(true, found["pii"]?.any { it.path.endsWith("-> address") })
    }

    @Test
    fun `flags an auth-category field by name`() {
        val schema = GQLSchema(sdl)
        val found = POIScanner(schema).scan()
        assertEquals(true, found["auth"]?.any { it.path.endsWith("-> account") })
    }

    @Test
    fun `does not flag an unrelated field`() {
        val schema = GQLSchema(sdl)
        val found = POIScanner(schema).scan()
        assertFalse(found.values.flatten().any { it.path.endsWith("-> uninteresting") })
    }

    @Test
    fun `restricting categories only flags the requested ones`() {
        val schema = GQLSchema(sdl)
        val found = POIScanner(schema, categories = setOf("auth")).scan()
        assertTrue(found.containsKey("auth"))
        assertFalse(found.containsKey("pii"))
    }

    @Test
    fun `custom keywords are flagged under the custom category`() {
        // Note: the schema's User<->Account cycle means this field is reachable via more than one
        // distinct path (once directly, once through account->owner), so each gets its own entry —
        // same per-path semantics as the upstream scanner this was ported from, not a bug.
        val schema = GQLSchema(sdl)
        val found = POIScanner(schema, categories = emptySet(), customKeywords = listOf("uninteresting")).scan()
        val customMatches = found["custom"] ?: emptyList()
        assertTrue(customMatches.isNotEmpty())
        assertTrue(customMatches.all { it.path.endsWith("-> uninteresting") })
    }
}
