package io.bitbytelab.raijin.graphql.scanners

import io.bitbytelab.raijin.graphql.GQLSchema
import org.junit.jupiter.api.Timeout
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
    fun `a root-level query field name is itself checked, not just fields inside its return type`() {
        // Previously scan() only ever called checkField() on INNER fields reached while walking
        // a root field's return type — the root field itself (e.g. "login") was never checked.
        val schema = GQLSchema("type Query { login: String }")
        val found = POIScanner(schema).scan()
        assertEquals(true, found["auth"]?.any { it.path == "-> login" && it.queryType == "Query" })
    }

    @Test
    fun `a root-level mutation field name is itself checked`() {
        val schema = GQLSchema("type Query { ping: String }\ntype Mutation { admin: Boolean }")
        val found = POIScanner(schema).scan()
        assertEquals(true, found["privileged"]?.any { it.path == "-> admin" && it.queryType == "Mutation" })
    }

    @Test
    fun `the correctly-spelled 'privileged' category id matches the bundled upstream-typo'd keywords file`() {
        // keywords.json has id "priviliged" (typo, vendored verbatim from InQL); every other
        // place in Raijin's own API (DEFAULT_CATEGORIES, the tool description, the skill docs)
        // says "privileged" — a caller using that obvious spelling must not match nothing.
        val schema = GQLSchema("type Query { admin: Boolean }")
        val found = POIScanner(schema, categories = setOf("privileged")).scan()
        assertEquals(true, found["privileged"]?.any { it.path.endsWith("-> admin") })
    }

    @Test
    fun `custom keywords are flagged under the custom category`() {
        // The schema's User<->Account cycle makes this field reachable through more than one path
        // (directly, and again through account->owner); it is reported once, at the shortest.
        val schema = GQLSchema(sdl)
        val found = POIScanner(schema, categories = emptySet(), customKeywords = listOf("uninteresting")).scan()
        assertEquals(listOf("-> viewer -> uninteresting"), found["custom"]?.map { it.path })
    }

    @Test
    @Timeout(20)
    fun `recursive types are walked once and each field is reported at its shortest path`() {
        // Following every path through these mutually recursive types to the default depth of 10
        // means tens of millions of paths; expanding each type once makes it a handful of steps.
        val schema = GQLSchema(
            """
            type Query { viewer: User }
            type User {
                id: ID!
                email: String
                friends: [User!]
                bestFriend: User
                manager: User
                team: Team
                account: Account
            }
            type Team { lead: User, members: [User], parent: Team, owner: Account }
            type Account { owner: User, team: Team, parent: Account }
            """.trimIndent()
        )
        val found = POIScanner(schema).scan()
        assertEquals(listOf("-> viewer -> email"), found["pii"]?.map { it.path })
        assertEquals(listOf("-> viewer -> account"), found["auth"]?.map { it.path })
        assertEquals(setOf("pii", "auth"), found.keys)
    }

    @Test
    fun `each operation type reports the fields it reaches`() {
        val schema = GQLSchema(
            """
            type Query { me: User }
            type Mutation { rename(name: String): User }
            type User { email: String, friends: [User] }
            """.trimIndent()
        )
        val pii = POIScanner(schema).scan()["pii"].orEmpty()
        assertEquals(
            setOf("Query" to "-> me -> email", "Mutation" to "-> rename -> email"),
            pii.map { it.queryType to it.path }.toSet(),
        )
    }

    @Test
    fun `fields of an interface and of its implementations are scanned`() {
        val schema = GQLSchema(
            """
            type Query { actor: Actor }
            interface Actor { email: String }
            type User implements Actor { email: String, ssn: String }
            type Bot implements Actor { email: String, token: String }
            """.trimIndent()
        )
        val found = POIScanner(schema).scan()
        // The interface's own field is reported on the interface, not again under every implementation.
        assertEquals(
            listOf("-> actor -> email", "-> actor -> ... on User -> ssn"),
            found["pii"]?.map { it.path },
        )
        assertEquals(listOf("-> actor -> ... on Bot -> token"), found["auth"]?.map { it.path })
    }

    @Test
    fun `members of a union are scanned, also when the union recurses`() {
        val schema = GQLSchema(
            """
            type Query { search: SearchResult }
            union SearchResult = Article | Secret
            type Article { title: String }
            type Secret { token: String, related: SearchResult }
            """.trimIndent()
        )
        val found = POIScanner(schema).scan()
        assertEquals(listOf("-> search -> ... on Secret -> token"), found["auth"]?.map { it.path })
    }

    @Test
    fun `depth limits how far below a root field the walk goes`() {
        val schema = GQLSchema(
            """
            type Query { a: A }
            type A { b: B }
            type B { email: String }
            """.trimIndent()
        )
        assertFalse(POIScanner(schema).scan(depth = 0).containsKey("pii"))
        assertEquals(listOf("-> a -> b -> email"), POIScanner(schema).scan(depth = 1)["pii"]?.map { it.path })
    }

    @Test
    fun `custom keywords are matched literally, as a whole name or a whole underscore-separated part`() {
        val schema = GQLSchema("type Query { abc: String, plain: String, very_plain_field: String, plainly: String }")
        fun custom(vararg keywords: String) =
            POIScanner(schema, categories = emptySet(), customKeywords = keywords.toList()).scan()["custom"].orEmpty().map { it.path }

        assertEquals(listOf("-> plain", "-> very_plain_field"), custom("PLAIN"))
        // As a regex "a.c" would match "abc"; as the literal text it is, it matches nothing.
        assertEquals(emptyList(), custom("a.c"))
        // Regex metacharacters in a keyword are text too: nothing to match, and nothing thrown.
        assertEquals(emptyList(), custom("pla(in", "[", "*"))
        assertEquals(listOf("-> plain", "-> very_plain_field"), custom("(", "  ", "plain"))
    }

    @Test
    fun `bundled keywords stay regex fragments`() {
        // keywords.json writes "api.?key": the separator is optional or any one character.
        val schema = GQLSchema("type Query { apikey: String, api_key: String, apiXkey: String, apiary: String }")
        val auth = POIScanner(schema, categories = setOf("auth")).scan()["auth"].orEmpty().map { it.path }
        assertEquals(listOf("-> apikey", "-> api_key", "-> apiXkey"), auth)
    }

    @Test
    fun `identical paths on Query and Mutation are both preserved`() {
        val schema = GQLSchema(
            """
            type Query { users: User }
            type Mutation { users: User }
            type User { email: String }
            """.trimIndent()
        )
        val pii = POIScanner(schema, categories = setOf("pii")).scan()["pii"].orEmpty()
        assertEquals(
            setOf("Query" to "-> users -> email", "Mutation" to "-> users -> email"),
            pii.map { it.queryType to it.path }.toSet(),
        )
    }
}
