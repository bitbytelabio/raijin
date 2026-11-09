package io.bitbytelab.raijin.graphql

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class GQLSchemaTest {

    private val sdl = """
        type Query {
            viewer: User
            node(id: ID!): User
        }
        type Mutation {
            updateAddress(id: ID!, address: String!): User
        }
        type User {
            id: ID!
            address: String
            account: Account
            friends: [User!]
        }
        type Account {
            owner: User
        }
    """.trimIndent()

    @Test
    fun `parses SDL text and exposes query and mutation fields`() {
        val schema = GQLSchema(sdl)
        assertEquals(setOf("viewer", "node"), schema.queries.keys)
        assertEquals(setOf("updateAddress"), schema.mutations.keys)
        assertTrue(schema.subscriptions.isEmpty())
    }

    @Test
    fun `operationAsText generates a runnable query for a field`() {
        val schema = GQLSchema(sdl)
        val text = schema.operationAsText("viewer", GQLSchema.OperationType.QUERY)
        requireNotNull(text)
        assertTrue(text.contains("query viewer {"))
        assertTrue(text.contains("id"))
        assertTrue(text.contains("address"))
    }

    @Test
    fun `operationAsText returns null for an operation that does not exist`() {
        val schema = GQLSchema(sdl)
        assertNull(schema.operationAsText("doesNotExist", GQLSchema.OperationType.QUERY))
    }

    @Test
    fun `sdlSchema round-trips back to printable SDL`() {
        val schema = GQLSchema(sdl)
        assertTrue(schema.sdlSchema.contains("type User"))
        assertTrue(schema.sdlSchema.contains("type Account"))
    }
}
