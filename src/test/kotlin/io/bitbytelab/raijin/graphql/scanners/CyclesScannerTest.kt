package io.bitbytelab.raijin.graphql.scanners

import io.bitbytelab.raijin.graphql.GQLSchema
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class CyclesScannerTest {

    @Test
    fun `detects a self-referencing type as a cycle`() {
        val schema = GQLSchema(
            """
            type Query { viewer: User }
            type User { id: ID!, friends: [User!] }
            """.trimIndent()
        )
        val cycles = CyclesScanner(schema).detect().cycles()
        assertTrue(cycles.isNotEmpty())
        assertTrue(cycles.any { cycle -> cycle.any { (_, type) -> type == "User" } })
    }

    @Test
    fun `an acyclic schema reports no cycles`() {
        val schema = GQLSchema(
            """
            type Query { viewer: User }
            type User { id: ID!, account: Account }
            type Account { balance: Int }
            """.trimIndent()
        )
        val cycles = CyclesScanner(schema).detect().cycles()
        assertEquals(0, cycles.size)
    }

    @Test
    fun `detects a longer mutual cycle between two types`() {
        val schema = GQLSchema(
            """
            type Query { viewer: User }
            type User { id: ID!, account: Account }
            type Account { owner: User }
            """.trimIndent()
        )
        val cycles = CyclesScanner(schema).detect().cycles()
        assertTrue(cycles.isNotEmpty())
    }
}
