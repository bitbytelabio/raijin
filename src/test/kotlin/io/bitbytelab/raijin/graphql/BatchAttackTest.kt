package io.bitbytelab.raijin.graphql

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class BatchAttackTest {

    /** Collapses whitespace runs to a single space so assertions aren't sensitive to the exact incidental spacing GraphQL ignores anyway. */
    private fun norm(s: String) = s.replace(Regex("\\s+"), " ").trim()

    @Test
    fun `expands an INT placeholder into N aliased sub-operations`() {
        val query = "query { \$[INT:0:3] node(id: \"\$INT\") { id } }"
        val result = BatchAttack.expand(query)
        requireNotNull(result)
        assertEquals(3, result.count)
        val normalized = norm(result.query)
        assertTrue(normalized.contains("op0: node(id: \"0\") { id }"))
        assertTrue(normalized.contains("op1: node(id: \"1\") { id }"))
        assertTrue(normalized.contains("op2: node(id: \"2\") { id }"))
        assertTrue(!normalized.contains("op3:"))
        assertTrue(normalized.startsWith("query {"))
        assertTrue(normalized.endsWith("}"))
    }

    @Test
    fun `expands a LIST placeholder once per supplied value`() {
        val query = "query { \$[LIST] lookup(id: \"\$LIST\") { name } }"
        val result = BatchAttack.expand(query, values = listOf("a1", "b2", "c3"))
        requireNotNull(result)
        assertEquals(3, result.count)
        val normalized = norm(result.query)
        assertTrue(normalized.contains("op0: lookup(id: \"a1\") { name }"))
        assertTrue(normalized.contains("op1: lookup(id: \"b2\") { name }"))
        assertTrue(normalized.contains("op2: lookup(id: \"c3\") { name }"))
    }

    @Test
    fun `a LIST placeholder with no values yields no expansion`() {
        assertNull(BatchAttack.expand("query { \$[LIST] lookup(id: \"\$LIST\") { name } }", values = null))
        assertNull(BatchAttack.expand("query { \$[LIST] lookup(id: \"\$LIST\") { name } }", values = emptyList()))
    }

    @Test
    fun `descends one brace level when the placeholder is not in the outermost prefix`() {
        val query = "query { viewer { \$[INT:0:2] node(id: \"\$INT\") { id } } }"
        val result = BatchAttack.expand(query)
        requireNotNull(result)
        assertEquals(2, result.count)
        val normalized = norm(result.query)
        assertTrue(normalized.contains("op0: node(id: \"0\") { id }"))
        assertTrue(normalized.contains("op1: node(id: \"1\") { id }"))
        assertTrue(!normalized.contains("op2:"))
        assertTrue(normalized.startsWith("query { viewer {"))
    }

    @Test
    fun `no placeholder anywhere yields null`() {
        assertNull(BatchAttack.expand("query { viewer { id name } }"))
    }
}
