package io.bitbytelab.raijin.graphql

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
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

    private fun intTemplate(first: String, last: String) = "query { \$[INT:$first:$last] node(id: \"\$INT\") { id } }"

    @Test
    fun `aliases of an INT range are the values themselves`() {
        val result = BatchAttack.expand(intTemplate("5", "7"))
        requireNotNull(result)
        assertEquals(2, result.count)
        val normalized = norm(result.query)
        assertTrue(normalized.contains("op5: node(id: \"5\") { id }"))
        assertTrue(normalized.contains("op6: node(id: \"6\") { id }"))
        assertTrue(!normalized.contains("op7:"))
    }

    @Test
    fun `an expansion up to the cap is produced and one past it is refused`() {
        assertEquals(3, BatchAttack.expand(intTemplate("0", "3"), maxOperations = 3)?.count)

        val error = assertFailsWith<BatchAttack.ExpansionException> { BatchAttack.expand(intTemplate("0", "4"), maxOperations = 3) }
        assertTrue("4 sub-operations" in error.message!!, error.message)
        assertTrue("limit is 3" in error.message!!, error.message)
    }

    @Test
    fun `the default cap refuses a range that would exhaust memory, before building anything`() {
        val justOver = assertFailsWith<BatchAttack.ExpansionException> {
            BatchAttack.expand(intTemplate("0", (BatchAttack.MAX_OPERATIONS + 1).toString()))
        }
        assertTrue("limit is ${BatchAttack.MAX_OPERATIONS}" in justOver.message!!, justOver.message)

        // Two billion sub-operations: returning at all shows nothing was generated first.
        assertFailsWith<BatchAttack.ExpansionException> { BatchAttack.expand(intTemplate("0", "2000000000")) }
        assertEquals(BatchAttack.MAX_OPERATIONS, BatchAttack.expand(intTemplate("0", BatchAttack.MAX_OPERATIONS.toString()))?.count)
    }

    @Test
    fun `a LIST longer than the cap is refused`() {
        val template = "query { \$[LIST] lookup(id: \"\$LIST\") { name } }"
        assertEquals(3, BatchAttack.expand(template, values = listOf("a", "b", "c"), maxOperations = 3)?.count)
        assertFailsWith<BatchAttack.ExpansionException> {
            BatchAttack.expand(template, values = listOf("a", "b", "c", "d"), maxOperations = 3)
        }
    }

    @Test
    fun `range bounds too large for a number are a clear error, not a NumberFormatException`() {
        val error = assertFailsWith<BatchAttack.ExpansionException> {
            BatchAttack.expand(intTemplate("0", "99999999999999999999999"))
        }
        assertTrue("64-bit" in error.message!!, error.message)
    }

    @Test
    fun `an empty or reversed range is a clear error`() {
        for ((first, last) in listOf("5" to "5", "7" to "3")) {
            val error = assertFailsWith<BatchAttack.ExpansionException> { BatchAttack.expand(intTemplate(first, last)) }
            assertTrue("empty range" in error.message!!, error.message)
        }
    }

    @Test
    fun `an expansion that would outgrow the character cap is refused`() {
        // 100 sub-operations is far below the operation cap, but each one is 100 000 characters long.
        val bulky = "query { \$[INT:0:100] node(id: \"\$INT\") { ${"a".repeat(100_000)} } }"
        val error = assertFailsWith<BatchAttack.ExpansionException> { BatchAttack.expand(bulky) }
        assertTrue(BatchAttack.MAX_QUERY_CHARS.toString() in error.message!!, error.message)
    }
}
