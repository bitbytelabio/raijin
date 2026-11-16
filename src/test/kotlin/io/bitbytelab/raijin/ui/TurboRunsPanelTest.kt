package io.bitbytelab.raijin.ui

import kotlin.test.Test
import kotlin.test.assertEquals

class TurboRunsPanelTest {

    private fun row(id: String, status: String = "running", results: Int = 0) =
        RunRow(id = id, number = 1, source = "MCP", status = status, results = results, fails = 0, createdAt = 1L)

    @Test
    fun `identical snapshots fire nothing`() {
        val rows = listOf(row("a"), row("b"))
        assertEquals(RunRowsChange.None, diffRunRows(rows, rows.map { it.copy() }))
        assertEquals(RunRowsChange.None, diffRunRows(emptyList(), emptyList()))
    }

    @Test
    fun `changed values in the same runs update only those rows`() {
        val old = listOf(row("a"), row("b"), row("c"))
        val new = listOf(row("a", results = 5), row("b"), row("c", status = "completed"))
        assertEquals(RunRowsChange.Updated(listOf(0, 2)), diffRunRows(old, new))
    }

    @Test
    fun `added, removed or reordered runs rebuild the table`() {
        val old = listOf(row("a"), row("b"))
        assertEquals(RunRowsChange.Structure, diffRunRows(old, listOf(row("c"), row("a"), row("b"))))
        assertEquals(RunRowsChange.Structure, diffRunRows(old, listOf(row("a"))))
        assertEquals(RunRowsChange.Structure, diffRunRows(old, listOf(row("b"), row("a"))))
    }

    @Test
    fun `stop and delete need a selected run with nothing in flight for it`() {
        assertEquals(false, runActionsEnabled(null, emptySet()))
        assertEquals(true, runActionsEnabled("a", emptySet()))
        assertEquals(false, runActionsEnabled("a", setOf("a")))
        assertEquals(true, runActionsEnabled("b", setOf("a")))
    }
}
