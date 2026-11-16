package io.bitbytelab.raijin.ui

import javax.swing.JTable
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SnapshotTableModelTest {

    @Test
    fun `unchanged rows leave the table untouched`() {
        val model = SnapshotTableModel(arrayOf("ID", "Enabled"), mapOf(1 to SnapshotTableModel.BOOLEAN))
        var events = 0
        model.addTableModelListener { events++ }

        assertTrue(model.update(listOf(listOf("r1", true), listOf("r2", false))))
        assertFalse(model.update(listOf(listOf("r1", true), listOf("r2", false))))

        assertEquals(1, events)
        assertEquals(2, model.rowCount)
        assertEquals(Boolean::class.javaObjectType, model.getColumnClass(1))
        assertFalse(model.isCellEditable(0, 1))
    }

    @Test
    fun `a change replaces the rows in one event`() {
        val model = SnapshotTableModel(arrayOf("ID"))
        model.update(listOf(listOf("a"), listOf("b")))
        var events = 0
        model.addTableModelListener { events++ }

        assertTrue(model.update(listOf(listOf("b"), listOf("c"), listOf("d"))))

        assertEquals(1, events)
        assertEquals(listOf("b", "c", "d"), (0 until model.rowCount).map { model.getValueAt(it, 0) })
    }

    @Test
    fun `the selected row follows its key across a rebuild`() {
        val model = SnapshotTableModel(arrayOf("ID", "Value"))
        val table = JTable(model)
        model.update(listOf(listOf("a", 1), listOf("b", 2), listOf("c", 3)), table)
        table.setRowSelectionInterval(1, 1)

        model.update(listOf(listOf("new", 0), listOf("a", 1), listOf("b", 5), listOf("c", 3)), table)
        assertEquals("b", model.getValueAt(table.selectedRow, 0))

        model.update(listOf(listOf("a", 1), listOf("c", 3)), table)
        assertEquals(-1, table.selectedRow)
    }
}
