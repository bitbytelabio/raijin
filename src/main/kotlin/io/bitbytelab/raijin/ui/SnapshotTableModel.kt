package io.bitbytelab.raijin.ui

import javax.swing.JTable
import javax.swing.table.DefaultTableModel

/**
 * A read-only table model refreshed from live state by a timer. [update] replaces the rows only
 * when they changed, so an unchanged table keeps its selection instead of being rebuilt every tick.
 */
internal class SnapshotTableModel(
    columns: Array<String>,
    private val columnClasses: Map<Int, Class<*>> = emptyMap(),
) : DefaultTableModel(columns, 0) {
    private var rows: List<List<Any?>> = emptyList()

    override fun isCellEditable(row: Int, column: Int) = false

    /** Per-column classes (Boolean renders a checkbox, numbers sort numerically); Object otherwise. */
    override fun getColumnClass(column: Int): Class<*> = columnClasses[column] ?: Any::class.java

    companion object {
        val BOOLEAN: Class<*> = Boolean::class.javaObjectType
        val INT: Class<*> = Int::class.javaObjectType
        val LONG: Class<*> = Long::class.javaObjectType
    }

    /**
     * Replaces the rows with [next] when they differ; true when the table changed. One
     * data-changed event, so a sorted table re-sorts once rather than once per row.
     */
    fun update(next: List<List<Any?>>): Boolean {
        if (next == rows) return false
        rows = next
        dataVector.clear()
        next.forEach { dataVector.add(java.util.Vector<Any?>(it)) }
        fireTableDataChanged()
        return true
    }

    /** [update], then re-selects in [table] the row whose [keyColumn] matches the previously selected one. */
    fun update(next: List<List<Any?>>, table: JTable, keyColumn: Int = 0): Boolean {
        val selected = table.selectedRow
        val key = if (selected in 0 until table.rowCount) getValueAt(table.convertRowIndexToModel(selected), keyColumn) else null
        if (!update(next)) return false
        if (key != null) {
            val modelRow = (0 until rowCount).firstOrNull { getValueAt(it, keyColumn) == key } ?: return true
            val viewRow = table.convertRowIndexToView(modelRow)
            if (viewRow >= 0) table.setRowSelectionInterval(viewRow, viewRow)
        }
        return true
    }
}
