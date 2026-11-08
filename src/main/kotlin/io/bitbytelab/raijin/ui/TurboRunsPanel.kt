package io.bitbytelab.raijin.ui

import io.bitbytelab.raijin.turbo.TurboModule
import io.bitbytelab.raijin.turbo.mcp.ActiveRun
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.text.SimpleDateFormat
import java.util.Date
import javax.swing.*
import javax.swing.table.AbstractTableModel
import javax.swing.table.DefaultTableCellRenderer

/**
 * The Turbo sub-tab: every run in the shared [TurboModule.runManager] (started from the script
 * dialog or by an MCP client), with stop / delete, and a button that opens the script dialog.
 */
class TurboRunsPanel : JPanel(BorderLayout()) {

    private val clock = SimpleDateFormat("HH:mm:ss")
    private var rows: List<ActiveRun> = emptyList()

    private val model = object : AbstractTableModel() {
        private val columns = arrayOf("#", "Source", "Status", "Results", "Fails", "Started", "Run id")
        override fun getRowCount() = rows.size
        override fun getColumnCount() = columns.size
        override fun getColumnName(c: Int) = columns[c]
        override fun getColumnClass(c: Int): Class<*> = if (c == 0 || c == 3 || c == 4) Integer::class.java else String::class.java
        override fun getValueAt(r: Int, c: Int): Any {
            val run = rows[r]
            return when (c) {
                0 -> run.sequenceNumber.toInt() + 1
                1 -> run.source
                2 -> run.handler.status()
                3 -> run.store.count()
                4 -> run.handler.failCount()
                5 -> clock.format(Date(run.createdAt))
                else -> run.id
            }
        }
    }

    private val table = JTable(model)
    private val status = JLabel(" ")

    init {
        table.autoCreateRowSorter = false
        table.rowHeight = maxOf(table.rowHeight, 22)
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        table.columnModel.getColumn(2).cellRenderer = object : DefaultTableCellRenderer() {
            override fun getTableCellRendererComponent(t: JTable, v: Any?, s: Boolean, f: Boolean, r: Int, c: Int) =
                super.getTableCellRendererComponent(t, v, s, f, r, c).also {
                    if (!s) foreground = when (v?.toString()) {
                        "running" -> RaijinTheme.info()
                        "completed" -> RaijinTheme.success()
                        "failed" -> RaijinTheme.error()
                        else -> RaijinTheme.muted()
                    }
                }
        }
        listOf(0 to 40, 1 to 60, 2 to 90, 3 to 70, 4 to 60, 5 to 80).forEach { (i, w) ->
            table.columnModel.getColumn(i).preferredWidth = w
        }

        val newBtn = JButton("New script…").apply {
            toolTipText = "Open the Turbo script dialog (or right-click a request > Send to Raijin Turbo)"
            addActionListener { TurboModule.openBlankDialog() }
        }
        val stopBtn = JButton("Stop").apply { addActionListener { selected()?.let { TurboModule.runManager.stopRun(it.id); refresh() } } }
        val deleteBtn = JButton("Delete").apply { addActionListener { selected()?.let { TurboModule.runManager.deleteRun(it.id); refresh() } } }
        val copyBtn = JButton("Copy run id").apply {
            addActionListener { selected()?.let { java.awt.Toolkit.getDefaultToolkit().systemClipboard.setContents(java.awt.datatransfer.StringSelection(it.id), null) } }
        }

        val bar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        listOf(newBtn, stopBtn, deleteBtn, copyBtn).forEach { bar.add(it) }
        bar.add(status)

        add(bar, BorderLayout.NORTH)
        add(JScrollPane(table), BorderLayout.CENTER)
        add(JLabel("  Runs started by MCP clients (turbo_start_run) and from the script dialog appear here.").apply {
            font = RaijinTheme.displayFont(11f); foreground = RaijinTheme.muted()
        }, BorderLayout.SOUTH)

        Timer(1000) { refresh() }.apply { isRepeats = true; start() }
        refresh()
    }

    private fun selected(): ActiveRun? = table.selectedRow.takeIf { it >= 0 }?.let { rows.getOrNull(table.convertRowIndexToModel(it)) }

    private fun refresh() {
        val keep = selected()?.id
        rows = TurboModule.runManager.listRuns()
        model.fireTableDataChanged()
        keep?.let { id -> rows.indexOfFirst { it.id == id }.takeIf { it >= 0 }?.let { table.setRowSelectionInterval(it, it) } }
        val running = rows.count { it.handler.status() == "running" }
        status.text = "  ${rows.size} runs, $running running"
    }
}
