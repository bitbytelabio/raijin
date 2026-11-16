package io.bitbytelab.raijin.ui

import burp.api.montoya.core.ByteArray as MontoyaBytes
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.ui.editor.EditorOptions
import burp.api.montoya.ui.editor.HttpRequestEditor
import burp.api.montoya.ui.editor.HttpResponseEditor
import io.bitbytelab.raijin.turbo.Request
import io.bitbytelab.raijin.turbo.RequestTableModel
import io.bitbytelab.raijin.turbo.TurboModule
import io.bitbytelab.raijin.turbo.Utils
import io.bitbytelab.raijin.turbo.mcp.ActiveRun
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.text.SimpleDateFormat
import java.util.Date
import javax.swing.*
import javax.swing.table.AbstractTableModel
import javax.swing.table.DefaultTableCellRenderer
import javax.swing.table.TableRowSorter

/** One run as the table shows it. A snapshot, so painting and sorting never call into a live run. */
internal data class RunRow(
    val id: String,
    val number: Int,
    val source: String,
    val status: String,
    val results: Int,
    val fails: Int,
    val createdAt: Long,
)

/** What a refresh has to tell the runs table. */
internal sealed interface RunRowsChange {
    /** Nothing changed: fire nothing (keeps selection, scroll and sort untouched). */
    data object None : RunRowsChange
    /** Same runs in the same order; only these model rows changed. */
    data class Updated(val rows: List<Int>) : RunRowsChange
    /** Runs were added, removed or reordered. */
    data object Structure : RunRowsChange
}

internal fun diffRunRows(old: List<RunRow>, new: List<RunRow>): RunRowsChange {
    if (old.size != new.size || old.indices.any { old[it].id != new[it].id }) return RunRowsChange.Structure
    val changed = new.indices.filter { old[it] != new[it] }
    return if (changed.isEmpty()) RunRowsChange.None else RunRowsChange.Updated(changed)
}

/** Stop / Delete apply to the selected run, unless one of them is still in flight for it. */
internal fun runActionsEnabled(selectedId: String?, busy: Set<String>): Boolean = selectedId != null && selectedId !in busy

/**
 * The Turbo sub-tab: every run in the shared [TurboModule.runManager] (started from the script
 * dialog or by an MCP client), with stop / delete, a button that opens the script dialog, and a
 * detail pane for the selected run (status, results, script, base request).
 */
class TurboRunsPanel : JPanel(BorderLayout()) {

    private val clock = SimpleDateFormat("HH:mm:ss")
    private var rows: List<RunRow> = emptyList()

    private val model = object : AbstractTableModel() {
        private val columns = arrayOf("#", "Source", "Status", "Results", "Fails", "Started", "Run id")
        override fun getRowCount() = rows.size
        override fun getColumnCount() = columns.size
        override fun getColumnName(c: Int) = columns[c]
        override fun getColumnClass(c: Int): Class<*> = when (c) {
            0, 3, 4 -> Integer::class.java
            5 -> java.lang.Long::class.java
            else -> String::class.java
        }
        override fun getValueAt(r: Int, c: Int): Any {
            val run = rows[r]
            return when (c) {
                0 -> run.number
                1 -> run.source
                2 -> run.status
                3 -> run.results
                4 -> run.fails
                5 -> run.createdAt
                else -> run.id
            }
        }
    }

    private val table = JTable(model)
    private val status = JLabel(" ")
    private val notice = TintedLabel(" ") { RaijinTheme.error() }
    private val refreshTimer = Timer(1000) { refresh() }.apply { isRepeats = true }

    /**
     * Stop and Delete abort the run, which can block for up to 30 s while its engine winds down, so
     * they run here instead of on the EDT. [dispose] shuts the pool down.
     */
    private val tasks = UiTasks { desc, e ->
        SwingUtilities.invokeLater { notice.text = "  $desc failed: ${e.message ?: e.javaClass.simpleName}" }
    }

    /** Runs with a Stop or Delete in flight. EDT only. */
    private val busyRuns = mutableSetOf<String>()
    private val stopBtn = JButton("Stop")
    private val deleteBtn = JButton("Delete")

    /** True while [refresh] rebuilds the table, so the selection churn does not reload the detail pane. */
    private var refreshing = false

    // ---- detail pane: the selected run ----
    private var detailRun: ActiveRun? = null
    private var detailShown = 0
    private var shownCode: String? = null
    private var shownBaseRequest: String? = null
    private var resultsModel = RequestTableModel()
    private val resultsTable = JTable(resultsModel).apply {
        autoCreateRowSorter = true
        autoResizeMode = JTable.AUTO_RESIZE_OFF
        setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
    }
    /** The shown run's status, which colours [detailHeader] at paint time (so it follows theme switches). */
    private var detailStatus: String? = null
    private val detailHeader = TintedLabel(" ") { statusColour(detailStatus) }
    private val scriptArea = readOnlyArea()
    private val baseRequestArea = readOnlyArea()
    private val requestViewer: HttpRequestEditor? =
        runCatching { Utils.montoyaApi?.userInterface()?.createHttpRequestEditor(EditorOptions.READ_ONLY) }.getOrNull()
    private val responseViewer: HttpResponseEditor? =
        runCatching { Utils.montoyaApi?.userInterface()?.createHttpResponseEditor(EditorOptions.READ_ONLY) }.getOrNull()

    init {
        table.rowSorter = TableRowSorter(model).apply { sortsOnUpdates = true }
        table.rowHeight = maxOf(table.rowHeight, 22)
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        table.columnModel.getColumn(2).cellRenderer = object : DefaultTableCellRenderer() {
            override fun getTableCellRendererComponent(t: JTable, v: Any?, s: Boolean, f: Boolean, r: Int, c: Int) =
                super.getTableCellRendererComponent(t, v, s, f, r, c).also {
                    if (!s) foreground = statusColour(v?.toString())
                }
        }
        table.columnModel.getColumn(5).cellRenderer = object : DefaultTableCellRenderer() {
            override fun setValue(value: Any?) {
                text = (value as? Long)?.let { clock.format(Date(it)) } ?: ""
            }
        }
        listOf(0 to 40, 1 to 60, 2 to 90, 3 to 70, 4 to 60, 5 to 80).forEach { (i, w) ->
            table.columnModel.getColumn(i).preferredWidth = w
        }
        table.selectionModel.addListSelectionListener {
            if (it.valueIsAdjusting) return@addListSelectionListener
            if (!refreshing) showDetail(selectedRun())
            updateRunButtons()
        }
        resultsTable.selectionModel.addListSelectionListener {
            if (!it.valueIsAdjusting) showResult(selectedResult())
        }

        val newBtn = JButton("New script…").apply {
            toolTipText = "Open the Turbo script dialog (or right-click a request > Send to Raijin Turbo)"
            addActionListener { TurboModule.openBlankDialog() }
        }
        stopBtn.addActionListener { onSelectedRun("Stopping") { TurboModule.runManager.stopRun(it) } }
        deleteBtn.addActionListener { onSelectedRun("Deleting") { TurboModule.runManager.deleteRun(it) } }
        val copyBtn = JButton("Copy run id").apply {
            addActionListener { selectedId()?.let { java.awt.Toolkit.getDefaultToolkit().systemClipboard.setContents(java.awt.datatransfer.StringSelection(it), null) } }
        }

        val bar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        listOf(newBtn, stopBtn, deleteBtn, copyBtn).forEach { bar.add(it) }
        bar.add(status)
        bar.add(notice)

        val split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(table), buildDetailPane()).apply {
            resizeWeight = 0.35
            dividerSize = 5
        }

        add(bar, BorderLayout.NORTH)
        add(split, BorderLayout.CENTER)
        add(mutedHintLabel("  Runs started by MCP clients (turbo_start_run) and from the script dialog appear here.", 11f), BorderLayout.SOUTH)

        refreshTimer.start()
        refresh()
    }

    /** Stops the periodic UI refresh timer and the Stop/Delete pool on extension unload. */
    fun dispose() {
        refreshTimer.stop()
        tasks.dispose()
    }

    /**
     * Runs [op] on the selected run's id off the EDT; Stop and Delete stay disabled for that run
     * until it returns, then the table refreshes.
     */
    private fun onSelectedRun(verb: String, op: (String) -> Unit) {
        val id = selectedId() ?: return
        if (!busyRuns.add(id)) return
        notice.text = " "
        updateRunButtons()
        tasks.execute("$verb run $id") {
            try {
                op(id)
            } finally {
                SwingUtilities.invokeLater {
                    busyRuns.remove(id)
                    if (!tasks.isDisposed) refresh()
                }
            }
        }
    }

    private fun updateRunButtons() {
        val enabled = runActionsEnabled(selectedId(), busyRuns)
        stopBtn.isEnabled = enabled
        deleteBtn.isEnabled = enabled
    }

    private fun buildDetailPane(): JComponent {
        val resultsPane: JComponent = if (requestViewer != null && responseViewer != null) {
            val viewers = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestViewer.uiComponent(), responseViewer.uiComponent()).apply {
                resizeWeight = 0.5
            }
            JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(resultsTable), viewers).apply { resizeWeight = 0.4 }
        } else {
            JScrollPane(resultsTable)
        }
        val tabs = JTabbedPane(JTabbedPane.TOP).apply {
            addTab("Results", resultsPane)
            addTab("Script", JScrollPane(scriptArea))
            addTab("Base request", JScrollPane(baseRequestArea))
        }
        detailHeader.border = BorderFactory.createEmptyBorder(4, 6, 4, 6)
        return JPanel(BorderLayout()).apply {
            add(detailHeader, BorderLayout.NORTH)
            add(tabs, BorderLayout.CENTER)
        }
    }

    private fun selectedId(): String? =
        table.selectedRow.takeIf { it >= 0 }?.let { rows.getOrNull(table.convertRowIndexToModel(it))?.id }

    private fun selectedRun(): ActiveRun? = selectedId()?.let { TurboModule.runManager.getRun(it) }

    private fun selectedResult(): Request? =
        resultsTable.selectedRow.takeIf { it >= 0 }?.let { resultsModel.getRequest(resultsTable.convertRowIndexToModel(it)) }

    private fun refresh() {
        val runs = TurboModule.runManager.listRuns()
        val next = runs.map { run ->
            RunRow(
                id = run.id,
                number = run.sequenceNumber.toInt() + 1,
                source = run.source,
                status = run.handler.status(),
                results = run.store.count(),
                fails = run.handler.failCount(),
                createdAt = run.createdAt,
            )
        }
        when (val change = diffRunRows(rows, next)) {
            RunRowsChange.None -> Unit
            is RunRowsChange.Updated -> {
                rows = next
                change.rows.forEach { model.fireTableRowsUpdated(it, it) }
            }
            RunRowsChange.Structure -> {
                val keep = selectedId()
                refreshing = true
                try {
                    rows = next
                    model.fireTableDataChanged()
                    keep?.let { id -> rows.indexOfFirst { it.id == id } }?.takeIf { it >= 0 }?.let { modelRow ->
                        val viewRow = table.convertRowIndexToView(modelRow)
                        if (viewRow >= 0) table.setRowSelectionInterval(viewRow, viewRow)
                    }
                } finally {
                    refreshing = false
                }
                showDetail(selectedRun())
            }
        }
        val running = next.count { it.status == "running" }
        val busy = if (busyRuns.isEmpty()) "" else ", ${busyRuns.size} stopping"
        status.text = "  ${next.size} runs, $running running$busy"
        updateRunButtons()
        updateDetail()
    }

    /** Loads [run] into the detail pane (no-op when it is already shown). */
    private fun showDetail(run: ActiveRun?) {
        if (run?.id == detailRun?.id) return
        detailRun = run
        detailShown = 0
        shownCode = null
        shownBaseRequest = null
        resultsModel = RequestTableModel()
        resultsTable.model = resultsModel
        showResult(null)
        scriptArea.text = ""
        baseRequestArea.text = ""
        updateDetail()
    }

    /** Brings the shown run's status, script and results up to date, appending only new results. */
    private fun updateDetail() {
        val run = detailRun ?: run {
            detailHeader.text = " Select a run to see its results and script."
            detailHeader.toolTipText = null
            showDetailStatus(null)
            return
        }
        val handler = run.handler
        val runStatus = handler.status()
        detailHeader.text = " #${run.sequenceNumber + 1} (${run.source}, $runStatus): ${handler.statusString()}"
        detailHeader.toolTipText = handler.failureSummary() ?: detailHeader.text
        showDetailStatus(runStatus)
        // Compared with what was last set, not the text area (which may normalise line endings).
        val code = handler.code
        if (code != shownCode) {
            shownCode = code
            scriptArea.text = code
            scriptArea.caretPosition = 0
        }
        val baseRequest = handler.baseRequest
        if (baseRequest != shownBaseRequest) {
            shownBaseRequest = baseRequest
            baseRequestArea.text = baseRequest
            baseRequestArea.caretPosition = 0
        }

        val count = run.store.count()
        if (count < detailShown) {
            // The store was cleared (the script dialog was reconfigured): start over.
            detailShown = 0
            resultsModel = RequestTableModel()
            resultsTable.model = resultsModel
            showResult(null)
        }
        if (count > detailShown) {
            val added = (detailShown until count).mapNotNull { run.store.getRequestByIndex(it) }
            detailShown = count
            resultsModel.addRows(added)
        }
    }

    private fun showDetailStatus(runStatus: String?) {
        if (runStatus == detailStatus) return
        detailStatus = runStatus
        detailHeader.repaint()
    }

    private fun showResult(req: Request?) {
        val reqViewer = requestViewer ?: return
        val respViewer = responseViewer ?: return
        if (req == null) {
            runCatching { reqViewer.request = HttpRequest.httpRequest(); respViewer.response = HttpResponse.httpResponse() }
            return
        }
        runCatching {
            val bytes = MontoyaBytes.byteArray(*req.getRequestAsBytes())
            val service = req.montoyaReq?.httpService()
            reqViewer.request = if (service != null) HttpRequest.httpRequest(service, bytes) else HttpRequest.httpRequest(bytes)
        }
        respViewer.response = runCatching {
            HttpResponse.httpResponse(MontoyaBytes.byteArray(*(req.getResponseAsBytes() ?: ByteArray(0))))
        }.getOrElse { HttpResponse.httpResponse() }
    }

    private fun statusColour(status: String?) = when (status) {
        "running" -> RaijinTheme.info()
        "completed" -> RaijinTheme.success()
        "failed" -> RaijinTheme.error()
        else -> RaijinTheme.muted()
    }

    private fun readOnlyArea() = JTextArea().apply {
        isEditable = false
        font = RaijinTheme.editorFont(11f)
    }
}

/**
 * A hint label in the muted text colour. Re-applies the colour in updateUI, which Swing calls on
 * every Burp theme switch, so the label does not keep the previous theme's colour. (The font is set
 * once: a non-UIResource font survives updateUI.)
 */
internal fun mutedHintLabel(text: String, size: Float): JLabel = object : JLabel(text) {
    override fun updateUI() {
        super.updateUI()
        foreground = RaijinTheme.muted()
    }
}.apply { font = RaijinTheme.displayFont(size) }
