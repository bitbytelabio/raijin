package io.bitbytelab.raijin.turbo

import burp.api.montoya.core.ByteArray as MontoyaBytes
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import burp.api.montoya.ui.editor.EditorOptions
import burp.api.montoya.ui.editor.HttpRequestEditor
import burp.api.montoya.ui.editor.HttpResponseEditor
import java.awt.BorderLayout
import java.awt.Component
import java.awt.Dialog
import java.awt.Dimension
import java.awt.Frame
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import java.net.URL
import java.text.NumberFormat
import javax.swing.*
import javax.swing.border.BevelBorder
import javax.swing.table.DefaultTableCellRenderer
import javax.swing.table.TableRowSorter


class UpdateStatusbar(val message: JLabel, val handler: RunHandler): ActionListener {
    lateinit var timer: Timer

    override fun actionPerformed(e: ActionEvent?) {
        val window = SwingUtilities.getWindowAncestor(message)
        val terminal = handler.status() != "running"

        message.text = handler.statusString()
        // The label clips at the width of the window rather than wrapping. A run that has
        // a reason to report leads with it so the start of it survives, and the tooltip is
        // where the rest of the line, underlying error included, can still be read.
        message.toolTipText = if (handler.failureSummary() != null) message.text else null

        if (terminal || window == null) {
            timer.stop()
        }

        if (terminal) {
            when (window) {
                is Frame -> window.title = window.title?.replace(" - running", " - done")
                is Dialog -> window.title = window.title?.replace(" - running", " - done")
            }
        }
    }

}

interface OutputHandler {
    abstract fun add(req: Request)
    abstract fun getAllRquests(): List<Request>
}

/**
 * The order a script set with `table.setSortOrder()` that the results table has yet to apply, or
 * null. Scripts are handed the [ResultStore] as `table`, so their order lands in the store and the
 * table follows it. Told apart by identity: every call records a new [ResultSortOrder], so calling
 * it again sorts again, same column and direction included, after the user has sorted by hand.
 */
internal fun scriptSortOrderToApply(requested: ResultSortOrder?, applied: ResultSortOrder?): ResultSortOrder? =
    requested?.takeIf { it !== applied }

class RequestTable(val store: ResultStore, val service: TurboService, val handler: RunHandler): JPanel() {
    val model = RequestTableModel()
    val issueTable = JTable(model)
    val requestEditor: HttpRequestEditor
    val responseEditor: HttpResponseEditor
    val bottomSplit: JSplitPane
    val requestListView: JScrollPane
    private var currentRequest: Request? = null
    private val lock = Object()
    private var descending = true
    @Volatile private var initialized = false
    @Volatile private var sortModifiedAfterInit = false
    private val panelUpdater: Timer
    private val storePoller: Timer

    fun clear() {
        model.clear()
    }

    /** Stops UI polling timers when the Turbo dialog closes or extension unloads. Idempotent. */
    fun dispose() {
        storePoller.stop()
        panelUpdater.stop()
    }

    // The table is shown once per run and never re-parented: leaving the component tree (dialog
    // disposed, run reconfigured) means its timers have nothing left to update.
    override fun removeNotify() {
        super.removeNotify()
        dispose()
    }

    fun hasSortBeenModified(): Boolean = sortModifiedAfterInit

    fun setCurrentRequest(req: Request?) {
        if (req == null) return
        synchronized(lock) {
            currentRequest = req
            val montoyaService = req.montoyaReq?.httpService() ?: service.toMontoya()
            requestEditor.request = HttpRequest.httpRequest(montoyaService, MontoyaBytes.byteArray(*req.getRequestAsBytes()))
            val responseBytes = Utils.replaceFirst(
                req.getResponseAsBytes() ?: ByteArray(0),
                "Content-Encoding: gzip",
                "X-Content-Encoding: gz"
            )
            responseEditor.response = try {
                HttpResponse.httpResponse(MontoyaBytes.byteArray(*responseBytes))
            } catch (e: RuntimeException) {
                HttpResponse.httpResponse()
            }
        }
    }

    /** Sorts by [column]. Callable from any thread (Jython scripts run off the EDT). */
    fun setSortOrder(column: Int, descending: Boolean) {
        require(column in 0 until model.columnCount) { "Sort column must be 0..${model.columnCount - 1}, got $column" }
        if (initialized) {
            sortModifiedAfterInit = true
        }
        val apply = {
            this.descending = descending
            val order = if (descending) SortOrder.DESCENDING else SortOrder.ASCENDING
            issueTable.rowSorter.sortKeys = listOf(RowSorter.SortKey(column, order))
        }
        if (SwingUtilities.isEventDispatchThread()) apply() else SwingUtilities.invokeLater(apply)
    }

    internal fun autoSortByAnomalyRank() {
        descending = true
        val order = SortOrder.DESCENDING
        issueTable.rowSorter.sortKeys = listOf(RowSorter.SortKey(3, order))
    }

    init {

        val sorter = object : TableRowSorter<RequestTableModel>(model) {
            override fun toggleSortOrder(column: Int) {
                sortModifiedAfterInit = true
                val sortKeys = this.sortKeys
                if (sortKeys.isEmpty() || sortKeys[0].column != column) {
                    // First click: descending
                    this.sortKeys = listOf(RowSorter.SortKey(column, SortOrder.DESCENDING))
                } else if (sortKeys[0].sortOrder == SortOrder.DESCENDING) {
                    // Second click: ascending
                    this.sortKeys = listOf(RowSorter.SortKey(column, SortOrder.ASCENDING))
                } else {
                    // Third click: unsorted
                    this.sortKeys = emptyList()
                }
            }
        }
        issueTable.rowSorter = sorter
        setSortOrder(0, true)

        // Add custom renderer for anomaly rank column to format with commas
        val anomalyRankRenderer = object : DefaultTableCellRenderer() {
            private val numberFormat = NumberFormat.getNumberInstance()

            override fun getTableCellRendererComponent(
                table: JTable?,
                value: Any?,
                isSelected: Boolean,
                hasFocus: Boolean,
                row: Int,
                column: Int
            ): Component {
                val formattedValue = if (value is Number) {
                    numberFormat.format(value)
                } else {
                    value
                }
                return super.getTableCellRendererComponent(table, formattedValue, isSelected, hasFocus, row, column)
            }
        }
        issueTable.columnModel.getColumn(3).cellRenderer = anomalyRankRenderer

        issueTable.autoResizeMode = JTable.AUTO_RESIZE_OFF
        //issueTable.getColumnModel().getColumn(0).setPreferredWidth(500)

        issueTable.selectionModel.addListSelectionListener {
            val viewRow = issueTable.selectedRow
            if (viewRow < 0) return@addListSelectionListener
            val req = model.getRequest(issueTable.convertRowIndexToModel(viewRow)) ?: return@addListSelectionListener
            setCurrentRequest(req)
        }

        requestListView = JScrollPane(issueTable)

        val turboSize = Utils.getTurboSize()
        val ui = Utils.montoyaApi!!.userInterface()
        requestEditor = ui.createHttpRequestEditor(EditorOptions.READ_ONLY)
        responseEditor = ui.createHttpResponseEditor(EditorOptions.READ_ONLY)
        bottomSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestEditor.uiComponent(), responseEditor.uiComponent())
        bottomSplit.resizeWeight = 0.5
        bottomSplit.preferredSize = Dimension(turboSize.width, turboSize.height/2)


        val splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT, requestListView, bottomSplit)

        requestListView.preferredSize = Dimension(turboSize.width, turboSize.height/2)
        splitPane.setDividerLocation(0.2)
        splitPane.preferredSize = Dimension(turboSize.width, turboSize.height)

        this.layout = BorderLayout()
        this.add(splitPane, BorderLayout.CENTER)


        splitPane.resizeWeight = 0.5


        val statusPanel = JPanel()
        statusPanel.border = BevelBorder(BevelBorder.LOWERED)
        this.add(statusPanel, BorderLayout.SOUTH) //
        statusPanel.preferredSize = Dimension(this.getWidth(), 30)
        statusPanel.layout = BoxLayout(statusPanel, BoxLayout.X_AXIS)
        val statusLabel = JLabel("")
        statusLabel.horizontalAlignment = SwingConstants.LEFT
        statusPanel.add(statusLabel)

        val updateStatusbar = UpdateStatusbar(statusLabel, handler)
        panelUpdater = Timer(1000, updateStatusbar)
        updateStatusbar.timer = panelUpdater
        panelUpdater.start()

        // Poll ResultStore for new results
        var lastKnownSize = 0
        var finishedAt: Long? = null
        var appliedScriptSort: ResultSortOrder? = null
        storePoller = javax.swing.Timer(100) {
            // Stop polling 10 seconds after run completes
            if (handler.status() != "running") {
                if (finishedAt == null) {
                    finishedAt = System.currentTimeMillis()
                } else if (System.currentTimeMillis() - finishedAt!! > 10000) {
                    (it.source as javax.swing.Timer).stop()
                    return@Timer
                }
            }
            val currentSize = store.count()
            if (currentSize > lastKnownSize) {
                for (i in lastKnownSize until currentSize) {
                    val req = store.getRequestByIndex(i)
                    if (req != null) {
                        model.addRow(req)
                        if (lastKnownSize == 0) {
                            setCurrentRequest(req)
                        }
                    }
                }
                lastKnownSize = currentSize
            }
            scriptSortOrderToApply(store.sortOrder(), appliedScriptSort)?.let { order ->
                appliedScriptSort = order
                setSortOrder(order.column, order.descending)
            }
        }
        storePoller.start()

        val menu = JPopupMenu()

        val reportToOrganizerButton = JMenuItem("Save to Organizer")
        reportToOrganizerButton.addActionListener {
            val comment = JOptionPane.showInputDialog(menu, "Comment", "", JOptionPane.PLAIN_MESSAGE) as? String
                ?: return@addActionListener
            val reqs = getSelectedRequests().mapNotNull(Request::getMontoyaRequest)
            val notes = comment + "\n" + handler.statusString() + "\n\n" + SCRIPT_MARKER + "\n" + handler.code
            for (req in reqs) {
                req.annotations().setNotes(notes)
                Utils.montoyaApi!!.organizer().sendToOrganizer(req)
            }
        }
        menu.add(reportToOrganizerButton)

        // warning, this doesn't reliably save entries with duplicate URLs
        val addToSitemap = JMenuItem("Add to sitemap")
        addToSitemap.addActionListener {
            for (req in getSelectedRequests()) {
                req.getMontoyaRequest()?.let { Utils.montoyaApi!!.siteMap().add(it) }
            }
        }
        menu.add(addToSitemap)

        val createIssueButton = JMenuItem("Report as issue")
        createIssueButton.addActionListener {
            val reqs = getSelectedRequests().mapNotNull(Request::getMontoyaRequest)
            if (reqs.isEmpty()) return@addActionListener

            val comment = JOptionPane.showInputDialog(menu, "Comment", "", JOptionPane.PLAIN_MESSAGE) as? String
                ?: return@addActionListener

            val montoyaService = reqs[0].httpService()
            val baseReq = HttpRequestResponse.httpRequestResponse(
                HttpRequest.httpRequest(montoyaService, MontoyaBytes.byteArray(*Utils.stringToBytes(handler.baseRequest))),
                HttpResponse.httpResponse()
            )
            val scheme = if (montoyaService.secure()) "https" else "http"
            val url = "$scheme://${montoyaService.host()}:${montoyaService.port()}"
            val detail = TurboIssueDetail.html(
                comment = comment,
                status = statusLabel.text,
                script = handler.code,
                rows = getSelectedRequests().map { req ->
                    TurboIssueDetail.Row(
                        req.words.firstOrNull() ?: "", req.status, req.ttfb, req.ttlb, req.arrival,
                        req.label, req.order, req.connectionId ?: "",
                    )
                },
            )
            val issue = AuditIssue.auditIssue(
                "Raijin Turbo finding",
                detail,
                "",
                url,
                AuditIssueSeverity.INFORMATION,
                AuditIssueConfidence.CERTAIN,
                null,
                null,
                AuditIssueSeverity.INFORMATION,
                listOf(baseReq) + reqs
            )
            Utils.montoyaApi!!.siteMap().add(issue)
        }
        menu.add(createIssueButton)


        issueTable.componentPopupMenu = menu
        Utils.montoyaApi!!.userInterface().applyThemeToComponent(this)

        initialized = true
    }

    private fun getSelectedRequests(): ArrayList<Request> {
        synchronized(lock) {
            val requests = ArrayList<Request>()
            val table = issueTable.model as RequestTableModel
            for (index in issueTable.selectedRows) {
                if (index < 0) continue
                val req = table.getRequest(issueTable.convertRowIndexToModel(index))
                if (req != null) {
                    requests.add(req)
                }
            }
            return requests
        }
    }

}
