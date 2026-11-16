package io.bitbytelab.raijin.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.ui.editor.EditorOptions
import burp.api.montoya.ui.editor.HttpRequestEditor
import burp.api.montoya.ui.editor.HttpResponseEditor
import io.bitbytelab.raijin.bridge.BridgeFactory
import io.bitbytelab.raijin.core.BuildInfo
import io.bitbytelab.raijin.core.RaijinExtension
import io.bitbytelab.raijin.core.RebindOutcome
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.state.McpActivityEntry
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.state.StoredFinding
import io.bitbytelab.raijin.transport.ActivityStore
import io.bitbytelab.raijin.transport.FindingsStore
import io.bitbytelab.raijin.transport.McpServerManager
import kotlinx.serialization.json.*
import java.awt.*
import java.awt.event.MouseEvent
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import javax.swing.*
import javax.swing.border.EmptyBorder
import javax.swing.table.DefaultTableCellRenderer
import javax.swing.table.DefaultTableModel

/**
 * Native multi-tab Burp Suite UI for Raijin.
 *
 * Tabs:
 * 1. MCP Activity   — Real-time tool call monitor with Burp request/response editors
 * 2. Proxy Explorer  — Browse/search proxy history with Burp-native viewers
 * 3. Scanner         — Live scanner findings with severity/confidence display
 * 4. Findings        — Agent-recorded findings (findings_add tool working memory)
 * 5. Autorize        — Live replay rules and the access-control mismatches they flagged
 * 6. Collaborator    — Create OOB clients, generate payloads, poll interactions; client list
 * 7. Rules           — Proxy, traffic, session and WebSocket rules; target scope
 * 8. JWT, Turbo      — Token tooling and Turbo runs
 * 9. Server          — Connection info, tool policy, bind address and remote security, stats
 *
 * Every timer, listener, subscription and worker the tab starts is released by [dispose], so a
 * reload leaves nothing running (and leaves listeners it does not own, such as persistence, alone).
 * The one exception is added by [dispose] itself: the trackers that keep queued store writes'
 * snapshots current until StateManager.cleanup(), which removes them (see [findingsSnapshot]).
 */
class RaijinTab(
    private val api: MontoyaApi,
    private val serverManager: McpServerManager,
    private val eventBus: EventBus,
    private val stateManager: StateManager,
    private val bridges: BridgeFactory.Bridges,
    bindHost: String,
    rebindNow: (String, Boolean) -> RebindOutcome
) {
    companion object {
        const val MAX_TABLE_ROWS = 2000
        private val TIME_FORMAT = DateTimeFormatter.ofPattern("HH:mm:ss.SSS")
        private val FINDING_TIME_FORMAT = DateTimeFormatter.ofPattern("MM-dd HH:mm:ss")

        /**
         * Findings as a queued store write saves them: frozen when [tasks] are disposed, which on unload
         * happens before the extension clears [state] (see [StoreSnapshot]). The tracking listeners go
         * ahead of the store's own, as [StoreSnapshot] requires; StateManager.cleanup() removes them.
         */
        internal fun findingsSnapshot(tasks: UiTasks, state: StateManager): StoreSnapshot<StoredFinding, String> =
            tasks.storeSnapshot({ state.findings.toList() }, { it.id }, newestFirst = false) { added, removed ->
                state.findingsListeners.add(0, added)
                state.findingsRemoveListeners.add(0, removed)
            }

        /** MCP activity as a queued store write saves it, newest first like the live deque; see [findingsSnapshot]. */
        internal fun activitySnapshot(tasks: UiTasks, state: StateManager): StoreSnapshot<McpActivityEntry, Long> =
            tasks.storeSnapshot({ state.mcpActivity.toList() }, { it.id }, newestFirst = true) { added, _ ->
                state.mcpActivityListeners.add(0, added)
            }
    }

    private val mainPanel = JPanel(BorderLayout(0, 0))
    private val tabbedPane = JTabbedPane(JTabbedPane.TOP)
    private val totalToolCalls = AtomicLong(0)
    private val totalErrors = AtomicLong(0)
    private val perToolCounts = ConcurrentHashMap<String, AtomicLong>()

    // dispose() runs these newest first; the background pool is registered first, so it stops last.
    private val disposer = Disposer { what, e -> api.logging().logToError("Raijin UI: releasing $what failed: ${e.message}") }
    private val tasks = UiTasks { desc, e -> reportBackgroundError(desc, e) }
    private val savedFindings = findingsSnapshot(tasks, stateManager)
    private val savedActivity = activitySnapshot(tasks, stateManager)

    // Fetch buttons captured so tabs can lazily auto-load on first view.
    private var proxyFetchButton: JButton? = null
    private var scannerFetchButton: JButton? = null

    // State read by the tab builders init calls, so it is declared (and set) before init runs.
    private val activityById = ConcurrentHashMap<Long, McpActivityEntry>()
    private var activityFilter = "all"
    private var activitySearch = ""
    private var shownActivityId: Long? = null
    private val activityPrettyJson = Json { prettyPrint = true; prettyPrintIndent = "  " }
    private val proxyHistoryCache = mutableListOf<JsonObject>()
    private var scannerIssuesCache = listOf<JsonObject>()
    private val findingsCache = mutableListOf<StoredFinding>()
    private var findingsSeverityFilter = "Any"
    private var findingsSearch = ""
    private var findingsSnapshot: List<String> = emptyList()
    private var shownFindingId: String? = null
    private var rebuildingFindings = false

    private val httpToolNames = setOf(
        "http_send_request", "http_send_requests_parallel", "http_send_request_chain",
        "http_fuzz", "http_send_raw_bytes", "http_race", "http_cookie_jar_get",
        "http_cookie_jar_set", "http_analyze_keywords", "http_analyze_variations",
        "http_set_traffic_rule", "http_list_traffic_rules", "http_remove_traffic_rule",
        "auth_diff", "api_import_openapi"
    )
    private val proxyToolNames = setOf(
        "proxy_history", "proxy_history_search", "proxy_websocket_history",
        "proxy_websocket_history_search", "proxy_intercept_enable", "proxy_intercept_disable",
        "proxy_intercept_status", "proxy_annotate", "proxy_set_request_rule",
        "proxy_set_response_rule", "proxy_list_rules", "proxy_remove_rule", "proxy_auto_auth"
    )
    private val scannerToolNames = setOf(
        "scanner_start_crawl", "scanner_start_audit", "scanner_task_status",
        "scanner_task_list", "scanner_task_delete", "scanner_task_issues",
        "scanner_get_all_issues", "scanner_generate_report", "scanner_create_issue",
        "scanner_import_bcheck", "scanner_register_check", "scanner_unregister_check",
        "bcheck_create", "bcheck_import", "bcheck_list", "bcheck_remove",
        "scancheck_create_passive", "scancheck_create_active", "scancheck_list", "scancheck_remove"
    )

    private val autorizePanel = AutorizePanel(api, stateManager, bridges.autorize, tasks)
    private val serverPanel = ServerPanel(api, eventBus, stateManager, bindHost, rebindNow, tasks) { totalToolCalls.get() }

    init {
        try {
            buildTabs()
        } catch (t: Throwable) {
            // A tab that fails to build is never handed to the extension, whose unload handler
            // therefore cannot dispose it: release what was already started here.
            disposer.dispose()
            throw t
        }
    }

    private fun buildTabs() {
        disposer.add("background tasks") { tasks.dispose() }
        tabbedPane.font = tabbedPane.font.deriveFont(12f)
        tabbedPane.addTab("MCP Activity", buildActivityTab())
        val proxyTab = buildProxyTab().also { tabbedPane.addTab("Proxy Explorer", it) }
        val scannerTab = buildScannerTab().also { tabbedPane.addTab("Scanner", it) }
        val findingsTab = buildFindingsTab().also { tabbedPane.addTab("Findings", it) }
        tabbedPane.addTab("Autorize", autorizePanel)
        tabbedPane.addTab("Collaborator", buildCollaboratorTab())
        tabbedPane.addTab("Rules", buildRulesTab())
        val jwtPanel = JwtPanel(bridges.jwt)
        disposer.add("JWT panel") { jwtPanel.dispose() }
        tabbedPane.addTab("JWT", jwtPanel)
        val runsPanel = TurboRunsPanel()
        disposer.add("Turbo runs panel") { runsPanel.dispose() }
        tabbedPane.addTab("Turbo", runsPanel)
        tabbedPane.addTab("Server", serverPanel)
        mainPanel.add(RaijinTheme.brandHeader(BuildInfo.VERSION), BorderLayout.NORTH)
        mainPanel.add(tabbedPane, BorderLayout.CENTER)

        // Render persisted MCP activity (the deque is seeded on startup by the dashboard
        // persistence), rebuild the id->entry lookup, and seed the counters BEFORE wiring the
        // live listener so new calls increment on top without double-counting.
        initActivityFromRestore()
        wireActivityListener()

        val refreshTimer = Timer(1500) {
            serverPanel.refresh()
            refreshRulesTab()
            refreshFindingsTab()
            refreshCollaboratorClients()
            autorizePanel.refresh()
            // Activity stats (incl. Events count from the event bus) must refresh on
            // the timer too — otherwise the bar is frozen until an MCP tool call fires
            // the activity listener, so "Events: 0" never updates from proxy traffic.
            updateActivityStats()
        }
        refreshTimer.isRepeats = true
        refreshTimer.start()
        disposer.add("refresh timer") { refreshTimer.stop() }

        // Lazily load Proxy/Scanner the first time each tab is shown, so they are
        // not permanently blank waiting for a manual Fetch click.
        var proxyLoaded = false
        var scannerLoaded = false
        tabbedPane.addChangeListener {
            when (tabbedPane.selectedComponent) {
                proxyTab -> if (!proxyLoaded) { proxyLoaded = true; proxyFetchButton?.doClick() }
                scannerTab -> if (!scannerLoaded) { scannerLoaded = true; scannerFetchButton?.doClick() }
                findingsTab -> rebuildFindingsTable()
            }
        }

        // Burp's own theming covers every widget here (including its request/response editors);
        // Raijin adds nothing but semantic colours (see RaijinTheme), so dark and light both work.
        RaijinTheme.apply(mainPanel)
    }

    fun getComponent(): Component = mainPanel

    /** Releases everything the tab started (timers, listeners, subscriptions, workers). Idempotent. */
    fun dispose() = disposer.dispose()

    fun log(level: String, category: String, message: String) {
        when (level.uppercase()) {
            "ERROR", "FATAL" -> api.logging().logToError("Raijin [$category]: $message")
            "WARN", "WARNING" -> api.logging().logToOutput("Raijin [WARN/$category]: $message")
            "INFO" -> api.logging().logToOutput("Raijin: $message")
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  TAB 1: MCP ACTIVITY
    // ═══════════════════════════════════════════════════════════════════════

    private lateinit var activityTableModel: DefaultTableModel
    private lateinit var activityTable: JTable
    private lateinit var activityRequestEditor: HttpRequestEditor
    private lateinit var activityResponseEditor: HttpResponseEditor
    private lateinit var activityDetailInfo: JTextArea
    private lateinit var activityStatsLabel: JLabel

    private fun buildActivityTab(): JPanel {
        val panel = JPanel(BorderLayout(0, 0))

        // Stats bar
        activityStatsLabel = JLabel("  Calls: 0  |  Errors: 0  |  Events: 0")
        activityStatsLabel.font = RaijinTheme.editorFont(11f)
        activityStatsLabel.border = BorderFactory.createCompoundBorder(RaijinTheme.ruleBorder(0, 0, 1, 0), EmptyBorder(4, 8, 4, 8))

        // Filter bar
        val filterBar = JPanel(FlowLayout(FlowLayout.LEFT, 4, 3))
        val group = ButtonGroup()
        for ((label, filter) in listOf("All" to "all", "HTTP" to "http", "Proxy" to "proxy", "Scanner" to "scanner", "Other" to "other")) {
            val btn = JToggleButton(label, filter == "all")
            btn.font = btn.font.deriveFont(11f); btn.margin = Insets(2, 8, 2, 8); btn.isFocusPainted = false
            btn.addActionListener { activityFilter = filter; applyActivityFilter() }
            group.add(btn); filterBar.add(btn)
        }
        filterBar.add(Box.createHorizontalStrut(8))
        filterBar.add(JLabel("Search:"))
        val searchField = JTextField(18)
        searchField.font = RaijinTheme.editorFont(11f)
        searchField.addKeyListener(object : java.awt.event.KeyAdapter() {
            override fun keyReleased(e: java.awt.event.KeyEvent?) { activitySearch = searchField.text.trim().lowercase(); applyActivityFilter() }
        })
        filterBar.add(searchField)
        // "Clear View" — cosmetic only: empties the visible table, keeps memory + saved history
        // (repopulates on a filter change). Distinct from "Delete Saved History" below. Issue #8.
        fun clearViewOnly() {
            activityTableModel.rowCount = 0; activityById.clear()
            totalToolCalls.set(0); totalErrors.set(0); perToolCounts.clear(); updateActivityStats()
        }
        val clearBtn = JButton("Clear View"); clearBtn.font = clearBtn.font.deriveFont(11f); clearBtn.margin = Insets(2, 8, 2, 8)
        clearBtn.toolTipText = "Clear the visible table only — keeps in-memory activity and any saved history"
        clearBtn.addActionListener { clearViewOnly() }
        filterBar.add(clearBtn)

        // "Delete Saved History" — the real, durable clear: wipes the in-memory deque, this
        // project's rows in the on-disk store, and the dashboard event buffer. Confirmed. Issue #8.
        val deleteSavedBtn = JButton("Delete Saved History"); deleteSavedBtn.font = deleteSavedBtn.font.deriveFont(11f); deleteSavedBtn.margin = Insets(2, 8, 2, 8)
        deleteSavedBtn.toolTipText = "Permanently delete this project's MCP activity from memory AND disk"
        deleteSavedBtn.addActionListener {
            val n = stateManager.mcpActivity.size
            val ok = JOptionPane.showConfirmDialog(
                mainPanel,
                "Permanently delete $n MCP activity record(s) for this project — including the saved\n" +
                    "history on disk (${ActivityStore.path()})?\n\nThis cannot be undone.",
                "Delete Saved History", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE
            )
            if (ok != JOptionPane.YES_OPTION) return@addActionListener
            val project = currentProject()
            stateManager.clearMcpActivity()
            eventBus.clear()
            clearViewOnly()
            tasks.persist("Delete saved MCP activity") {
                ActivityStore.deleteForProject(project)
                ActivityStore.lastError?.let { api.logging().logToError("Raijin: deleting saved MCP activity failed: $it") }
            }
        }
        filterBar.add(deleteSavedBtn)

        // Persistence toggle + always-visible status so neither default silently surprises anyone.
        val persistStatus = TintedLabel { if (ActivityStore.enabled) RaijinTheme.success() else RaijinTheme.muted() }
        fun refreshPersistStatus() {
            persistStatus.text = if (ActivityStore.enabled) "  Saved: ON → disk" else "  Saved: OFF (session only)"
            persistStatus.toolTipText = if (ActivityStore.enabled) ActivityStore.path() else "MCP activity is not saved to disk"
            persistStatus.repaint()
        }
        val persistCheck = JCheckBox("Persist", ActivityStore.enabled); persistCheck.font = persistCheck.font.deriveFont(11f)
        persistCheck.toolTipText = "Save MCP activity to disk so it survives Burp restarts. Off = this session only."
        persistCheck.addActionListener {
            val enabled = persistCheck.isSelected
            ActivityStore.enabled = enabled
            api.persistence().preferences().setBoolean("mcp_persist_activity", enabled)
            // Flush on enable: save what's already in memory. The store takes the snapshot under its
            // file lock, so a write racing this one cannot be overwritten with older data; once the tab
            // is disposed it is the frozen copy, so a write still queued at unload never saves a cleared list.
            if (enabled) {
                val project = currentProject()
                tasks.persist("Save MCP activity") {
                    ActivityStore.flushProject(project) { savedActivity.read() }
                    ActivityStore.lastError?.let { api.logging().logToError("Raijin: saving MCP activity failed: $it") }
                }
            }
            refreshPersistStatus()
        }
        filterBar.add(Box.createHorizontalStrut(10))
        filterBar.add(persistCheck)
        filterBar.add(persistStatus)
        refreshPersistStatus()

        val topBar = JPanel(BorderLayout()); topBar.add(activityStatsLabel, BorderLayout.NORTH); topBar.add(filterBar, BorderLayout.SOUTH)

        // Table
        activityTableModel = object : DefaultTableModel(arrayOf("#", "Time", "Tool", "Method", "URL / Detail", "Host", "Status", "ms"), 0) {
            override fun isCellEditable(r: Int, c: Int) = false
        }
        activityTable = JTable(activityTableModel)
        activityTable.fillsViewportHeight = true; activityTable.rowHeight = 22; activityTable.setShowGrid(false)
        activityTable.intercellSpacing = Dimension(0, 0); activityTable.autoCreateRowSorter = true
        activityTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        val cols = activityTable.columnModel
        cols.getColumn(0).preferredWidth = 40; cols.getColumn(0).maxWidth = 60
        cols.getColumn(1).preferredWidth = 90; cols.getColumn(1).maxWidth = 110
        cols.getColumn(2).preferredWidth = 180; cols.getColumn(2).maxWidth = 250
        cols.getColumn(3).preferredWidth = 55; cols.getColumn(3).maxWidth = 70
        cols.getColumn(4).preferredWidth = 400
        cols.getColumn(5).preferredWidth = 130; cols.getColumn(5).maxWidth = 200
        cols.getColumn(6).preferredWidth = 50; cols.getColumn(6).maxWidth = 65
        cols.getColumn(7).preferredWidth = 50; cols.getColumn(7).maxWidth = 70
        cols.getColumn(2).cellRenderer = ColorRenderer({ category ->
            when (category) { "http" -> RaijinTheme.info(); "proxy" -> RaijinTheme.success(); "scanner" -> RaijinTheme.error(); else -> null }
        }) { name ->
            when { name in httpToolNames -> "http"; name in proxyToolNames -> "proxy"; name in scannerToolNames -> "scanner"; else -> "" }
        }
        cols.getColumn(3).cellRenderer = MethodRenderer()
        cols.getColumn(6).cellRenderer = StatusCodeRenderer()

        activityTable.selectionModel.addListSelectionListener { e -> if (!e.valueIsAdjusting) showActivityDetail() }
        activityTable.addMouseListener(ContextMenuListener { row, e -> showActivityContextMenu(row, e) })

        // Detail panel
        activityRequestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY)
        activityResponseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY)
        activityDetailInfo = JTextArea(3, 60)
        activityDetailInfo.isEditable = false; activityDetailInfo.font = RaijinTheme.editorFont(11f)
        activityDetailInfo.lineWrap = true; activityDetailInfo.wrapStyleWord = true
        activityDetailInfo.text = "Select an activity row to view details."

        val detailTabs = JTabbedPane(JTabbedPane.TOP)
        detailTabs.addTab("Info", JScrollPane(activityDetailInfo))
        detailTabs.addTab("Request", activityRequestEditor.uiComponent())
        detailTabs.addTab("Response", activityResponseEditor.uiComponent())

        val split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(activityTable), detailTabs)
        split.resizeWeight = 0.6; split.dividerSize = 5
        panel.add(topBar, BorderLayout.NORTH); panel.add(split, BorderLayout.CENTER)
        return panel
    }

    private fun wireActivityListener() {
        val listener: (McpActivityEntry) -> Unit = { entry ->
            totalToolCalls.incrementAndGet()
            if (entry.isError) totalErrors.incrementAndGet()
            perToolCounts.computeIfAbsent(entry.toolName) { AtomicLong(0) }.incrementAndGet()
            activityById[entry.id] = entry
            SwingUtilities.invokeLater {
                while (activityTableModel.rowCount >= MAX_TABLE_ROWS) {
                    val oldId = activityTableModel.getValueAt(activityTableModel.rowCount - 1, 0) as? Long
                    if (oldId != null) activityById.remove(oldId)
                    activityTableModel.removeRow(activityTableModel.rowCount - 1)
                }
                if (passesActivityFilter(entry)) addActivityRow(entry, 0)
                updateActivityStats()
            }
        }
        // Removes this instance only: the persistence listener in the same list must outlive the tab.
        disposer.listen("MCP activity listener", stateManager.mcpActivityListeners, listener)
    }

    /**
     * Restores the MCP Activity view from the entries the StateManager loaded on startup
     * (dashboard persistence): renders the rows, rebuilds the id->entry lookup so restored rows
     * are clickable, and seeds the Calls/Errors/per-tool counters. Called once, before
     * [wireActivityListener], so subsequent live calls increment on top without double-counting.
     */
    private fun initActivityFromRestore() {
        val restored = stateManager.mcpActivity.toList()
        if (restored.isNotEmpty()) {
            totalToolCalls.set(restored.size.toLong())
            totalErrors.set(restored.count { it.isError }.toLong())
            restored.forEach { perToolCounts.computeIfAbsent(it.toolName) { AtomicLong(0) }.incrementAndGet() }
        }
        applyActivityFilter()
        updateActivityStats()
    }

    private fun passesActivityFilter(e: McpActivityEntry): Boolean {
        when (activityFilter) {
            "http" -> if (e.toolName !in httpToolNames) return false
            "proxy" -> if (e.toolName !in proxyToolNames) return false
            "scanner" -> if (e.toolName !in scannerToolNames) return false
            "other" -> if (e.toolName in httpToolNames || e.toolName in proxyToolNames || e.toolName in scannerToolNames) return false
        }
        if (activitySearch.isNotEmpty() && activitySearch !in "${e.toolName} ${e.url} ${e.host} ${e.method}".lowercase()) return false
        return true
    }

    private fun addActivityRow(e: McpActivityEntry, at: Int) {
        activityById[e.id] = e   // every rendered row (incl. persisted/restored ones) must be clickable
        val time = try { LocalDateTime.ofInstant(Instant.parse(e.timestamp), ZoneId.systemDefault()).format(TIME_FORMAT) } catch (_: Exception) { e.timestamp.takeLast(12) }
        activityTableModel.insertRow(at, arrayOf<Any?>(e.id, time, e.toolName, e.method.ifEmpty { "-" }, e.url.ifEmpty { e.argsSummary.take(120) }, e.host, if (e.statusCode > 0) e.statusCode else null as Int?, e.durationMs.toInt()))
    }

    private fun applyActivityFilter() {
        activityTableModel.rowCount = 0
        for (e in stateManager.mcpActivity.toList()) {
            if (passesActivityFilter(e)) addActivityRow(e, activityTableModel.rowCount)
            if (activityTableModel.rowCount >= MAX_TABLE_ROWS) break
        }
    }

    /** Current Burp project key — matching [RaijinExtension.projectKey] across stores. */
    private fun currentProject(): String = RaijinExtension.projectKey(api)

    private fun updateActivityStats() {
        val top = perToolCounts.entries.sortedByDescending { it.value.get() }.take(3).joinToString("  ") { "${it.key}(${it.value.get()})" }
        activityStatsLabel.text = "  Calls: ${totalToolCalls.get()}  |  Errors: ${totalErrors.get()}  |  Events: ${eventBus.size()}  |  Top: $top"
    }

    private fun showActivityDetail() {
        val vr = activityTable.selectedRow
        val id = if (vr >= 0) activityTableModel.getValueAt(activityTable.convertRowIndexToModel(vr), 0) as? Long else null
        val entry = id?.let { activityById[it] }
        // A live row inserted above moves the selection without changing it: leave the viewers alone.
        if (entry != null && entry.id == shownActivityId) return
        shownActivityId = entry?.id
        if (entry == null) {
            activityDetailInfo.text = "Select an activity row to view details."
            activityRequestEditor.clear()
            activityResponseEditor.clear()
            return
        }
        activityDetailInfo.text = "Tool: ${entry.toolName}  |  Duration: ${entry.durationMs}ms  |  Error: ${entry.isError}\n" +
            "URL: ${entry.url}\nHost: ${entry.host}\n\n" +
            "Arguments:\n${prettyActivityJson(entry.argsSummary)}\n\n" +
            "Result:\n${prettyActivityJson(entry.resultSummary)}"
        activityDetailInfo.caretPosition = 0
        val rr = entry.requestResponse
        val req = try { rr?.request() } catch (_: Exception) { null }
        val resp = try { rr?.response() } catch (_: Exception) { null }
        try { if (req != null) activityRequestEditor.request = req else activityRequestEditor.clear() } catch (_: Exception) {}
        try { if (resp != null) activityResponseEditor.response = resp else activityResponseEditor.clear() } catch (_: Exception) {}
    }

    /**
     * Pretty-prints a compact JSON string ([McpActivityEntry.argsSummary]/`resultSummary`) for
     * the Activity tab's Info panel: parses and re-indents it, then un-escapes literal `\r\n`/
     * `\n` sequences remaining *inside* string leaves (the same normalization idiom
     * [io.bitbytelab.raijin.bridge.InjectionBridge] uses on raw request text) so a multi-line
     * `script`/`base_request` field reads as real lines instead of one escaped blob. Falls back
     * to the raw string on any parse failure (e.g. a legacy or malformed entry) — this is purely
     * a rendering step; the stored/persisted value is untouched.
     */
    private fun prettyActivityJson(raw: String): String {
        if (raw.isBlank()) return raw
        val pretty = try {
            activityPrettyJson.encodeToString(JsonElement.serializer(), Json.parseToJsonElement(raw))
        } catch (_: Exception) {
            return raw
        }
        return pretty.replace("\\r\\n", "\n").replace("\\n", "\n")
    }

    private fun showActivityContextMenu(viewRow: Int, e: MouseEvent) {
        val id = activityTableModel.getValueAt(activityTable.convertRowIndexToModel(viewRow), 0) as? Long ?: return
        val entry = activityById[id] ?: return
        val menu = JPopupMenu()
        menu.add(JMenuItem("Send to Repeater").apply { addActionListener {
            val req = entry.requestResponse?.request() ?: if (entry.url.isNotEmpty()) HttpRequest.httpRequestFromUrl(entry.url) else null
            req?.let { api.repeater().sendToRepeater(it, "MCP-${entry.toolName}") }
        }})
        menu.add(JMenuItem("Send to Intruder").apply { addActionListener {
            val req = entry.requestResponse?.request() ?: if (entry.url.isNotEmpty()) HttpRequest.httpRequestFromUrl(entry.url) else null
            req?.let { api.intruder().sendToIntruder(it, "MCP-${entry.toolName}") }
        }})
        menu.addSeparator()
        if (entry.host.isNotEmpty()) {
            menu.add(JMenuItem("Add '${entry.host}' to Scope").apply { addActionListener {
                try { api.scope().includeInScope("https://${entry.host}") } catch (_: Exception) {}
            }})
        }
        if (entry.url.isNotEmpty()) menu.add(JMenuItem("Copy URL").apply { addActionListener { copyToClipboard(entry.url) } })
        menu.add(JMenuItem("Copy Result JSON").apply { addActionListener { copyToClipboard(entry.resultSummary) } })
        menu.show(e.component, e.x, e.y)
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  TAB 2: PROXY EXPLORER
    // ═══════════════════════════════════════════════════════════════════════

    private lateinit var proxyTableModel: DefaultTableModel
    private lateinit var proxyTable: JTable
    private lateinit var proxyRequestEditor: HttpRequestEditor
    private lateinit var proxyResponseEditor: HttpResponseEditor

    private fun buildProxyTab(): JPanel {
        val panel = JPanel(BorderLayout(0, 0))

        // Controls bar
        val controls = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        val hostField = JTextField(15); hostField.toolTipText = "Host filter"
        val methodCombo = JComboBox(arrayOf("Any", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"))
        val statusField = JTextField(5); statusField.toolTipText = "Status code"
        val scopeCheck = JCheckBox("In-scope only", false)
        val countField = JTextField("100", 4); countField.toolTipText = "Max results"
        val fetchBtn = JButton("Fetch History")
        val searchField = JTextField(15); searchField.toolTipText = "Regex search"
        val searchBtn = JButton("Search")

        controls.add(JLabel("Host:")); controls.add(hostField)
        controls.add(JLabel("Method:")); controls.add(methodCombo)
        controls.add(JLabel("Status:")); controls.add(statusField)
        controls.add(scopeCheck)
        controls.add(JLabel("Count:")); controls.add(countField)
        controls.add(fetchBtn)
        controls.add(Box.createHorizontalStrut(12))
        controls.add(JLabel("Regex:")); controls.add(searchField); controls.add(searchBtn)

        // Table
        proxyTableModel = object : DefaultTableModel(arrayOf("#", "Method", "URL", "Host", "Status", "MIME", "Length"), 0) {
            override fun isCellEditable(r: Int, c: Int) = false
        }
        proxyTable = JTable(proxyTableModel)
        proxyTable.fillsViewportHeight = true; proxyTable.rowHeight = 22; proxyTable.setShowGrid(false)
        proxyTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        proxyTable.columnModel.getColumn(0).preferredWidth = 50; proxyTable.columnModel.getColumn(0).maxWidth = 70
        proxyTable.columnModel.getColumn(1).preferredWidth = 60; proxyTable.columnModel.getColumn(1).maxWidth = 80
        proxyTable.columnModel.getColumn(2).preferredWidth = 400
        proxyTable.columnModel.getColumn(3).preferredWidth = 140; proxyTable.columnModel.getColumn(3).maxWidth = 200
        proxyTable.columnModel.getColumn(4).preferredWidth = 55; proxyTable.columnModel.getColumn(4).maxWidth = 70
        proxyTable.columnModel.getColumn(5).preferredWidth = 80; proxyTable.columnModel.getColumn(5).maxWidth = 120
        proxyTable.columnModel.getColumn(6).preferredWidth = 70; proxyTable.columnModel.getColumn(6).maxWidth = 100
        proxyTable.columnModel.getColumn(1).cellRenderer = MethodRenderer()
        proxyTable.columnModel.getColumn(4).cellRenderer = StatusCodeRenderer()

        // Detail
        proxyRequestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY)
        proxyResponseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY)
        val detailTabs = JTabbedPane(JTabbedPane.TOP)
        detailTabs.addTab("Request", proxyRequestEditor.uiComponent())
        detailTabs.addTab("Response", proxyResponseEditor.uiComponent())

        proxyTable.selectionModel.addListSelectionListener { e -> if (!e.valueIsAdjusting) showProxyDetail() }
        proxyTable.addMouseListener(ContextMenuListener { row, ev -> showProxyContextMenu(row, ev) })

        // Fetch action. The filters are read here on the EDT; only the bridge call runs in the background.
        proxyFetchButton = fetchBtn
        fetchBtn.addActionListener {
            val host = hostField.text.trim().ifEmpty { null }
            val method = if (methodCombo.selectedIndex == 0) null else methodCombo.selectedItem as String
            val status = statusField.text.trim().toIntOrNull()
            val count = countField.text.trim().toIntOrNull() ?: 100
            val inScope = scopeCheck.isSelected
            tasks.compute("Fetch proxy history", {
                bridges.proxy.getHistory(0, count, host, method, status, null, inScope, true, true, null)
            }) { result -> if (!showBridgeError(result, "Fetch proxy history")) showProxyItems(result) }
        }

        // Search action. searchHistory returns the same "items" array shape as
        // getHistory (plus total_matches) — NOT a "matches" key; reading the old
        // key silently emptied the table for every search.
        searchBtn.addActionListener {
            val pattern = searchField.text.trim(); if (pattern.isEmpty()) return@addActionListener
            val inScope = scopeCheck.isSelected
            tasks.compute("Search proxy history", {
                bridges.proxy.searchHistory(pattern, "both", false, 200, inScope, true, true, null)
            }) { result -> if (!showBridgeError(result, "Search proxy history")) showProxyItems(result) }
        }

        val split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(proxyTable), detailTabs)
        split.resizeWeight = 0.55; split.dividerSize = 5
        panel.add(controls, BorderLayout.NORTH); panel.add(split, BorderLayout.CENTER)
        return panel
    }

    /**
     * Rebuilds the cache and the table together on the EDT: clearing the cache on a worker thread
     * left a window where a click indexed an empty cache against a still-populated table.
     */
    private fun showProxyItems(result: JsonObject) {
        val items = result["items"] as? JsonArray ?: JsonArray(emptyList())
        proxyHistoryCache.clear()
        proxyTableModel.rowCount = 0
        for (item in items) {
            val obj = item as? JsonObject ?: continue
            proxyHistoryCache.add(obj)
            proxyTableModel.addRow(arrayOf<Any?>(
                obj["index"]?.jsonPrimitive?.intOrNull ?: 0,
                obj["method"]?.jsonPrimitive?.contentOrNull ?: "",
                obj["url"]?.jsonPrimitive?.contentOrNull ?: "",
                obj["host"]?.jsonPrimitive?.contentOrNull ?: "",
                obj["status_code"]?.jsonPrimitive?.intOrNull as Int?,
                obj["response_mime_type"]?.jsonPrimitive?.contentOrNull ?: "",
                obj["response_length"]?.jsonPrimitive?.intOrNull ?: 0
            ))
        }
    }

    private fun showProxyDetail() {
        val vr = proxyTable.selectedRow
        val item = if (vr >= 0) proxyHistoryCache.getOrNull(proxyTable.convertRowIndexToModel(vr)) else null
        if (item == null) {
            proxyRequestEditor.clear()
            proxyResponseEditor.clear()
            return
        }
        try {
            val reqStr = item["request"]?.jsonPrimitive?.contentOrNull
            if (reqStr != null) {
                val host = item["host"]?.jsonPrimitive?.contentOrNull ?: ""
                val port = item["port"]?.jsonPrimitive?.intOrNull ?: 443
                val tls = item["secure"]?.jsonPrimitive?.booleanOrNull ?: (port == 443)
                val service = burp.api.montoya.http.HttpService.httpService(host, port, tls)
                proxyRequestEditor.request = HttpRequest.httpRequest(service, reqStr)
            } else {
                proxyRequestEditor.clear()
            }
        } catch (_: Exception) {
            proxyRequestEditor.clear()
        }
        try {
            val respStr = item["response"]?.jsonPrimitive?.contentOrNull
            if (respStr != null) proxyResponseEditor.response = HttpResponse.httpResponse(respStr)
            else proxyResponseEditor.clear()
        } catch (_: Exception) {
            proxyResponseEditor.clear()
        }
    }

    private fun showProxyContextMenu(viewRow: Int, e: MouseEvent) {
        val mr = proxyTable.convertRowIndexToModel(viewRow)
        if (mr >= proxyHistoryCache.size) return
        val item = proxyHistoryCache[mr]
        val url = item["url"]?.jsonPrimitive?.contentOrNull ?: ""
        val host = item["host"]?.jsonPrimitive?.contentOrNull ?: ""
        val menu = JPopupMenu()
        menu.add(JMenuItem("Send to Repeater").apply { addActionListener {
            try {
                val reqStr = item["request"]?.jsonPrimitive?.contentOrNull ?: return@addActionListener
                val service = burp.api.montoya.http.HttpService.httpService(host, item["port"]?.jsonPrimitive?.intOrNull ?: 443, item["secure"]?.jsonPrimitive?.booleanOrNull ?: true)
                api.repeater().sendToRepeater(HttpRequest.httpRequest(service, reqStr), "Proxy-$host")
            } catch (_: Exception) {}
        }})
        menu.add(JMenuItem("Send to Intruder").apply { addActionListener {
            try {
                val reqStr = item["request"]?.jsonPrimitive?.contentOrNull ?: return@addActionListener
                val service = burp.api.montoya.http.HttpService.httpService(host, item["port"]?.jsonPrimitive?.intOrNull ?: 443, item["secure"]?.jsonPrimitive?.booleanOrNull ?: true)
                api.intruder().sendToIntruder(HttpRequest.httpRequest(service, reqStr))
            } catch (_: Exception) {}
        }})
        menu.addSeparator()
        if (host.isNotEmpty()) menu.add(JMenuItem("Add '$host' to Scope").apply { addActionListener { try { api.scope().includeInScope("https://$host") } catch (_: Exception) {} } })
        if (url.isNotEmpty()) menu.add(JMenuItem("Copy URL").apply { addActionListener { copyToClipboard(url) } })
        menu.show(e.component, e.x, e.y)
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  TAB 3: SCANNER
    // ═══════════════════════════════════════════════════════════════════════

    private lateinit var scannerTableModel: DefaultTableModel
    private lateinit var scannerDetailArea: JTextArea
    private lateinit var scannerRequestEditor: HttpRequestEditor

    /** Extracts the host from a serialized issue url (the bridge emits baseUrl, not host). */
    private fun hostOf(url: String): String = try {
        java.net.URI.create(url).host ?: url.substringBefore('/')
    } catch (_: Exception) {
        url.substringBefore('/')
    }

    private fun buildScannerTab(): JPanel {
        val panel = JPanel(BorderLayout(0, 0))

        // Controls
        val controls = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        val urlField = JTextField(20); urlField.toolTipText = "URL prefix filter"
        val sevCombo = JComboBox(arrayOf("Any", "HIGH", "MEDIUM", "LOW", "INFORMATION"))
        val confCombo = JComboBox(arrayOf("Any", "CERTAIN", "FIRM", "TENTATIVE"))
        val fetchBtn = JButton("Fetch Issues")
        val countLabel = JLabel("Issues: 0")
        controls.add(JLabel("URL prefix:")); controls.add(urlField)
        controls.add(JLabel("Severity:")); controls.add(sevCombo)
        controls.add(JLabel("Confidence:")); controls.add(confCombo)
        controls.add(fetchBtn); controls.add(Box.createHorizontalStrut(16)); controls.add(countLabel)

        // Table
        scannerTableModel = object : DefaultTableModel(arrayOf("Severity", "Confidence", "Name", "URL", "Host"), 0) {
            override fun isCellEditable(r: Int, c: Int) = false
        }
        val scannerTable = JTable(scannerTableModel)
        scannerTable.fillsViewportHeight = true; scannerTable.rowHeight = 22; scannerTable.setShowGrid(false)
        scannerTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        scannerTable.columnModel.getColumn(0).preferredWidth = 80; scannerTable.columnModel.getColumn(0).maxWidth = 120
        scannerTable.columnModel.getColumn(1).preferredWidth = 80; scannerTable.columnModel.getColumn(1).maxWidth = 120
        scannerTable.columnModel.getColumn(2).preferredWidth = 250
        scannerTable.columnModel.getColumn(3).preferredWidth = 350
        scannerTable.columnModel.getColumn(4).preferredWidth = 150
        scannerTable.columnModel.getColumn(0).cellRenderer = SeverityRenderer()

        // Detail: issue metadata + the triggering request when the issue carries evidence
        scannerDetailArea = JTextArea(8, 60)
        scannerDetailArea.isEditable = false; scannerDetailArea.font = RaijinTheme.editorFont(11f)
        scannerDetailArea.lineWrap = true; scannerDetailArea.wrapStyleWord = true
        scannerDetailArea.text = "Click 'Fetch Issues' to load scanner findings."
        scannerRequestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY)
        val detailTabs = JTabbedPane(JTabbedPane.TOP)
        detailTabs.addTab("Details", JScrollPane(scannerDetailArea))
        detailTabs.addTab("Request Evidence", scannerRequestEditor.uiComponent())

        fun showScannerDetail() {
            val vr = scannerTable.selectedRow
            val issue = if (vr >= 0) scannerIssuesCache.getOrNull(scannerTable.convertRowIndexToModel(vr)) else null
            if (issue == null) {
                scannerDetailArea.text = "Select an issue to view its details."
                scannerRequestEditor.clear()
                return
            }
            val url = issue["url"]?.jsonPrimitive?.contentOrNull ?: ""
            val sb = StringBuilder()
            sb.appendLine("Name: ${issue["name"]?.jsonPrimitive?.contentOrNull ?: ""}")
            sb.appendLine("Severity: ${issue["severity"]?.jsonPrimitive?.contentOrNull ?: ""}")
            sb.appendLine("Confidence: ${issue["confidence"]?.jsonPrimitive?.contentOrNull ?: ""}")
            sb.appendLine("URL: $url")
            sb.appendLine()
            sb.appendLine("Detail:")
            sb.appendLine(issue["detail"]?.jsonPrimitive?.contentOrNull ?: "(none)")
            sb.appendLine()
            sb.appendLine("Remediation:")
            sb.appendLine(issue["remediation"]?.jsonPrimitive?.contentOrNull ?: "(none)")
            scannerDetailArea.text = sb.toString()
            scannerDetailArea.caretPosition = 0

            // The bridge serializes each evidence pair with the raw request text and its
            // URL — render the first available one in the read-only Burp request editor.
            try {
                val pair = issue["request_responses"]?.jsonArray
                    ?.mapNotNull { runCatching { it.jsonObject }.getOrNull() }
                    ?.firstOrNull { !it["request"]?.jsonPrimitive?.contentOrNull.isNullOrBlank() }
                val reqText = pair?.get("request")?.jsonPrimitive?.contentOrNull
                val reqUrl = pair?.get("request_url")?.jsonPrimitive?.contentOrNull?.ifEmpty { null } ?: url
                if (!reqText.isNullOrBlank() && reqUrl.isNotEmpty()) {
                    scannerRequestEditor.request =
                        HttpRequest.httpRequest(burp.api.montoya.http.HttpService.httpService(reqUrl), reqText)
                } else {
                    scannerRequestEditor.clear()
                }
            } catch (_: Exception) {
                scannerRequestEditor.clear()
            }
        }
        scannerTable.selectionModel.addListSelectionListener { e ->
            if (!e.valueIsAdjusting) showScannerDetail()
        }

        // The filters are read here on the EDT; only the bridge call runs in the background.
        scannerFetchButton = fetchBtn
        fetchBtn.addActionListener {
            val urlPrefix = urlField.text.trim().ifEmpty { null }
            val sev = if (sevCombo.selectedIndex == 0) null else (sevCombo.selectedItem as String).lowercase()
            val conf = if (confCombo.selectedIndex == 0) null else (confCombo.selectedItem as String).lowercase()
            tasks.compute("Fetch scanner issues", { bridges.scanner.getAllIssues(urlPrefix, sev, conf, 500) }) { result ->
                if (showBridgeError(result, "Fetch scanner issues")) return@compute
                val fetched = (result["issues"] as? JsonArray).orEmpty().filterIsInstance<JsonObject>()
                scannerIssuesCache = fetched
                scannerTableModel.rowCount = 0
                for (issue in fetched) {
                    val url = issue["url"]?.jsonPrimitive?.contentOrNull ?: ""
                    scannerTableModel.addRow(arrayOf(
                        issue["severity"]?.jsonPrimitive?.contentOrNull ?: "",
                        issue["confidence"]?.jsonPrimitive?.contentOrNull ?: "",
                        issue["name"]?.jsonPrimitive?.contentOrNull ?: "",
                        url,
                        hostOf(url)
                    ))
                }
                countLabel.text = "Issues: ${fetched.size}"
            }
        }

        val split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(scannerTable), detailTabs)
        split.resizeWeight = 0.6; split.dividerSize = 5
        panel.add(controls, BorderLayout.NORTH); panel.add(split, BorderLayout.CENTER)
        return panel
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  TAB 4: FINDINGS (agent-recorded working memory)
    // ═══════════════════════════════════════════════════════════════════════

    private lateinit var findingsTableModel: DefaultTableModel
    private lateinit var findingsTable: JTable
    private lateinit var findingsDetailArea: JTextArea
    private lateinit var findingsRequestEditor: HttpRequestEditor
    private lateinit var findingsResponseEditor: HttpResponseEditor
    private lateinit var findingsCountLabel: JLabel

    private fun buildFindingsTab(): JPanel {
        val panel = JPanel(BorderLayout(0, 0))

        // Controls
        val controls = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        val sevCombo = JComboBox(arrayOf("Any", "Critical", "High", "Medium", "Low", "Info"))
        sevCombo.toolTipText = "Severity filter (prefix match, case-insensitive)"
        val searchField = JTextField(16); searchField.toolTipText = "Search type / URL / location / detail / OWASP"
        val refreshBtn = JButton("Refresh")
        val clearBtn = JButton("Clear All")
        controls.add(JLabel("Severity:")); controls.add(sevCombo)
        controls.add(JLabel("Search:")); controls.add(searchField)
        controls.add(refreshBtn)
        controls.add(Box.createHorizontalStrut(12))
        controls.add(clearBtn)
        controls.add(Box.createHorizontalStrut(12))
        findingsCountLabel = JLabel("Findings: 0")
        controls.add(findingsCountLabel)

        sevCombo.addActionListener { findingsSeverityFilter = sevCombo.selectedItem as String; rebuildFindingsTable() }
        searchField.addKeyListener(object : java.awt.event.KeyAdapter() {
            override fun keyReleased(e: java.awt.event.KeyEvent?) { findingsSearch = searchField.text.trim().lowercase(); rebuildFindingsTable() }
        })
        refreshBtn.addActionListener { rebuildFindingsTable() }
        clearBtn.toolTipText = "Delete every recorded finding (memory + saved store — the agent can re-add them)"
        clearBtn.addActionListener {
            val n = stateManager.findings.size
            if (n == 0) return@addActionListener
            val ok = JOptionPane.showConfirmDialog(
                mainPanel,
                "Delete all $n recorded finding(s)?\nThe agent can re-add them via the findings_add tool.",
                "Clear Findings", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE
            )
            if (ok != JOptionPane.YES_OPTION) return@addActionListener
            stateManager.findings.clear()
            syncFindingsStore()
            rebuildFindingsTable()
        }

        // Table
        findingsTableModel = object : DefaultTableModel(arrayOf("ID", "Severity", "CVSS", "Type", "OWASP 2021", "URL", "Location", "Created"), 0) {
            override fun isCellEditable(r: Int, c: Int) = false
        }
        findingsTable = JTable(findingsTableModel)
        findingsTable.fillsViewportHeight = true; findingsTable.rowHeight = 22; findingsTable.setShowGrid(false)
        findingsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        findingsTable.columnModel.getColumn(0).preferredWidth = 80; findingsTable.columnModel.getColumn(0).maxWidth = 100
        findingsTable.columnModel.getColumn(1).preferredWidth = 70; findingsTable.columnModel.getColumn(1).maxWidth = 90
        findingsTable.columnModel.getColumn(2).preferredWidth = 45; findingsTable.columnModel.getColumn(2).maxWidth = 60
        findingsTable.columnModel.getColumn(3).preferredWidth = 120
        findingsTable.columnModel.getColumn(4).preferredWidth = 220
        findingsTable.columnModel.getColumn(5).preferredWidth = 260
        findingsTable.columnModel.getColumn(6).preferredWidth = 110
        findingsTable.columnModel.getColumn(7).preferredWidth = 95; findingsTable.columnModel.getColumn(7).maxWidth = 110
        findingsTable.columnModel.getColumn(1).cellRenderer = SeverityRenderer()
        findingsTable.columnModel.getColumn(2).cellRenderer = CvssRenderer()

        // Detail: full metadata + the recorded request/response evidence
        findingsDetailArea = JTextArea(10, 60)
        findingsDetailArea.isEditable = false; findingsDetailArea.font = RaijinTheme.editorFont(11f)
        findingsDetailArea.lineWrap = true; findingsDetailArea.wrapStyleWord = true
        findingsDetailArea.text = "Findings the agent records via the findings_add tool appear here automatically."
        findingsRequestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY)
        findingsResponseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY)
        val detailTabs = JTabbedPane(JTabbedPane.TOP)
        detailTabs.addTab("Details", JScrollPane(findingsDetailArea))
        detailTabs.addTab("Request", findingsRequestEditor.uiComponent())
        detailTabs.addTab("Response", findingsResponseEditor.uiComponent())

        findingsTable.selectionModel.addListSelectionListener { e ->
            if (!e.valueIsAdjusting && !rebuildingFindings) showFindingDetail()
        }
        findingsTable.addMouseListener(ContextMenuListener { row, e -> showFindingsContextMenu(row, e) })

        val split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(findingsTable), detailTabs)
        split.resizeWeight = 0.55; split.dividerSize = 5
        panel.add(controls, BorderLayout.NORTH); panel.add(split, BorderLayout.CENTER)
        rebuildFindingsTable()
        return panel
    }

    private fun passesFindingsFilter(f: StoredFinding): Boolean {
        if (findingsSeverityFilter != "Any") {
            val sev = f.severity.lowercase()
            if (!sev.startsWith(findingsSeverityFilter.lowercase())) return false
        }
        if (findingsSearch.isNotEmpty() &&
            findingsSearch !in "${f.type} ${f.url} ${f.location} ${f.detail} ${f.owaspCategory}".lowercase()
        ) return false
        return true
    }

    /** Rebuilds the findings table from StateManager, preserving the current selection by id. */
    private fun rebuildFindingsTable() {
        val selectedId = runCatching {
            val vr = findingsTable.selectedRow
            if (vr >= 0) findingsTableModel.getValueAt(findingsTable.convertRowIndexToModel(vr), 0)?.toString() else null
        }.getOrNull()

        SwingUtilities.invokeLater {
            // The rebuild clears and restores the selection; the detail must not flicker through "nothing selected".
            rebuildingFindings = true
            try {
                findingsCache.clear()
                findingsTableModel.rowCount = 0
                for (f in stateManager.findings.filter { passesFindingsFilter(it) }) {
                    findingsCache.add(f)
                    val time = try {
                        LocalDateTime.ofInstant(Instant.parse(f.createdAt), ZoneId.systemDefault()).format(FINDING_TIME_FORMAT)
                    } catch (_: Exception) { f.createdAt.takeLast(12) }
                    findingsTableModel.addRow(arrayOf<Any?>(
                        f.id, f.severity.ifEmpty { "-" }, f.cvssScore.ifEmpty { "-" }, f.type,
                        f.owaspCategory, f.url, f.location.ifEmpty { "-" }, time
                    ))
                }
                findingsSnapshot = stateManager.findings.map { it.id }
                findingsCountLabel.text = "Findings: ${stateManager.findings.size}"
                // Restore selection if the row survived the rebuild
                if (selectedId != null) {
                    val row = (0 until findingsTableModel.rowCount).firstOrNull {
                        findingsTableModel.getValueAt(it, 0)?.toString() == selectedId
                    }
                    if (row != null && row < findingsTable.rowCount) findingsTable.setRowSelectionInterval(row, row)
                }
            } finally {
                rebuildingFindings = false
            }
            showFindingDetail()
        }
    }

    /**
     * Timer hook: rebuild only when the underlying findings list actually changed,
     * so an operator reading the tab never has their selection reset every 1.5 s.
     */
    private fun refreshFindingsTab() {
        val ids = stateManager.findings.map { it.id }
        if (ids != findingsSnapshot) rebuildFindingsTable()
    }

    private fun findingAt(modelRow: Int): StoredFinding? =
        if (modelRow in 0 until findingsCache.size) findingsCache[modelRow] else null

    private fun showFindingDetail() {
        val vr = findingsTable.selectedRow
        val f = if (vr >= 0) findingAt(findingsTable.convertRowIndexToModel(vr)) else null
        if (f != null && f.id == shownFindingId) return
        shownFindingId = f?.id
        if (f == null) {
            findingsDetailArea.text = "Findings the agent records via the findings_add tool appear here automatically."
            findingsRequestEditor.clear()
            findingsResponseEditor.clear()
            return
        }
        val sb = StringBuilder()
        sb.appendLine("ID: ${f.id}")
        sb.appendLine("Type: ${f.type}")
        sb.appendLine("Severity: ${f.severity}")
        if (f.cvssScore.isNotEmpty() || f.cvssVector.isNotEmpty()) {
            sb.appendLine("CVSS: ${f.cvssScore.ifEmpty { "-" }}${if (f.cvssVector.isNotEmpty()) "  (${f.cvssVector})" else ""}")
        }
        if (f.owaspCategory.isNotEmpty()) sb.appendLine("OWASP 2021: ${f.owaspCategory}")
        sb.appendLine("URL: ${f.url}")
        sb.appendLine("Location: ${f.location}")
        sb.appendLine("Created: ${f.createdAt}")
        sb.appendLine()
        sb.appendLine("Detail:")
        sb.appendLine(f.detail.ifEmpty { "(none)" })
        if (f.stepsToReproduce.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine("Steps to reproduce:")
            sb.appendLine(f.stepsToReproduce)
        }
        sb.appendLine()
        sb.appendLine("Evidence:")
        sb.appendLine(f.evidence.ifEmpty { "(none)" })
        findingsDetailArea.text = sb.toString()
        findingsDetailArea.caretPosition = 0

        // Recorded evidence viewers. The service comes from the finding URL, with a raw fallback
        // for non-URL entries; a viewer the finding has no evidence for is emptied.
        findingsRequestEditor.showRaw(f.request, f.url)
        findingsResponseEditor.showRaw(f.response)
    }

    private fun showFindingsContextMenu(viewRow: Int, e: MouseEvent) {
        val mr = findingsTable.convertRowIndexToModel(viewRow)
        val f = findingAt(mr) ?: return
        val menu = JPopupMenu()
        if (f.url.isNotEmpty()) menu.add(JMenuItem("Copy URL").apply { addActionListener { copyToClipboard(f.url) } })
        menu.add(JMenuItem("Copy Finding JSON").apply {
            addActionListener {
                copyToClipboard(
                    buildJsonObject {
                        put("id", f.id); put("type", f.type); put("severity", f.severity)
                        put("url", f.url); put("location", f.location); put("detail", f.detail)
                        put("evidence", f.evidence)
                        put("cvss_score", f.cvssScore); put("cvss_vector", f.cvssVector)
                        put("owasp_category", f.owaspCategory); put("steps_to_reproduce", f.stepsToReproduce)
                        put("request", f.request); put("response", f.response)
                        put("created_at", f.createdAt)
                    }.toString()
                )
            }
        })
        menu.addSeparator()
        menu.add(JMenuItem("Delete Finding").apply {
            addActionListener {
                stateManager.findings.removeIf { it.id == f.id }
                syncFindingsStore()
                rebuildFindingsTable()
            }
        })
        menu.show(e.component, e.x, e.y)
    }

    /**
     * Operator-side mutations (delete / clear) bypass FindingsBridge, so they must
     * rewrite the durable store themselves — otherwise a deleted finding reappears
     * after the next extension reload.
     */
    private fun syncFindingsStore() {
        val project = currentProject()
        // Snapshotted under the store's file lock, so a removal racing this write cannot resurrect a finding;
        // a write still queued at unload saves the copy frozen at dispose, not the cleared list.
        tasks.persist("Save findings") {
            FindingsStore.replaceProject(project) { savedFindings.read() }
            FindingsStore.lastError?.let { api.logging().logToError("Raijin: saving findings failed: $it") }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  TAB 5: COLLABORATOR
    // ═══════════════════════════════════════════════════════════════════════

    private lateinit var collabTabs: JTabbedPane
    private lateinit var collabClientsModel: SnapshotTableModel
    private lateinit var collabClientsTable: JTable

    private fun buildCollaboratorTab(): JPanel {
        val panel = JPanel(BorderLayout(0, 4))
        panel.border = EmptyBorder(8, 8, 8, 8)

        // Top: create client + generate payload
        val topPanel = JPanel(GridBagLayout())
        topPanel.border = BorderFactory.createTitledBorder("Collaborator Client")
        val gbc = GridBagConstraints().apply { insets = Insets(4, 6, 4, 6); anchor = GridBagConstraints.WEST }

        val clientIdField = JTextField(30); clientIdField.isEditable = false
        val serverField = JTextField(30); serverField.isEditable = false
        val payloadField = JTextField(40); payloadField.isEditable = false
        val createBtn = JButton("Create Client")
        val generateBtn = JButton("Generate Payload"); generateBtn.isEnabled = false
        val pollBtn = JButton("Poll Interactions"); pollBtn.isEnabled = false
        val copyPayloadBtn = JButton("Copy Payload"); copyPayloadBtn.isEnabled = false

        gbc.gridy = 0; gbc.gridx = 0; topPanel.add(JLabel("Client ID:"), gbc)
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0; topPanel.add(clientIdField, gbc)
        gbc.gridx = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0.0; topPanel.add(createBtn, gbc)
        gbc.gridy = 1; gbc.gridx = 0; topPanel.add(JLabel("Server:"), gbc)
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0; topPanel.add(serverField, gbc)
        gbc.gridy = 2; gbc.gridx = 0; topPanel.add(JLabel("Payload:"), gbc)
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; topPanel.add(payloadField, gbc)
        gbc.gridx = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0.0
        val payloadBtnPanel = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
        payloadBtnPanel.add(generateBtn); payloadBtnPanel.add(copyPayloadBtn); payloadBtnPanel.add(pollBtn)
        topPanel.add(payloadBtnPanel, gbc)

        // Bottom: interactions table
        val interTableModel = object : DefaultTableModel(arrayOf("Type", "Client IP", "Timestamp", "Payload ID", "Details"), 0) {
            override fun isCellEditable(r: Int, c: Int) = false
        }
        val interTable = JTable(interTableModel)
        interTable.fillsViewportHeight = true; interTable.rowHeight = 22; interTable.setShowGrid(false)
        interTable.columnModel.getColumn(0).preferredWidth = 60; interTable.columnModel.getColumn(0).maxWidth = 80
        interTable.columnModel.getColumn(1).preferredWidth = 130; interTable.columnModel.getColumn(1).maxWidth = 180
        interTable.columnModel.getColumn(2).preferredWidth = 160
        interTable.columnModel.getColumn(3).preferredWidth = 120
        interTable.columnModel.getColumn(4).preferredWidth = 350
        val interScroll = JScrollPane(interTable)

        // Read-only list of the Collaborator clients the agent or this tab created.
        collabClientsModel = SnapshotTableModel(arrayOf("Client ID", "Server", "Created"))
        collabClientsTable = JTable(collabClientsModel)
        collabClientsTable.fillsViewportHeight = true; collabClientsTable.rowHeight = 22; collabClientsTable.setShowGrid(false)
        collabClientsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        collabClientsTable.addMouseListener(ContextMenuListener { row, e ->
            val id = collabClientsModel.getValueAt(row, 0)?.toString() ?: return@ContextMenuListener
            val server = collabClientsModel.getValueAt(row, 1)?.toString().orEmpty()
            val menu = JPopupMenu()
            menu.add(JMenuItem("Copy Client ID").apply { addActionListener { copyToClipboard(id) } })
            if (server.isNotEmpty()) menu.add(JMenuItem("Copy Server").apply { addActionListener { copyToClipboard(server) } })
            menu.show(e.component, e.x, e.y)
        })
        collabTabs = JTabbedPane(JTabbedPane.TOP)
        collabTabs.addTab("Interactions", interScroll)
        collabTabs.addTab("Clients", JScrollPane(collabClientsTable))

        // Maps a serialized interaction (the shape produced by
        // CollaboratorBridge.serializeInteraction) to a table row. The bridge
        // emits `id` + type-specific `*_details` objects — NOT the flat
        // `payload_id`/`details`/`raw_query` keys the old code looked for, which
        // is why the Payload ID and Details columns were always blank.
        fun interactionRow(obj: JsonObject): Array<Any?> {
            val type = obj["type"]?.jsonPrimitive?.contentOrNull ?: ""
            val details = when (type) {
                "dns" -> obj["dns_details"]?.jsonObject?.let {
                    "${it["query_type"]?.jsonPrimitive?.contentOrNull ?: ""} ${it["query_name"]?.jsonPrimitive?.contentOrNull ?: ""}".trim()
                }
                "http" -> obj["http_details"]?.jsonObject?.let {
                    "${it["request_method"]?.jsonPrimitive?.contentOrNull ?: ""} ${it["request_url"]?.jsonPrimitive?.contentOrNull ?: ""} (${it["response_status"]?.jsonPrimitive?.contentOrNull ?: "?"})".trim()
                }
                "smtp" -> obj["smtp_details"]?.jsonObject?.get("conversation")?.jsonPrimitive?.contentOrNull
                else -> null
            } ?: ""
            return arrayOf(
                type,
                obj["client_ip"]?.jsonPrimitive?.contentOrNull ?: "",
                obj["timestamp"]?.jsonPrimitive?.contentOrNull ?: "",
                obj["id"]?.jsonPrimitive?.contentOrNull ?: "",
                details
            )
        }

        // Dedup by interaction id so a hit observed by both a manual poll and
        // the MCP-driven poll (which also emits collaborator.interaction events)
        // is only listed once.
        val seenInteractions = java.util.Collections.synchronizedSet(HashSet<String>())
        fun addInteraction(obj: JsonObject) {
            // `id` is the payload's interaction id, shared by every hit of that payload;
            // `seq` is unique per interaction.
            val id = (obj["seq"] ?: obj["id"])?.jsonPrimitive?.contentOrNull ?: ""
            if (id.isNotEmpty() && !seenInteractions.add(id)) return
            val row = interactionRow(obj)
            SwingUtilities.invokeLater { interTableModel.addRow(row) }
        }

        // Reflect agent/MCP-driven collaborator activity live. CollaboratorBridge
        // emits one collaborator.interaction event per hit on every poll — from
        // an MCP tool call OR this panel's Poll button — so the table now fills
        // even when the operator never touched these controls.
        val subscription = eventBus.subscribeInternal(listOf("collaborator.interaction")) { event ->
            addInteraction(event.data)
        }
        disposer.add("Collaborator interaction events") { eventBus.unsubscribe(subscription) }

        val currentClientId = AtomicReference("")

        createBtn.addActionListener {
            tasks.compute("Create collaborator client", { bridges.collaborator.createClient() }) { result ->
                if (showBridgeError(result, "Create collaborator client")) return@compute
                val cid = result["client_id"]?.jsonPrimitive?.contentOrNull ?: ""
                val server = result["server"]?.jsonPrimitive?.contentOrNull ?: ""
                currentClientId.set(cid)
                clientIdField.text = cid; serverField.text = server
                generateBtn.isEnabled = cid.isNotEmpty(); pollBtn.isEnabled = cid.isNotEmpty()
                refreshCollaboratorClients()
            }
        }

        generateBtn.addActionListener {
            val cid = currentClientId.get()
            if (cid.isEmpty()) return@addActionListener
            tasks.compute("Generate payload", { bridges.collaborator.generatePayload(cid, null) }) { result ->
                if (showBridgeError(result, "Generate payload")) return@compute
                val payload = result["payload"]?.jsonPrimitive?.contentOrNull ?: ""
                payloadField.text = payload; copyPayloadBtn.isEnabled = payload.isNotEmpty()
            }
        }

        copyPayloadBtn.addActionListener { copyToClipboard(payloadField.text) }

        pollBtn.addActionListener {
            val cid = currentClientId.get()
            if (cid.isEmpty()) return@addActionListener
            tasks.compute("Poll interactions", { bridges.collaborator.pollInteractions(cid, null, null) }) { result ->
                if (showBridgeError(result, "Poll interactions")) return@compute
                // pollInteractions already emits collaborator.interaction events
                // that the subscription above renders (deduped). Route the direct
                // results through the same path so manual polls of THIS panel's
                // client also appear, regardless of event timing.
                (result["interactions"] as? JsonArray).orEmpty().forEach { (it as? JsonObject)?.let(::addInteraction) }
            }
        }

        panel.add(topPanel, BorderLayout.NORTH); panel.add(collabTabs, BorderLayout.CENTER)
        return panel
    }

    /** Timer hook for the read-only client list: rebuilt only when the set of clients changed. */
    private fun refreshCollaboratorClients() {
        val rows = stateManager.collaboratorClients.values
            .sortedBy { it.createdAt }
            .map { listOf<Any?>(it.clientId, it.server, it.createdAt) }
        collabClientsModel.update(rows, collabClientsTable)
        setTabTitle(collabTabs, 1, "Clients (${rows.size})")
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  TAB 6: RULES MANAGER
    // ═══════════════════════════════════════════════════════════════════════

    private lateinit var rulesTabbed: JTabbedPane
    private lateinit var proxyRulesModel: SnapshotTableModel
    private lateinit var proxyRulesTable: JTable
    private lateinit var trafficRulesModel: SnapshotTableModel
    private lateinit var trafficRulesTable: JTable
    private lateinit var sessionRulesModel: SnapshotTableModel
    private lateinit var sessionRulesTable: JTable
    private lateinit var wsRulesModel: SnapshotTableModel
    private lateinit var wsRulesTable: JTable

    private fun buildRulesTab(): JPanel {
        val panel = JPanel(BorderLayout(0, 0))
        panel.border = EmptyBorder(8, 8, 8, 8)

        rulesTabbed = JTabbedPane(JTabbedPane.TOP)
        fun rulesTable(model: SnapshotTableModel) = JTable(model).apply {
            fillsViewportHeight = true; rowHeight = 22
            setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        }

        // Proxy Rules
        proxyRulesModel = SnapshotTableModel(
            arrayOf("ID", "Type", "Action", "Match Host", "Match URL", "Match Method", "Enabled"),
            mapOf(6 to SnapshotTableModel.BOOLEAN),
        )
        proxyRulesTable = rulesTable(proxyRulesModel)
        proxyRulesTable.addMouseListener(ContextMenuListener { row, e ->
            val menu = JPopupMenu()
            val ruleId = proxyRulesModel.getValueAt(row, 0)?.toString() ?: return@ContextMenuListener
            menu.add(JMenuItem("Toggle Enable/Disable").apply { addActionListener {
                val rule = stateManager.proxyRules.find { it.ruleId == ruleId }
                if (rule != null) { rule.enabled = !rule.enabled; refreshRulesTab() }
            }})
            menu.add(JMenuItem("Delete Rule").apply { addActionListener {
                stateManager.proxyRules.removeIf { it.ruleId == ruleId }; refreshRulesTab()
            }})
            menu.show(e.component, e.x, e.y)
        })
        rulesTabbed.addTab("Proxy Rules", JScrollPane(proxyRulesTable))

        // Traffic Rules
        trafficRulesModel = SnapshotTableModel(
            arrayOf("ID", "Direction", "Match URL", "Match Host", "Add Header", "Enabled"),
            mapOf(5 to SnapshotTableModel.BOOLEAN),
        )
        trafficRulesTable = rulesTable(trafficRulesModel)
        trafficRulesTable.addMouseListener(ContextMenuListener { row, e ->
            val menu = JPopupMenu()
            val ruleId = trafficRulesModel.getValueAt(row, 0)?.toString() ?: return@ContextMenuListener
            menu.add(JMenuItem("Toggle Enable/Disable").apply { addActionListener {
                val rule = stateManager.trafficRules.find { it.ruleId == ruleId }
                if (rule != null) { rule.enabled = !rule.enabled; refreshRulesTab() }
            }})
            menu.add(JMenuItem("Delete Rule").apply { addActionListener {
                stateManager.trafficRules.removeIf { it.ruleId == ruleId }; refreshRulesTab()
            }})
            menu.show(e.component, e.x, e.y)
        })
        rulesTabbed.addTab("Traffic Rules", JScrollPane(trafficRulesTable))

        // Session Rules
        sessionRulesModel = SnapshotTableModel(
            arrayOf("Name", "Scope", "Extract From", "Inject Into", "Last Value", "Enabled"),
            mapOf(5 to SnapshotTableModel.BOOLEAN),
        )
        sessionRulesTable = rulesTable(sessionRulesModel)
        rulesTabbed.addTab("Session Rules", JScrollPane(sessionRulesTable))

        // WebSocket intercept rules: read-only here, the agent manages them with the websocket tool.
        wsRulesModel = SnapshotTableModel(
            arrayOf("ID", "Direction", "Action", "Match URL", "Match Message", "Modify", "Tag", "Enabled"),
            mapOf(7 to SnapshotTableModel.BOOLEAN),
        )
        wsRulesTable = rulesTable(wsRulesModel)
        rulesTabbed.addTab("WebSocket Rules", JScrollPane(wsRulesTable))

        // Burp's target scope, read-only.
        val scopeViewer = ScopeViewerPanel(bridges.scope, eventBus, tasks)
        disposer.add("scope viewer") { scopeViewer.dispose() }
        rulesTabbed.addTab("Scope", scopeViewer)

        val refreshBtn = JButton("Refresh")
        refreshBtn.addActionListener { refreshRulesTab() }
        val btnPanel = JPanel(FlowLayout(FlowLayout.RIGHT)); btnPanel.add(refreshBtn)

        panel.add(btnPanel, BorderLayout.NORTH); panel.add(rulesTabbed, BorderLayout.CENTER)
        onEdt { refreshRulesTab() }
        return panel
    }

    /** Timer hook: a table is rebuilt only when its rules changed, and keeps the selected rule selected. */
    private fun refreshRulesTab() {
        proxyRulesModel.update(stateManager.proxyRules.map { r ->
            listOf<Any?>(r.ruleId, r.type, r.action, r.matchHost ?: "*", r.matchUrl ?: "*", r.matchMethod ?: "*", r.enabled)
        }, proxyRulesTable)
        trafficRulesModel.update(stateManager.trafficRules.map { r ->
            listOf<Any?>(r.ruleId, r.direction, r.matchUrl ?: "*", r.matchHost ?: "*", r.modifyAddHeader ?: "", r.enabled)
        }, trafficRulesTable)
        sessionRulesModel.update(stateManager.sessionRules.map { r ->
            listOf<Any?>(r.ruleName, r.scope, r.extractFrom, r.injectInto, r.lastExtractedValue ?: "(none)", r.enabled)
        }, sessionRulesTable)
        wsRulesModel.update(stateManager.websocketInterceptRules.map { r ->
            listOf<Any?>(
                r.ruleId, r.direction, r.action, r.matchUrl ?: "*", r.matchMessage ?: "*",
                r.modifyRegex?.let { "$it → ${r.modifyReplacement.orEmpty()}" }.orEmpty(), r.tagComment.orEmpty(), r.enabled,
            )
        }, wsRulesTable)
        setTabTitle(rulesTabbed, 0, "Proxy Rules (${proxyRulesModel.rowCount})")
        setTabTitle(rulesTabbed, 1, "Traffic Rules (${trafficRulesModel.rowCount})")
        setTabTitle(rulesTabbed, 2, "Session Rules (${sessionRulesModel.rowCount})")
        setTabTitle(rulesTabbed, 3, "WebSocket Rules (${wsRulesModel.rowCount})")
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  SHARED UTILITIES
    // ═══════════════════════════════════════════════════════════════════════

    /** Retitles [tabs] at [index] only when the text changed (the timer calls this every tick). */
    private fun setTabTitle(tabs: JTabbedPane, index: Int, title: String) {
        if (tabs.getTitleAt(index) != title) tabs.setTitleAt(index, title)
    }

    /** A failed background job: logged and shown, so "errored" never looks like "no data". */
    private fun reportBackgroundError(desc: String, e: Exception) {
        api.logging().logToError("Raijin UI: $desc failed: ${e.message}")
        SwingUtilities.invokeLater {
            JOptionPane.showMessageDialog(
                mainPanel, e.message ?: e.javaClass.simpleName, "$desc failed", JOptionPane.WARNING_MESSAGE
            )
        }
    }

    /**
     * Bridges return `{"error": "..."}` instead of throwing. If [result] carries
     * an error, surface it (dialog + Burp error log) and return true so the caller
     * can bail — otherwise a failed fetch clears the table to 0 rows and looks
     * indistinguishable from a genuinely empty result.
     */
    private fun showBridgeError(result: JsonObject, context: String): Boolean {
        val err = result["error"]?.jsonPrimitive?.contentOrNull ?: return false
        api.logging().logToError("Raijin UI: $context: $err")
        SwingUtilities.invokeLater {
            JOptionPane.showMessageDialog(mainPanel, err, "$context failed", JOptionPane.WARNING_MESSAGE)
        }
        return true
    }

    // ── Shared Renderers (the method, status and severity ones live in UiSupport) ──

    /** Colors a CVSS score cell by qualitative band (0–10 scale; blank stays muted). */
    private class CvssRenderer : DefaultTableCellRenderer() {
        init { horizontalAlignment = CENTER }
        override fun getTableCellRendererComponent(t: JTable, v: Any?, s: Boolean, f: Boolean, r: Int, c: Int): Component {
            val comp = super.getTableCellRendererComponent(t, v, s, f, r, c)
            val score = v?.toString()?.trim()?.toDoubleOrNull()
            if (!s) foreground = when {
                score == null -> RaijinTheme.muted()
                score >= 9.0 -> RaijinTheme.critical()
                score >= 7.0 -> RaijinTheme.error()
                score >= 4.0 -> RaijinTheme.warning()
                else -> RaijinTheme.info()
            }
            if (score != null) font = font.deriveFont(Font.BOLD)
            return comp
        }
    }

    /** Generic renderer that maps cell value to a color category via a classifier function. */
    private class ColorRenderer(private val colorFor: (String) -> Color?, private val classifier: (String) -> String) : DefaultTableCellRenderer() {
        override fun getTableCellRendererComponent(t: JTable, v: Any?, s: Boolean, f: Boolean, r: Int, c: Int): Component {
            val comp = super.getTableCellRendererComponent(t, v, s, f, r, c)
            if (!s) foreground = colorFor(classifier(v?.toString() ?: "")) ?: t.foreground
            return comp
        }
    }
}
