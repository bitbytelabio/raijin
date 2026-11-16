package io.bitbytelab.raijin.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.ui.editor.EditorOptions
import io.bitbytelab.raijin.bridge.AutorizeBridge
import io.bitbytelab.raijin.state.AutorizeMatch
import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.DefaultComboBoxModel
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JMenuItem
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JPopupMenu
import javax.swing.JScrollPane
import javax.swing.JSpinner
import javax.swing.JSplitPane
import javax.swing.JTabbedPane
import javax.swing.JTable
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.ListSelectionModel
import javax.swing.SpinnerNumberModel
import javax.swing.table.DefaultTableModel

/**
 * The Autorize tab: live proxy taps that replay matching traffic under other identities (driven by
 * AutorizeTap), and the mismatches they flagged, each shown as the captured original next to what
 * every identity sent and received. Rules go through [AutorizeBridge], the path the `autorize` MCP
 * tool uses, so the operator and the agent edit one rule set. [refresh] re-reads [StateManager];
 * the tables change only when the state did.
 */
internal class AutorizePanel(
    private val api: MontoyaApi,
    private val stateManager: StateManager,
    private val autorize: AutorizeBridge,
    private val tasks: UiTasks,
) : JPanel(BorderLayout()) {

    // ── Rules ────────────────────────────────────────────────────────────────
    private var ruleRows: List<List<Any?>> = emptyList()
    private val rulesModel = object : DefaultTableModel(
        arrayOf("On", "Rule", "Identities", "Filters", "Threshold", "Matches", "Created"), 0
    ) {
        override fun isCellEditable(row: Int, column: Int) = column == 0
        override fun getColumnClass(column: Int): Class<*> = when (column) {
            0 -> SnapshotTableModel.BOOLEAN
            5 -> SnapshotTableModel.INT
            else -> Any::class.java
        }
        override fun setValueAt(value: Any?, row: Int, column: Int) {
            super.setValueAt(value, row, column)
            val ruleId = getValueAt(row, 1) as? String
            if (column == 0 && value is Boolean && ruleId != null) toggleRule(ruleId, value)
        }
    }
    private val rulesTable = JTable(rulesModel)

    // ── Matches ──────────────────────────────────────────────────────────────
    private val ruleFilter = JComboBox(arrayOf(ALL_RULES))
    private val severityFilter = JComboBox(arrayOf("Any severity", "High and critical", "Critical only"))
    private var ruleFilterIds: List<String> = emptyList()
    private var matchesKey: List<Any?>? = null
    private var matchesById: Map<Long, AutorizeMatch> = emptyMap()
    private val matchesModel = SnapshotTableModel(
        arrayOf("#", "Time", "Rule", "Severity", "Method", "URL", "Status", "Replays", "Verdict"),
        mapOf(0 to SnapshotTableModel.LONG, 6 to SnapshotTableModel.INT),
    )
    private val matchesTable = JTable(matchesModel)
    private val resetSeenCheck = JCheckBox("Replay seen endpoints again")
    private val statusLabel = TintedLabel { RaijinTheme.muted() }

    // ── Detail: the verdict, and the captured original next to one identity's replay ─────────
    private val verdictArea = JTextArea(PLACEHOLDER)
    private val originalRequestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY)
    private val originalResponseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY)
    private val replayRequestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY)
    private val replayResponseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY)
    private val originalLabel = JLabel(ORIGINAL_TITLE)
    private val replayChooser = JComboBox<String>()
    private val replayStatus = TintedLabel { RaijinTheme.muted() }
    private val highlightField = JTextField(18)
    private var shownMatchId: Long? = null
    private var shownMatch: AutorizeMatch? = null
    // A rebuild clears and restores the selection; the detail must not flicker through "nothing selected".
    private var rebuildingMatches = false
    // Refilling the identity chooser fires selection events that are not the operator's choice.
    private var fillingReplayChooser = false

    init {
        rulesTable.fillsViewportHeight = true; rulesTable.rowHeight = 22; rulesTable.setShowGrid(false)
        rulesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        rulesTable.columnModel.apply {
            getColumn(0).apply { preferredWidth = 36; maxWidth = 44 }
            getColumn(1).apply { preferredWidth = 90; maxWidth = 130 }
            getColumn(2).preferredWidth = 200
            getColumn(3).preferredWidth = 320
            getColumn(4).apply { preferredWidth = 70; maxWidth = 90 }
            getColumn(5).apply { preferredWidth = 60; maxWidth = 80 }
            getColumn(6).apply { preferredWidth = 110; maxWidth = 130 }
        }
        rulesTable.toolTipText = "Tick On to tap proxy traffic with the rule. Double-click a rule to edit it."
        rulesTable.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                if (e.clickCount == 2 && rulesTable.columnAtPoint(e.point) != 0) editSelectedRule()
            }
        })

        matchesTable.fillsViewportHeight = true; matchesTable.rowHeight = 22; matchesTable.setShowGrid(false)
        matchesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        matchesTable.autoCreateRowSorter = true
        matchesTable.columnModel.apply {
            getColumn(0).apply { preferredWidth = 50; maxWidth = 70 }
            getColumn(1).apply { preferredWidth = 110; maxWidth = 130 }
            getColumn(2).apply { preferredWidth = 90; maxWidth = 130 }
            getColumn(3).apply { preferredWidth = 80; maxWidth = 100; cellRenderer = SeverityRenderer() }
            getColumn(4).apply { preferredWidth = 60; maxWidth = 80; cellRenderer = MethodRenderer() }
            getColumn(5).preferredWidth = 380
            getColumn(6).apply { preferredWidth = 55; maxWidth = 70; cellRenderer = StatusCodeRenderer() }
            getColumn(7).preferredWidth = 160
            getColumn(8).preferredWidth = 220
        }
        matchesTable.selectionModel.addListSelectionListener { e ->
            if (!e.valueIsAdjusting && !rebuildingMatches) showSelectedMatch()
        }
        matchesTable.addMouseListener(ContextMenuListener { row, e -> showMatchMenu(row, e) })

        verdictArea.isEditable = false; verdictArea.font = RaijinTheme.editorFont(11f)
        verdictArea.lineWrap = true; verdictArea.wrapStyleWord = true
        highlightField.toolTipText = "Text to highlight in the original and the replayed messages"
        highlightField.document.addDocumentListener(documentListener { applyHighlight() })
        replayChooser.toolTipText = "The identity whose replay is shown next to the original"
        replayChooser.addActionListener { if (!fillingReplayChooser) showReplay(shownMatch, replayChooser.selectedIndex) }

        ruleFilter.addActionListener { refreshMatches() }
        severityFilter.addActionListener { refreshMatches() }

        val toolbar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        toolbar.add(JButton("New Rule…").apply { addActionListener { newRule() } })
        toolbar.add(JButton("Edit…").apply { addActionListener { editSelectedRule() } })
        toolbar.add(JButton("Delete").apply { addActionListener { deleteSelectedRule() } })
        toolbar.add(Box.createHorizontalStrut(12))
        toolbar.add(JLabel("Show:")); toolbar.add(ruleFilter); toolbar.add(severityFilter)
        toolbar.add(Box.createHorizontalStrut(12))
        toolbar.add(JButton("Clear Matches").apply { addActionListener { clearMatches() } })
        toolbar.add(resetSeenCheck.apply {
            toolTipText = "Also forget which endpoints were already replayed, so they are replayed again"
        })
        toolbar.add(Box.createHorizontalStrut(12))
        toolbar.add(statusLabel)

        val rulesScroll = JScrollPane(rulesTable).apply { border = BorderFactory.createTitledBorder("Rules") }
        val matchesScroll = JScrollPane(matchesTable).apply { border = BorderFactory.createTitledBorder("Flagged matches") }

        val originalTabs = JTabbedPane(JTabbedPane.TOP).apply {
            addTab("Request", originalRequestEditor.uiComponent())
            addTab("Response", originalResponseEditor.uiComponent())
        }
        val replayTabs = JTabbedPane(JTabbedPane.TOP).apply {
            addTab("Request", replayRequestEditor.uiComponent())
            addTab("Response", replayResponseEditor.uiComponent())
        }
        // Both sides show the same part of the exchange, the responses first.
        originalTabs.addChangeListener { if (replayTabs.selectedIndex != originalTabs.selectedIndex) replayTabs.selectedIndex = originalTabs.selectedIndex }
        replayTabs.addChangeListener { if (originalTabs.selectedIndex != replayTabs.selectedIndex) originalTabs.selectedIndex = replayTabs.selectedIndex }
        originalTabs.selectedIndex = 1
        val originalSide = JPanel(BorderLayout()).apply {
            add(JPanel(FlowLayout(FlowLayout.LEFT, 6, 2)).apply { add(originalLabel) }, BorderLayout.NORTH)
            add(originalTabs, BorderLayout.CENTER)
        }
        val replaySide = JPanel(BorderLayout()).apply {
            add(JPanel(FlowLayout(FlowLayout.LEFT, 6, 2)).apply {
                add(JLabel("Replayed as:")); add(replayChooser); add(replayStatus)
            }, BorderLayout.NORTH)
            add(replayTabs, BorderLayout.CENTER)
        }
        val compare = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, originalSide, replaySide).apply { resizeWeight = 0.5; dividerSize = 5 }

        val detailTabs = JTabbedPane(JTabbedPane.TOP)
        detailTabs.addTab("Verdict", JScrollPane(verdictArea))
        detailTabs.addTab("Original vs replay", compare)
        val detail = JPanel(BorderLayout())
        detail.add(JPanel(FlowLayout(FlowLayout.LEFT, 6, 2)).apply {
            add(JLabel("Highlight:")); add(highlightField)
        }, BorderLayout.NORTH)
        detail.add(detailTabs, BorderLayout.CENTER)

        val lower = JSplitPane(JSplitPane.VERTICAL_SPLIT, matchesScroll, detail).apply { resizeWeight = 0.5; dividerSize = 5 }
        val split = JSplitPane(JSplitPane.VERTICAL_SPLIT, rulesScroll, lower).apply { resizeWeight = 0.25; dividerSize = 5 }
        add(toolbar, BorderLayout.NORTH)
        add(split, BorderLayout.CENTER)
        onEdt { refresh() }
    }

    /** Re-reads rules and matches; call on the EDT. */
    fun refresh() {
        refreshRules()
        refreshMatches()
    }

    private fun refreshRules() {
        val rules = stateManager.autorizeRules.toList()
        val matches = stateManager.autorizeMatches.toList()
        val counts = matches.groupingBy { it.ruleId }.eachCount()
        val rows = rules.map { r ->
            listOf<Any?>(
                r.enabled, r.ruleId, AutorizeRuleForm.identityNames(r), AutorizeRuleForm.filtersSummary(r),
                AutorizeRuleForm.percent(r.similarityThreshold), counts[r.ruleId] ?: 0, shortTime(r.createdAt),
            )
        }
        // An in-progress edit of the On box would be lost by a rebuild; the next tick catches up.
        if (rows != ruleRows && !rulesTable.isEditing) {
            val selected = selectedRuleId()
            ruleRows = rows
            rulesModel.rowCount = 0
            rows.forEach { rulesModel.addRow(it.toTypedArray()) }
            val row = (0 until rulesModel.rowCount).firstOrNull { rulesModel.getValueAt(it, 1) == selected }
            if (row != null) rulesTable.setRowSelectionInterval(row, row)
        }
        updateRuleFilter((rules.map { it.ruleId } + counts.keys).distinct().sorted())
        val softDenials = matches.count { it.softDenial }
        statusLabel.text = "Rules: ${rules.size} (${rules.count { it.enabled }} on) · Matches: ${matches.size}" +
            if (softDenials > 0) " ($softDenials soft denials)" else ""
    }

    private fun updateRuleFilter(ids: List<String>) {
        if (ids == ruleFilterIds) return
        ruleFilterIds = ids
        val selected = ruleFilter.selectedItem as? String
        ruleFilter.model = DefaultComboBoxModel((listOf(ALL_RULES) + ids).toTypedArray())
        ruleFilter.selectedItem = if (selected != null && selected in ids) selected else ALL_RULES
    }

    private fun refreshMatches() {
        val ruleId = currentRuleFilter()
        val minRank = when (severityFilter.selectedIndex) { 1 -> RANK_HIGH; 2 -> RANK_CRITICAL; else -> 0 }
        val all = stateManager.autorizeMatches
        val key = listOf(all.peekFirst()?.id, all.size, ruleId, minRank)
        if (key == matchesKey) return
        matchesKey = key
        val matches = all.filter { m -> (ruleId == null || m.ruleId == ruleId) && rank(topSeverity(m)) >= minRank }
        matchesById = matches.associateBy { it.id }
        val rows = matches.map { m ->
            listOf(
                m.id, shortTime(m.timestamp), m.ruleId, topSeverity(m).uppercase(), m.method, m.url,
                m.originalStatus.takeIf { it > 0 }, replaySummary(m), verdictSummary(m),
            )
        }
        rebuildingMatches = true
        try {
            matchesModel.update(rows, matchesTable)
        } finally {
            rebuildingMatches = false
        }
        showSelectedMatch()
    }

    private fun currentRuleFilter(): String? = (ruleFilter.selectedItem as? String)?.takeIf { it != ALL_RULES }

    private fun selectedRuleId(): String? {
        val row = rulesTable.selectedRow
        return if (row >= 0) rulesModel.getValueAt(row, 1) as? String else null
    }

    private fun selectedMatch(): AutorizeMatch? {
        val view = matchesTable.selectedRow
        if (view < 0) return null
        val id = matchesModel.getValueAt(matchesTable.convertRowIndexToModel(view), 0) as? Long ?: return null
        return matchesById[id]
    }

    private fun showSelectedMatch() {
        val match = selectedMatch()
        if (match?.id == shownMatchId) return
        shownMatchId = match?.id
        shownMatch = match
        fillReplayChooser(match)
        if (match == null) {
            verdictArea.text = PLACEHOLDER
            originalLabel.text = ORIGINAL_TITLE
            originalRequestEditor.clear()
            originalResponseEditor.clear()
            showReplay(null, -1)
            return
        }
        verdictArea.text = verdictText(match)
        verdictArea.caretPosition = 0
        originalLabel.text = "$ORIGINAL_TITLE: ${match.originalStatus}"
        originalRequestEditor.showRaw(match.request, match.url)
        originalResponseEditor.showRaw(match.response)
        showReplay(match, if (match.replays.isEmpty()) -1 else 0)
    }

    /** Lists [match]'s replayed identities in the chooser, the first one selected. */
    private fun fillReplayChooser(match: AutorizeMatch?) {
        fillingReplayChooser = true
        try {
            val names = match?.replays?.map { "${it.identity} (${it.status})" }.orEmpty()
            replayChooser.model = DefaultComboBoxModel(names.toTypedArray())
            replayChooser.isEnabled = names.size > 1
        } finally {
            fillingReplayChooser = false
        }
    }

    /** Shows what the identity at [index] of [match]'s replays sent and received. */
    private fun showReplay(match: AutorizeMatch?, index: Int) {
        val replay = match?.replays?.getOrNull(index)
        if (match == null || replay == null) {
            replayRequestEditor.clear()
            replayResponseEditor.clear()
            replayStatus.text = if (match == null) "" else "No replay stored with this match"
            return
        }
        replayStatus.text = "status ${replay.status}" +
            if (replay.status == match.originalStatus) ", as the original" else ", original ${match.originalStatus}"
        replayRequestEditor.showRaw(replay.request, match.url)
        replayResponseEditor.showRaw(replay.response)
        applyHighlight()
    }

    private fun applyHighlight() {
        val expression = highlightField.text
        try { originalRequestEditor.setSearchExpression(expression) } catch (_: Exception) {}
        try { originalResponseEditor.setSearchExpression(expression) } catch (_: Exception) {}
        try { replayRequestEditor.setSearchExpression(expression) } catch (_: Exception) {}
        try { replayResponseEditor.setSearchExpression(expression) } catch (_: Exception) {}
    }

    private fun verdictText(m: AutorizeMatch): String = buildString {
        val rule = stateManager.autorizeRules.firstOrNull { it.ruleId == m.ruleId }
        append("Rule: ${m.ruleId}")
        appendLine(rule?.let { "  ·  identities: ${AutorizeRuleForm.identityNames(it)}" } ?: "  (rule deleted)")
        appendLine("Request: ${m.method} ${m.url}")
        appendLine("Original (captured) response status: ${m.originalStatus}")
        if (m.replays.isNotEmpty()) {
            appendLine("Replayed as: " + m.replays.joinToString(", ") { "${it.identity} → ${it.status}" })
        }
        appendLine("Time: ${m.timestamp}")
        if (m.softDenial) {
            appendLine()
            appendLine(
                "Soft denial: an identity got a success status whose body reads as a refusal (a login page or a " +
                    "denial message), so the verdict is informational. Judged on status and body similarity alone it " +
                    "would be flagged: compare the responses to decide."
            )
        }
        for (finding in m.findings) {
            appendLine()
            appendLine("[${text(finding, "severity").uppercase()}] ${text(finding, "id")}")
            text(finding, "detail").takeIf { it.isNotEmpty() }?.let { appendLine(it) }
        }
        appendLine()
        append(
            if (m.replays.isEmpty()) "'Original vs replay' shows the captured original; no replay was stored with this match."
            else "'Original vs replay' shows the captured original next to what each identity sent and received."
        )
    }

    private fun showMatchMenu(viewRow: Int, e: MouseEvent) {
        val id = matchesModel.getValueAt(matchesTable.convertRowIndexToModel(viewRow), 0) as? Long ?: return
        val match = matchesById[id] ?: return
        val menu = JPopupMenu()
        menu.add(JMenuItem("Send Original to Repeater").apply {
            addActionListener { sendToRepeater(match, match.request, "Autorize-${match.ruleId}") }
        })
        match.replays.forEach { replay ->
            menu.add(JMenuItem("Send Replay as ${replay.identity} to Repeater").apply {
                addActionListener { sendToRepeater(match, replay.request, "Autorize-${match.ruleId}-${replay.identity}") }
            })
        }
        menu.add(JMenuItem("Copy URL").apply { addActionListener { copyToClipboard(match.url) } })
        menu.add(JMenuItem("Copy Verdict").apply { addActionListener { copyToClipboard(verdictText(match)) } })
        menu.show(e.component, e.x, e.y)
    }

    private fun sendToRepeater(match: AutorizeMatch, rawRequest: String, caption: String) {
        try {
            api.repeater().sendToRepeater(HttpRequest.httpRequest(HttpService.httpService(match.url), rawRequest), caption)
        } catch (ex: Exception) {
            api.logging().logToError("Raijin UI: Send to Repeater failed: ${ex.message}")
        }
    }

    // ── Rule editing ─────────────────────────────────────────────────────────

    private fun newRule() {
        val form = editRule("New Autorize Rule", AutorizeRuleForm.newRule()) ?: return
        save(null, form)
    }

    private fun editSelectedRule() {
        val id = selectedRuleId() ?: return
        val rule = stateManager.autorizeRules.firstOrNull { it.ruleId == id } ?: return
        val form = editRule("Edit Autorize Rule $id", AutorizeRuleForm.from(rule)) ?: return
        save(id, form)
    }

    private fun save(ruleId: String?, form: AutorizeRuleForm) {
        tasks.compute("Save Autorize rule", { form.save(autorize, stateManager, ruleId) }) { result ->
            reportError(result, "Save Autorize rule")
            refresh()
        }
    }

    private fun toggleRule(ruleId: String, enabled: Boolean) {
        tasks.compute("Update Autorize rule", {
            autorize.setRule(
                ruleId = ruleId, identities = null, inScopeOnly = null, includeHostPattern = null,
                excludeUrlRegex = null, methods = null, ignoreStaticAssets = null,
                similarityThreshold = null, enabled = enabled,
            )
        }) { result ->
            reportError(result, "Update Autorize rule")
            refresh()
        }
    }

    private fun deleteSelectedRule() {
        val id = selectedRuleId() ?: return
        val ok = JOptionPane.showConfirmDialog(
            this, "Delete Autorize rule $id? Its flagged matches stay listed.",
            "Delete Autorize Rule", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE
        )
        if (ok != JOptionPane.YES_OPTION) return
        tasks.compute("Delete Autorize rule", { autorize.removeRule(id) }) { result ->
            reportError(result, "Delete Autorize rule")
            refresh()
        }
    }

    private fun clearMatches() {
        val ruleId = currentRuleFilter()
        val resetSeen = resetSeenCheck.isSelected
        val ok = JOptionPane.showConfirmDialog(
            this,
            "Clear the flagged matches of ${ruleId?.let { "rule $it" } ?: "every rule"}?" +
                if (resetSeen) "\nEndpoints already replayed will be replayed again." else "",
            "Clear Matches", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE
        )
        if (ok != JOptionPane.YES_OPTION) return
        tasks.compute("Clear Autorize matches", { autorize.clearMatches(ruleId, resetSeen) }) { refresh() }
    }

    private fun reportError(result: JsonObject, context: String) {
        val error = (result["error"] as? JsonPrimitive)?.contentOrNull ?: return
        api.logging().logToError("Raijin UI: $context: $error")
        JOptionPane.showMessageDialog(this, error, "$context failed", JOptionPane.WARNING_MESSAGE)
    }

    /** Shows the rule editor until the input validates or the operator cancels. */
    private fun editRule(title: String, initial: AutorizeRuleForm): AutorizeRuleForm? {
        // The last column keeps the headers an identity set through MCP sends beyond the one shown; it is not displayed.
        val identityModel = DefaultTableModel(arrayOf("Name", "Header name", "Header value", "Remove headers", "Other headers"), 0)
        initial.identities.forEach {
            identityModel.addRow(arrayOf(it.name, it.headerName, it.headerValue, it.removeHeaders.joinToString(", "), it.otherHeaders))
        }
        val identityTable = JTable(identityModel).apply {
            rowHeight = 22
            putClientProperty("terminateEditOnFocusLost", true)
            preferredScrollableViewportSize = Dimension(660, 110)
            removeColumn(columnModel.getColumn(OTHER_HEADERS_COLUMN))
        }
        identityTable.columnModel.getColumn(3).headerValue = "Remove headers (comma-separated)"
        val addIdentity = JButton("Add").apply {
            addActionListener { identityModel.addRow(arrayOf("", "", "", "", emptyMap<String, String>())) }
        }
        val removeIdentity = JButton("Remove").apply {
            addActionListener {
                if (identityTable.isEditing) identityTable.cellEditor.stopCellEditing()
                identityTable.selectedRows.sortedDescending().forEach { identityModel.removeRow(identityTable.convertRowIndexToModel(it)) }
            }
        }
        val inScope = JCheckBox("In-scope requests only", initial.inScopeOnly)
        val ignoreStatic = JCheckBox("Skip static assets", initial.ignoreStaticAssets)
        val includeMutating = JCheckBox("Replay POST, PUT, DELETE and PATCH", initial.includeMutating).apply {
            toolTipText = "Off: state-changing requests are never replayed. On: each replay repeats the action once per identity."
        }
        val enabled = JCheckBox("Enabled", initial.enabled)
        val hostField = JTextField(initial.includeHostPattern.orEmpty(), 28).apply {
            toolTipText = "Glob such as *.example.com, or a regex. Blank: every host."
        }
        val excludeField = JTextField(initial.excludeUrlRegex.orEmpty(), 28).apply {
            toolTipText = "Requests whose URL matches this regex are not replayed (e.g. logout). Blank: none."
        }
        val methodsField = JTextField(initial.methods?.joinToString(", ").orEmpty(), 28).apply {
            toolTipText = "Comma-separated, e.g. GET, POST. Blank: every method (state-changing ones only with the box below)."
        }
        val threshold = JSpinner(SpinnerNumberModel(initial.similarityThreshold.coerceIn(0.0, 100.0), 0.0, 100.0, 1.0)).apply {
            toolTipText = "How similar (percent) a replayed response must be to the captured one to count as the same content"
        }
        val error = TintedLabel(" ") { RaijinTheme.error() }

        val form = JPanel(GridBagLayout())
        val c = GridBagConstraints().apply { insets = Insets(3, 4, 3, 4); anchor = GridBagConstraints.WEST; fill = GridBagConstraints.HORIZONTAL }
        var row = 0
        fun full(comp: JComponent) {
            c.gridy = row++; c.gridx = 0; c.gridwidth = 2; c.weightx = 1.0
            form.add(comp, c)
            c.gridwidth = 1
        }
        fun field(label: String, comp: JComponent) {
            c.gridy = row++; c.gridx = 0; c.weightx = 0.0
            form.add(JLabel(label), c)
            c.gridx = 1; c.weightx = 1.0
            form.add(comp, c)
        }
        full(JLabel("Identities, each replayed against the captured request:"))
        full(JScrollPane(identityTable))
        full(JPanel(FlowLayout(FlowLayout.LEFT, 4, 0)).apply { add(addIdentity); add(removeIdentity) })
        full(TintedLabel(
            "A header name and value replace that header; Remove headers drops headers. 'none', 'unauth' or " +
                "'anonymous' strip every credential header (Authorization, Cookie, X-API-Key, ...) and the headers " +
                "the other identities set. An identity that changes nothing is not replayed."
        ) { RaijinTheme.muted() })
        if (initial.identities.any { it.otherHeaders.isNotEmpty() }) {
            full(TintedLabel("Identities set through MCP send more headers than the table shows; they are kept.") { RaijinTheme.muted() })
        }
        field("Host pattern:", hostField)
        field("Exclude URL regex:", excludeField)
        field("Methods:", methodsField)
        field("Similarity threshold (%):", threshold)
        full(JPanel(FlowLayout(FlowLayout.LEFT, 0, 0)).apply { add(inScope); add(ignoreStatic); add(includeMutating); add(enabled) })
        full(error)

        while (true) {
            val choice = JOptionPane.showConfirmDialog(this, form, title, JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE)
            if (choice != JOptionPane.OK_OPTION) return null
            if (identityTable.isEditing) identityTable.cellEditor.stopCellEditing()
            try { threshold.commitEdit() } catch (_: java.text.ParseException) {}
            val identities = (0 until identityModel.rowCount)
                .map { r ->
                    fun cell(column: Int) = identityModel.getValueAt(r, column)?.toString()?.trim().orEmpty()
                    val other = (identityModel.getValueAt(r, OTHER_HEADERS_COLUMN) as? Map<*, *>)
                        ?.entries?.associate { (k, v) -> k.toString() to v.toString() }.orEmpty()
                    AutorizeIdentity(cell(0), cell(1), cell(2), AutorizeRuleForm.parseHeaderNames(cell(3)), other)
                }
                .filterNot {
                    it.name.isEmpty() && it.headerName.isEmpty() && it.headerValue.isEmpty() &&
                        it.removeHeaders.isEmpty() && it.otherHeaders.isEmpty()
                }
            val result = AutorizeRuleForm(
                identities = identities,
                inScopeOnly = inScope.isSelected,
                includeHostPattern = hostField.text.trim().ifEmpty { null },
                excludeUrlRegex = excludeField.text.trim().ifEmpty { null },
                methods = AutorizeRuleForm.parseMethods(methodsField.text),
                ignoreStaticAssets = ignoreStatic.isSelected,
                similarityThreshold = (threshold.value as? Number)?.toDouble() ?: initial.similarityThreshold,
                enabled = enabled.isSelected,
                includeMutating = includeMutating.isSelected,
            )
            error.text = result.validate() ?: return result
        }
    }

    private companion object {
        const val ALL_RULES = "All rules"
        const val PLACEHOLDER = "Select a flagged match to see the verdict, the captured original and what each identity received."
        const val ORIGINAL_TITLE = "Original (captured)"
        const val OTHER_HEADERS_COLUMN = 4
        const val RANK_HIGH = 2
        const val RANK_CRITICAL = 3
        val TIME_FORMAT: DateTimeFormatter = DateTimeFormatter.ofPattern("MM-dd HH:mm:ss")

        fun rank(severity: String): Int = when (severity.lowercase()) {
            "critical" -> RANK_CRITICAL
            "high" -> RANK_HIGH
            "info" -> 1
            else -> 0
        }

        fun text(finding: JsonObject, key: String): String = (finding[key] as? JsonPrimitive)?.contentOrNull.orEmpty()

        fun topSeverity(m: AutorizeMatch): String = m.findings.map { text(it, "severity") }.maxByOrNull(::rank).orEmpty()

        fun verdictIds(m: AutorizeMatch): String = m.findings.map { text(it, "id") }.filter { it.isNotEmpty() }.distinct().joinToString(", ")

        /** The Verdict column: the finding ids, marked when the match is a soft denial. */
        fun verdictSummary(m: AutorizeMatch): String = if (m.softDenial) "soft denial · ${verdictIds(m)}" else verdictIds(m)

        /** The Replays column: each replayed identity and the status it got. */
        fun replaySummary(m: AutorizeMatch): String = m.replays.joinToString(" · ") { "${it.identity} ${it.status}" }

        fun shortTime(iso: String): String = try {
            LocalDateTime.ofInstant(Instant.parse(iso), ZoneId.systemDefault()).format(TIME_FORMAT)
        } catch (_: Exception) {
            iso.takeLast(12)
        }
    }
}
