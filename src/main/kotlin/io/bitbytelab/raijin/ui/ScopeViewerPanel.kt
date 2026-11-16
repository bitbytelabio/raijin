package io.bitbytelab.raijin.ui

import io.bitbytelab.raijin.bridge.ScopeBridge
import io.bitbytelab.raijin.events.EventBus
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.awt.event.HierarchyEvent
import javax.swing.JButton
import javax.swing.JMenuItem
import javax.swing.JPanel
import javax.swing.JPopupMenu
import javax.swing.JScrollPane
import javax.swing.JTable
import javax.swing.ListSelectionModel

/**
 * Read-only view of Burp's target scope: the include and exclude lists of `target.scope`. Loads the
 * first time it is shown, then again on every scope change Burp reports.
 */
internal class ScopeViewerPanel(
    private val scope: ScopeBridge,
    private val eventBus: EventBus,
    private val tasks: UiTasks,
) : JPanel(BorderLayout()) {
    private val model = SnapshotTableModel(
        arrayOf("List", "#", "Enabled", "Rule"),
        mapOf(1 to SnapshotTableModel.INT, 2 to SnapshotTableModel.BOOLEAN),
    )
    private val table = JTable(model)
    private val status = TintedLabel(" ") { RaijinTheme.muted() }
    private var loadedOnce = false
    private val subscription: String

    init {
        table.fillsViewportHeight = true; table.rowHeight = 22; table.setShowGrid(false)
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        table.columnModel.getColumn(0).apply { preferredWidth = 70; maxWidth = 90 }
        table.columnModel.getColumn(1).apply { preferredWidth = 40; maxWidth = 60 }
        table.columnModel.getColumn(2).apply { preferredWidth = 60; maxWidth = 80 }
        table.columnModel.getColumn(3).preferredWidth = 600
        table.addMouseListener(ContextMenuListener { row, e ->
            val rule = model.getValueAt(row, 3)?.toString() ?: return@ContextMenuListener
            JPopupMenu().apply {
                add(JMenuItem("Copy Rule").apply { addActionListener { copyToClipboard(rule) } })
            }.show(e.component, e.x, e.y)
        })

        val bar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        bar.add(JButton("Refresh").apply { addActionListener { load() } })
        bar.add(status)
        add(bar, BorderLayout.NORTH)
        add(JScrollPane(table), BorderLayout.CENTER)

        addHierarchyListener { e ->
            if (e.changeFlags and HierarchyEvent.SHOWING_CHANGED.toLong() != 0L && isShowing && !loadedOnce) load()
        }
        subscription = eventBus.subscribeInternal(listOf("scope.changed")) { onEdt { if (loadedOnce) load() } }
    }

    fun load() {
        loadedOnce = true
        status.text = "Loading…"
        status.tint = { RaijinTheme.muted() }
        tasks.compute("Load target scope", { scope.list() }) { result -> render(result) }
    }

    fun dispose() = eventBus.unsubscribe(subscription)

    private fun render(result: JsonObject) {
        val error = (result["error"] as? JsonPrimitive)?.contentOrNull
        if (error != null) {
            status.text = error
            status.tint = { RaijinTheme.error() }
            return
        }
        val rows = rowsOf(result)
        model.update(rows, table)
        val included = rows.count { it[0] == INCLUDE }
        status.text = "Include rules: $included · Exclude rules: ${rows.size - included}"
        status.tint = { RaijinTheme.muted() }
    }

    companion object {
        private const val INCLUDE = "Include"

        /** Table rows for [ScopeBridge.list]'s `include` and `exclude` arrays. */
        fun rowsOf(list: JsonObject): List<List<Any?>> = buildList {
            for ((key, label) in listOf("include" to INCLUDE, "exclude" to "Exclude")) {
                val rules = list[key] as? JsonArray ?: continue
                for (element in rules) {
                    val rule = element as? JsonObject ?: continue
                    add(
                        listOf(
                            label,
                            (rule["index"] as? JsonPrimitive)?.intOrNull,
                            (rule["enabled"] as? JsonPrimitive)?.booleanOrNull ?: true,
                            ruleText(rule),
                        )
                    )
                }
            }
        }

        /** A simple-mode rule is a URL `prefix`; an advanced-mode rule a set of protocol/host/port/file patterns. */
        fun ruleText(rule: JsonObject): String {
            fun text(key: String) = (rule[key] as? JsonPrimitive)?.contentOrNull?.ifBlank { null }
            text("prefix")?.let { prefix ->
                val subdomains = (rule["include_subdomains"] as? JsonPrimitive)?.booleanOrNull == true
                return if (subdomains) "$prefix (and subdomains)" else prefix
            }
            return listOf("protocol", "host", "port", "file")
                .mapNotNull { key -> text(key)?.let { "$key $it" } }
                .joinToString(" · ")
                .ifEmpty { "(any)" }
        }
    }
}
