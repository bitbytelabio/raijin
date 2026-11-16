package io.bitbytelab.raijin.ui

import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.ui.editor.HttpRequestEditor
import burp.api.montoya.ui.editor.HttpResponseEditor
import java.awt.Component
import java.awt.Font
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.ComboBoxEditor
import javax.swing.JComboBox
import javax.swing.JTable
import javax.swing.SwingUtilities
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.table.DefaultTableCellRenderer
import javax.swing.text.JTextComponent

// Shared Swing helpers for the Raijin tab and its panels.

internal fun copyToClipboard(text: String) {
    Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(text), null)
}

/** Runs [block] now when on the EDT, else posts it there. */
internal fun onEdt(block: () -> Unit) {
    if (SwingUtilities.isEventDispatchThread()) block() else SwingUtilities.invokeLater(block)
}

/** Empties a viewer so it never keeps showing the previously selected row's message. */
internal fun HttpRequestEditor.clear() {
    try { request = HttpRequest.httpRequest() } catch (_: Exception) {}
}

internal fun HttpResponseEditor.clear() {
    try { response = HttpResponse.httpResponse() } catch (_: Exception) {}
}

/** Shows a request captured as raw text, with [url]'s service when it parses; empties the viewer for blank text. */
internal fun HttpRequestEditor.showRaw(raw: String, url: String) {
    if (raw.isEmpty()) return clear()
    try {
        request = try {
            HttpRequest.httpRequest(HttpService.httpService(url), raw)
        } catch (_: Exception) {
            HttpRequest.httpRequest(raw)
        }
    } catch (_: Exception) {
        clear()
    }
}

internal fun HttpResponseEditor.showRaw(raw: String) {
    if (raw.isEmpty()) return clear()
    try { response = HttpResponse.httpResponse(raw) } catch (_: Exception) { clear() }
}

internal fun documentListener(onChange: () -> Unit): DocumentListener = object : DocumentListener {
    override fun insertUpdate(e: DocumentEvent) = onChange()
    override fun removeUpdate(e: DocumentEvent) = onChange()
    override fun changedUpdate(e: DocumentEvent) = onChange()
}

/** The text in an editable combo's editor (what the operator typed), or the selected item. */
internal fun JComboBox<*>.editorText(): String =
    ((editor?.editorComponent as? JTextComponent)?.text ?: selectedItem?.toString()).orEmpty()

/**
 * Calls [onChange] on every keystroke in an editable combo. A theme switch installs a new editor
 * component, so the listener follows the `editor` property instead of staying on the first one.
 */
internal fun JComboBox<*>.onEditorTextChange(onChange: () -> Unit) {
    val listener = documentListener(onChange)
    fun textOf(e: ComboBoxEditor?) = e?.editorComponent as? JTextComponent
    textOf(editor)?.document?.addDocumentListener(listener)
    addPropertyChangeListener("editor") { e ->
        textOf(e.oldValue as? ComboBoxEditor)?.document?.removeDocumentListener(listener)
        textOf(e.newValue as? ComboBoxEditor)?.document?.addDocumentListener(listener)
    }
}

/** Right-click handler: selects the row under the pointer and passes its view index on. */
internal class ContextMenuListener(private val handler: (Int, MouseEvent) -> Unit) : MouseAdapter() {
    override fun mousePressed(e: MouseEvent) = check(e)
    override fun mouseReleased(e: MouseEvent) = check(e)
    private fun check(e: MouseEvent) {
        if (e.isPopupTrigger) {
            val table = e.component as JTable
            val row = table.rowAtPoint(e.point)
            if (row >= 0) { table.setRowSelectionInterval(row, row); handler(row, e) }
        }
    }
}

internal class MethodRenderer : DefaultTableCellRenderer() {
    init { horizontalAlignment = CENTER }
    override fun getTableCellRendererComponent(t: JTable, v: Any?, s: Boolean, f: Boolean, r: Int, c: Int): Component {
        val comp = super.getTableCellRendererComponent(t, v, s, f, r, c)
        if (!s) foreground = when (v?.toString()) {
            "GET" -> RaijinTheme.success(); "POST" -> RaijinTheme.info()
            "PUT" -> RaijinTheme.warning(); "DELETE" -> RaijinTheme.error()
            "PATCH" -> RaijinTheme.purple(); else -> RaijinTheme.muted()
        }
        return comp
    }
}

internal class StatusCodeRenderer : DefaultTableCellRenderer() {
    init { horizontalAlignment = CENTER }
    override fun getTableCellRendererComponent(t: JTable, v: Any?, s: Boolean, f: Boolean, r: Int, c: Int): Component {
        val comp = super.getTableCellRendererComponent(t, v, s, f, r, c)
        if (!s && v != null) {
            val code = (v as? Int) ?: 0
            foreground = when { code in 200..299 -> RaijinTheme.success(); code in 300..399 -> RaijinTheme.info(); code in 400..499 -> RaijinTheme.warning(); code >= 500 -> RaijinTheme.error(); else -> RaijinTheme.muted() }
        }
        return comp
    }
}

internal class SeverityRenderer : DefaultTableCellRenderer() {
    init { horizontalAlignment = CENTER }
    override fun getTableCellRendererComponent(t: JTable, v: Any?, s: Boolean, f: Boolean, r: Int, c: Int): Component {
        val comp = super.getTableCellRendererComponent(t, v, s, f, r, c)
        if (!s) foreground = when (v?.toString()?.uppercase()) {
            "CRITICAL" -> RaijinTheme.critical()
            "HIGH" -> RaijinTheme.error(); "MEDIUM" -> RaijinTheme.warning()
            "LOW" -> RaijinTheme.info()
            "INFORMATION", "INFO" -> RaijinTheme.muted()
            else -> t.foreground
        }
        font = font.deriveFont(Font.BOLD)
        return comp
    }
}
