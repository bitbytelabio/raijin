package io.bitbytelab.raijin.turbo

import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse.SelectionContext
import java.awt.Component
import java.util.ArrayList
import javax.swing.JMenuItem
import kotlin.jvm.optionals.getOrNull

const val SCRIPT_MARKER = "--- Script ---"

fun extractScriptFromNotes(notes: String?): String? {
    if (notes.isNullOrBlank()) return null
    val idx = notes.lastIndexOf(SCRIPT_MARKER)
    if (idx < 0) return null
    val script = notes.substring(idx + SCRIPT_MARKER.length).trim()
    return script.ifBlank { null }
}

/** "Send to Raijin Turbo": opens the script dialog on the selected message (and text selection). */
class OfferTurboIntruder : ContextMenuItemsProvider {
    override fun provideMenuItems(event: ContextMenuEvent?): MutableList<Component> {
        if (event == null) return mutableListOf()
        val editor = event.messageEditorRequestResponse().getOrNull()
        val target: HttpRequestResponse
        var bounds = IntArray(0)
        if (editor != null) {
            target = editor.requestResponse()
            val offsets = editor.selectionOffsets().getOrNull()
            if (offsets != null && editor.selectionContext() == SelectionContext.REQUEST) {
                bounds = intArrayOf(offsets.startIndexInclusive(), offsets.endIndexExclusive())
            }
        } else {
            target = event.selectedRequestResponses().firstOrNull() ?: return mutableListOf()
        }
        val item = JMenuItem("Send to Raijin Turbo")
        item.addActionListener(TurboIntruderFrame(target, bounds, null, null, null))
        return mutableListOf(item)
    }
}

class BulkMenu(): ContextMenuItemsProvider {
    override fun provideMenuItems(event: ContextMenuEvent?): MutableList<Component> {
        if (event == null || event!!.selectedRequestResponses() === null || event!!.selectedRequestResponses().isEmpty()) {
            return mutableListOf();
        }
        val item = JMenuItem("Raijin Turbo (bulk)")
        item.addActionListener(TurboIntruderFrame(event.selectedRequestResponses()[0], IntArray(0), null, null, event.selectedRequestResponses()))
        return mutableListOf(item)
    }
}

class OfferTurboIntruderWithScript : ContextMenuItemsProvider {
    override fun provideMenuItems(event: ContextMenuEvent?): MutableList<Component> {
        if (event == null) return mutableListOf()
        val target = pickTarget(event) ?: return mutableListOf()
        val script = extractScriptFromNotes(target.annotations()?.notes()) ?: return mutableListOf()

        val item = JMenuItem("Send to Raijin Turbo (with script from notes)")
        item.addActionListener(TurboIntruderFrame(target, IntArray(0), script, null, null))
        return mutableListOf(item)
    }

    private fun pickTarget(event: ContextMenuEvent): HttpRequestResponse? {
        val editor = event.messageEditorRequestResponse().getOrNull()
        if (editor != null) return editor.requestResponse()
        val selected = event.selectedRequestResponses()
        if (selected != null && selected.isNotEmpty()) return selected[0]
        return null
    }
}