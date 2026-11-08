package io.bitbytelab.raijin.turbo

import java.awt.Component
import javax.swing.DefaultListCellRenderer
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JSeparator
import javax.swing.ListCellRenderer
import javax.swing.border.EmptyBorder

/** Script picker renderer: adds padding and renders separators as-is. */
internal class ComboBoxRenderer(padding: Int) : ListCellRenderer<Any?> {
    private val insetBorder = EmptyBorder(padding, padding, padding, padding)
    private val defaultRenderer = DefaultListCellRenderer()

    override fun getListCellRendererComponent(
        list: JList<out Any?>?, value: Any?, index: Int, isSelected: Boolean, cellHasFocus: Boolean
    ): Component {
        if (value is JSeparator) return value
        val renderer = defaultRenderer.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus) as JLabel
        renderer.border = insetBorder
        return renderer
    }
}
