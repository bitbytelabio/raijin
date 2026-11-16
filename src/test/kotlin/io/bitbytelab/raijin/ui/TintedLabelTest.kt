package io.bitbytelab.raijin.ui

import java.awt.Color
import javax.swing.JLabel
import kotlin.test.Test
import kotlin.test.assertEquals

class TintedLabelTest {

    @Test
    fun `the colour is looked up on every paint, so a theme switch recolours the label`() {
        var themeColour = Color(0x3F, 0xB9, 0x50) // dark-theme success
        val label = TintedLabel("Saved: ON") { themeColour }
        assertEquals(themeColour, label.foreground)

        themeColour = Color(0x1A, 0x7F, 0x37) // light-theme success
        assertEquals(Color(0x1A, 0x7F, 0x37), label.foreground)
    }

    @Test
    fun `without a tint the label keeps the look and feel colour`() {
        val plain = JLabel("x")
        assertEquals(plain.foreground, TintedLabel("x").foreground)
        assertEquals(plain.foreground, TintedLabel("x") { null }.foreground)
    }

    @Test
    fun `the tint can change after construction`() {
        val label = TintedLabel("status")
        label.tint = { Color.RED }
        assertEquals(Color.RED, label.foreground)
    }
}
