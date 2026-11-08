package io.bitbytelab.raijin.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.ui.Theme
import java.awt.*
import javax.swing.*
import javax.swing.border.EmptyBorder

/**
 * Raijin's look follows Burp's: surfaces, text, borders and fonts come from Burp's own Look and
 * Feel (via [UIManager] and the Montoya theme API) and are read when a component paints, so
 * switching Burp between dark and light restyles the tab without a reload. Only the semantic
 * colours (success / warning / error / ...) are ours, in a dark and a light variant.
 */
object RaijinTheme {
    @Volatile private var api: MontoyaApi? = null

    fun init(api: MontoyaApi) { this.api = api }

    fun isDark(): Boolean = api?.userInterface()?.currentTheme()?.let { it == Theme.DARK }
        ?: (luminance(UIManager.getColor("Panel.background") ?: Color.WHITE) < 0.5)

    private fun luminance(c: Color) = (0.299 * c.red + 0.587 * c.green + 0.114 * c.blue) / 255.0

    // ── Surfaces (always Burp's) ───────────────────────────────────────────────
    fun background(): Color = UIManager.getColor("Panel.background") ?: Color(0x2B, 0x2B, 0x2B)
    fun foreground(): Color = UIManager.getColor("Label.foreground") ?: if (isDark()) Color(0xDF, 0xE1, 0xE5) else Color.BLACK
    fun muted(): Color = UIManager.getColor("Label.disabledForeground") ?: Color.GRAY
    fun border(): Color = UIManager.getColor("Component.borderColor") ?: UIManager.getColor("Separator.foreground") ?: Color.GRAY

    /** Burp's orange accent (selected-tab underline etc.). */
    fun accent(): Color = UIManager.getColor("Component.accentColor")
        ?: UIManager.getColor("TabbedPane.underlineColor")
        ?: Color(0xFF, 0x66, 0x33)

    // ── Semantic colours (dark / light variants) ───────────────────────────────
    fun success(): Color = if (isDark()) Color(0x3F, 0xB9, 0x50) else Color(0x1A, 0x7F, 0x37)
    fun warning(): Color = if (isDark()) Color(0xD2, 0x99, 0x22) else Color(0x9A, 0x67, 0x00)
    fun error(): Color = if (isDark()) Color(0xF8, 0x51, 0x49) else Color(0xCF, 0x22, 0x2E)
    fun info(): Color = if (isDark()) Color(0x58, 0xA6, 0xFF) else Color(0x09, 0x69, 0xDA)
    fun purple(): Color = if (isDark()) Color(0xBC, 0x8C, 0xFF) else Color(0x82, 0x50, 0xDF)
    fun critical(): Color = if (isDark()) Color(0xE5, 0x3E, 0x3E) else Color(0xA4, 0x0E, 0x26)

    // ── Fonts ──────────────────────────────────────────────────────────────────
    // Burp's display/editor fonts already carry CJK fallback (issue #17); only fall back to the
    // JDK logical names (which also do) when the API is unavailable.
    fun displayFont(size: Float? = null, style: Int = Font.PLAIN): Font {
        val base = api?.userInterface()?.currentDisplayFont() ?: Font("Dialog", Font.PLAIN, 12)
        return base.deriveFont(style, size ?: base.size2D)
    }

    fun editorFont(size: Float? = null): Font {
        val base = api?.userInterface()?.currentEditorFont() ?: Font("Monospaced", Font.PLAIN, 12)
        return base.deriveFont(size ?: base.size2D)
    }

    // ── Components ─────────────────────────────────────────────────────────────

    /** Flat header: logo, name, tagline and a version chip. No fills — it sits on Burp's panel colour. */
    fun brandHeader(version: String): JComponent {
        val header = JPanel(BorderLayout(10, 0))
        header.border = BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, border()),
            EmptyBorder(8, 12, 8, 12)
        )

        logo(32)?.let { header.add(JLabel(it), BorderLayout.WEST) }

        val text = JPanel().apply { isOpaque = false; layout = BoxLayout(this, BoxLayout.Y_AXIS) }
        text.add(JLabel("Raijin").apply {
            font = displayFont(18f, Font.BOLD); alignmentX = Component.LEFT_ALIGNMENT
        })
        text.add(JLabel("AI-driven MCP control and Turbo request engine for Burp Suite").apply {
            font = displayFont(11f); foreground = muted(); alignmentX = Component.LEFT_ALIGNMENT
        })
        header.add(text, BorderLayout.CENTER)

        header.add(JPanel(FlowLayout(FlowLayout.RIGHT, 6, 0)).apply {
            isOpaque = false
            add(chip("v$version"))
        }, BorderLayout.EAST)
        return header
    }

    fun logo(size: Int): Icon? {
        val file = when {
            size <= 16 -> "logo-16.png"; size <= 32 -> "logo-32.png"; else -> "logo-64.png"
        }
        val url = RaijinTheme::class.java.getResource("/raijin/$file") ?: return null
        return ImageIcon(url)
    }

    /** Section header: an accent bar and a bold label. */
    fun sectionHeader(text: String): JComponent {
        val p = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0)).apply { isOpaque = false }
        p.add(object : JPanel() {
            init { preferredSize = Dimension(4, 18); isOpaque = true }
            override fun getBackground(): Color = accent()
        })
        p.add(JLabel("  $text").apply { font = displayFont(13f, Font.BOLD) })
        return p
    }

    /** A small rounded pill outlined in the accent colour (a version or a count). */
    fun chip(text: String): JLabel {
        val l = object : JLabel(text, SwingConstants.CENTER) {
            override fun paintComponent(g: Graphics) {
                val g2 = g.create() as Graphics2D
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
                g2.color = accent()
                g2.drawRoundRect(0, 0, width - 1, height - 1, height, height)
                g2.dispose()
                super.paintComponent(g)
            }
        }
        l.font = displayFont(11f, Font.BOLD)
        l.border = EmptyBorder(3, 11, 3, 11)
        l.isOpaque = false
        return l
    }

    /**
     * Hands [c] to Burp's own theming (so request/response editors and our widgets all use the
     * current Look and Feel). Call again after Burp's theme changes.
     */
    fun apply(c: Component) {
        try { api?.userInterface()?.applyThemeToComponent(c) } catch (_: Exception) { /* never break the UI */ }
    }
}
