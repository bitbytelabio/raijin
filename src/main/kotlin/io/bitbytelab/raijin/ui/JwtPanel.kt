package io.bitbytelab.raijin.ui

import io.bitbytelab.raijin.bridge.JwtBridge
import kotlinx.serialization.json.*
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTabbedPane
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.SwingUtilities
import javax.swing.border.EmptyBorder

/**
 * The JWT tab: decode/analyze a token, sign it, run the `jwt_attack` attack modes, and manage
 * the key ring — a thin Swing wrapper over [JwtBridge], calling it directly (no MCP round-trip,
 * mirroring how [TurboRunsPanel] and the Collaborator tab in [RaijinTab] work). Every action's
 * raw JSON result is pretty-printed into the shared output pane at the bottom rather than a
 * narrower, hand-picked summary, so nothing the bridge reports is hidden.
 *
 * [JwtBridge] does no Montoya/network I/O (pure in-memory JOSE/crypto), so every action here
 * runs synchronously on the EDT — no background worker thread is needed.
 */
class JwtPanel(private val bridge: JwtBridge) : JPanel(BorderLayout(0, 4)) {

    private val prettyJson = Json { prettyPrint = true; prettyPrintIndent = "  " }

    private val tokenField = JTextArea(3, 60).apply {
        lineWrap = true; wrapStyleWord = true; font = RaijinTheme.editorFont(11f)
    }

    private val output = JTextArea(10, 60).apply {
        isEditable = false
        font = RaijinTheme.editorFont(11f)
        lineWrap = true
        wrapStyleWord = true
        text = "Results appear here."
    }

    private val keyRingModel = object : javax.swing.table.AbstractTableModel() {
        private val columns = arrayOf("Key id", "kty", "alg", "crv", "Public only")
        var rows: List<JsonObject> = emptyList()
        override fun getRowCount() = rows.size
        override fun getColumnCount() = columns.size
        override fun getColumnName(c: Int) = columns[c]
        override fun getValueAt(r: Int, c: Int): Any {
            val row = rows[r]
            return when (c) {
                0 -> row["key_id"]?.jsonPrimitive?.contentOrNullSafe() ?: ""
                1 -> row["kty"]?.jsonPrimitive?.contentOrNullSafe() ?: ""
                2 -> row["alg"]?.jsonPrimitive?.contentOrNullSafe() ?: ""
                3 -> row["crv"]?.jsonPrimitive?.contentOrNullSafe() ?: ""
                else -> row["public_only"]?.toString() ?: ""
            }
        }
    }
    private val keyRingTable = javax.swing.JTable(keyRingModel).apply { rowHeight = 20; fillsViewportHeight = true }

    private fun show(result: JsonObject) {
        output.text = try {
            prettyJson.encodeToString(JsonObject.serializer(), result)
        } catch (_: Exception) {
            result.toString()
        }
        output.caretPosition = 0
        output.foreground = if (result["error"] != null) RaijinTheme.error() else RaijinTheme.foreground()
    }

    private fun runAttack(
        mode: String,
        secret: String? = null,
        publicKey: String? = null,
        wordlist: List<String>? = null,
        overridesText: String? = null,
        alg: String? = null,
        keyId: String? = null,
        enc: String? = null,
        header: String? = null,
        url: String? = null,
    ) {
        val token = tokenField.text.trim()
        if (token.isEmpty()) {
            show(kotlinx.serialization.json.buildJsonObject { put("error", "Paste a token first") })
            return
        }
        val overrides = overridesText?.trim()?.takeIf { it.isNotEmpty() }?.let {
            try { Json.parseToJsonElement(it) as? JsonObject } catch (_: Exception) { null }
        }
        val result = bridge.attack(
            token = token, mode = mode, secret = secret, publicKey = publicKey, wordlist = wordlist,
            overrides = overrides, alg = alg, keyId = keyId, enc = enc, header = header, url = url
        )
        show(result)
    }

    private fun refreshKeyRing() {
        val result = bridge.keys(action = "list")
        val keys = result["keys"]?.let { el -> (el as? kotlinx.serialization.json.JsonArray)?.mapNotNull { it as? JsonObject } } ?: emptyList()
        keyRingModel.rows = keys
        keyRingModel.fireTableDataChanged()
    }

    private val ringCombos = mutableListOf<JComboBox<String>>()

    /** A key_id dropdown kept in sync with the ring: refreshed now, and again by
     *  [refreshKeyRingCombos] whenever the Key Ring tab generates/imports/deletes a key. */
    private fun keyIdCombo(): JComboBox<String> {
        val combo = JComboBox<String>()
        refreshComboFromRing(combo)
        ringCombos.add(combo)
        return combo
    }

    private fun refreshKeyRingCombos() { ringCombos.forEach { refreshComboFromRing(it) } }

    private fun refreshComboFromRing(combo: JComboBox<String>) {
        val result = bridge.keys(action = "list")
        val keys = result["keys"]?.let { el -> (el as? kotlinx.serialization.json.JsonArray)?.mapNotNull { it as? JsonObject } } ?: emptyList()
        combo.removeAllItems()
        combo.addItem("")
        keys.forEach { k -> k["key_id"]?.jsonPrimitive?.contentOrNullSafe()?.let { combo.addItem(it) } }
    }

    init {
        border = EmptyBorder(8, 8, 8, 8)

        val tokenPanel = JPanel(BorderLayout(4, 2))
        tokenPanel.border = BorderFactory.createTitledBorder("Token")
        tokenPanel.add(JScrollPane(tokenField), BorderLayout.CENTER)
        val tokenHint = JLabel("  Shared by every sub-tab below. Attack/sign modes replace this with their forged result when you copy it back in.")
        tokenHint.font = RaijinTheme.displayFont(10f)
        tokenHint.foreground = RaijinTheme.muted()
        tokenPanel.add(tokenHint, BorderLayout.SOUTH)

        val tabs = JTabbedPane(JTabbedPane.TOP)
        tabs.addTab("Decode", buildDecodeTab())
        tabs.addTab("Sign", buildSignTab())
        tabs.addTab("Attacks", buildAttacksTab())
        tabs.addTab("Key Ring", buildKeyRingTab())

        val outputPanel = JPanel(BorderLayout())
        outputPanel.border = BorderFactory.createTitledBorder("Result")
        outputPanel.add(JScrollPane(output), BorderLayout.CENTER)
        val copyBtn = JButton("Copy token from result").apply {
            toolTipText = "Copies the 'token' field of the last result into the Token box above"
            addActionListener {
                val text = output.text
                try {
                    val obj = Json.parseToJsonElement(text) as? JsonObject
                    val t = obj?.get("token")?.jsonPrimitive?.contentOrNullSafe()
                    if (t != null) tokenField.text = t
                } catch (_: Exception) { }
            }
        }
        val outputBar = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2)).apply { add(copyBtn) }
        outputPanel.add(outputBar, BorderLayout.SOUTH)

        val split = JSplitPane(JSplitPane.VERTICAL_SPLIT, tabs, outputPanel)
        split.resizeWeight = 0.6
        split.dividerSize = 5

        add(tokenPanel, BorderLayout.NORTH)
        add(split, BorderLayout.CENTER)
    }

    // ---------------------------------------------------------------
    // Decode
    // ---------------------------------------------------------------
    private fun buildDecodeTab(): JPanel {
        val panel = JPanel(BorderLayout())
        val analyzeBtn = JButton("Analyze").apply {
            toolTipText = "Decode header/payload and flag alg:none, HMAC, asymmetric alg, kid/jku, missing exp"
            addActionListener { runAttack(mode = "analyze") }
        }
        val verifyBtn = JButton("Verify against every ring key").apply {
            addActionListener { runAttack(mode = "verify") }
        }
        val bar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 6)).apply { add(analyzeBtn); add(verifyBtn) }
        panel.add(bar, BorderLayout.NORTH)
        return panel
    }

    // ---------------------------------------------------------------
    // Sign
    // ---------------------------------------------------------------
    private fun buildSignTab(): JPanel {
        val panel = JPanel(GridBagLayout())
        val gbc = GridBagConstraints().apply { insets = Insets(4, 6, 4, 6); anchor = GridBagConstraints.WEST }

        val secretField = JTextField(24)
        val keyCombo = keyIdCombo()
        val refreshBtn = JButton("↻").apply { toolTipText = "Refresh key list"; addActionListener { refreshComboFromRing(keyCombo) } }
        val algField = JTextField(10)
        val overridesField = JTextField(30).apply { toolTipText = """Claims to override, e.g. {"sub":"admin"}""" }

        var row = 0
        gbc.gridy = row++; gbc.gridx = 0; panel.add(JLabel("HMAC secret:"), gbc)
        gbc.gridx = 1; gbc.gridwidth = 2; panel.add(secretField, gbc); gbc.gridwidth = 1
        val signSecretBtn = JButton("Sign with secret").apply {
            addActionListener { runAttack(mode = "sign", secret = secretField.text.ifBlank { null }, alg = algField.text.ifBlank { null }, overridesText = overridesField.text) }
        }
        gbc.gridx = 3; panel.add(signSecretBtn, gbc)

        gbc.gridy = row++; gbc.gridx = 0; panel.add(JLabel("Key ring id:"), gbc)
        gbc.gridx = 1; panel.add(keyCombo, gbc)
        gbc.gridx = 2; panel.add(refreshBtn, gbc)
        val signKeyBtn = JButton("Sign with key").apply {
            addActionListener {
                val id = keyCombo.selectedItem as? String
                if (id.isNullOrBlank()) return@addActionListener
                runAttack(mode = "sign_key", keyId = id, alg = algField.text.ifBlank { null }, overridesText = overridesField.text)
            }
        }
        gbc.gridx = 3; panel.add(signKeyBtn, gbc)

        gbc.gridy = row++; gbc.gridx = 0; panel.add(JLabel("alg (optional):"), gbc)
        gbc.gridx = 1; panel.add(algField, gbc)

        gbc.gridy = row++; gbc.gridx = 0; panel.add(JLabel("payload_overrides:"), gbc)
        gbc.gridx = 1; gbc.gridwidth = 3; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0
        panel.add(overridesField, gbc)

        return panel
    }

    // ---------------------------------------------------------------
    // Attacks
    // ---------------------------------------------------------------
    private fun buildAttacksTab(): JPanel {
        val panel = JPanel(GridBagLayout())
        val gbc = GridBagConstraints().apply { insets = Insets(4, 6, 4, 6); anchor = GridBagConstraints.WEST }

        val publicKeyArea = JTextArea(3, 28).apply { lineWrap = true; wrapStyleWord = true }
        val keyCombo = keyIdCombo()
        val refreshBtn = JButton("↻").apply { addActionListener { refreshComboFromRing(keyCombo) } }
        val wordlistField = JTextField(24).apply { toolTipText = "Comma-separated candidate secrets; blank = built-in list" }
        val headerCombo = JComboBox(arrayOf("jku", "x5u"))
        val urlField = JTextField(24)
        val overridesField = JTextField(24)

        var row = 0
        gbc.gridy = row; gbc.gridx = 0; panel.add(JLabel("public_key (PEM or JWK JSON):"), gbc)
        gbc.gridx = 1; gbc.gridwidth = 2; panel.add(JScrollPane(publicKeyArea), gbc); gbc.gridwidth = 1
        row++

        gbc.gridy = row; gbc.gridx = 0; panel.add(JLabel("...or key_id:"), gbc)
        gbc.gridx = 1; panel.add(keyCombo, gbc)
        gbc.gridx = 2; panel.add(refreshBtn, gbc)
        val algConfusionBtn = JButton("alg_confusion").apply {
            toolTipText = "RS->HS confusion: sign with the server's public key as the HMAC secret"
            addActionListener {
                val id = keyCombo.selectedItem as? String
                runAttack(mode = "alg_confusion", publicKey = publicKeyArea.text.ifBlank { null }, keyId = id?.ifBlank { null })
            }
        }
        gbc.gridx = 3; panel.add(algConfusionBtn, gbc)
        row++

        gbc.gridy = row; gbc.gridx = 0; panel.add(JLabel("wordlist:"), gbc)
        gbc.gridx = 1; panel.add(wordlistField, gbc)
        val crackBtn = JButton("crack").apply {
            toolTipText = "Recover the HMAC secret by brute force"
            addActionListener {
                val list = wordlistField.text.split(",").map { it.trim() }.filter { it.isNotEmpty() }.takeIf { it.isNotEmpty() }
                runAttack(mode = "crack", wordlist = list)
            }
        }
        gbc.gridx = 3; panel.add(crackBtn, gbc)
        row++

        gbc.gridy = row; gbc.gridx = 0; panel.add(JLabel("header_url: header"), gbc)
        gbc.gridx = 1; panel.add(headerCombo, gbc)
        row++
        gbc.gridy = row; gbc.gridx = 0; panel.add(JLabel("url"), gbc)
        gbc.gridx = 1; panel.add(urlField, gbc)
        val headerUrlBtn = JButton("header_url").apply {
            toolTipText = "Set jku/x5u to a URL you control, for a JWKS-fetch SSRF/forgery check"
            addActionListener { runAttack(mode = "header_url", header = headerCombo.selectedItem as? String, url = urlField.text.ifBlank { null }) }
        }
        gbc.gridx = 3; panel.add(headerUrlBtn, gbc)
        row++

        gbc.gridy = row; gbc.gridx = 0; panel.add(JLabel("payload_overrides:"), gbc)
        gbc.gridx = 1; gbc.gridwidth = 2; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0
        panel.add(overridesField, gbc); gbc.gridwidth = 1; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0.0
        row++

        gbc.gridy = row; gbc.gridx = 0; gbc.gridwidth = 4
        val quickBar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        quickBar.add(JButton("forge_none").apply {
            toolTipText = "Unsigned token variants (alg:none, case permutations)"
            addActionListener { runAttack(mode = "forge_none", overridesText = overridesField.text) }
        })
        quickBar.add(JButton("embed_jwk").apply {
            toolTipText = "Sign and embed the public JWK in the header (needs key_id above)"
            addActionListener {
                val id = keyCombo.selectedItem as? String
                runAttack(mode = "embed_jwk", keyId = id?.ifBlank { null }, overridesText = overridesField.text)
            }
        })
        quickBar.add(JButton("empty_hmac").apply {
            addActionListener { runAttack(mode = "empty_hmac", overridesText = overridesField.text) }
        })
        quickBar.add(JButton("psychic").apply {
            toolTipText = "ES256/ES384/ES512 token with a zero ECDSA signature (CVE-2022-21449-style)"
            addActionListener { runAttack(mode = "psychic", overridesText = overridesField.text) }
        })
        panel.add(quickBar, gbc)

        return panel
    }

    // ---------------------------------------------------------------
    // Key ring
    // ---------------------------------------------------------------
    private fun buildKeyRingTab(): JPanel {
        val panel = JPanel(BorderLayout(0, 4))

        val tableScroll = JScrollPane(keyRingTable)
        tableScroll.border = BorderFactory.createTitledBorder("Keys")

        val genKtyCombo = JComboBox(arrayOf("RSA", "EC", "OKP", "oct", "password"))
        val genSizeOrCrvField = JTextField(8).apply { toolTipText = "RSA bits / oct bits, or EC/OKP curve name (e.g. P-256, Ed25519)" }
        val genIdField = JTextField(10)
        val genBtn = JButton("Generate").apply {
            addActionListener {
                val kty = genKtyCombo.selectedItem as String
                val sizeOrCrv = genSizeOrCrvField.text.trim()
                val size = sizeOrCrv.toIntOrNull()
                val crv = if (size == null) sizeOrCrv.ifBlank { null } else null
                val id = genIdField.text.ifBlank { null }
                val result = bridge.keys(action = "generate", kty = kty, size = size, crv = crv, keyId = id)
                show(result)
                refreshKeyRing(); refreshKeyRingCombos()
            }
        }
        val genBar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4)).apply {
            border = BorderFactory.createTitledBorder("Generate")
            add(JLabel("kty:")); add(genKtyCombo)
            add(JLabel("size/crv:")); add(genSizeOrCrvField)
            add(JLabel("key_id:")); add(genIdField)
            add(genBtn)
        }

        val importArea = JTextArea(4, 50).apply { lineWrap = true; wrapStyleWord = true; toolTipText = "PEM text or JWK/JWK-set JSON" }
        val importBtn = JButton("Import").apply {
            addActionListener {
                val text = importArea.text.trim()
                if (text.isEmpty()) return@addActionListener
                val looksJwk = text.startsWith("{")
                val result = bridge.keys(action = "import", pem = if (!looksJwk) text else null, jwk = if (looksJwk) text else null)
                show(result)
                refreshKeyRing(); refreshKeyRingCombos()
            }
        }
        val importPanel = JPanel(BorderLayout(4, 4))
        importPanel.border = BorderFactory.createTitledBorder("Import (PEM or JWK JSON)")
        importPanel.add(JScrollPane(importArea), BorderLayout.CENTER)
        importPanel.add(importBtn, BorderLayout.EAST)

        val exportFormatCombo = JComboBox(arrayOf("jwk", "pem"))
        val exportPrivateCheck = javax.swing.JCheckBox("include private")
        val exportBtn = JButton("Export selected").apply {
            addActionListener {
                val id = selectedKeyId() ?: return@addActionListener
                show(bridge.keys(action = "export", keyId = id, format = exportFormatCombo.selectedItem as String, includePrivate = exportPrivateCheck.isSelected))
            }
        }
        val deleteBtn = JButton("Delete selected").apply {
            addActionListener {
                val id = selectedKeyId() ?: return@addActionListener
                show(bridge.keys(action = "delete", keyId = id))
                refreshKeyRing(); refreshKeyRingCombos()
            }
        }
        val rowBar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4)).apply {
            add(JLabel("format:")); add(exportFormatCombo); add(exportPrivateCheck); add(exportBtn); add(deleteBtn)
        }

        val bottom = JPanel(BorderLayout())
        bottom.add(genBar, BorderLayout.NORTH)
        bottom.add(importPanel, BorderLayout.CENTER)
        bottom.add(rowBar, BorderLayout.SOUTH)

        panel.add(tableScroll, BorderLayout.CENTER)
        panel.add(bottom, BorderLayout.SOUTH)

        SwingUtilities.invokeLater { refreshKeyRing() }
        return panel
    }

    private fun selectedKeyId(): String? {
        val row = keyRingTable.selectedRow
        if (row < 0) return null
        return keyRingModel.rows.getOrNull(keyRingTable.convertRowIndexToModel(row))
            ?.get("key_id")?.jsonPrimitive?.contentOrNullSafe()
    }
}

/** Null-safe [kotlinx.serialization.json.JsonPrimitive.content] — avoids throwing on JsonNull. */
private fun kotlinx.serialization.json.JsonPrimitive.contentOrNullSafe(): String? =
    if (this is kotlinx.serialization.json.JsonNull) null else content
