package io.bitbytelab.raijin.ui

import io.bitbytelab.raijin.bridge.JwtBridge
import io.bitbytelab.raijin.jwt.Jwt
import kotlinx.serialization.json.*
import java.awt.BorderLayout
import java.awt.Color
import java.awt.FlowLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTabbedPane
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.SwingUtilities
import javax.swing.border.EmptyBorder

/** What the payload_overrides box holds. */
internal sealed interface OverridesInput {
    data object Empty : OverridesInput
    data class Ok(val claims: JsonObject) : OverridesInput
    data class Invalid(val message: String) : OverridesInput
}

internal fun parseOverrides(text: String?): OverridesInput {
    val trimmed = text?.trim().orEmpty()
    if (trimmed.isEmpty()) return OverridesInput.Empty
    val element = try {
        Json.parseToJsonElement(trimmed)
    } catch (e: Exception) {
        val reason = e.message?.lineSequence()?.firstOrNull()?.trim().orEmpty().ifEmpty { e.javaClass.simpleName }
        return OverridesInput.Invalid("payload_overrides is not valid JSON: $reason")
    }
    if (element is JsonObject) return OverridesInput.Ok(element)
    val kind = when {
        element is JsonArray -> "an array"
        element is JsonNull -> "null"
        element is JsonPrimitive && element.isString -> "a string"
        else -> "a number or boolean"
    }
    return OverridesInput.Invalid("payload_overrides must be a JSON object such as {\"sub\":\"admin\"}, not $kind")
}

/**
 * Tokens in a bridge result that can go back into the Token box: `token` (sign / forge modes,
 * `encrypt`), every `variants` entry (`forge_none`), and a `plaintext` that is itself a compact
 * JWS/JWE (`decrypt` of a nested token).
 */
internal fun copyableTokens(result: JsonObject): List<String> {
    val out = mutableListOf<String>()
    (result["token"] as? JsonPrimitive)?.takeIf { it.isString }?.content?.let(out::add)
    (result["variants"] as? JsonArray)?.forEach { v -> (v as? JsonPrimitive)?.takeIf { it.isString }?.content?.let(out::add) }
    (result["plaintext"] as? JsonPrimitive)?.takeIf { it.isString }?.content?.trim()
        ?.takeIf { p -> !p.any(Char::isWhitespace) && p.count { it == '.' }.let { it == 2 || it == 4 } }
        ?.let(out::add)
    return out
}

/** Key ids listed in a `keys(action = "list")` result, in ring order. */
internal fun ringKeyIds(listResult: JsonObject): List<String> =
    ringKeys(listResult).mapNotNull { (it["key_id"] as? JsonPrimitive)?.contentOrNullSafe() }

/** The `jwt_attack` modes each listed key reports it can serve, by key id. */
internal fun ringKeyModes(listResult: JsonObject): Map<String, List<String>> =
    ringKeys(listResult).mapNotNull { key ->
        val id = (key["key_id"] as? JsonPrimitive)?.contentOrNullSafe() ?: return@mapNotNull null
        id to keyModes(key)
    }.toMap()

private fun keyModes(key: JsonObject): List<String> =
    (key["modes"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNullSafe() } ?: emptyList()

private fun ringKeys(listResult: JsonObject): List<JsonObject> =
    (listResult["keys"] as? JsonArray)?.mapNotNull { it as? JsonObject } ?: emptyList()

/**
 * Why [mode] cannot run with key ring id [keyId], or null when it can. A blank [keyId] passes when
 * the mode also works without a key ([keyOptional]). A key missing from [modes] (listed before the
 * ring changed) passes too: the bridge then gives the real answer.
 */
internal fun keyModeBlocker(mode: String, keyId: String?, modes: Map<String, List<String>>, keyOptional: Boolean): String? {
    if (keyId.isNullOrBlank()) return if (keyOptional) null else "Pick a key ring id first"
    val supported = modes[keyId] ?: return null
    if (mode in supported) return null
    val can = if (supported.isEmpty()) "no jwt_attack mode" else supported.joinToString(", ")
    return "Key '$keyId' cannot run $mode (it supports: $can)"
}

/** The document a `header_url` result says to serve at the `jku` / `x5u` URL. */
internal data class HostedDocument(val url: String, val contentType: String, val body: String)

/** The `host` object of a signed `header_url` result, or null when the result has none. */
internal fun hostedDocument(result: JsonObject): HostedDocument? {
    val host = result["host"] as? JsonObject ?: return null
    fun text(name: String) = (host[name] as? JsonPrimitive)?.takeIf { it.isString }?.content
    val body = text("body") ?: return null
    return HostedDocument(url = text("url").orEmpty(), contentType = text("content_type").orEmpty(), body = body)
}

/**
 * The JWT tab: decode/analyze a token, sign it, run the `jwt_attack` modes, JWE encrypt/decrypt,
 * and manage the key ring — a thin Swing wrapper over [JwtBridge], calling it directly (no MCP
 * round-trip, mirroring how [TurboRunsPanel] and the Collaborator tab in [RaijinTab] work). Every
 * action's raw JSON result is pretty-printed into the shared output pane at the bottom rather than
 * a narrower, hand-picked summary, so nothing the bridge reports is hidden. A signed `header_url`
 * result also shows the JWK set / certificate chain to serve, beside the result.
 *
 * Bridge operations run on the panel's own [UiTasks] pool (crack with a large wordlist, RSA 4096
 * generation and PEM parsing can take long), which [dispose] stops; only the in-memory ring
 * listing stays on the EDT.
 */
class JwtPanel(private val bridge: JwtBridge) : JPanel(BorderLayout(0, 4)) {

    private val prettyJson = Json { prettyPrint = true; prettyPrintIndent = "  " }

    private val tasks = UiTasks { desc, e ->
        SwingUtilities.invokeLater { showError("$desc failed: ${e.message ?: e.javaClass.simpleName}") }
    }

    private val tokenField = JTextArea(3, 60).apply {
        lineWrap = true; wrapStyleWord = true; font = RaijinTheme.editorFont(11f)
    }

    private val output = ToneArea(10, 60).apply {
        isEditable = false
        font = RaijinTheme.editorFont(11f)
        lineWrap = true
        wrapStyleWord = true
        text = "Results appear here."
    }
    private val outputScroll = JScrollPane(output)

    /** The result currently shown in [output]; what "Copy token from result" reads. */
    private var lastResult: JsonObject? = null

    /** Bumped by every background run; only the newest run's result reaches [output]. */
    private var runSeq = 0

    // ---- the document a signed header_url result says to serve ----
    private var hosted: HostedDocument? = null
    private val hostUrlField = JTextField(30).apply { isEditable = false }
    private val hostTypeField = JTextField(20).apply { isEditable = false }
    private val hostBody = JTextArea(8, 40).apply {
        isEditable = false
        lineWrap = true
        font = RaijinTheme.editorFont(11f)
    }
    private val hostPanel = buildHostPanel()
    private val resultSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT).apply {
        resizeWeight = 0.5
        dividerSize = 5
    }
    /** Holds [outputScroll] alone, or [resultSplit] (output | hosted document) when there is a document. */
    private val resultHolder = JPanel(BorderLayout()).apply { add(outputScroll, BorderLayout.CENTER) }

    private val keyRingModel = object : javax.swing.table.AbstractTableModel() {
        private val columns = arrayOf("Key id", "kty", "alg", "crv", "Public only", "Modes")
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
                4 -> row["public_only"]?.toString() ?: ""
                else -> keyModes(row).joinToString(", ")
            }
        }
    }
    private val keyRingTable = javax.swing.JTable(keyRingModel).apply { rowHeight = 20; fillsViewportHeight = true }

    private fun show(result: JsonObject) {
        lastResult = result
        output.text = try {
            prettyJson.encodeToString(JsonObject.serializer(), result)
        } catch (_: Exception) {
            result.toString()
        }
        output.caretPosition = 0
        output.tone = if (result["error"] != null) ToneArea.Tone.ERROR else ToneArea.Tone.NORMAL
        showHosted(hostedDocument(result))
    }

    private fun showError(message: String) = show(buildJsonObject { put("error", message) })

    /** Shows [doc] beside the result, or hides the document pane when [doc] is null. */
    private fun showHosted(doc: HostedDocument?) {
        val wasShown = hosted != null
        hosted = doc
        if (doc != null) {
            hostUrlField.text = doc.url
            hostUrlField.caretPosition = 0
            hostTypeField.text = doc.contentType
            hostBody.text = doc.body
            hostBody.caretPosition = 0
        }
        if (wasShown == (doc != null)) return
        resultHolder.removeAll()
        if (doc != null) {
            resultSplit.leftComponent = outputScroll
            resultSplit.rightComponent = hostPanel
            resultHolder.add(resultSplit, BorderLayout.CENTER)
        } else {
            resultSplit.leftComponent = null
            resultSplit.rightComponent = null
            resultHolder.add(outputScroll, BorderLayout.CENTER)
        }
        resultHolder.revalidate()
        resultHolder.repaint()
    }

    private fun buildHostPanel(): JComponent {
        val fields = JPanel(GridBagLayout())
        val gbc = GridBagConstraints().apply { insets = Insets(2, 4, 2, 4); anchor = GridBagConstraints.WEST }
        gbc.gridy = 0; gbc.gridx = 0; fields.add(JLabel("URL:"), gbc)
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0; fields.add(hostUrlField, gbc)
        gbc.gridy = 1; gbc.gridx = 0; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0.0; fields.add(JLabel("Content-Type:"), gbc)
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0; fields.add(hostTypeField, gbc)

        val copyDoc = JButton("Copy document").apply {
            toolTipText = "Copies the document exactly as it has to be served"
            addActionListener { hosted?.let { copyToClipboard(it.body) } }
        }
        val copyUrl = JButton("Copy URL").apply { addActionListener { hosted?.let { copyToClipboard(it.url) } } }
        val bar = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2)).apply { add(copyDoc); add(copyUrl) }

        return JPanel(BorderLayout(0, 2)).apply {
            border = BorderFactory.createTitledBorder("Serve at the header URL")
            add(fields, BorderLayout.NORTH)
            add(JScrollPane(hostBody), BorderLayout.CENTER)
            add(bar, BorderLayout.SOUTH)
        }
    }

    private fun copyToClipboard(text: String) =
        Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(text), null)

    /**
     * Runs [op] off the EDT, then on the EDT shows its result (unless a newer run started meanwhile)
     * and runs [after].
     */
    private fun runInBackground(label: String, op: () -> JsonObject, after: (() -> Unit)? = null) {
        val seq = ++runSeq
        lastResult = null
        showHosted(null)
        output.tone = ToneArea.Tone.MUTED
        output.text = "$label..."
        tasks.execute(label) {
            val result = try {
                op()
            } catch (e: Exception) {
                buildJsonObject { put("error", "$label failed: ${e.message ?: e.javaClass.simpleName}") }
            }
            SwingUtilities.invokeLater {
                if (tasks.isDisposed) return@invokeLater
                if (seq == runSeq) show(result)
                after?.invoke()
            }
        }
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
            showError("Paste a token first")
            return
        }
        val overrides = when (val parsed = parseOverrides(overridesText)) {
            OverridesInput.Empty -> null
            is OverridesInput.Ok -> parsed.claims
            is OverridesInput.Invalid -> {
                showError(parsed.message)
                return
            }
        }
        runInBackground("Running $mode", {
            bridge.attack(
                token = token, mode = mode, secret = secret, publicKey = publicKey, wordlist = wordlist,
                overrides = overrides, alg = alg, keyId = keyId, enc = enc, header = header, url = url
            )
        })
    }

    private val ringCombos = mutableListOf<JComboBox<String>>()

    /** What each ring key can do, from the last listing; drives [gates]. */
    private var ringModes: Map<String, List<String>> = emptyMap()

    /** Re-evaluates one button's enabled state against [ringModes] and its key combo. */
    private val gates = mutableListOf<() -> Unit>()

    /** A key_id dropdown kept in sync with the ring by [refreshRing]. */
    private fun keyIdCombo(): JComboBox<String> {
        val combo = JComboBox<String>()
        ringCombos.add(combo)
        val listed = bridge.keys(action = "list")
        ringModes = ringKeyModes(listed)
        fillCombo(combo, ringKeyIds(listed))
        return combo
    }

    /**
     * Keeps [button] enabled only while the key picked in [combo] can run [mode] (or, with
     * [keyOptional], no key is picked); the tooltip says why it is disabled.
     */
    private fun gate(button: JButton, combo: JComboBox<String>, mode: String, keyOptional: Boolean) {
        val tip = button.toolTipText
        val update: () -> Unit = {
            val blocker = keyModeBlocker(mode, combo.selectedItem as? String, ringModes, keyOptional)
            button.isEnabled = blocker == null
            button.toolTipText = blocker ?: tip
        }
        combo.addActionListener { update() }
        gates += update
        update()
    }

    /** Reloads the key table and every key_id dropdown, keeping each one's current selection. */
    private fun refreshRing() {
        val listed = bridge.keys(action = "list")
        ringModes = ringKeyModes(listed)
        val keepRow = selectedKeyId()
        keyRingModel.rows = ringKeys(listed)
        keyRingModel.fireTableDataChanged()
        keepRow?.let { id -> keyRingModel.rows.indexOfFirst { it["key_id"]?.jsonPrimitive?.contentOrNullSafe() == id } }
            ?.takeIf { it >= 0 }
            ?.let { keyRingTable.convertRowIndexToView(it) }
            ?.takeIf { it >= 0 }
            ?.let { keyRingTable.setRowSelectionInterval(it, it) }
        val ids = ringKeyIds(listed)
        ringCombos.forEach { fillCombo(it, ids) }
        gates.forEach { it() }
    }

    private fun fillCombo(combo: JComboBox<String>, ids: List<String>) {
        val keep = combo.selectedItem as? String
        combo.removeAllItems()
        combo.addItem("")
        ids.forEach { combo.addItem(it) }
        if (keep != null && keep in ids) combo.selectedItem = keep
    }

    private fun refreshButton() = JButton("↻").apply { toolTipText = "Refresh key list"; addActionListener { refreshRing() } }

    init {
        border = EmptyBorder(8, 8, 8, 8)

        val tokenPanel = JPanel(BorderLayout(4, 2))
        tokenPanel.border = BorderFactory.createTitledBorder("Token")
        tokenPanel.add(JScrollPane(tokenField), BorderLayout.CENTER)
        tokenPanel.add(
            mutedHintLabel("  Shared by every sub-tab below. Attack/sign modes replace this with their forged result when you copy it back in.", 10f),
            BorderLayout.SOUTH
        )

        val tabs = JTabbedPane(JTabbedPane.TOP)
        tabs.addTab("Decode", buildDecodeTab())
        tabs.addTab("Sign", buildSignTab())
        tabs.addTab("Attacks", buildAttacksTab())
        tabs.addTab("JWE", buildJweTab())
        tabs.addTab("Key Ring", buildKeyRingTab())

        val outputPanel = JPanel(BorderLayout())
        outputPanel.border = BorderFactory.createTitledBorder("Result")
        outputPanel.add(resultHolder, BorderLayout.CENTER)
        val copyBtn = JButton("Copy token from result").apply {
            toolTipText = "Puts the result's token (or a forge_none variant you pick, or a decrypted nested token) into the Token box above"
            addActionListener { copyTokenFromResult() }
        }
        val outputBar = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2)).apply { add(copyBtn) }
        outputPanel.add(outputBar, BorderLayout.SOUTH)

        val split = JSplitPane(JSplitPane.VERTICAL_SPLIT, tabs, outputPanel)
        split.resizeWeight = 0.6
        split.dividerSize = 5

        add(tokenPanel, BorderLayout.NORTH)
        add(split, BorderLayout.CENTER)
    }

    /** Stops the background pool; results of runs still in flight are dropped. */
    fun dispose() = tasks.dispose()

    private fun copyTokenFromResult() {
        val tokens = lastResult?.let(::copyableTokens).orEmpty()
        val chosen = when (tokens.size) {
            0 -> {
                JOptionPane.showMessageDialog(this, "The last result has no token to copy.", "JWT", JOptionPane.INFORMATION_MESSAGE)
                null
            }
            1 -> tokens[0]
            else -> {
                val labels = tokens.mapIndexed { i, t ->
                    val alg = runCatching { Jwt.decode(t)?.alg }.getOrNull()
                    "${i + 1}. alg=${alg ?: "?"}  ${t.take(48)}${if (t.length > 48) "…" else ""}"
                }.toTypedArray()
                val pick = JOptionPane.showInputDialog(
                    this, "Choose the token to put in the Token box:", "Copy token",
                    JOptionPane.PLAIN_MESSAGE, null, labels, labels[0]
                )
                labels.indexOf(pick).takeIf { it >= 0 }?.let { tokens[it] }
            }
        }
        if (chosen != null) tokenField.text = chosen
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
        val algCombo = algCombo(JWS_ALGS, "Blank = HS256 for a secret, the key's own alg for a ring key; type any other value")
        val overridesField = JTextField(30).apply { toolTipText = """Claims to override, e.g. {"sub":"admin"}""" }

        var row = 0
        gbc.gridy = row++; gbc.gridx = 0; panel.add(JLabel("HMAC secret:"), gbc)
        gbc.gridx = 1; gbc.gridwidth = 2; panel.add(secretField, gbc); gbc.gridwidth = 1
        val signSecretBtn = JButton("Sign with secret").apply {
            addActionListener { runAttack(mode = "sign", secret = secretField.text.ifBlank { null }, alg = comboText(algCombo), overridesText = overridesField.text) }
        }
        gbc.gridx = 3; panel.add(signSecretBtn, gbc)

        gbc.gridy = row++; gbc.gridx = 0; panel.add(JLabel("Key ring id:"), gbc)
        gbc.gridx = 1; panel.add(keyCombo, gbc)
        gbc.gridx = 2; panel.add(refreshButton(), gbc)
        val signKeyBtn = JButton("Sign with key").apply {
            addActionListener {
                runAttack(mode = "sign_key", keyId = selectedKey(keyCombo), alg = comboText(algCombo), overridesText = overridesField.text)
            }
        }
        gate(signKeyBtn, keyCombo, "sign_key", keyOptional = false)
        gbc.gridx = 3; panel.add(signKeyBtn, gbc)

        gbc.gridy = row++; gbc.gridx = 0; panel.add(JLabel("alg:"), gbc)
        gbc.gridx = 1; panel.add(algCombo, gbc)

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
        val keyCombo = keyIdCombo().apply {
            toolTipText = "Ring key for alg_confusion (instead of public_key), embed_jwk, and a signed header_url"
        }
        val algCombo = algCombo(JWS_ALGS, "Blank = each mode's default (HS256 for alg_confusion, the key's own alg for a ring key)")
        val wordlistField = JTextField(24).apply { toolTipText = "Comma-separated candidate secrets; blank = built-in list" }
        val headerCombo = JComboBox(JwtBridge.URL_HEADERS.toTypedArray())
        val urlField = JTextField(24).apply { toolTipText = "A URL you control, where the target can fetch the document" }
        val overridesField = JTextField(24)

        var row = 0
        gbc.gridy = row; gbc.gridx = 0; panel.add(JLabel("public_key (PEM or JWK JSON):"), gbc)
        gbc.gridx = 1; gbc.gridwidth = 2; panel.add(JScrollPane(publicKeyArea), gbc); gbc.gridwidth = 1
        row++

        gbc.gridy = row; gbc.gridx = 0; panel.add(JLabel("key_id:"), gbc)
        gbc.gridx = 1; panel.add(keyCombo, gbc)
        gbc.gridx = 2; panel.add(refreshButton(), gbc)
        val algConfusionBtn = JButton("alg_confusion").apply {
            toolTipText = "RS->HS confusion: sign with the server's public key as the HMAC secret"
            addActionListener {
                runAttack(
                    mode = "alg_confusion", publicKey = publicKeyArea.text.ifBlank { null }, keyId = selectedKey(keyCombo),
                    alg = comboText(algCombo), overridesText = overridesField.text
                )
            }
        }
        gate(algConfusionBtn, keyCombo, "alg_confusion", keyOptional = true)
        gbc.gridx = 3; panel.add(algConfusionBtn, gbc)
        row++

        gbc.gridy = row; gbc.gridx = 0; panel.add(JLabel("alg:"), gbc)
        gbc.gridx = 1; panel.add(algCombo, gbc)
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
            toolTipText = "Point jku/x5u at url. With a key_id the token is signed with that key and the JWK set " +
                "(jku) or certificate chain (x5u) to serve at url appears beside the result; without one only the header changes"
            addActionListener {
                runAttack(
                    mode = "header_url", header = headerCombo.selectedItem as? String, url = urlField.text.ifBlank { null },
                    keyId = selectedKey(keyCombo), alg = comboText(algCombo), overridesText = overridesField.text
                )
            }
        }
        gate(headerUrlBtn, keyCombo, "header_url", keyOptional = true)
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
        val embedJwkBtn = JButton("embed_jwk").apply {
            toolTipText = "Sign and embed the public JWK in the header (needs key_id above)"
            addActionListener {
                runAttack(mode = "embed_jwk", keyId = selectedKey(keyCombo), alg = comboText(algCombo), overridesText = overridesField.text)
            }
        }
        gate(embedJwkBtn, keyCombo, "embed_jwk", keyOptional = false)
        quickBar.add(embedJwkBtn)
        quickBar.add(JButton("empty_hmac").apply {
            addActionListener { runAttack(mode = "empty_hmac", alg = comboText(algCombo), overridesText = overridesField.text) }
        })
        quickBar.add(JButton("psychic").apply {
            toolTipText = "ES256/ES384/ES512 token with a zero ECDSA signature (CVE-2022-21449-style)"
            addActionListener { runAttack(mode = "psychic", alg = comboText(algCombo), overridesText = overridesField.text) }
        })
        panel.add(quickBar, gbc)

        return panel
    }

    // ---------------------------------------------------------------
    // JWE
    // ---------------------------------------------------------------
    private fun buildJweTab(): JPanel {
        val panel = JPanel(GridBagLayout())
        val gbc = GridBagConstraints().apply { insets = Insets(4, 6, 4, 6); anchor = GridBagConstraints.WEST }

        val keyCombo = keyIdCombo()
        val algCombo = algCombo(JWE_ALGS, "Key management alg. Blank = the key's default (RSA-OAEP-256 for RSA, PBES2-HS256+A128KW for a password)")
        val encCombo = algCombo(JWE_ENCS, "Content encryption. Blank = A256GCM")

        var row = 0
        gbc.gridy = row++; gbc.gridx = 0; panel.add(JLabel("Key ring id:"), gbc)
        gbc.gridx = 1; panel.add(keyCombo, gbc)
        gbc.gridx = 2; panel.add(refreshButton(), gbc)

        gbc.gridy = row++; gbc.gridx = 0; panel.add(JLabel("alg:"), gbc)
        gbc.gridx = 1; panel.add(algCombo, gbc)

        gbc.gridy = row++; gbc.gridx = 0; panel.add(JLabel("enc:"), gbc)
        gbc.gridx = 1; panel.add(encCombo, gbc)

        val encryptBtn = JButton("Encrypt").apply {
            toolTipText = "Encrypt the Token box (any text, typically a signed JWT) into a compact JWE"
            addActionListener {
                runAttack(mode = "encrypt", keyId = selectedKey(keyCombo), alg = comboText(algCombo), enc = comboText(encCombo))
            }
        }
        gate(encryptBtn, keyCombo, "encrypt", keyOptional = false)
        val decryptBtn = JButton("Decrypt").apply {
            toolTipText = "Decrypt the compact JWE in the Token box (alg and enc come from its header)"
            addActionListener { runAttack(mode = "decrypt", keyId = selectedKey(keyCombo)) }
        }
        gate(decryptBtn, keyCombo, "decrypt", keyOptional = false)
        gbc.gridy = row; gbc.gridx = 0; gbc.gridwidth = 3
        panel.add(JPanel(FlowLayout(FlowLayout.LEFT, 6, 4)).apply { add(encryptBtn); add(decryptBtn) }, gbc)

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
                isEnabled = false
                runInBackground("Generating $kty key", { bridge.keys(action = "generate", kty = kty, size = size, crv = crv, keyId = id) }) {
                    isEnabled = true
                    refreshRing()
                }
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
                runInBackground("Importing", {
                    bridge.keys(action = "import", pem = if (!looksJwk) text else null, jwk = if (looksJwk) text else null)
                }) { refreshRing() }
            }
        }
        val importPanel = JPanel(BorderLayout(4, 4))
        importPanel.border = BorderFactory.createTitledBorder("Import (PEM or JWK JSON)")
        importPanel.add(JScrollPane(importArea), BorderLayout.CENTER)
        importPanel.add(importBtn, BorderLayout.EAST)

        val exportFormatCombo = JComboBox(JwtBridge.EXPORT_FORMATS.toTypedArray())
        val exportPrivateCheck = javax.swing.JCheckBox("include private")
        val exportBtn = JButton("Export selected").apply {
            addActionListener {
                val id = selectedKeyId() ?: return@addActionListener
                val format = exportFormatCombo.selectedItem as String
                val includePrivate = exportPrivateCheck.isSelected
                runInBackground("Exporting $id", { bridge.keys(action = "export", keyId = id, format = format, includePrivate = includePrivate) })
            }
        }
        val deleteBtn = JButton("Delete selected").apply {
            addActionListener {
                val id = selectedKeyId() ?: return@addActionListener
                runInBackground("Deleting $id", { bridge.keys(action = "delete", keyId = id) }) { refreshRing() }
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

        SwingUtilities.invokeLater { refreshRing() }
        return panel
    }

    private fun selectedKeyId(): String? {
        val row = keyRingTable.selectedRow
        if (row < 0) return null
        return keyRingModel.rows.getOrNull(keyRingTable.convertRowIndexToModel(row))
            ?.get("key_id")?.jsonPrimitive?.contentOrNullSafe()
    }

    /** The key ring id picked in [combo]; null when blank. */
    private fun selectedKey(combo: JComboBox<String>): String? = (combo.selectedItem as? String)?.ifBlank { null }

    /** Editable alg dropdown: blank first (bridge default), then the common values; any other value can be typed. */
    private fun algCombo(values: List<String>, tip: String) = JComboBox((listOf("") + values).toTypedArray()).apply {
        isEditable = true
        toolTipText = tip
    }

    /** The combo's text, including a value typed but not yet committed with Enter; null when blank. */
    private fun comboText(combo: JComboBox<String>): String? =
        (combo.editor?.item ?: combo.selectedItem)?.toString()?.trim()?.ifBlank { null }

    private companion object {
        val JWS_ALGS = listOf(
            "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
            "ES256", "ES256K", "ES384", "ES512", "EdDSA",
        )
        val JWE_ALGS = listOf(
            "RSA-OAEP-256", "RSA-OAEP-384", "RSA-OAEP-512", "RSA-OAEP", "RSA1_5",
            "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW",
            "A128KW", "A192KW", "A256KW", "A128GCMKW", "A192GCMKW", "A256GCMKW", "dir",
            "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW",
        )
        val JWE_ENCS = listOf("A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512")
    }
}

/** Result pane whose colour carries meaning (normal / muted / error) and follows Burp theme switches. */
private class ToneArea(rows: Int, columns: Int) : JTextArea(rows, columns) {
    enum class Tone { NORMAL, MUTED, ERROR }

    // Null while JTextArea's constructor runs: it calls updateUI before this class's fields exist.
    private var current: Tone? = null

    var tone: Tone
        get() = current ?: Tone.NORMAL
        set(value) {
            current = value
            foreground = colour(value)
        }

    override fun updateUI() {
        super.updateUI()
        foreground = colour(tone)
    }

    private fun colour(t: Tone): Color = when (t) {
        Tone.NORMAL -> RaijinTheme.foreground()
        Tone.MUTED -> RaijinTheme.muted()
        Tone.ERROR -> RaijinTheme.error()
    }
}

/** Null-safe [kotlinx.serialization.json.JsonPrimitive.content] — avoids throwing on JsonNull. */
private fun kotlinx.serialization.json.JsonPrimitive.contentOrNullSafe(): String? =
    if (this is kotlinx.serialization.json.JsonNull) null else content
