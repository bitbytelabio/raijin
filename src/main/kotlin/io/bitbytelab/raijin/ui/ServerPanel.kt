package io.bitbytelab.raijin.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.persistence.Preferences
import io.bitbytelab.raijin.core.ConnectionInfo
import io.bitbytelab.raijin.core.RebindOutcome
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.safety.ActionPolicy
import io.bitbytelab.raijin.safety.ScopeMode
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.transport.BindHostPolicy
import io.bitbytelab.raijin.transport.NetworkHosts
import io.bitbytelab.raijin.transport.RemoteAccess
import java.awt.BorderLayout
import java.awt.Component
import java.awt.FlowLayout
import java.awt.Font
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.text.NumberFormat
import javax.swing.BorderFactory
import javax.swing.DefaultComboBoxModel
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JPasswordField
import javax.swing.JScrollPane
import javax.swing.JSeparator
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.JToggleButton
import javax.swing.border.EmptyBorder

/**
 * The Server tab: connection details, the operator's tool policy (scope mode, destructive tools),
 * the bind address with its remote-access security, the client config to paste, and live stats.
 *
 * The tool policy is saved on change and applies to the next tool call. Bind and security settings
 * are saved to Burp preferences by "Save & Rebind Now", whose rebind re-resolves [RemoteAccess].
 * [refresh] re-reads the live state ([ConnectionInfo.endpoints], [RemoteAccess.current]).
 */
internal class ServerPanel(
    private val api: MontoyaApi,
    private val eventBus: EventBus,
    private val stateManager: StateManager,
    initialBindHost: String,
    private val rebindNow: (String, Boolean) -> RebindOutcome,
    private val tasks: UiTasks,
    private val toolCalls: () -> Long,
) : JPanel(BorderLayout()) {
    private val prefs: Preferences get() = api.persistence().preferences()
    private val overridden = ServerSettings.overriddenPrefs(System::getProperty)
    private val startedAt = System.currentTimeMillis()

    // Connection
    private val primaryUrlLabel = JLabel()
    private val secondaryUrlLabel = JLabel()
    private val dashboardUrlLabel = JLabel()

    // Tool policy
    private val scopeModeCombo = JComboBox(ScopeMode.entries.toTypedArray())
    private val scopeHint = hint("")
    private val destructiveCheck = JCheckBox("Allow destructive tools (${ActionPolicy.DESTRUCTIVE_TOOLS.sorted().joinToString(", ")})")

    // Bind address and remote security
    private val bindHostCombo = JComboBox<String>()
    private val allowRemoteCheck = JCheckBox("Allow remote (non-loopback) bind — exposes tools to your network")
    private val requireAuthCheck = JCheckBox("Require Auth Token")
    private val requireAuthNote = hint("")
    private val tokenField = JPasswordField(32)
    private val hiddenEchoChar = tokenField.echoChar
    private val showTokenToggle = JToggleButton("Show")
    private val regenerateBtn = JButton("Regenerate")
    private val copyTokenBtn = JButton("Copy Token")
    private val allowedIpsField = JTextField(32)
    private val allowedHostsField = JTextField(32)
    private var effectiveTone = ServerSettings.Tone.MUTED
    private val effectiveLabel = TintedLabel(" ") { toneColor(effectiveTone) }
    private val unsavedLabel = TintedLabel(" ") { RaijinTheme.warning() }
    private val saveBtn = JButton(SAVE_LABEL)

    // Client config
    private val clientHostCombo = JComboBox<String>()
    private val configArea = JTextArea(8, 60)
    private val commandArea = JTextArea(2, 60)
    private val configNote = hint(" ")

    // Live statistics
    private val uptimeLabel = JLabel("00:00:00")
    private val toolCallsLabel = JLabel("0")
    private val eventsLabel = JLabel("0")
    private val wsLabel = JLabel("0")
    private val collabLabel = JLabel("0")
    private val scanLabel = JLabel("0")

    /** The operator's own Require Auth Token choice; the checkbox shows it forced on for a non-loopback host. */
    private var requireAuthChoice = prefBool(RemoteAccess.PREF_REQUIRE_AUTH) ?: false
    private var formKind: BindHostPolicy.Kind? = ServerSettings.quickKind(initialBindHost)
    private var localAddresses: List<String> = emptyList()
    private var boundHost: String? = null
    private var boundKind: BindHostPolicy.Kind? = null
    private var clientHostsSource: Pair<String?, List<String>>? = null
    private var renderedConfig: Pair<String, String?>? = null
    private var savedForm: ServerSettings.RemoteForm? = null

    init {
        border = EmptyBorder(12, 12, 12, 12)
        add(JScrollPane(buildContent()).apply { verticalScrollBar.unitIncrement = 16 }, BorderLayout.CENTER)

        // Initial values first, listeners after, so loading the saved settings writes nothing back.
        val scopeMode = ScopeMode.fromString(prefString(ServerSettings.PREF_SCOPE_MODE))
        scopeModeCombo.selectedItem = scopeMode
        scopeHint.text = ServerSettings.scopeModeHint(scopeMode)
        destructiveCheck.isSelected = prefBool(ServerSettings.PREF_ALLOW_DESTRUCTIVE) ?: false
        bindHostCombo.isEditable = true
        bindHostCombo.model = DefaultComboBoxModel(ServerSettings.bindHostSuggestions(initialBindHost, emptyList()).toTypedArray())
        bindHostCombo.selectedItem = initialBindHost
        allowRemoteCheck.isSelected = prefBool(ServerSettings.PREF_ALLOW_REMOTE_BIND) ?: false
        tokenField.text = System.getProperty(RemoteAccess.PROP_AUTH_TOKEN)
            ?: prefString(RemoteAccess.PREF_AUTH_TOKEN)?.ifBlank { null }
            ?: RemoteAccess.current.token.orEmpty()
        allowedIpsField.text = System.getProperty(RemoteAccess.PROP_ALLOWED_IPS) ?: prefString(RemoteAccess.PREF_ALLOWED_IPS).orEmpty()
        allowedHostsField.text = System.getProperty(RemoteAccess.PROP_ALLOWED_HOSTS) ?: prefString(RemoteAccess.PREF_ALLOWED_HOSTS).orEmpty()
        clientHostCombo.isEditable = true
        lockOverridden()
        savedForm = currentForm()
        applyAuthState()
        wireListeners()

        loadLocalAddresses()
        if (formKind == null) classifyFormHost(initialBindHost)
        onEdt { refresh() }
    }

    /** Re-reads the live listener and security state and the statistics; call on the EDT. */
    fun refresh() {
        val host = ConnectionInfo.endpoints.host
        primaryUrlLabel.text = ConnectionInfo.primaryMcpUrlForHost(host)
        secondaryUrlLabel.text = ConnectionInfo.secondaryMcpUrlForHost(host)
        dashboardUrlLabel.text = ConnectionInfo.dashboardUrlForHost(host)
        if (host != boundHost) onBoundHostChanged(host)

        val config = RemoteAccess.current
        val status = ServerSettings.effectiveStatus(config, RemoteAccess.exposed)
        effectiveLabel.text = status.text
        if (status.tone != effectiveTone) {
            effectiveTone = status.tone
            effectiveLabel.repaint()
        }
        if (clientHostsSource != boundHost to config.allowedHosts) updateClientHosts(reset = false)
        renderClientConfig()

        val elapsed = System.currentTimeMillis() - startedAt
        uptimeLabel.text = String.format("%02d:%02d:%02d", elapsed / 3_600_000, elapsed % 3_600_000 / 60_000, elapsed % 60_000 / 1000)
        toolCallsLabel.text = NUMBER_FORMAT.format(toolCalls())
        eventsLabel.text = "${eventBus.size()} events buffered"
        wsLabel.text = "${stateManager.websocketConnections.size} active"
        collabLabel.text = "${stateManager.collaboratorClients.size} active"
        scanLabel.text = "${stateManager.scanTasks.size} active"
    }

    // ── Layout ───────────────────────────────────────────────────────────────

    private fun buildContent(): JPanel {
        val content = JPanel(GridBagLayout())
        val c = GridBagConstraints().apply { insets = Insets(4, 8, 4, 8); anchor = GridBagConstraints.WEST; fill = GridBagConstraints.HORIZONTAL }
        var row = 0
        fun full(comp: Component) {
            c.gridy = row++; c.gridx = 0; c.gridwidth = 2; c.weightx = 1.0
            content.add(comp, c)
            c.gridwidth = 1
        }
        fun pair(label: String, comp: Component) {
            c.gridy = row++; c.gridx = 0; c.weightx = 0.0
            content.add(JLabel(label).apply { font = font.deriveFont(Font.BOLD) }, c)
            c.gridx = 1; c.weightx = 1.0
            content.add(comp, c)
        }
        fun header(text: String) = full(JLabel(text).apply { font = font.deriveFont(Font.BOLD, 14f) })

        header("Connection Information")
        for (label in listOf(primaryUrlLabel, secondaryUrlLabel, dashboardUrlLabel)) label.font = RaijinTheme.editorFont(12f)
        pair("MCP (Streamable HTTP):", primaryUrlLabel)
        pair("MCP (secondary):", secondaryUrlLabel)
        pair("Dashboard:", dashboardUrlLabel)
        full(JSeparator())

        header("Tool Policy")
        scopeModeCombo.toolTipText = "Preference ${ServerSettings.PREF_SCOPE_MODE}: checks requests the agent sends against Burp's target scope"
        pair("Scope mode:", flow(scopeModeCombo, scopeHint))
        destructiveCheck.toolTipText = "Preference ${ServerSettings.PREF_ALLOW_DESTRUCTIVE}; applies to the next tool call"
        full(destructiveCheck)
        full(JSeparator())

        // Bind address (GitHub issue #4). A non-loopback address exposes the tools to the network:
        // saving it asks for confirmation, which also sets the mcp_allow_remote_bind opt-in the
        // BindHostPolicy gate requires, and the bearer token becomes mandatory.
        header("Server Bind Address")
        bindHostCombo.prototypeDisplayValue = "fd7a:115c:a1e0:ab12:4843::1"
        bindHostCombo.toolTipText = "Preference ${ServerSettings.PREF_BIND_HOST}. Pick one of this machine's addresses or type one."
        pair("Bind host:", flow(bindHostCombo, JButton("Refresh List").apply {
            toolTipText = "Re-read this machine's network interfaces"
            addActionListener { loadLocalAddresses() }
        }))
        full(allowRemoteCheck)
        full(buildSecurityGroup())
        full(flow(saveBtn, unsavedLabel))
        full(JSeparator())

        header("MCP Client Config")
        clientHostCombo.prototypeDisplayValue = "burp-vm.tailnet-0000.ts.net"
        clientHostCombo.toolTipText = "The address clients use to reach this machine; the config and command below use it"
        pair("Client host:", flow(clientHostCombo, configNote))
        for (area in listOf(configArea, commandArea)) {
            area.isEditable = false; area.font = RaijinTheme.editorFont(11f); area.lineWrap = true; area.wrapStyleWord = false
        }
        full(configArea)
        full(flow(JButton("Copy MCP Config").apply {
            addActionListener { copyToClipboard(ConnectionInfo.clientConfigJson(host = clientHost(), token = liveToken())) }
        }))
        full(JLabel("Claude Code:").apply { font = font.deriveFont(Font.ITALIC, 11f) })
        full(commandArea)
        full(flow(JButton("Copy Command").apply {
            addActionListener { copyToClipboard(ConnectionInfo.claudeCodeCommand(host = clientHost(), token = liveToken())) }
        }))
        full(JSeparator())

        header("Live Statistics")
        for (label in listOf(uptimeLabel, toolCallsLabel, eventsLabel, wsLabel, collabLabel, scanLabel)) label.font = RaijinTheme.editorFont(12f)
        pair("Uptime:", uptimeLabel)
        pair("Total MCP Tool Calls:", toolCallsLabel)
        pair("Event Buffer:", eventsLabel)
        pair("WebSocket Connections:", wsLabel)
        pair("Collaborator Clients:", collabLabel)
        pair("Active Scan Tasks:", scanLabel)

        c.gridy = row; c.gridx = 0; c.gridwidth = 2; c.weighty = 1.0
        content.add(JLabel(), c)
        return content
    }

    private fun buildSecurityGroup(): JPanel {
        val group = JPanel(GridBagLayout())
        group.border = BorderFactory.createTitledBorder("Remote Security")
        val c = GridBagConstraints().apply { insets = Insets(3, 6, 3, 6); anchor = GridBagConstraints.WEST; fill = GridBagConstraints.HORIZONTAL }
        var row = 0
        fun line(label: String?, comp: Component) {
            c.gridy = row++; c.gridx = 0; c.weightx = 0.0
            if (label != null) group.add(JLabel(label), c)
            c.gridx = 1; c.weightx = 1.0
            group.add(comp, c)
        }
        requireAuthCheck.toolTipText = "Preference ${RemoteAccess.PREF_REQUIRE_AUTH}: clients must send Authorization: Bearer <token>"
        line(null, flow(requireAuthCheck, requireAuthNote))
        tokenField.font = RaijinTheme.editorFont(12f)
        tokenField.toolTipText = "Preference ${RemoteAccess.PREF_AUTH_TOKEN}"
        line("Token:", flow(tokenField, showTokenToggle, regenerateBtn, copyTokenBtn))
        allowedIpsField.toolTipText = "Preference ${RemoteAccess.PREF_ALLOWED_IPS}"
        line("Allowed IPs/CIDR:", allowedIpsField)
        line(null, hint("Comma-separated, e.g. 192.168.56.1, 10.0.2.2, 100.64.0.0/10. Empty: any source. Loopback is always allowed."))
        allowedHostsField.toolTipText = "Preference ${RemoteAccess.PREF_ALLOWED_HOSTS}"
        line("Allowed Hosts:", allowedHostsField)
        line(null, hint("Extra names clients may use in the URL (Host/Origin), e.g. burp-vm.tailnet.ts.net, burp.internal"))
        line("Effective now:", effectiveLabel)
        return group
    }

    // ── Behaviour ────────────────────────────────────────────────────────────

    private fun wireListeners() {
        scopeModeCombo.addActionListener {
            val mode = scopeModeCombo.selectedItem as? ScopeMode ?: return@addActionListener
            scopeHint.text = ServerSettings.scopeModeHint(mode)
            prefs.setString(ServerSettings.PREF_SCOPE_MODE, ServerSettings.scopeModeValue(mode))
        }
        destructiveCheck.addActionListener {
            if (destructiveCheck.isSelected) {
                val ok = JOptionPane.showConfirmDialog(
                    this,
                    "Let MCP clients shut down Burp and replace its project and user configuration?\n" +
                        "(${ActionPolicy.DESTRUCTIVE_TOOLS.sorted().joinToString(", ")})",
                    "Allow destructive tools", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE
                )
                if (ok != JOptionPane.YES_OPTION) {
                    destructiveCheck.isSelected = false
                    return@addActionListener
                }
            }
            prefs.setBoolean(ServerSettings.PREF_ALLOW_DESTRUCTIVE, destructiveCheck.isSelected)
        }

        bindHostCombo.onEditorTextChange { onBindHostEdited() }
        bindHostCombo.addActionListener { onBindHostCommitted() }
        allowRemoteCheck.addActionListener { updateUnsaved() }
        requireAuthCheck.addActionListener {
            if (requireAuthCheck.isEnabled) requireAuthChoice = requireAuthCheck.isSelected
            updateUnsaved()
        }
        showTokenToggle.addActionListener {
            val show = showTokenToggle.isSelected
            tokenField.echoChar = if (show) '\u0000' else hiddenEchoChar
            showTokenToggle.text = if (show) "Hide" else "Show"
        }
        regenerateBtn.addActionListener { tokenField.text = RemoteAccess.generateToken() }
        copyTokenBtn.addActionListener {
            val token = String(tokenField.password).trim()
            if (token.isEmpty()) {
                JOptionPane.showMessageDialog(
                    this, "No token is set. Click Regenerate, or tick Require Auth Token and save.",
                    "Copy Token", JOptionPane.INFORMATION_MESSAGE
                )
            } else {
                copyToClipboard(token)
            }
        }
        for (field in listOf(tokenField, allowedIpsField, allowedHostsField)) {
            field.document.addDocumentListener(documentListener { updateUnsaved() })
        }
        saveBtn.addActionListener { saveAndRebind() }

        clientHostCombo.onEditorTextChange { renderClientConfig() }
        clientHostCombo.addActionListener { renderClientConfig() }
    }

    /** Disables the controls a `-Draijin.*` property overrides; RemoteAccess reads the property, not the field. */
    private fun lockOverridden() {
        fun lock(pref: String, prop: String, vararg components: javax.swing.JComponent) {
            if (pref !in overridden) return
            for (component in components) {
                component.isEnabled = false
                component.toolTipText = "Set by -D$prop. Change or remove that JVM option to edit it here."
            }
        }
        lock(RemoteAccess.PREF_AUTH_TOKEN, RemoteAccess.PROP_AUTH_TOKEN, tokenField, regenerateBtn)
        lock(RemoteAccess.PREF_ALLOWED_IPS, RemoteAccess.PROP_ALLOWED_IPS, allowedIpsField)
        lock(RemoteAccess.PREF_ALLOWED_HOSTS, RemoteAccess.PROP_ALLOWED_HOSTS, allowedHostsField)
    }

    private fun onBindHostEdited() {
        val kind = ServerSettings.quickKind(bindHostCombo.editorText())
        if (kind != null) {
            formKind = kind
            applyAuthState()
        } else {
            updateUnsaved()
        }
    }

    private fun onBindHostCommitted() {
        val host = bindHostCombo.editorText()
        val kind = ServerSettings.quickKind(host)
        if (kind == null) {
            classifyFormHost(host)
        } else {
            formKind = kind
            applyAuthState()
        }
    }

    /** A host name needs DNS to classify, so it is resolved off the EDT. */
    private fun classifyFormHost(host: String) {
        tasks.compute("Resolve bind host", { BindHostPolicy.classify(host) }) { kind ->
            if (bindHostCombo.editorText() == host) {
                formKind = kind
                applyAuthState()
            }
        }
    }

    private fun applyAuthState() {
        val forced = ServerSettings.authForced(formKind)
        val fromProperty = System.getProperty(RemoteAccess.PROP_REQUIRE_AUTH)?.trim()?.toBooleanStrictOrNull()
        requireAuthCheck.isSelected = forced || (fromProperty ?: requireAuthChoice)
        requireAuthCheck.isEnabled = !forced && fromProperty == null
        requireAuthNote.text = when {
            forced -> "Always on for a non-loopback bind."
            fromProperty != null -> "Set by -D${RemoteAccess.PROP_REQUIRE_AUTH}."
            else -> "Optional on loopback."
        }
        updateUnsaved()
    }

    private fun currentForm() = ServerSettings.RemoteForm.of(
        bindHost = bindHostCombo.editorText(),
        allowRemoteBind = allowRemoteCheck.isSelected,
        requireAuth = requireAuthChoice,
        token = String(tokenField.password),
        allowedIps = allowedIpsField.text,
        allowedHosts = allowedHostsField.text,
    )

    private fun updateUnsaved() {
        val saved = savedForm ?: return
        unsavedLabel.text = if (currentForm() != saved) "Unsaved changes: Save & Rebind Now applies them." else " "
    }

    private fun saveAndRebind() {
        val form = currentForm()
        if (RemoteAccess.PREF_ALLOWED_IPS !in overridden) {
            val bad = ServerSettings.invalidIpEntries(form.allowedIps)
            if (bad.isNotEmpty()) return showError("Not an IP address or CIDR range: ${bad.joinToString(", ")}", "Invalid Allowed IPs/CIDR")
        }
        if (RemoteAccess.PREF_ALLOWED_HOSTS !in overridden) {
            val bad = ServerSettings.invalidHostEntries(form.allowedHosts)
            if (bad.isNotEmpty()) {
                return showError("Allowed Hosts takes bare host names, without scheme, path or port: ${bad.joinToString(", ")}", "Invalid Allowed Hosts")
            }
        }
        val host = form.bindHost.ifEmpty { BindHostPolicy.LOOPBACK }
        setBusy("Checking…")
        tasks.compute("Check bind host", { BindHostPolicy.classify(host) }) { kind -> confirmAndRebind(host, kind) }
    }

    private fun confirmAndRebind(host: String, kind: BindHostPolicy.Kind) {
        if (bindHostCombo.editorText() != host) bindHostCombo.selectedItem = host
        formKind = kind
        applyAuthState()
        when (kind) {
            BindHostPolicy.Kind.INVALID -> {
                setIdle()
                showError("\"$host\" is not a valid IP address or hostname.", "Invalid Bind Address")
                return
            }
            BindHostPolicy.Kind.LOOPBACK -> {}
            BindHostPolicy.Kind.WILDCARD, BindHostPolicy.Kind.OTHER -> {
                val ips = System.getProperty(RemoteAccess.PROP_ALLOWED_IPS)?.let(RemoteAccess::parseList) ?: currentForm().allowedIps
                val ok = JOptionPane.showConfirmDialog(
                    this, ServerSettings.exposureWarning(host, ips), "Confirm network exposure",
                    JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE
                )
                if (ok != JOptionPane.YES_OPTION) {
                    setIdle()
                    return
                }
                allowRemoteCheck.isSelected = true  // confirming the exposure is the opt-in
            }
        }
        // Generate the token here, where the operator sees and can copy it, rather than at resolve time.
        if (RemoteAccess.PREF_AUTH_TOKEN !in overridden && String(tokenField.password).isBlank() &&
            ServerSettings.authRequired(kind, requireAuthChoice, System::getProperty)
        ) {
            tokenField.text = RemoteAccess.generateToken()
        }
        val form = currentForm()
        persist(form)
        savedForm = form
        setBusy("Rebinding…")
        tasks.compute("Rebind", {
            try {
                rebindNow(host, form.allowRemoteBind)
            } catch (e: Exception) {
                RebindOutcome(effectiveHost = host, exposed = false, downgraded = false, boundOk = false, message = e.message)
            }
        }) { outcome ->
            setIdle()
            refresh()
            JOptionPane.showMessageDialog(
                this, ServerSettings.rebindMessage(outcome, RemoteAccess.current), "Raijin",
                if (outcome.boundOk && !outcome.exposed) JOptionPane.INFORMATION_MESSAGE else JOptionPane.WARNING_MESSAGE
            )
        }
    }

    private fun persist(form: ServerSettings.RemoteForm) {
        val p = prefs
        p.setString(ServerSettings.PREF_BIND_HOST, form.bindHost.ifEmpty { BindHostPolicy.LOOPBACK })
        p.setBoolean(ServerSettings.PREF_ALLOW_REMOTE_BIND, form.allowRemoteBind)
        if (RemoteAccess.PREF_REQUIRE_AUTH !in overridden) p.setBoolean(RemoteAccess.PREF_REQUIRE_AUTH, form.requireAuth)
        if (RemoteAccess.PREF_AUTH_TOKEN !in overridden) p.setOrDelete(RemoteAccess.PREF_AUTH_TOKEN, form.token)
        if (RemoteAccess.PREF_ALLOWED_IPS !in overridden) p.setOrDelete(RemoteAccess.PREF_ALLOWED_IPS, form.allowedIps.joinToString(", "))
        if (RemoteAccess.PREF_ALLOWED_HOSTS !in overridden) p.setOrDelete(RemoteAccess.PREF_ALLOWED_HOSTS, form.allowedHosts.joinToString(", "))
    }

    private fun Preferences.setOrDelete(key: String, value: String) {
        if (value.isEmpty()) deleteString(key) else setString(key, value)
    }

    private fun setBusy(text: String) {
        saveBtn.isEnabled = false
        saveBtn.text = text
    }

    private fun setIdle() {
        saveBtn.isEnabled = true
        saveBtn.text = SAVE_LABEL
        updateUnsaved()
    }

    private fun loadLocalAddresses() {
        tasks.compute("List network interfaces", { NetworkHosts.local() }) { addresses ->
            localAddresses = addresses
            val text = bindHostCombo.editorText()
            bindHostCombo.model = DefaultComboBoxModel(ServerSettings.bindHostSuggestions(text, addresses).toTypedArray())
            bindHostCombo.selectedItem = text
            updateClientHosts(reset = false)
        }
    }

    private fun onBoundHostChanged(host: String) {
        boundHost = host
        val kind = ServerSettings.quickKind(host)
        if (kind != null) {
            boundKind = kind
            updateClientHosts(reset = true)
            return
        }
        boundKind = null
        updateClientHosts(reset = true)
        tasks.compute("Resolve bound host", { BindHostPolicy.classify(host) }) { resolved ->
            if (boundHost == host) {
                boundKind = resolved
                updateClientHosts(reset = true)
            }
        }
    }

    /** Rebuilds the client-host choices; [reset] (the listeners moved) drops what the operator typed. */
    private fun updateClientHosts(reset: Boolean) {
        val extraHosts = RemoteAccess.current.allowedHosts
        clientHostsSource = boundHost to extraHosts
        val hosts = ServerSettings.clientHosts(boundHost ?: BindHostPolicy.LOOPBACK, boundKind, localAddresses, extraHosts)
        val typed = clientHostCombo.editorText().trim()
        clientHostCombo.model = DefaultComboBoxModel(hosts.toTypedArray())
        clientHostCombo.selectedItem = if (reset || typed.isEmpty()) hosts.first() else typed
        renderClientConfig()
    }

    private fun clientHost(): String = clientHostCombo.editorText().trim().ifEmpty { boundHost ?: BindHostPolicy.LOOPBACK }

    /** The token clients must send now, or null while the listeners do not require one. */
    private fun liveToken(): String? = RemoteAccess.current.let { if (it.authRequired) it.token else null }

    /** Shows the config with the token masked; the copy buttons put the real one on the clipboard. */
    private fun renderClientConfig() {
        val host = clientHost()
        val token = liveToken()
        if (renderedConfig == host to token) return
        renderedConfig = host to token
        val shown = token?.let(ServerSettings::mask)
        configArea.text = ConnectionInfo.clientConfigJson(host = host, token = shown)
        commandArea.text = ConnectionInfo.claudeCodeCommand(host = host, token = shown)
        configNote.text = if (token != null) "Token hidden here; the Copy buttons include it." else "No token needed right now."
    }

    private fun showError(message: String, title: String) {
        JOptionPane.showMessageDialog(this, message, title, JOptionPane.ERROR_MESSAGE)
    }

    private fun prefString(key: String): String? = try { prefs.getString(key) } catch (_: Exception) { null }

    private fun prefBool(key: String): Boolean? = try { prefs.getBoolean(key) } catch (_: Exception) { null }

    private companion object {
        const val SAVE_LABEL = "Save & Rebind Now"
        val NUMBER_FORMAT: NumberFormat = NumberFormat.getIntegerInstance()

        fun hint(text: String) = TintedLabel(text) { RaijinTheme.muted() }.apply { font = font.deriveFont(11f) }

        fun flow(vararg components: Component) = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0)).apply {
            for (component in components) add(component)
        }

        fun toneColor(tone: ServerSettings.Tone) = when (tone) {
            ServerSettings.Tone.OK -> RaijinTheme.success()
            ServerSettings.Tone.WARN -> RaijinTheme.warning()
            ServerSettings.Tone.ERROR -> RaijinTheme.error()
            ServerSettings.Tone.MUTED -> RaijinTheme.muted()
        }
    }
}
