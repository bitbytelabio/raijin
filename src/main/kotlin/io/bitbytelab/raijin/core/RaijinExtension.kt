package io.bitbytelab.raijin.core

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.transport.ActivityStore
import io.bitbytelab.raijin.transport.AuditLog
import io.bitbytelab.raijin.transport.BindHostPolicy
import io.bitbytelab.raijin.transport.FindingsStore
import io.bitbytelab.raijin.transport.JsonlStoreSupport
import io.bitbytelab.raijin.transport.McpServerManager
import io.bitbytelab.raijin.transport.DashboardServer
import io.bitbytelab.raijin.transport.PortPolicy
import io.bitbytelab.raijin.transport.RemoteAccess
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.bridge.BridgeFactory
import io.bitbytelab.raijin.bridge.HttpPipelineConnectionRegistry
import io.bitbytelab.raijin.turbo.TurboModule
import io.bitbytelab.raijin.ui.RaijinTab
import io.bitbytelab.raijin.ui.RaijinTheme

class RaijinExtension : BurpExtension {
    private lateinit var api: MontoyaApi
    private lateinit var serverManager: McpServerManager
    private lateinit var dashboardServer: DashboardServer
    private lateinit var eventBus: EventBus
    private lateinit var stateManager: StateManager
    private lateinit var uiTab: RaijinTab
    private var activeBridges: BridgeFactory.Bridges? = null

    companion object {
        /**
         * Stable per-project storage key for [ActivityStore] and [FindingsStore].
         * Named projects keep their exact name for compatibility; unnamed / temporary
         * projects disambiguate via Montoya `project().id()` so distinct sessions don't collide.
         */
        fun projectKey(api: MontoyaApi): String {
            val name = try { api.project().name().orEmpty().trim() } catch (_: Exception) { "" }
            if (name.isNotEmpty()) return name
            val id = try { api.project().id().orEmpty().trim() } catch (_: Exception) { "" }
            return if (id.isNotEmpty()) "temp-$id" else "default"
        }
    }

    override fun initialize(api: MontoyaApi) {
        this.api = api
        api.extension().setName("Raijin")

        // Turbo engine: settings panel, context menus, hotkey (must precede the MCP bridges)
        TurboModule.install(api)
        RaijinTheme.init(api)

        // Initialize event bus with ring buffer capacity
        eventBus = EventBus(maxBufferSize = 10000)

        // Initialize centralized state manager
        stateManager = StateManager()

        // Register the unload handler EARLY — before anything binds a socket — with existence
        // guards, so that even if a later init step throws, Burp can still stop whatever started
        // and release the ports on the next reload. Without this, a partial init (e.g. a UI
        // exception after the servers started) orphans the listeners and the next load fails with
        // "Address already in use". Each step is guarded independently so one failure can't block
        // the rest of the teardown.
        api.extension().registerUnloadingHandler {
            try { if (::uiTab.isInitialized) uiTab.dispose() } catch (e: Exception) { api.logging().logToError("Raijin: uiTab dispose failed: ${e.message}") }
            try { if (::dashboardServer.isInitialized) dashboardServer.stop() } catch (e: Exception) { api.logging().logToError("Raijin: dashboard stop failed: ${e.message}") }
            try { if (::serverManager.isInitialized) serverManager.stop() } catch (e: Exception) { api.logging().logToError("Raijin: server stop failed: ${e.message}") }
            try { activeBridges?.shutdown() } catch (e: Exception) { api.logging().logToError("Raijin: bridges shutdown failed: ${e.message}") }
            try { io.bitbytelab.raijin.safety.BoundedHttp.shutdown() } catch (e: Exception) { api.logging().logToError("Raijin: BoundedHttp shutdown failed: ${e.message}") }
            try { TurboModule.uninstall() } catch (e: Exception) { api.logging().logToError("Raijin: turbo shutdown failed: ${e.message}") }
            try { HttpPipelineConnectionRegistry.shutdownAll() } catch (e: Exception) { api.logging().logToError("Raijin: pipeline registry shutdown failed: ${e.message}") }
            try { eventBus.clearAll() } catch (_: Exception) {}
            try { stateManager.cleanup() } catch (_: Exception) {}
            JsonlStoreSupport.errorSink = null
            api.logging().logToOutput("Raijin: Extension unloaded")
        }

        // Disk-store failures (activity, findings, audit log) reach Burp's error log, once per
        // distinct failure until the store recovers, whichever thread hit them.
        JsonlStoreSupport.errorSink = { message -> api.logging().logToError(message) }

        // Restore the dashboard MCP activity from the durable store so it survives extension
        // reloads / Burp restarts / crashes (the in-memory deque + EventBus are otherwise lost
        // on every reload, wiping the dashboard). Repopulates the Swing tab (via the deque) AND
        // the web dashboard (by re-seeding the EventBus ring buffer with the historical events).
        try {
            val projectName = projectKey(api)
            // Persistence is operator-controlled (pref mcp_persist_activity, default ON — issue #8).
            // When OFF, don't restore the saved history and don't write new entries (session-only).
            ActivityStore.enabled =
                try { api.persistence().preferences().getBoolean("mcp_persist_activity") } catch (_: Exception) { null } ?: true
            if (ActivityStore.enabled) {
                val restored = ActivityStore.load(projectName, stateManager.activityCapacity)
                stateManager.restoreMcpActivity(restored)
                restored.asReversed().forEach { e -> eventBus.emit("tool.called", ActivityStore.toEventData(e)) }
                ActivityStore.compact(ActivityStore.MAX_LINES)
                api.logging().logToOutput("Raijin: restored ${restored.size} dashboard activity entries (project: $projectName); persistence ON → ${ActivityStore.path()}")
            } else {
                api.logging().logToOutput("Raijin: MCP activity persistence is OFF (session only) — toggle it on the Server tab")
            }
            // Listener is always registered; ActivityStore.append() no-ops while persistence is OFF.
            stateManager.mcpActivityListeners.add { entry -> ActivityStore.append(entry, projectName) }
        } catch (e: Exception) {
            api.logging().logToError("Raijin: activity restore failed: ${e.message}")
        }

        // Restore the agent's findings working memory from its durable store. Without this,
        // findings only lived in memory and were wiped by cleanup() on every extension
        // reload/Burp restart — while the (persisted) MCP activity log still showed the
        // historical findings_add calls, making it look like the findings vanished for no
        // reason. FindingsBridge.add() appends new ones via the listener below.
        try {
            val projectName = projectKey(api)
            val restoredFindings = FindingsStore.load(projectName)
            if (restoredFindings.isNotEmpty()) stateManager.restoreFindings(restoredFindings)
            stateManager.findingsListeners.add { f -> FindingsStore.append(f, projectName) }
            // The snapshot is taken under the store's lock, so a finding added concurrently is not lost.
            stateManager.findingsRemoveListeners.add { _ ->
                FindingsStore.replaceProject(projectName) { stateManager.findings.toList() }
            }
            api.logging().logToOutput(
                "Raijin: restored ${restoredFindings.size} agent finding(s) (project: ${projectName.ifEmpty { "default" }}); store → ${FindingsStore.path()}"
            )
        } catch (e: Exception) {
            api.logging().logToError("Raijin: findings restore failed: ${e.message}")
        }

        // On loopback MCP clients connect with the URL alone: browser-borne attacks are stopped by
        // the Host/Origin checks in SecurityConfig. A non-loopback bind (operator opt-in, see
        // BindHostPolicy) or mcp_require_auth adds the bearer token and the allowlists (RemoteAccess).
        val prefs = api.persistence().preferences()

        // Configurable bind host (GitHub issue #4). The requested host comes from a JVM system
        // property (ops override), else a persisted Burp preference, else loopback. It is then
        // passed through the SECURITY GATE: a non-loopback bind exposes 149 Burp-driving tools to
        // the network, so it is only honored when the operator has explicitly opted in
        // (mcp_allow_remote_bind / -Draijin.allowRemoteBind). Otherwise it is refused and
        // downgraded back to loopback. See BindHostPolicy.
        val requestedHost = System.getProperty("raijin.bindHost")?.trim()?.ifEmpty { null }
            ?: prefs.getString("mcp_bind_host")?.trim()?.ifEmpty { null }
            ?: "127.0.0.1"
        val allowRemoteBind = System.getProperty("raijin.allowRemoteBind")?.toBooleanStrictOrNull()
            ?: (try { prefs.getBoolean("mcp_allow_remote_bind") } catch (_: Exception) { null } ?: false)
        val bindDecision = BindHostPolicy.resolve(requestedHost, allowRemoteBind)
        val bindHost = bindDecision.effectiveHost

        // Installed before any listener starts, so the first request is already checked.
        logRemoteAccess(applyRemoteAccess(bindDecision.exposed))

        // Create all bridge instances via factory
        val bridges = BridgeFactory.createAll(api, eventBus, stateManager).also { activeBridges = it }

        // Initialize the MCP + dashboard servers. From here on a socket may be bound, so if ANY
        // later init step throws we must stop them (see the early unload handler above) — otherwise
        // the partially-initialized instance orphans its listeners and the next reload fails with
        // "Address already in use".
        // Configurable ports, resolved on the same ladder as the bind host (system property, then
        // preference, then default). PortSwigger's own "MCP Server" extension also defaults to
        // 9876, so an operator running both needs a way out of the clash. See PortPolicy.
        fun port(sysProp: String, prefKey: String, default: Int): Int = PortPolicy.resolve(
            System.getProperty(sysProp),
            try { prefs.getString(prefKey) } catch (_: Exception) { null },
            default
        )
        // Two listeners configured on one port would leave one of them unable to bind; move it.
        val ports = PortPolicy.resolveDistinct(
            port("raijin.ssePort", PortPolicy.PREF_SSE_PORT, PortPolicy.DEFAULT_SSE),
            port("raijin.httpPort", PortPolicy.PREF_HTTP_PORT, PortPolicy.DEFAULT_HTTP),
            port("raijin.dashboardPort", PortPolicy.PREF_DASHBOARD_PORT, PortPolicy.DEFAULT_DASHBOARD)
        )
        ports.messages.forEach { msg -> api.logging().logToError(msg) }
        val ssePort = ports.ssePort
        val httpPort = ports.httpPort
        val dashboardPort = ports.dashboardPort
        ConnectionInfo.publish(ConnectionInfo.Endpoints(bindHost, ssePort, httpPort, dashboardPort))

        serverManager = McpServerManager(
            bridges = bridges,
            eventBus = eventBus,
            stateManager = stateManager,
            bindHost = bindHost,
            ssePort = ssePort,
            httpPort = httpPort,
            logging = api.logging()
        )
        dashboardServer = DashboardServer(
            bridges, eventBus, stateManager, bindHost, dashboardPort, api.logging(),
            primaryMcpPort = ssePort, secondaryMcpPort = httpPort
        )
        try {
            serverManager.start()
            dashboardServer.start()

            // Register Burp Suite event handlers for proxy, scanner, scope, websocket, and HTTP traffic
            registerBurpHandlers(bridges)

            // Initialize and register the UI tab
            uiTab = RaijinTab(api, serverManager, eventBus, stateManager, bridges, bindHost, ::rebindServers)
            api.userInterface().registerSuiteTab("Raijin", uiTab.getComponent())
        } catch (t: Throwable) {
            api.logging().logToError(
                "Raijin: initialization failed after the servers started — stopping them so " +
                    "the ports are released (avoids orphaned listeners): ${t.message}"
            )
            try { dashboardServer.stop() } catch (_: Exception) {}
            try { serverManager.stop() } catch (_: Exception) {}
            throw t
        }

        // Single startup banner with REAL counts. uiTab.log() also writes to Burp's
        // output log, so one channel covers both surfaces.
        val (toolCount, resourceCount, promptCount) = serverManager.registeredCounts()
        uiTab.log("INFO", "System", "Raijin v${BuildInfo.VERSION} started")
        uiTab.log("INFO", "System", "MCP (primary):   ${ConnectionInfo.mcpUrl(ssePort, bindHost)}  (legacy SSE: ${ConnectionInfo.legacySseUrl(ssePort, bindHost)})")
        uiTab.log("INFO", "System", "MCP (secondary): ${ConnectionInfo.mcpUrl(httpPort, bindHost)}")
        uiTab.log("INFO", "System", "Dashboard:                 ${ConnectionInfo.dashboardUrlForHost(bindHost)}")
        uiTab.log("INFO", "System", "Tools: $toolCount  |  MCP Resources: $resourceCount  |  MCP Prompts: $promptCount")
        api.logging().raiseInfoEvent("Raijin v${BuildInfo.VERSION} started on $bindHost (SSE $ssePort/$httpPort, dashboard $dashboardPort)")

        // Surface the bind-host gate decision. A refused (downgraded) request and — especially —
        // an honored network exposure are security-relevant, so warn loudly and leave a durable
        // audit-log entry an operator can reconstruct later.
        if (bindDecision.downgraded) {
            val msg = bindDecision.message ?: "requested bind host was refused; using loopback"
            // A warning about a deliberate/edge choice, not a failure — Output tab, not Errors.
            api.logging().logToOutput("Raijin: ⚠ $msg")
            uiTab.log("WARN", "System", msg)
        }
        if (bindDecision.exposed) {
            val msg = "SECURITY: ${bindDecision.message}"
            // Loud, but it's an operator-chosen exposure warning — Output tab, not Errors.
            api.logging().logToOutput("Raijin: ⚠ $msg")
            uiTab.log("WARN", "System", msg)
            AuditLog.record(
                toolName = "server.remote_bind",
                timestampIso = java.time.Instant.now().toString(),
                durationMs = 0, isError = false, args = null,
                url = "", host = bindHost, method = "", statusCode = 0
            )
        }

        uiTab.log("INFO", "System", "Ready-to-paste MCP client config: Raijin -> Server tab.")
    }

    /**
     * Live (no-reload) rebind of all three servers to [requestedHost], triggered by the Server-tab
     * "Save & Rebind Now" button. Runs the same [BindHostPolicy] gate as startup, re-reads the
     * remote-access settings (token, allowlists) the tab saved, restarts the transports, and — on a
     * network exposure — warns loudly and writes a durable audit entry, exactly as the startup path
     * does. Called OFF the Swing EDT by the UI.
     */
    private fun rebindServers(requestedHost: String, allowRemoteBind: Boolean): RebindOutcome {
        val d = BindHostPolicy.resolve(requestedHost, allowRemoteBind)
        // Before the new listeners open, so an exposed bind is never served without its token.
        logRemoteAccess(applyRemoteAccess(d.exposed))
        ConnectionInfo.publish(ConnectionInfo.endpoints.copy(host = d.effectiveHost))
        val boundOk = try {
            val ok = serverManager.rebind(d.effectiveHost)
            dashboardServer.rebind(d.effectiveHost)
            ok
        } catch (e: Exception) {
            api.logging().logToError("Raijin: live rebind to ${d.effectiveHost} failed: ${e.message}")
            false
        }
        if (d.downgraded) {
            api.logging().logToOutput("Raijin: ⚠ ${d.message}")
        }
        if (d.exposed) {
            api.logging().logToOutput("Raijin: ⚠ SECURITY: ${d.message}")
            AuditLog.record(
                toolName = "server.remote_bind",
                timestampIso = java.time.Instant.now().toString(),
                durationMs = 0, isError = false, args = null,
                url = "", host = d.effectiveHost, method = "", statusCode = 0
            )
        }
        api.logging().logToOutput(
            "Raijin: live rebind to ${d.effectiveHost} — ${if (boundOk) "listening" else "NOT listening (check for a bind error)"}"
        )
        return RebindOutcome(d.effectiveHost, d.exposed, d.downgraded, boundOk, d.message)
    }

    /**
     * Resolves the remote-access settings (Burp preferences, then `-Draijin.*`) for a bind that is
     * [exposed], saves a generated token and installs the result. Returns (level, message) lines to
     * log; none of them contains the token.
     */
    private fun applyRemoteAccess(exposed: Boolean): List<Pair<String, String>> {
        val resolved = RemoteAccess.applyFromPreferences(api.persistence().preferences(), exposed)
        val config = resolved.config
        val lines = mutableListOf<Pair<String, String>>()
        if (config.authRequired) {
            val reason = if (exposed) "the listeners bind a non-loopback address" else "${RemoteAccess.PREF_REQUIRE_AUTH} is on"
            lines += "INFO" to "Remote access: a bearer token is required ($reason). Clients send " +
                "'Authorization: Bearer <token>'; the token is on the Raijin Server tab (preference " +
                "${RemoteAccess.PREF_AUTH_TOKEN})" + if (resolved.generatedToken) ", newly generated and saved." else "."
        }
        if (config.allowedIps.isNotEmpty()) {
            lines += "INFO" to "Remote access: source IP allowlist ${config.allowedIps.joinToString(", ")} (loopback always allowed)."
        }
        if (config.allowedHosts.isNotEmpty()) {
            lines += "INFO" to "Remote access: extra allowed hosts ${config.allowedHosts.joinToString(", ")}."
        }
        RemoteAccess.warnings(config, exposed).forEach { lines += "WARN" to "Remote access: $it" }
        return lines
    }

    private fun logRemoteAccess(lines: List<Pair<String, String>>) {
        lines.forEach { (level, message) ->
            if (::uiTab.isInitialized) uiTab.log(level, "System", message)
            else api.logging().logToOutput(if (level == "WARN") "Raijin [WARN/System]: $message" else "Raijin: $message")
        }
    }

    private fun registerBurpHandlers(bridges: BridgeFactory.Bridges) {
        // Register proxy request/response handlers for event collection
        api.proxy().registerRequestHandler(bridges.proxy.createRequestHandler())
        api.proxy().registerResponseHandler(bridges.proxy.createResponseHandler())

        // Register scanner audit issue handler (Pro edition only)
        try {
            api.scanner().registerAuditIssueHandler(bridges.scanner.createIssueHandler())
        } catch (e: Exception) {
            api.logging().logToOutput(
                "Raijin: Scanner handler not available (Community Edition?)"
            )
        }

        // Register scope change handler for live scope tracking
        api.scope().registerScopeChangeHandler(bridges.scope.createScopeChangeHandler())

        // Register WebSocket creation handler
        api.websockets().registerWebSocketCreatedHandler(
            bridges.websocket.createWebSocketHandler()
        )

        // Register global HTTP handler for traffic interception rules
        api.http().registerHttpHandler(bridges.http.createGlobalHttpHandler())
    }
}
