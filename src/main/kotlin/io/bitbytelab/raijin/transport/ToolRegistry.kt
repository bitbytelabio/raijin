package io.bitbytelab.raijin.transport

import io.bitbytelab.raijin.bridge.BridgeFactory
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.tools.proxy.ProxyTools
import io.bitbytelab.raijin.tools.http.HttpTools
import io.bitbytelab.raijin.tools.scanner.ScannerTools
import io.bitbytelab.raijin.tools.collaborator.CollaboratorTools
import io.bitbytelab.raijin.tools.repeater.RepeaterTools
import io.bitbytelab.raijin.tools.intruder.IntruderTools
import io.bitbytelab.raijin.tools.sitemap.SitemapTools
import io.bitbytelab.raijin.tools.scope.ScopeTools
import io.bitbytelab.raijin.tools.comparer.ComparerTools
import io.bitbytelab.raijin.tools.decoder.DecoderTools
import io.bitbytelab.raijin.tools.organizer.OrganizerTools
import io.bitbytelab.raijin.tools.turbo.TurboTools
import io.bitbytelab.raijin.tools.websocket.WebSocketTools
import io.bitbytelab.raijin.tools.burpsuite.BurpSuiteTools
import io.bitbytelab.raijin.tools.utilities.UtilitiesTools
import io.bitbytelab.raijin.tools.ai.AiTools
import io.bitbytelab.raijin.tools.bambda.BambdaTools
import io.bitbytelab.raijin.tools.persistence.PersistenceTools
import io.bitbytelab.raijin.tools.project.ProjectTools
import io.bitbytelab.raijin.tools.logging.LoggingTools
import io.bitbytelab.raijin.tools.events.EventsTools
import io.bitbytelab.raijin.tools.analysis.AnalysisTools
import io.bitbytelab.raijin.tools.config.ConfigTools
import io.bitbytelab.raijin.tools.session.SessionTools
import io.bitbytelab.raijin.tools.extension.ExtensionTools
import io.bitbytelab.raijin.tools.bcheck.BCheckTools
import io.bitbytelab.raijin.tools.scancheck.ScanCheckTools
import io.bitbytelab.raijin.tools.authdiff.AuthDiffTools
import io.bitbytelab.raijin.tools.apiimport.ApiImportTools
import io.bitbytelab.raijin.tools.passiveintel.PassiveIntelTools
import io.bitbytelab.raijin.tools.jwt.JwtTools
import io.bitbytelab.raijin.tools.findings.FindingsTools
import io.bitbytelab.raijin.tools.recon.ReconTools
import io.bitbytelab.raijin.tools.graphql.GraphQlTools
import io.bitbytelab.raijin.tools.webprobe.WebProbeTools
import io.bitbytelab.raijin.tools.accesscontrol.AccessControlTools
import io.bitbytelab.raijin.tools.injection.InjectionTools
import io.bitbytelab.raijin.tools.idor.IdorTools
import io.bitbytelab.raijin.tools.skills.SkillTools
import io.bitbytelab.raijin.tools.ToolConsolidation
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities

/**
 * Central registry that wires every MCP tool onto an MCP [Server].
 *
 * Each tool category is implemented as a standalone object with a
 * `register(server, bridge, ...)` function. This keeps tool definitions
 * modular while giving the registry a single place to invoke them all.
 *
 * The authoritative tool count is `server.tools.size` after [registerAll]
 * (exposed via [McpServerManager.registeredCounts]); do not hardcode a number
 * here — earlier copies drifted to 137/134/121 and lied to operators.
 */
object ToolRegistry {

    /**
     * Registers all tool categories on the given MCP [server].
     * Called once per server instance during [McpServerManager.createMcpServer].
     */
    fun registerAll(
        server: Server,
        bridges: BridgeFactory.Bridges,
        eventBus: EventBus,
        stateManager: StateManager
    ) {
        // Tools register one by one onto a scratch server; ToolConsolidation then publishes them
        // on the real server with families folded into `action` tools (see its KDoc).
        val scratch = Server(
            Implementation(name = "raijin-scratch", version = "0"),
            ServerOptions(ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false)))
        )
        registerMembers(scratch, bridges, eventBus, stateManager)
        ToolConsolidation.apply(scratch, server)
    }

    private fun registerMembers(
        server: Server,
        bridges: BridgeFactory.Bridges,
        eventBus: EventBus,
        stateManager: StateManager
    ) {
        // Proxy tools: history, intercept, rules, WebSocket proxy
        ProxyTools.register(server, bridges.proxy, stateManager)

        // HTTP tools: send request, request builder, traffic rules
        HttpTools.register(server, bridges.http, stateManager)

        // Scanner tools: active/passive scan, crawl, audit issues
        ScannerTools.register(server, bridges.scanner, stateManager)

        // Collaborator tools: create client, generate payloads, poll interactions
        CollaboratorTools.register(server, bridges.collaborator, stateManager)

        // Repeater tools: send to repeater, create tab, send request
        RepeaterTools.register(server, bridges.repeater)

        // Intruder tools: create attack, configure payloads, start/stop
        IntruderTools.register(server, bridges.intruder, stateManager)

        // Sitemap tools: get tree, filter, add items
        SitemapTools.register(server, bridges.sitemap)

        // Scope tools: include/exclude, check, get/set
        ScopeTools.register(server, bridges.scope)

        // Comparer tools: compare requests/responses
        ComparerTools.register(server, bridges.comparer)

        // Decoder tools: encode, decode, hash, smart decode
        DecoderTools.register(server, bridges.decoder)

        // Organizer tools: add notes, get items, manage
        OrganizerTools.register(server, bridges.organizer)

        // Turbo tools: scripted high-speed runs (single-packet race, H2/H3 gates, desync)
        TurboTools.register(server, bridges.turbo)

        // WebSocket tools: connect, send, receive, intercept
        WebSocketTools.register(server, bridges.websocket, stateManager)

        // BurpSuite tools: version, product info, config
        BurpSuiteTools.register(server, bridges.burpSuite)

        // Utilities tools: URL analysis, regex, diff, timing
        UtilitiesTools.register(server, bridges.utilities)

        // AI tools: Montoya AI integration (Burp 2025+)
        AiTools.register(server, bridges.ai)

        // Bambda tools: evaluate, list, manage Bambda expressions
        BambdaTools.register(server, bridges.bambda)

        // Persistence tools: get/set/delete extension data
        PersistenceTools.register(server, bridges.persistence)

        // Project tools: project info, data, export
        ProjectTools.register(server, bridges.project)

        // Logging tools: log events, get logs, configure
        LoggingTools.register(server, bridges.logging)

        // Events tools: poll, subscribe, filter events
        EventsTools.register(server, eventBus)

        // Analysis tools: cross-bridge analysis and reporting
        AnalysisTools.register(server, bridges)

        // Config tools: get/set project and user config
        ConfigTools.register(server, bridges.burpSuite)

        // Session tools: session rules, token extraction/injection
        SessionTools.register(server, bridges.http, stateManager)

        // Extension tools: extension info, registered handlers, state
        ExtensionTools.register(server, bridges.extension)

        // BCheck tools: create, import, templates, list, remove BCheck scan checks
        BCheckTools.register(server, bridges.bcheck)

        // ScanCheck tools: Script-mode scan checks via Montoya ScanCheck API
        ScanCheckTools.register(server, bridges.scanCheck)

        // AuthDiff tools: auth level diffing for IDOR/privilege escalation detection
        AuthDiffTools.register(server, bridges)

        // API Import tools: import OpenAPI/Swagger specs to generate requests
        ApiImportTools.register(server, bridges.apiImport)

        // Passive Intel tools: scan proxy history for leaked secrets, tokens, internal URLs, etc.
        PassiveIntelTools.register(server, bridges.passiveIntel)

        // JWT tools: analyze/forge/crack JSON Web Tokens (alg:none, RS->HS confusion, weak-secret crack)
        JwtTools.register(server, bridges.jwt)

        // Findings store: the agent's deduplicated working memory of issues (add/list)
        FindingsTools.register(server, bridges.findings)

        // Recon: JS endpoint harvest, content discovery, param mining (scope-gated)
        ReconTools.register(server, bridges.recon)

        // GraphQL: introspection + field-suggestion enumeration (scope-gated)
        GraphQlTools.register(server, bridges.graphql)

        // Web misconfig recon: CORS probing + tech/WAF fingerprinting (scope-gated)
        WebProbeTools.register(server, bridges.webProbe)

        // Access-control sweep: batch broken-access-control / IDOR across identities (scope-gated)
        AccessControlTools.register(server, bridges.accessControl)

        // Injection probe: guided sqli/ssti/lfi detection with confirmation oracles (scope-gated)
        InjectionTools.register(server, bridges.injection)

        // IDOR hunt: horizontal object-id swap with canary confirmation (scope-gated)
        IdorTools.register(server, bridges.idorHunt)

        // Skills: usage guides a client loads on demand (skill_list / skill_get)
        SkillTools.register(server)
    }
}
