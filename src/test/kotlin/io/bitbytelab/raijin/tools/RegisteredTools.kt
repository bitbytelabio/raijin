package io.bitbytelab.raijin.tools

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.bridge.AccessControlBridge
import io.bitbytelab.raijin.bridge.AiBridge
import io.bitbytelab.raijin.bridge.AnalysisBridge
import io.bitbytelab.raijin.bridge.ApiImportBridge
import io.bitbytelab.raijin.bridge.AutorizeBridge
import io.bitbytelab.raijin.bridge.BCheckBridge
import io.bitbytelab.raijin.bridge.BambdaBridge
import io.bitbytelab.raijin.bridge.BridgeFactory
import io.bitbytelab.raijin.bridge.BurpSuiteBridge
import io.bitbytelab.raijin.bridge.CollaboratorBridge
import io.bitbytelab.raijin.bridge.ComparerBridge
import io.bitbytelab.raijin.bridge.ConfigBridge
import io.bitbytelab.raijin.bridge.DecoderBridge
import io.bitbytelab.raijin.bridge.ExtensionBridge
import io.bitbytelab.raijin.bridge.FindingsBridge
import io.bitbytelab.raijin.bridge.GraphQlBridge
import io.bitbytelab.raijin.bridge.HttpBridge
import io.bitbytelab.raijin.bridge.IdorHuntBridge
import io.bitbytelab.raijin.bridge.InjectionBridge
import io.bitbytelab.raijin.bridge.IntruderBridge
import io.bitbytelab.raijin.bridge.JwtBridge
import io.bitbytelab.raijin.bridge.LoggingBridge
import io.bitbytelab.raijin.bridge.OrganizerBridge
import io.bitbytelab.raijin.bridge.PassiveIntelBridge
import io.bitbytelab.raijin.bridge.PersistenceBridge
import io.bitbytelab.raijin.bridge.ProjectBridge
import io.bitbytelab.raijin.bridge.ProxyBridge
import io.bitbytelab.raijin.bridge.ReconBridge
import io.bitbytelab.raijin.bridge.RepeaterBridge
import io.bitbytelab.raijin.bridge.ScanCheckBridge
import io.bitbytelab.raijin.bridge.ScannerBridge
import io.bitbytelab.raijin.bridge.ScopeBridge
import io.bitbytelab.raijin.bridge.SitemapBridge
import io.bitbytelab.raijin.bridge.TurboBridge
import io.bitbytelab.raijin.bridge.UtilitiesBridge
import io.bitbytelab.raijin.bridge.WebProbeBridge
import io.bitbytelab.raijin.bridge.WebSocketBridge
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.transport.ToolRegistry
import io.bitbytelab.raijin.turbo.mcp.BurpCollaboratorProvider
import io.bitbytelab.raijin.turbo.mcp.RunManager
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import java.lang.reflect.Proxy

/**
 * Raijin's tools registered as the extension registers them, on a Montoya stand-in whose every call
 * returns null, so no Burp has to run. Registering a tool calls no Burp API; calling one may, so
 * these servers are for checking schemas and dispatch.
 *
 * - [members]: the fine-grained tools, as each `XxxTools.register` defines them
 *   ([ToolRegistry.registerMembers]).
 * - [published]: what an MCP client lists ([ToolRegistry.registerAll]: the members folded into
 *   `action` tools by [ToolConsolidation]).
 *
 * The bridges are [BridgeFactory.createAll]'s, except that none reads or writes the user's files or
 * shared state: Autorize matches are not restored, Turbo runs go to a run manager of their own and
 * the Collaborator bridge to a provider of its own. [close] stops the bridges' background threads.
 */
internal class RegisteredTools : AutoCloseable {

    private val eventBus = EventBus()
    private val state = StateManager()
    private val bridges = bridges(nullMontoyaApi(), eventBus, state)

    val members: Server = mcpServer().also { ToolRegistry.registerMembers(it, bridges, eventBus, state) }

    val published: Server by lazy { mcpServer().also { ToolRegistry.registerAll(it, bridges, eventBus, state) } }

    override fun close() = bridges.shutdown()

    private companion object {

        fun mcpServer() = Server(
            Implementation("raijin-test", "0"),
            ServerOptions(ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false))),
        )

        /** Montoya API whose every call returns null, `Object`'s own methods aside. */
        fun nullMontoyaApi(): MontoyaApi =
            Proxy.newProxyInstance(MontoyaApi::class.java.classLoader, arrayOf(MontoyaApi::class.java)) { proxy, method, args ->
                when (method.name) {
                    "hashCode" -> System.identityHashCode(proxy)
                    "equals" -> proxy === args?.firstOrNull()
                    "toString" -> "MontoyaApi stand-in"
                    else -> null
                }
            } as MontoyaApi

        fun bridges(api: MontoyaApi, eventBus: EventBus, state: StateManager): BridgeFactory.Bridges {
            val findings = FindingsBridge(state)
            return BridgeFactory.Bridges(
                proxy = ProxyBridge(api, eventBus, state, findings, autorizeStore = null),
                http = HttpBridge(api, eventBus, state),
                scanner = ScannerBridge(api, eventBus, state),
                collaborator = CollaboratorBridge(api, eventBus, state, BurpCollaboratorProvider(BurpCollaboratorProvider.State())),
                repeater = RepeaterBridge(api),
                intruder = IntruderBridge(api, state),
                sitemap = SitemapBridge(api),
                scope = ScopeBridge(api, eventBus),
                comparer = ComparerBridge(api),
                decoder = DecoderBridge(api),
                organizer = OrganizerBridge(api),
                turbo = TurboBridge(RunManager()),
                websocket = WebSocketBridge(api, eventBus, state),
                burpSuite = BurpSuiteBridge(api),
                utilities = UtilitiesBridge(api),
                ai = AiBridge(api),
                bambda = BambdaBridge(api),
                persistence = PersistenceBridge(api),
                project = ProjectBridge(api),
                logging = LoggingBridge(api),
                extension = ExtensionBridge(api, state),
                bcheck = BCheckBridge(api, state),
                scanCheck = ScanCheckBridge(api, state),
                apiImport = ApiImportBridge(api, state),
                passiveIntel = PassiveIntelBridge(api),
                analysis = AnalysisBridge(api),
                jwt = JwtBridge(),
                findings = findings,
                recon = ReconBridge(api),
                graphql = GraphQlBridge(api),
                webProbe = WebProbeBridge(api),
                accessControl = AccessControlBridge(api),
                injection = InjectionBridge(api),
                idorHunt = IdorHuntBridge(api),
                autorize = AutorizeBridge(state),
                config = ConfigBridge(api),
            )
        }
    }
}
