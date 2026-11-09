package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive

class BridgeFactory {

    /**
     * Container holding all bridge instances. Each bridge wraps a specific
     * area of the Montoya API and exposes MCP-friendly methods.
     */
    data class Bridges(
        val proxy: ProxyBridge,
        val http: HttpBridge,
        val scanner: ScannerBridge,
        val collaborator: CollaboratorBridge,
        val repeater: RepeaterBridge,
        val intruder: IntruderBridge,
        val sitemap: SitemapBridge,
        val scope: ScopeBridge,
        val comparer: ComparerBridge,
        val decoder: DecoderBridge,
        val organizer: OrganizerBridge,
        val turbo: TurboBridge,
        val websocket: WebSocketBridge,
        val burpSuite: BurpSuiteBridge,
        val utilities: UtilitiesBridge,
        val ai: AiBridge,
        val bambda: BambdaBridge,
        val persistence: PersistenceBridge,
        val project: ProjectBridge,
        val logging: LoggingBridge,
        val extension: ExtensionBridge,
        val bcheck: BCheckBridge,
        val scanCheck: ScanCheckBridge,
        val apiImport: ApiImportBridge,
        val passiveIntel: PassiveIntelBridge,
        val analysis: AnalysisBridge,
        val jwt: JwtBridge,
        val findings: FindingsBridge,
        val recon: ReconBridge,
        val graphql: GraphQlBridge,
        val webProbe: WebProbeBridge,
        val accessControl: AccessControlBridge,
        val injection: InjectionBridge,
        val idorHunt: IdorHuntBridge,
        val autorize: AutorizeBridge
    )

    companion object {
        /**
         * Creates all bridge instances in one shot. Bridges that need event
         * emission or state tracking receive the shared [eventBus] and
         * [stateManager] references; bridges that are stateless only
         * receive the Montoya [api].
         */
        fun createAll(
            api: MontoyaApi,
            eventBus: EventBus,
            stateManager: StateManager
        ): Bridges {
            val persistence = PersistenceBridge(api)
            val findings = FindingsBridge(stateManager)
            return Bridges(
                proxy = ProxyBridge(api, eventBus, stateManager, findings),
                http = HttpBridge(api, eventBus, stateManager),
                scanner = ScannerBridge(api, eventBus, stateManager),
                collaborator = CollaboratorBridge(api, eventBus, stateManager),
                repeater = RepeaterBridge(api),
                intruder = IntruderBridge(api, stateManager),
                sitemap = SitemapBridge(api),
                scope = ScopeBridge(api, eventBus),
                comparer = ComparerBridge(api),
                decoder = DecoderBridge(api),
                organizer = OrganizerBridge(api),
                turbo = TurboBridge(),
                websocket = WebSocketBridge(api, eventBus, stateManager),
                burpSuite = BurpSuiteBridge(api),
                utilities = UtilitiesBridge(api),
                ai = AiBridge(api),
                bambda = BambdaBridge(api),
                persistence = persistence,
                project = ProjectBridge(api),
                logging = LoggingBridge(api),
                extension = ExtensionBridge(api, stateManager),
                bcheck = BCheckBridge(api, stateManager),
                scanCheck = ScanCheckBridge(api, stateManager),
                apiImport = ApiImportBridge(api, stateManager),
                passiveIntel = PassiveIntelBridge(api),
                analysis = AnalysisBridge(api),
                jwt = JwtBridge(
                    load = {
                        val stored = persistence.get(JwtBridge.PERSIST_KEY)
                        val found = stored["found"]?.jsonPrimitive?.contentOrNull == "true"
                        if (found) stored["value"]?.jsonPrimitive?.contentOrNull else null
                    },
                    save = { value -> persistence.store(JwtBridge.PERSIST_KEY, value) },
                ),
                findings = findings,
                recon = ReconBridge(api),
                graphql = GraphQlBridge(api),
                webProbe = WebProbeBridge(api),
                accessControl = AccessControlBridge(api),
                injection = InjectionBridge(api),
                idorHunt = IdorHuntBridge(api),
                autorize = AutorizeBridge(stateManager)
            )
        }
    }
}
