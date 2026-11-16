package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.core.BuildInfo
import io.bitbytelab.raijin.core.ConnectionInfo
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.transport.RemoteAccess
import kotlinx.serialization.json.*

/**
 * Bridge wrapping the Montoya Extension API and runtime state.
 *
 * Provides introspection into the Raijin extension itself:
 * its name, version, filename, registered handlers, active rules,
 * and MCP server information.
 */
class ExtensionBridge(
    private val api: MontoyaApi,
    private val stateManager: StateManager
) {

    /**
     * Returns comprehensive information about the Raijin extension
     * including runtime state, registered handlers, and MCP server details.
     */
    fun getInfo(): JsonObject {
        return try {
            val extension = api.extension()

            buildJsonObject {
                // Extension identity
                put("name", extension.filename() ?: "Raijin")
                put("filename", extension.filename() ?: "unknown")
                put("is_bapp", extension.isBapp())

                // MCP server info. Both ports serve Streamable HTTP at /mcp and legacy SSE at /.
                // The token itself is never reported, only whether one is required.
                val endpoints = ConnectionInfo.endpoints
                val remote = RemoteAccess.current
                put("mcp", buildJsonObject {
                    put("version", BuildInfo.VERSION)
                    put("bind_host", endpoints.host)
                    put("remote_exposed", RemoteAccess.exposed)
                    put("sse_port_primary", endpoints.primaryPort)
                    put("sse_port_secondary", endpoints.secondaryPort)
                    put("dashboard_port", endpoints.dashboardPort)
                    put("auth_required", remote.authRequired)
                    putJsonArray("allowed_ips") { remote.allowedIps.forEach { add(it) } }
                    putJsonArray("allowed_hosts") { remote.allowedHosts.forEach { add(it) } }
                    put("transports", buildJsonArray {
                        add("Streamable HTTP (${ConnectionInfo.MCP_PATH})")
                        add("SSE (legacy, /)")
                    })
                })

                // Burp Suite version
                val version = api.burpSuite().version()
                put("burp_version", buildJsonObject {
                    put("product", version.name())
                    put("major", version.major())
                    put("minor", version.minor())
                    put("build", version.build())
                    put("edition", version.edition().name)
                })

                // Runtime state summary
                put("state", buildJsonObject {
                    put("proxy_rules", stateManager.proxyRules.size)
                    put("traffic_rules", stateManager.trafficRules.size)
                    put("session_rules", stateManager.sessionRules.size)
                    put("websocket_connections", stateManager.websocketConnections.size)
                    put("active_scan_tasks", stateManager.scanTasks.size)
                    put("collaborator_clients", stateManager.collaboratorClients.size)
                    put("registered_scan_checks", stateManager.registeredScanChecks.size)
                    put("registered_payload_processors", stateManager.registeredPayloadProcessors.size)
                    put("websocket_intercept_rules", stateManager.websocketInterceptRules.size)
                })

                // Registered handler counts
                put("registered_handlers", buildJsonObject {
                    put("scan_checks", stateManager.registeredScanChecks.toList().let { checks ->
                        buildJsonArray { checks.forEach { add(it) } }
                    })
                    put("payload_processors", stateManager.registeredPayloadProcessors.toList().let { processors ->
                        buildJsonArray { processors.forEach { add(it) } }
                    })
                })
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to retrieve extension info: ${e.message}")
            }
        }
    }
}
