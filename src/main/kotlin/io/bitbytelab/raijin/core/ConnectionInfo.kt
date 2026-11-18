package io.bitbytelab.raijin.core

import io.bitbytelab.raijin.transport.SecurityConfig
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import java.net.URLEncoder

/**
 * Single source of truth for how MCP clients connect to Raijin. Used by the dashboard, the
 * Server UI tab (and mirrored in the README/configs) so the connection details can never drift.
 *
 * Invariants:
 *  1. Clients connect over Streamable HTTP at [MCP_PATH] (`/mcp`). The legacy SSE transport
 *     still answers at the root path `/` (never `/sse`) for old configs.
 *  2. On loopback there is **no token**: clients connect with the URL alone. Once remote access
 *     requires one, the client sends `Authorization: Bearer <token>` (pass `token` below).
 */
object ConnectionInfo {
    const val PRIMARY_PORT = 9876
    const val SECONDARY_PORT = 9877
    const val DASHBOARD_PORT = 9878

    /** MCP server name used in client configs. */
    const val SERVER_NAME = "burpsuite"

    /** Path of the Streamable HTTP endpoint. */
    const val MCP_PATH = "/mcp"

    /**
     * Where the listeners actually run: the effective bind host and the resolved ports. The
     * defaults hold until the extension publishes the real values at startup and on rebind.
     */
    data class Endpoints(
        val host: String = "127.0.0.1",
        val primaryPort: Int = PRIMARY_PORT,
        val secondaryPort: Int = SECONDARY_PORT,
        val dashboardPort: Int = DASHBOARD_PORT
    )

    @Volatile
    var endpoints: Endpoints = Endpoints()
        private set

    fun publish(endpoints: Endpoints) {
        this.endpoints = endpoints
    }

    /** The Streamable HTTP endpoint URL for [port] on [host]. */
    fun mcpUrl(port: Int, host: String = "127.0.0.1"): String = "http://${authority(host)}:$port$MCP_PATH"

    val primaryMcpUrl: String get() = mcpUrl(endpoints.primaryPort)
    val secondaryMcpUrl: String get() = mcpUrl(endpoints.secondaryPort)
    val dashboardUrl: String get() = dashboardUrlForHost()

    // Host-aware variants — every displayed endpoint reflects the interface the servers bound to.
    fun primaryMcpUrlForHost(host: String): String = mcpUrl(endpoints.primaryPort, host)
    fun secondaryMcpUrlForHost(host: String): String = mcpUrl(endpoints.secondaryPort, host)

    /**
     * The dashboard URL on [host]. A non-null [token] makes it the one-time browser link: Raijin
     * swaps the `?token=` for an HttpOnly cookie and redirects to the clean URL.
     */
    fun dashboardUrlForHost(host: String = "127.0.0.1", token: String? = null): String {
        val base = "http://${authority(host)}:${endpoints.dashboardPort}"
        return if (token == null) base else "$base/?${SecurityConfig.TOKEN_QUERY_PARAM}=${URLEncoder.encode(token, Charsets.UTF_8)}"
    }

    /**
     * A ready-to-paste MCP client config (Claude Code / omp / Cursor style). A non-null [token]
     * adds the `Authorization: Bearer` header remote access requires.
     */
    fun clientConfigJson(port: Int = endpoints.primaryPort, host: String = "127.0.0.1", token: String? = null): String =
        buildJsonObject {
            putJsonObject("mcpServers") {
                putJsonObject(SERVER_NAME) {
                    put("type", "http")
                    put("url", mcpUrl(port, host))
                    if (token != null) putJsonObject("headers") { put("Authorization", "Bearer $token") }
                }
            }
        }.toString()

    /** The equivalent one-liner for Claude Code; a non-null [token] adds the bearer header. */
    fun claudeCodeCommand(port: Int = endpoints.primaryPort, host: String = "127.0.0.1", token: String? = null): String {
        val base = "claude mcp add --transport http $SERVER_NAME ${mcpUrl(port, host)}"
        return if (token == null) base else "$base --header ${shellQuote("Authorization: Bearer $token")}"
    }

    /** IPv6 literals bracketed, so a URL built from any bind host stays valid. */
    private fun authority(host: String): String = SecurityConfig.formatHostForAuthority(host)

    private fun shellQuote(s: String): String = "'" + s.replace("'", "'\\''") + "'"
}
