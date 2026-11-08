package io.bitbytelab.raijin.core

/**
 * Single source of truth for how MCP clients connect to Raijin. Used by the dashboard, the
 * Server UI tab (and mirrored in the README/configs) so the connection details can never drift.
 *
 * Invariants:
 *  1. The MCP SSE endpoint is the **root path `/`**, NOT `/sse`.
 *  2. There is **no token**: clients connect with the URL alone.
 */
object ConnectionInfo {
    const val PRIMARY_PORT = 9876
    const val SECONDARY_PORT = 9877
    const val DASHBOARD_PORT = 9878

    /** MCP server name used in client configs. */
    const val SERVER_NAME = "raijin"

    /** The MCP SSE endpoint URL for [port] on [host] — the ROOT path `/`, never `/sse`. */
    fun sseUrl(port: Int, host: String = "127.0.0.1"): String = "http://$host:$port/"

    val primarySseUrl: String get() = sseUrl(PRIMARY_PORT)
    val secondarySseUrl: String get() = sseUrl(SECONDARY_PORT)
    val dashboardUrl: String get() = dashboardUrlForHost()

    // Host-aware variants — every displayed endpoint reflects the interface the servers bound to.
    fun primarySseUrlForHost(host: String): String = sseUrl(PRIMARY_PORT, host)
    fun secondarySseUrlForHost(host: String): String = sseUrl(SECONDARY_PORT, host)
    fun dashboardUrlForHost(host: String = "127.0.0.1"): String = "http://$host:$DASHBOARD_PORT"

    /** A ready-to-paste MCP client config (Claude Desktop / Claude Code / Cursor style). */
    fun clientConfigJson(port: Int = PRIMARY_PORT, host: String = "127.0.0.1"): String =
        """{"mcpServers":{"$SERVER_NAME":{"type":"sse","url":"${sseUrl(port, host)}"}}}"""

    /** The equivalent one-liner for Claude Code. */
    fun claudeCodeCommand(port: Int = PRIMARY_PORT, host: String = "127.0.0.1"): String =
        "claude mcp add --transport sse $SERVER_NAME ${sseUrl(port, host)}"
}
