package io.bitbytelab.raijin.core

/**
 * Single source of truth for how MCP clients connect to Raijin. Used by the dashboard, the
 * Server UI tab (and mirrored in the README/configs) so the connection details can never drift.
 *
 * Invariants:
 *  1. Clients connect over Streamable HTTP at [MCP_PATH] (`/mcp`). The legacy SSE transport
 *     still answers at the root path `/` (never `/sse`) for old configs.
 *  2. There is **no token**: clients connect with the URL alone.
 */
object ConnectionInfo {
    const val PRIMARY_PORT = 9876
    const val SECONDARY_PORT = 9877
    const val DASHBOARD_PORT = 9878

    /** MCP server name used in client configs. */
    const val SERVER_NAME = "burpsuite"

    /** Path of the Streamable HTTP endpoint. */
    const val MCP_PATH = "/mcp"

    /** The Streamable HTTP endpoint URL for [port] on [host]. */
    fun mcpUrl(port: Int, host: String = "127.0.0.1"): String = "http://$host:$port$MCP_PATH"

    /** The legacy SSE endpoint URL for [port] on [host]: the ROOT path `/`, never `/sse`. */
    fun legacySseUrl(port: Int, host: String = "127.0.0.1"): String = "http://$host:$port/"

    val primaryMcpUrl: String get() = mcpUrl(PRIMARY_PORT)
    val secondaryMcpUrl: String get() = mcpUrl(SECONDARY_PORT)
    val dashboardUrl: String get() = dashboardUrlForHost()

    // Host-aware variants — every displayed endpoint reflects the interface the servers bound to.
    fun primaryMcpUrlForHost(host: String): String = mcpUrl(PRIMARY_PORT, host)
    fun secondaryMcpUrlForHost(host: String): String = mcpUrl(SECONDARY_PORT, host)
    fun dashboardUrlForHost(host: String = "127.0.0.1"): String = "http://$host:$DASHBOARD_PORT"

    /** A ready-to-paste MCP client config (Claude Code / omp / Cursor style). */
    fun clientConfigJson(port: Int = PRIMARY_PORT, host: String = "127.0.0.1"): String =
        """{"mcpServers":{"$SERVER_NAME":{"type":"http","url":"${mcpUrl(port, host)}"}}}"""

    /** The equivalent one-liner for Claude Code. */
    fun claudeCodeCommand(port: Int = PRIMARY_PORT, host: String = "127.0.0.1"): String =
        "claude mcp add --transport http $SERVER_NAME ${mcpUrl(port, host)}"
}
