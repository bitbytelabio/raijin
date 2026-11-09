package io.bitbytelab.raijin.core

import io.bitbytelab.raijin.transport.McpServerManager
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Clients connect over Streamable HTTP at /mcp; the legacy SSE URL is the root path; no credentials. */
class ConnectionInfoTest {

    @Test fun `mcp url is the streamable http path the server mounts`() {
        assertEquals("http://127.0.0.1:9876/mcp", ConnectionInfo.primaryMcpUrl)
        assertEquals("http://127.0.0.1:9877/mcp", ConnectionInfo.secondaryMcpUrl)
        assertEquals(McpServerManager.STREAMABLE_HTTP_PATH, ConnectionInfo.MCP_PATH)
    }

    @Test fun `legacy sse url is the root path, never slash-sse`() {
        assertEquals("http://127.0.0.1:9876/", ConnectionInfo.legacySseUrl(9876))
        assertFalse(ConnectionInfo.legacySseUrl(9876).contains("/sse"))
    }

    @Test fun `client config uses streamable http and carries no credentials`() {
        val c = ConnectionInfo.clientConfigJson()
        assertEquals("""{"mcpServers":{"burpsuite":{"type":"http","url":"http://127.0.0.1:9876/mcp"}}}""", c)
        assertFalse(c.contains("Authorization"), c)
        assertFalse(c.contains("Bearer"), c)
        assertFalse(c.contains("headers"), c)
    }

    @Test fun `client config honours a custom host and port`() {
        assertTrue(ConnectionInfo.clientConfigJson(port = 9877, host = "192.168.1.8").contains("http://192.168.1.8:9877/mcp"))
    }

    @Test fun `claude code command points at the streamable http endpoint`() {
        assertEquals("claude mcp add --transport http burpsuite http://127.0.0.1:9876/mcp", ConnectionInfo.claudeCodeCommand())
    }
}
