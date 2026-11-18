package io.bitbytelab.raijin.core

import io.bitbytelab.raijin.transport.McpServerManager
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Clients connect over Streamable HTTP at /mcp; no credentials on loopback. */
class ConnectionInfoTest {

    @Test fun `mcp url is the streamable http path the server mounts`() {
        assertEquals("http://127.0.0.1:9876/mcp", ConnectionInfo.primaryMcpUrl)
        assertEquals("http://127.0.0.1:9877/mcp", ConnectionInfo.secondaryMcpUrl)
        assertEquals(McpServerManager.STREAMABLE_HTTP_PATH, ConnectionInfo.MCP_PATH)
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

    @Test fun `a token adds the bearer header to the client config and the claude command`() {
        val c = Json.parseToJsonElement(ConnectionInfo.clientConfigJson(host = "192.168.56.10", token = "t\"k'1")).jsonObject
        val server = c.getValue("mcpServers").jsonObject.getValue("burpsuite").jsonObject
        assertEquals("http://192.168.56.10:9876/mcp", server.getValue("url").jsonPrimitive.content)
        assertEquals("Bearer t\"k'1", server.getValue("headers").jsonObject.getValue("Authorization").jsonPrimitive.content)
        assertEquals(
            "claude mcp add --transport http burpsuite http://127.0.0.1:9876/mcp --header 'Authorization: Bearer abc'",
            ConnectionInfo.claudeCodeCommand(token = "abc")
        )
        assertTrue(ConnectionInfo.claudeCodeCommand(token = "a'b").endsWith("'Authorization: Bearer a'\\''b'"))
    }

    @Test fun `IPv6 hosts are bracketed in every URL`() {
        assertEquals("http://[::1]:9876/mcp", ConnectionInfo.mcpUrl(9876, "::1"))
    }

    @Test fun `the dashboard link with a token carries it once, URL-encoded`() {
        assertEquals("http://127.0.0.1:9878", ConnectionInfo.dashboardUrlForHost())
        assertEquals("http://10.0.0.5:9878/?token=a%2Bb%2Fc%3D", ConnectionInfo.dashboardUrlForHost("10.0.0.5", token = "a+b/c="))
    }

    @Test fun `published endpoints drive the displayed ports`() {
        try {
            ConnectionInfo.publish(ConnectionInfo.Endpoints("10.0.0.5", 19876, 19877, 19878))
            assertEquals("http://10.0.0.5:19876/mcp", ConnectionInfo.primaryMcpUrlForHost("10.0.0.5"))
            assertEquals("http://127.0.0.1:19877/mcp", ConnectionInfo.secondaryMcpUrl)
            assertEquals("http://10.0.0.5:19878", ConnectionInfo.dashboardUrlForHost("10.0.0.5"))
            assertTrue(ConnectionInfo.clientConfigJson().contains(":19876/mcp"))
        } finally {
            ConnectionInfo.publish(ConnectionInfo.Endpoints())
        }
    }
}
