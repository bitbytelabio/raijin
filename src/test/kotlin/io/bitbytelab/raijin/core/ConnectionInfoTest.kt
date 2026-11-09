package io.bitbytelab.raijin.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The endpoint is the root path "/" (not "/sse") and the config carries no credentials. */
class ConnectionInfoTest {

    @Test fun `sse url is the root path, never slash-sse`() {
        assertTrue(ConnectionInfo.primarySseUrl.endsWith(":9876/"), ConnectionInfo.primarySseUrl)
        assertTrue(ConnectionInfo.secondarySseUrl.endsWith(":9877/"), ConnectionInfo.secondarySseUrl)
        assertFalse(ConnectionInfo.primarySseUrl.contains("/sse"))
        assertFalse(ConnectionInfo.secondarySseUrl.contains("/sse"))
    }

    @Test fun `client config is named raijin, uses the root url and carries no credentials`() {
        val c = ConnectionInfo.clientConfigJson()
        assertEquals("""{"mcpServers":{"burpsuite":{"type":"sse","url":"http://127.0.0.1:9876/"}}}""", c)
        assertFalse(c.contains("Authorization"), c)
        assertFalse(c.contains("Bearer"), c)
        assertFalse(c.contains("headers"), c)
    }

    @Test fun `client config honours a custom host and port`() {
        assertTrue(ConnectionInfo.clientConfigJson(port = 9877, host = "192.168.1.8").contains("http://192.168.1.8:9877/"))
    }

    @Test fun `claude code command points at the raijin server`() {
        assertEquals("claude mcp add --transport sse burpsuite http://127.0.0.1:9876/", ConnectionInfo.claudeCodeCommand())
    }
}
