package io.bitbytelab.raijin.graphql.subscriptions

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SubscriptionEndpointTest {

    private fun parse(url: String) = SubscriptionEndpoint.parse(url).getOrThrow()

    @Test
    fun `an https GraphQL URL is probed over wss on the same host, port and path`() {
        val endpoint = parse("https://api.example.com/graphql?v=2")
        assertEquals("api.example.com", endpoint.host)
        assertEquals(443, endpoint.port)
        assertTrue(endpoint.secure)
        assertEquals("wss://api.example.com/graphql?v=2", endpoint.wsUrl)
        assertEquals("https://api.example.com/graphql?v=2", endpoint.httpUrl)
    }

    @Test
    fun `ws and http are plaintext on port 80, and an explicit port is kept`() {
        val plain = parse("ws://example.com/subscriptions")
        assertFalse(plain.secure)
        assertEquals(80, plain.port)
        assertEquals("http://example.com/subscriptions", plain.httpUrl)

        val custom = parse("WSS://example.com:8443")
        assertTrue(custom.secure)
        assertEquals(8443, custom.port)
        assertEquals("wss://example.com:8443/", custom.wsUrl)
        assertEquals("https://example.com:8443/", custom.httpUrl)

        assertEquals("ws://localhost:4000/graphql", parse("http://localhost:4000/graphql").wsUrl)
    }

    @Test
    fun `an IPv6 literal keeps its brackets in URLs and loses them as a host`() {
        val endpoint = parse("ws://[::1]:4000/graphql")
        assertEquals("::1", endpoint.host)
        assertEquals("ws://[::1]:4000/graphql", endpoint.wsUrl)
        assertTrue("Host: [::1]:4000\r\n" in endpoint.upgradeRequest("graphql-ws", emptyMap(), "a2V5"))
    }

    @Test
    fun `other schemes and URLs without a host are refused with a message`() {
        for (url in listOf("ftp://example.com/graphql", "example.com/graphql", "/graphql", "")) {
            val message = SubscriptionEndpoint.parse(url).exceptionOrNull()?.message
            assertTrue(message != null && ("scheme" in message || "host" in message || "Invalid URL" in message), "'$url' -> $message")
        }
        assertTrue("missing host" in SubscriptionEndpoint.parse("wss:///graphql").exceptionOrNull()!!.message!!)
        assertTrue("Invalid URL" in SubscriptionEndpoint.parse("wss://exa mple.com/").exceptionOrNull()!!.message!!)
    }

    @Test
    fun `the upgrade request asks for the given subprotocol`() {
        val request = parse("wss://api.example.com/graphql?v=2").upgradeRequest("graphql-transport-ws", emptyMap(), "dGhlIHNhbXBsZSBub25jZQ==")
        assertEquals(
            "GET /graphql?v=2 HTTP/1.1\r\n" +
                "Host: api.example.com\r\n" +
                "Upgrade: websocket\r\n" +
                "Connection: Upgrade\r\n" +
                "Sec-WebSocket-Version: 13\r\n" +
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
                "Sec-WebSocket-Protocol: graphql-transport-ws\r\n" +
                "\r\n",
            request,
        )
    }

    @Test
    fun `caller headers are added, the handshake's own headers are not overridable`() {
        val request = parse("ws://example.com:8080/ws").upgradeRequest(
            "graphql-ws",
            linkedMapOf(
                "Cookie" to "sid=1",
                "Origin" to "https://app.example.com",
                "Sec-WebSocket-Protocol" to "something-else",
                "sec-websocket-key" to "bogus",
                "Upgrade" to "h2c",
                "Connection" to "close",
            ),
            "a2V5",
        )
        val lines = request.split("\r\n")
        assertEquals("GET /ws HTTP/1.1", lines.first())
        assertTrue("Host: example.com:8080" in lines)
        assertTrue("Cookie: sid=1" in lines)
        assertTrue("Origin: https://app.example.com" in lines)
        assertEquals(listOf("Sec-WebSocket-Protocol: graphql-ws"), lines.filter { it.startsWith("Sec-WebSocket-Protocol", ignoreCase = true) })
        assertEquals(listOf("Sec-WebSocket-Key: a2V5"), lines.filter { it.startsWith("Sec-WebSocket-Key", ignoreCase = true) })
        assertEquals(listOf("Upgrade: websocket"), lines.filter { it.startsWith("Upgrade", ignoreCase = true) })
        assertEquals(listOf("Connection: Upgrade"), lines.filter { it.startsWith("Connection", ignoreCase = true) })
        assertTrue(request.endsWith("\r\n\r\n"))
    }

    @Test
    fun `a caller Host header replaces the default one`() {
        val request = parse("wss://10.0.0.5/graphql").upgradeRequest("graphql-ws", mapOf("host" to "internal.example.com"), "a2V5")
        assertEquals(listOf("Host: internal.example.com"), request.split("\r\n").filter { it.startsWith("Host", ignoreCase = true) })
    }

    @Test
    fun `a newline in a header value cannot split the request`() {
        val request = parse("wss://example.com/graphql").upgradeRequest("graphql-ws", mapOf("X-Test" to "a\r\nInjected: 1"), "a2V5")
        assertTrue("X-Test: aInjected: 1\r\n" in request)
        assertFalse("\r\nInjected: 1" in request)
    }
}
