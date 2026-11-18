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
    fun `a host with an underscore, such as a Docker service, is read from the authority`() {
        val docker = parse("ws://graphql_api:4000/graphql?x=1")
        assertEquals("graphql_api", docker.host)
        assertEquals(4000, docker.port)
        assertFalse(docker.secure)
        assertEquals("ws://graphql_api:4000/graphql?x=1", docker.wsUrl)
        assertEquals("http://graphql_api:4000/graphql?x=1", docker.httpUrl)
        assertTrue("Host: graphql_api:4000\r\n" in docker.upgradeRequest("graphql-ws", emptyMap(), "a2V5"))

        // as for any host: the user info is dropped, and the default port is not written
        val withUser = parse("HTTPS://user:pw@my_api.internal")
        assertEquals("my_api.internal", withUser.host)
        assertEquals(443, withUser.port)
        assertEquals("wss://my_api.internal/", withUser.wsUrl)
        assertTrue("Host: my_api.internal\r\n" in withUser.upgradeRequest("graphql-ws", emptyMap(), "a2V5"))
        assertEquals("ws://graphql_api/x", parse("ws://graphql_api:/x").wsUrl)
        assertEquals("ws://graphql_api/x", parse("ws://graphql_api:80/x").wsUrl)
    }

    @Test
    fun `user info never reaches an IPv6 authority`() {
        val endpoint = parse("ws://u:p@[::1]:4000/g")
        assertEquals("::1", endpoint.host)
        assertEquals("ws://[::1]:4000/g", endpoint.wsUrl)
        assertTrue("Host: [::1]:4000\r\n" in endpoint.upgradeRequest("graphql-ws", emptyMap(), "a2V5"))
    }

    @Test
    fun `a port outside 1 to 65535 and a malformed authority are refused`() {
        fun message(url: String) = SubscriptionEndpoint.parse(url).exceptionOrNull()?.message.orEmpty()
        for (url in listOf("ws://graphql_api:0/", "ws://graphql_api:65536/", "ws://graphql_api:99999999999/", "ws://api.example.com:0/", "wss://api.example.com:70000/")) {
            assertTrue("out of range" in message(url), "$url -> ${message(url)}")
        }
        assertTrue("invalid port" in message("ws://graphql_api:4000:5/"), message("ws://graphql_api:4000:5/"))
        assertTrue("invalid host" in message("ws://bad;host/"), message("ws://bad;host/"))
        assertTrue("invalid host" in message("ws://a_b%20c/"), message("ws://a_b%20c/"))
        assertTrue("missing host" in message("ws://user@/graphql"), message("ws://user@/graphql"))
    }

    @Test
    fun `an anonymous session keeps only the caller headers that identify nobody`() {
        val caller = linkedMapOf(
            "Authorization" to "Bearer t",
            "Cookie" to "sid=1",
            "x-hasura-admin-secret" to "s3cret",
            "apikey" to "k",
            "X-Forwarded-For" to "127.0.0.1",
            " Origin " to "https://app.example.com",
            "User-Agent" to "probe/1.0",
            "host" to "internal.example.com",
        )
        assertEquals(
            mapOf(" Origin " to "https://app.example.com", "User-Agent" to "probe/1.0", "host" to "internal.example.com"),
            SubscriptionEndpoint.anonymousHeaders(caller),
        )
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
    fun `a header value is written exactly as given`() {
        val request = parse("wss://example.com/graphql").upgradeRequest("graphql-ws", mapOf("X-Test" to "a\r\nInjected: 1"), "a2V5")
        assertTrue("X-Test: a\r\nInjected: 1\r\n" in request)
    }
}
