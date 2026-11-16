package io.bitbytelab.raijin.transport

import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.options
import io.ktor.client.request.post
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The remote-access policy enforced by [installLocalhostSecurity]: loopback default without a token,
 * bearer token once exposed or opted in (401, preflights pass, `?token=` cookie bootstrap), the
 * source IP / CIDR allowlist (403, `X-Forwarded-For` ignored) and the Host / Origin allowlists
 * (IPv6, case, extra hosts). Routes mirror both MCP listeners and the dashboard.
 */
class RemoteAuthPolicyTest {

    private val port = 9876
    private val token = "s3cret-Token_value"
    private val authOn = RemoteAccess.Config(authRequired = true, token = token)

    /** Test-only header naming the socket peer, so one app can play many client addresses. */
    private val peerHeader = "X-Test-Peer"

    private fun ApplicationTestBuilder.mount(listenerPort: Int = port, config: () -> RemoteAccess.Config) = application {
        installLocalhostSecurity(
            ports = listOf(listenerPort),
            hosts = listOf("127.0.0.1", "localhost"),
            remoteAccess = config,
            sourceAddress = { call -> call.request.headers[peerHeader] ?: "127.0.0.1" }
        )
        routing {
            get("/") { call.respondText("root") }
            post("/") { call.respondText("posted") }
            route("/mcp") {
                get { call.respondText("mcp-get") }
                post { call.respondText("mcp-post") }
            }
            get("/events") { call.respondText("events") }
            get("/api/stats") { call.respondText("{}") }
        }
    }

    private suspend fun ApplicationTestBuilder.getAt(
        path: String,
        host: String = "127.0.0.1:$port",
        headers: Map<String, String> = emptyMap()
    ): HttpResponse = client.get(path) {
        header(HttpHeaders.Host, host)
        headers.forEach { (k, v) -> header(k, v) }
    }

    // ---- loopback default -------------------------------------------------

    @Test fun `loopback default needs no token`() = testApplication {
        mount { RemoteAccess.Config() }
        for (path in listOf("/", "/mcp", "/events", "/api/stats")) {
            val r = getAt(path)
            assertEquals(HttpStatusCode.OK, r.status, "$path: ${r.bodyAsText()}")
        }
    }

    @Test fun `loopback default reads RemoteAccess current per request`() = testApplication {
        application {
            installLocalhostSecurity(listOf(port))
            routing { get("/") { call.respondText("root") } }
        }
        try {
            assertEquals(HttpStatusCode.OK, getAt("/").status)
            RemoteAccess.install(authOn)
            assertEquals(HttpStatusCode.Unauthorized, getAt("/").status, "a live install must apply to the next request")
            assertEquals(HttpStatusCode.OK, getAt("/", headers = mapOf(HttpHeaders.Authorization to "Bearer $token")).status)
        } finally {
            RemoteAccess.install(RemoteAccess.Config())
        }
    }

    // ---- bearer token -------------------------------------------------------

    @Test fun `missing bearer gives 401 with a Bearer challenge on every route`() = testApplication {
        mount { authOn }
        for (path in listOf("/", "/mcp", "/events", "/api/stats", "/not-a-route")) {
            val r = getAt(path)
            assertEquals(HttpStatusCode.Unauthorized, r.status, path)
            assertTrue(r.headers[HttpHeaders.WWWAuthenticate].orEmpty().startsWith("Bearer"), path)
            assertFalse(r.bodyAsText().contains(token), "the token must never be echoed")
        }
        val post = client.post("/mcp") { header(HttpHeaders.Host, "127.0.0.1:$port") }
        assertEquals(HttpStatusCode.Unauthorized, post.status)
        val legacyPost = client.post("/?sessionId=abc") { header(HttpHeaders.Host, "127.0.0.1:$port") }
        assertEquals(HttpStatusCode.Unauthorized, legacyPost.status)
    }

    @Test fun `wrong bearer gives 401 invalid_token`() = testApplication {
        mount { authOn }
        for (bad in listOf("Bearer nope", "Bearer ${token}x", "Bearer ${token.dropLast(1)}", "Basic $token", "Bearer")) {
            val r = getAt("/mcp", headers = mapOf(HttpHeaders.Authorization to bad))
            assertEquals(HttpStatusCode.Unauthorized, r.status, bad)
        }
        val r = getAt("/mcp", headers = mapOf(HttpHeaders.Authorization to "Bearer nope"))
        assertTrue(r.headers[HttpHeaders.WWWAuthenticate].orEmpty().contains("invalid_token"))
    }

    @Test fun `correct bearer passes, scheme case-insensitive`() = testApplication {
        mount { authOn }
        assertEquals(HttpStatusCode.OK, getAt("/mcp", headers = mapOf(HttpHeaders.Authorization to "Bearer $token")).status)
        assertEquals(HttpStatusCode.OK, getAt("/mcp", headers = mapOf(HttpHeaders.Authorization to "bearer $token")).status)
        val post = client.post("/mcp") {
            header(HttpHeaders.Host, "127.0.0.1:$port")
            header(HttpHeaders.Authorization, "Bearer $token")
        }
        assertEquals("mcp-post", post.bodyAsText())
    }

    @Test fun `a CORS preflight passes without a token and allows the Authorization header`() = testApplication {
        mount { authOn }
        val r = client.options("/mcp") {
            header(HttpHeaders.Host, "127.0.0.1:$port")
            header(HttpHeaders.Origin, "http://127.0.0.1:$port")
            header(HttpHeaders.AccessControlRequestMethod, "POST")
            header(HttpHeaders.AccessControlRequestHeaders, "authorization, content-type")
        }
        assertEquals(HttpStatusCode.OK, r.status, r.bodyAsText())
        assertTrue(r.headers[HttpHeaders.AccessControlAllowHeaders].orEmpty().contains("Authorization", ignoreCase = true))
    }

    @Test fun `an OPTIONS request that is not a preflight still needs the token`() = testApplication {
        mount { authOn }
        val r = client.options("/mcp") { header(HttpHeaders.Host, "127.0.0.1:$port") }
        assertEquals(HttpStatusCode.Unauthorized, r.status)
    }

    @Test fun `a preflight from a foreign origin is still refused`() = testApplication {
        mount { authOn }
        val r = client.options("/mcp") {
            header(HttpHeaders.Host, "127.0.0.1:$port")
            header(HttpHeaders.Origin, "http://evil.example")
            header(HttpHeaders.AccessControlRequestMethod, "POST")
        }
        assertEquals(HttpStatusCode.Forbidden, r.status)
    }

    @Test fun `a preflight the CORS plugin passes on to the routes still needs the token`() = testApplication {
        mount { authOn }
        // The allowlist reads past an IPv6 zone index and blanks around the authority; CORS refuses an Origin
        // holding a `%` or a non-digit after the port and leaves the request to the routes. (Two Origin headers
        // do the same: see SecurityInterceptorTest, since this client joins repeated headers into one.)
        for (origin in listOf("http://[::1%25lo0]:$port", "http://127.0.0.1:$port /")) {
            val r = client.options("/mcp") {
                header(HttpHeaders.Host, "127.0.0.1:$port")
                header(HttpHeaders.Origin, origin)
                header(HttpHeaders.AccessControlRequestMethod, "POST")
            }
            assertEquals(HttpStatusCode.Unauthorized, r.status, "$origin: ${r.bodyAsText()}")
        }
    }

    @Test fun `token query sets an HttpOnly SameSite cookie that authenticates later requests`() = testApplication {
        mount { authOn }
        val first = getAt("/api/stats?token=$token")
        assertEquals(HttpStatusCode.OK, first.status)
        val setCookie = assertNotNull(first.headers[HttpHeaders.SetCookie])
        assertTrue(setCookie.startsWith("${SecurityConfig.AUTH_COOKIE}="), setCookie)
        assertTrue(setCookie.contains("HttpOnly", ignoreCase = true), setCookie)
        assertTrue(setCookie.contains("SameSite=Strict", ignoreCase = true), setCookie)
        assertTrue(setCookie.contains("Max-Age=${SecurityConfig.AUTH_COOKIE_MAX_AGE_SECONDS}"), setCookie)
        assertFalse(setCookie.contains(token), "the cookie carries a digest, never the token")

        val cookie = setCookie.substringBefore(';')
        assertEquals(HttpStatusCode.OK, getAt("/events", headers = mapOf(HttpHeaders.Cookie to cookie)).status)
        assertEquals(
            HttpStatusCode.Unauthorized,
            getAt("/events", headers = mapOf(HttpHeaders.Cookie to "${SecurityConfig.AUTH_COOKIE}=forged")).status
        )
        assertEquals(HttpStatusCode.Unauthorized, getAt("/api/stats?token=wrong").status)
    }

    @Test fun `a cookie minted on one listener port opens no other`() {
        // A browser sends a host's cookies to every port on it, so the dashboard's cookie reaches other services
        // there; replayed against an MCP listener it must not authenticate.
        val dashboardPort = 9878
        var cookie = ""
        testApplication {
            mount(dashboardPort) { authOn }
            cookie = assertNotNull(getAt("/?token=$token", host = "127.0.0.1:$dashboardPort").headers[HttpHeaders.SetCookie])
                .substringBefore(';')
            val reused = getAt("/events", host = "127.0.0.1:$dashboardPort", headers = mapOf(HttpHeaders.Cookie to cookie))
            assertEquals(HttpStatusCode.OK, reused.status)
        }
        testApplication {
            mount { authOn }
            val replayed = getAt("/mcp", headers = mapOf(HttpHeaders.Cookie to cookie))
            assertEquals(HttpStatusCode.Unauthorized, replayed.status)
            assertTrue(replayed.headers[HttpHeaders.WWWAuthenticate].orEmpty().contains("invalid_token"))
        }
    }

    @Test fun `a page load with the token redirects to the same URL without it`() = testApplication {
        mount { authOn }
        val noRedirect = createClient { followRedirects = false }
        val r = noRedirect.get("/?token=$token&tab=activity") {
            header(HttpHeaders.Host, "127.0.0.1:$port")
            header(HttpHeaders.Accept, "text/html,application/xhtml+xml")
        }
        assertEquals(HttpStatusCode.Found, r.status)
        assertEquals("/?tab=activity", r.headers[HttpHeaders.Location])
        assertNotNull(r.headers[HttpHeaders.SetCookie])
    }

    @Test fun `a rotated token invalidates the old cookie and bearer`() = testApplication {
        var config = authOn
        mount { config }
        val cookie = assertNotNull(getAt("/?token=$token").headers[HttpHeaders.SetCookie]).substringBefore(';')
        config = RemoteAccess.Config(authRequired = true, token = "rotated")
        assertEquals(HttpStatusCode.Unauthorized, getAt("/", headers = mapOf(HttpHeaders.Cookie to cookie)).status)
        assertEquals(HttpStatusCode.Unauthorized, getAt("/", headers = mapOf(HttpHeaders.Authorization to "Bearer $token")).status)
        assertEquals(HttpStatusCode.OK, getAt("/", headers = mapOf(HttpHeaders.Authorization to "Bearer rotated")).status)
    }

    @Test fun `auth required without a configured token fails closed`() = testApplication {
        mount { RemoteAccess.Config(authRequired = true, token = null) }
        assertEquals(HttpStatusCode.Unauthorized, getAt("/").status)
        assertEquals(HttpStatusCode.Unauthorized, getAt("/", headers = mapOf(HttpHeaders.Authorization to "Bearer ")).status)
    }

    // ---- source IP / CIDR allowlist ----------------------------------------

    private val ipConfig = RemoteAccess.Config(allowedIps = listOf("192.168.56.1", "100.64.0.0/10", "fd7a:115c:a1e0::/48"))

    @Test fun `a listed IP and CIDR members pass`() = testApplication {
        mount { ipConfig }
        for (peer in listOf("192.168.56.1", "100.64.0.1", "100.127.255.254", "fd7a:115c:a1e0:ab12::1")) {
            assertEquals(HttpStatusCode.OK, getAt("/", headers = mapOf(peerHeader to peer)).status, peer)
        }
    }

    @Test fun `a source outside the allowlist gets 403 on every route`() = testApplication {
        mount { ipConfig }
        for (peer in listOf("192.168.56.2", "100.128.0.1", "10.0.2.2", "fd7a:115c:a1e1::1", "unknown")) {
            for (path in listOf("/", "/mcp", "/events")) {
                val r = getAt(path, headers = mapOf(peerHeader to peer))
                assertEquals(HttpStatusCode.Forbidden, r.status, "$peer $path")
                assertTrue(r.bodyAsText().contains("source address"), r.toString())
            }
        }
    }

    @Test fun `loopback is always allowed by the source allowlist`() = testApplication {
        mount { ipConfig }
        for (peer in listOf("127.0.0.1", "127.0.0.2", "::1", "0:0:0:0:0:0:0:1")) {
            assertEquals(HttpStatusCode.OK, getAt("/", headers = mapOf(peerHeader to peer)).status, peer)
        }
    }

    @Test fun `X-Forwarded-For never widens the allowlist`() = testApplication {
        mount { ipConfig }
        val r = getAt(
            "/",
            headers = mapOf(peerHeader to "203.0.113.9", "X-Forwarded-For" to "192.168.56.1", "Forwarded" to "for=192.168.56.1")
        )
        assertEquals(HttpStatusCode.Forbidden, r.status)
    }

    @Test fun `the source check runs before the token check`() = testApplication {
        mount { ipConfig.copy(authRequired = true, token = token) }
        val outside = getAt("/", headers = mapOf(peerHeader to "198.51.100.7", HttpHeaders.Authorization to "Bearer $token"))
        assertEquals(HttpStatusCode.Forbidden, outside.status)
        val inside = getAt("/", headers = mapOf(peerHeader to "192.168.56.1"))
        assertEquals(HttpStatusCode.Unauthorized, inside.status)
        val both = getAt("/", headers = mapOf(peerHeader to "192.168.56.1", HttpHeaders.Authorization to "Bearer $token"))
        assertEquals(HttpStatusCode.OK, both.status)
    }

    // ---- Host / Origin ------------------------------------------------------

    @Test fun `IPv6 loopback and any letter case pass the Host check`() = testApplication {
        mount { RemoteAccess.Config() }
        for (host in listOf("[::1]:$port", "[0:0:0:0:0:0:0:1]:$port", "LOCALHOST:$port", "127.0.0.1:$port")) {
            assertEquals(HttpStatusCode.OK, getAt("/", host = host).status, host)
        }
        assertEquals(HttpStatusCode.Forbidden, getAt("/", host = "[::2]:$port").status)
        assertEquals(HttpStatusCode.Forbidden, getAt("/", host = "localhost:${port + 1}").status)
    }

    @Test fun `IPv6 and upper-case origins are accepted`() = testApplication {
        mount { RemoteAccess.Config() }
        for (origin in listOf("http://[::1]:$port", "HTTP://LOCALHOST:$port")) {
            val r = client.post("/") {
                header(HttpHeaders.Host, "127.0.0.1:$port")
                header(HttpHeaders.Origin, origin)
            }
            assertEquals(HttpStatusCode.OK, r.status, origin)
        }
    }

    @Test fun `configured extra hosts join the Host and Origin allowlists`() = testApplication {
        mount { RemoteAccess.Config(allowedHosts = listOf("Burp-VM.tailnet.ts.net", "burp.internal:8443", "[fd7a::5]")) }
        for (host in listOf("burp-vm.tailnet.ts.net:$port", "burp-vm.tailnet.ts.net", "BURP-VM.TAILNET.TS.NET:$port", "burp.internal:8443", "[fd7a::5]:$port")) {
            assertEquals(HttpStatusCode.OK, getAt("/", host = host).status, host)
        }
        for (host in listOf("other.tailnet.ts.net:$port", "burp.internal:$port", "evil.burp-vm.tailnet.ts.net")) {
            assertEquals(HttpStatusCode.Forbidden, getAt("/", host = host).status, host)
        }
        val viaProxy = client.post("/") {
            header(HttpHeaders.Host, "burp-vm.tailnet.ts.net")
            header(HttpHeaders.Origin, "https://burp-vm.tailnet.ts.net")
        }
        assertEquals(HttpStatusCode.OK, viaProxy.status)
        val crossPort = client.post("/") {
            header(HttpHeaders.Host, "127.0.0.1:$port")
            header(HttpHeaders.Origin, "https://burp-vm.tailnet.ts.net")
        }
        assertEquals(HttpStatusCode.OK, crossPort.status)
        assertEquals("https://burp-vm.tailnet.ts.net", crossPort.headers[HttpHeaders.AccessControlAllowOrigin])
    }

    @Test fun `a rebound Host is refused before the token is even considered`() = testApplication {
        mount { authOn }
        val r = getAt("/", host = "attacker.example", headers = mapOf(HttpHeaders.Authorization to "Bearer $token"))
        assertEquals(HttpStatusCode.Forbidden, r.status)
        assertNull(r.headers[HttpHeaders.WWWAuthenticate])
    }
}
