package io.bitbytelab.raijin.transport

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.cio.*
import io.ktor.server.engine.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sse.*
import io.ktor.sse.ServerSentEvent
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * End-to-end regression tests for the transport auth interceptor, driven over raw sockets against
 * a real CIO server wired exactly like [McpServerManager] (same `installLocalhostSecurity`, same
 * `install(SSE)`, same GET-selected SSE mount + POST back-channel at `/`).
 *
 * They pin the Host-header allowlist (anti DNS-rebinding) and Origin lockdown: a rebound Host or a
 * foreign Origin is refused on every verb *before* any handler runs, so no SSE stream (and no
 * session id) can be opened by a web page. There is no token — local clients just connect.
 */
class SecurityInterceptorTest {

    private fun freePort(): Int = ServerSocket(0).use { it.localPort }

    /** Stands up the real interceptor + the real route shape, then runs [block] against it. */
    private fun withServer(block: (Int) -> Unit) {
        val port = freePort()
        val server = embeddedServer(CIO, port = port, host = "127.0.0.1") {
            installLocalhostSecurity(listOf(port), listOf("127.0.0.1", "localhost"))
            install(SSE)
            install(IgnoreTrailingSlash)
            routing {
                // Mirrors McpServerManager: GET-selected SSE + POST back-channel.
                method(HttpMethod.Get) { sse { send(ServerSentEvent(event = "endpoint", data = "?sessionId=test-sid")) } }
                post { call.respondText("posted") }
            }
        }
        server.start(wait = false)
        try {
            waitForBind(port)
            block(port)
        } finally {
            server.stop(0, 0)
        }
    }

    private fun waitForBind(port: Int) {
        repeat(60) {
            try {
                Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), 200) }
                return
            } catch (_: Exception) { Thread.sleep(50) }
        }
        error("test server never bound on port $port")
    }

    /** Sends a raw request and returns whatever the server writes back (status line + any body). */
    private fun raw(port: Int, request: String, readMs: Int = 1500): String {
        Socket().use { s ->
            s.connect(InetSocketAddress("127.0.0.1", port), 2000)
            s.soTimeout = readMs
            s.getOutputStream().write(request.toByteArray())
            s.getOutputStream().flush()
            val buf = StringBuilder()
            try {
                val stream = s.getInputStream()
                val chunk = ByteArray(4096)
                while (buf.length < 4096) {
                    val n = stream.read(chunk)
                    if (n <= 0) break
                    buf.append(String(chunk, 0, n))
                }
            } catch (_: Exception) { /* read timeout on a held-open stream is expected */ }
            return buf.toString()
        }
    }

    private fun status(response: String): Int =
        Regex("^HTTP/1\\.1 (\\d{3})").find(response)?.groupValues?.get(1)?.toInt() ?: -1

    // ---- Host / Origin controls ---------------------------------------------

    @Test fun `OPTIONS with a rebound Host is rejected and mints no session`() {
        withServer { port ->
            val r = raw(port, "OPTIONS / HTTP/1.1\r\nHost: evil.attacker.com\r\nConnection: close\r\n\r\n")
            assertEquals(403, status(r), "a rebound Host must be refused for OPTIONS too: $r")
            assertFalse(r.contains("sessionId"), "no session id may ever be disclosed here: $r")
        }
    }

    @Test fun `a rebound Host never opens an SSE stream on any verb or path`() {
        withServer { port ->
            for (verb in listOf("GET", "OPTIONS", "POST")) {
                for (target in listOf("/", "/anything")) {
                    val r = raw(port, "$verb $target HTTP/1.1\r\nHost: evil.attacker.com\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    assertEquals(403, status(r), "$verb $target with a rebound Host must be refused: $r")
                    assertFalse(r.contains("text/event-stream"), "$verb $target opened a stream: $r")
                    assertFalse(r.contains("sessionId"), "$verb $target leaked a session id: $r")
                }
            }
        }
    }

    @Test fun `a cross-origin browser request is rejected`() {
        withServer { port ->
            val r = raw(port, "GET / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nOrigin: http://evil.example\r\nConnection: close\r\n\r\n")
            assertEquals(403, status(r), r)
        }
    }

    @Test fun `a genuine preflight from an allowed origin passes the interceptor`() {
        withServer { port ->
            val r = raw(
                port,
                "OPTIONS / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n" +
                    "Origin: http://127.0.0.1:$port\r\nAccess-Control-Request-Method: POST\r\nConnection: close\r\n\r\n"
            )
            assertTrue(status(r) !in listOf(401, 403), "an allowed-origin preflight must pass: $r")
        }
    }

    @Test fun `a preflight from a foreign origin is still rejected`() {
        withServer { port ->
            val r = raw(
                port,
                "OPTIONS / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n" +
                    "Origin: http://evil.example\r\nAccess-Control-Request-Method: POST\r\nConnection: close\r\n\r\n"
            )
            assertEquals(403, status(r), "cross-origin must be refused: $r")
        }
    }

    // ---- no token needed from a local client ---------------------------------

    @Test fun `GET from a loopback client opens the SSE stream without any credentials`() {
        withServer { port ->
            val r = raw(port, "GET / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\n\r\n")
            assertEquals(200, status(r), r)
            assertTrue(r.contains("text/event-stream"), r)
        }
    }

    @Test fun `POST back-channel from a loopback client is accepted`() {
        withServer { port ->
            val r = raw(port, "POST /?sessionId=test-sid HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
            assertEquals(200, status(r), r)
        }
    }
}
