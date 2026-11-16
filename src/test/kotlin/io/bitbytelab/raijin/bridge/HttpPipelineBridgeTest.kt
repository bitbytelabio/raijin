package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.lang.reflect.Proxy
import java.net.ServerSocket
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * [HttpPipelineBridge] against a real loopback server: which sockets are kept for reuse, where
 * reading stops, and that raw request text reaches the wire as typed.
 */
class HttpPipelineBridgeTest {

    /** Montoya is only asked for the scope mode, and the scope gate fails open when it cannot answer. */
    private val bridge = HttpPipelineBridge(
        Proxy.newProxyInstance(MontoyaApi::class.java.classLoader, arrayOf(MontoyaApi::class.java)) { proxy, method, args ->
            when (method.name) {
                "hashCode" -> System.identityHashCode(proxy)
                "equals" -> proxy === args?.firstOrNull()
                "toString" -> "MontoyaApi"
                else -> null
            }
        } as MontoyaApi
    )

    private val get = buildJsonObject { put("raw_request", "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n") }

    /** Accepts one connection and answers each request (headers up to the blank line) with [responses] in turn. */
    private fun serve(vararg responses: String): ServerSocket {
        val server = ServerSocket(0)
        thread(isDaemon = true) {
            server.accept().use { conn ->
                val input = conn.getInputStream().bufferedReader(Charsets.ISO_8859_1)
                for (response in responses) {
                    while (input.readLine()?.isNotEmpty() == true) { /* skip the request head */ }
                    conn.getOutputStream().write(response.toByteArray(Charsets.ISO_8859_1))
                    conn.getOutputStream().flush()
                }
                Thread.sleep(3000)
            }
        }
        return server
    }

    private fun send(
        port: Int,
        requests: List<JsonObject>,
        keepOpen: Boolean,
        connectionId: String? = null,
        maxResponses: Int? = null,
    ): JsonObject = bridge.send(
        "localhost", port, false, null, requests, "concat", 0, maxResponses,
        idleTimeoutMs = 1000, totalTimeoutMs = 5000, keepOpen = keepOpen, connectionId = connectionId, maxResponseLength = null,
    )

    private fun JsonObject.str(key: String) = getValue(key).jsonPrimitive.content
    private fun JsonObject.flag(key: String) = getValue(key).jsonPrimitive.boolean

    @Test
    fun `a socket is not kept for reuse after Connection close`() {
        serve("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok").use { server ->
            val result = send(server.localPort, listOf(get), keepOpen = true)
            assertEquals("max_responses", result.str("close_reason"))
            assertEquals(false, result.flag("connection_open"))
            assertEquals(JsonNull, result["connection_id"])
        }
    }

    @Test
    fun `a keep-alive socket is kept, reused by connection_id, then retired`() {
        val ok = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        serve(ok, ok).use { server ->
            val first = send(server.localPort, listOf(get), keepOpen = true)
            assertEquals(true, first.flag("connection_open"), first.toString())
            val id = first.str("connection_id")

            val second = send(server.localPort, listOf(get), keepOpen = false, connectionId = id)
            assertEquals(true, second.flag("connection_reused"), second.toString())
            assertEquals(200, second.getValue("responses").jsonArray[0].jsonObject.getValue("status_code").jsonPrimitive.int)
            assertNull(HttpPipelineConnectionRegistry.get(id), "keep_open=false retires the reused connection")
        }
    }

    @Test
    fun `reading stops after 101 Switching Protocols`() {
        serve("HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\n\u0000\u0000\u0012\u0004").use { server ->
            val result = send(server.localPort, listOf(get), keepOpen = true, maxResponses = 2)
            assertEquals("switching_protocols", result.str("close_reason"))
            assertEquals(1, result.getValue("responses_received").jsonPrimitive.int)
            assertEquals(false, result.flag("connection_open"))
        }
    }

    @Test
    fun `chunk trailers are reported per response`() {
        serve("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX-Checksum: 9\r\n\r\n").use { server ->
            val response = send(server.localPort, listOf(get), keepOpen = false).getValue("responses").jsonArray[0].jsonObject
            assertEquals("ok", response.str("body"))
            val trailer = response.getValue("trailers").jsonArray.single().jsonObject
            assertEquals("X-Checksum", trailer.str("name"))
            assertEquals("9", trailer.str("value"))
        }
    }

    @Test
    fun `raw_request text reaches the wire byte for byte`() {
        // Wrong Content-Length, a bare LF and a JSON \n escape in the body, a Latin-1 char: all kept.
        val raw = "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nab\ncd{\"x\":\"\\n\u00e9\"}"
        val expected = raw.toByteArray(Charsets.ISO_8859_1)
        val received = AtomicReference<ByteArray>()
        ServerSocket(0).use { server ->
            val worker = thread(isDaemon = true) {
                server.accept().use { conn ->
                    received.set(conn.getInputStream().readNBytes(expected.size))
                    conn.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".toByteArray())
                    conn.getOutputStream().flush()
                    Thread.sleep(1000)
                }
            }
            val result = send(server.localPort, listOf(buildJsonObject { put("raw_request", raw) }), keepOpen = false)
            assertEquals("max_responses", result.str("close_reason"), result.toString())
            worker.join(3000)
            assertContentEquals(expected, received.get())
        }
    }

    @Test
    fun `malformed hex is rejected before connecting, naming the item`() {
        val result = send(1, listOf(get, buildJsonObject { put("raw_request_hex", "4745Z") }), keepOpen = false)
        assertEquals("validate", result.str("phase"))
        assertTrue(result.str("error").startsWith("requests[1]:"), result.toString())
    }
}
