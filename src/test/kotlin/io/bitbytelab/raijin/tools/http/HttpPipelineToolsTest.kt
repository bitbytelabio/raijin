package io.bitbytelab.raijin.tools.http

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.bridge.HttpPipelineBridge
import io.bitbytelab.raijin.testClientConnection
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequestParams
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import java.lang.reflect.Proxy
import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The pipeline tools' argument layer: request items become byte-exact requests with their pauses,
 * a bad item is an error naming it, a clamped item number is a note, and the connections tool
 * reports what it closed.
 */
class HttpPipelineToolsTest {

    private val server = Server(
        Implementation("t", "0"),
        ServerOptions(ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false)))
    ).also { server ->
        val api = Proxy.newProxyInstance(MontoyaApi::class.java.classLoader, arrayOf(MontoyaApi::class.java)) { proxy, method, args ->
            when (method.name) {
                "hashCode" -> System.identityHashCode(proxy)
                "equals" -> proxy === args?.firstOrNull()
                "toString" -> "MontoyaApi"
                else -> null
            }
        } as MontoyaApi
        HttpPipelineTools.register(server, HttpPipelineBridge(api))
    }

    private val loopback: InetAddress = InetAddress.getLoopbackAddress()
    private val get = buildJsonObject { put("raw_request", "GET / HTTP/1.1\r\nHost: x\r\n\r\n") }

    private fun call(tool: String, args: JsonObject): CallToolResult = runBlocking {
        server.tools.getValue(tool).handler(testClientConnection, CallToolRequest(CallToolRequestParams(tool, args)))
    }

    private fun json(result: CallToolResult): JsonObject =
        Json.parseToJsonElement((result.content.first() as TextContent).text).jsonObject

    private fun errorOf(result: CallToolResult): String {
        assertEquals(true, result.isError, (result.content.first() as TextContent).text)
        return json(result).getValue("error").jsonPrimitive.content
    }

    private fun pipeline(port: Int, vararg items: JsonObject, extra: JsonObjectBuilder.() -> Unit = {}) = buildJsonObject {
        put("host", loopback.hostAddress)
        put("port", port)
        put("use_tls", false)
        putJsonArray("requests") { items.forEach { add(it) } }
        extra()
    }

    /** Accepts one connection and answers [count] requests (heads up to the blank line) with a 200 each. */
    private fun answering(count: Int): ServerSocket {
        val listener = ServerSocket(0, 50, loopback)
        thread(isDaemon = true) {
            runCatching {
                listener.accept().use { conn ->
                    val input = conn.getInputStream().bufferedReader(Charsets.ISO_8859_1)
                    repeat(count) {
                        while (input.readLine()?.isNotEmpty() == true) Unit
                        conn.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".toByteArray())
                        conn.getOutputStream().flush()
                    }
                    Thread.sleep(2000)
                }
            }
        }
        return listener
    }

    @Test
    fun `a bad request item is an error naming it`() {
        fun rejected(item: JsonObject, fragment: String) {
            val message = errorOf(call("http_send_pipeline", pipeline(1, get, item)))
            assertTrue(message.startsWith("requests[1]:"), message)
            assertTrue(fragment in message, "'$fragment' not in: $message")
        }
        rejected(buildJsonObject { put("raw_request_hex", "47455Z") }, "non-hex")
        rejected(buildJsonObject { put("raw_request", "") }, "empty")
        rejected(buildJsonObject { put("label", "x") }, "'raw_request'")
        rejected(JsonObject(get + ("pause_markers" to Json.parseToJsonElement("[\"\"]"))), "pause_markers[0] is empty")
        rejected(JsonObject(get + ("pause_before" to Json.parseToJsonElement("\"soon\""))), "'pause_before'")
    }

    @Test
    fun `raw_request text reaches the wire byte for byte`() {
        // Wrong Content-Length, a bare LF and a JSON \n escape in the body, a Latin-1 char: all kept.
        val raw = "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nab\ncd{\"x\":\"\\n\u00e9\"}"
        val expected = raw.toByteArray(Charsets.ISO_8859_1)
        val received = AtomicReference<ByteArray>()
        ServerSocket(0, 50, loopback).use { listener ->
            val worker = thread(isDaemon = true) {
                listener.accept().use { conn ->
                    received.set(conn.getInputStream().readNBytes(expected.size))
                    conn.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".toByteArray())
                    conn.getOutputStream().flush()
                    Thread.sleep(1000)
                }
            }
            val result = json(call("http_send_pipeline", pipeline(listener.localPort, buildJsonObject { put("raw_request", raw) })))
            assertEquals("max_responses", result.getValue("close_reason").jsonPrimitive.content, result.toString())
            worker.join(3000)
            assertContentEquals(expected, received.get())
        }
    }

    @Test
    fun `item pause numbers out of range are clamped with notes naming the item`() {
        val raw = get.getValue("raw_request").jsonPrimitive.content
        answering(2).use { listener ->
            val clamped = JsonObject(get + ("pause_before" to Json.parseToJsonElement("1000")) + ("pause_ms" to Json.parseToJsonElement("90000")))
            val unmatched = JsonObject(get + ("pause_markers" to Json.parseToJsonElement("[\"zzz\"]")))
            val result = json(call("http_send_pipeline", pipeline(listener.localPort, clamped, unmatched)))
            val notes = result.getValue("notes").jsonArray.map { it.jsonPrimitive.content }
            assertTrue(notes.any { it.startsWith("requests[0]: Parameter 'pause_before' = 1000") && it.endsWith("${raw.length + 1} was used.") }, notes.toString())
            assertTrue(notes.any { it.startsWith("requests[0]: Parameter 'pause_ms' = 90000") }, notes.toString())
            assertTrue(notes.any { it.startsWith("requests[1]: pause marker 'zzz' does not occur") }, notes.toString())

            val requests = result.getValue("requests").jsonArray.map { it.jsonObject }
            // pause_before = length + 1 sends the whole request, then pauses.
            val pause = requests[0].getValue("pauses").jsonArray.single().jsonObject
            assertEquals(raw.length, pause.getValue("offset").jsonPrimitive.int, result.toString())
            assertTrue("pauses" !in requests[1])
            assertEquals(2, result.getValue("responses_received").jsonPrimitive.int)
        }
    }

    @Test
    fun `the connections tool reports unknown ids and lists what is kept`() {
        val result = json(call("http_pipeline_connections", buildJsonObject { putJsonArray("close") { add("no-such-connection") } }))
        assertEquals(listOf("no-such-connection"), result.getValue("unknown").jsonArray.map { it.jsonPrimitive.content })
        assertTrue(result.getValue("closed").jsonArray.isEmpty())
        assertTrue("connections" in result)
        val listing = json(call("http_pipeline_connections", buildJsonObject {}))
        assertTrue("closed" !in listing && "connections" in listing, listing.toString())
    }

    @Test
    fun `request items publish their pause properties and the call its new parameters`() {
        val properties = server.tools.getValue("http_send_pipeline").tool.inputSchema.properties!!
        val items = properties.getValue("requests").jsonObject.getValue("items").jsonObject.getValue("properties").jsonObject
        assertEquals(setOf("raw_request", "raw_request_hex", "pause_before", "pause_markers", "pause_ms"), items.keys)
        assertTrue(properties.keys.containsAll(listOf("sni", "decode_content", "raw_hex_max_bytes")), properties.keys.toString())
    }
}
