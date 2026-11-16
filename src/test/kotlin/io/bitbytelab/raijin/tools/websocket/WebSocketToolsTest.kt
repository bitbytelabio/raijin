package io.bitbytelab.raijin.tools.websocket

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.bridge.WebSocketBridge
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.state.WebSocketConnection
import io.bitbytelab.raijin.testClientConnection
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequestParams
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.add
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import java.lang.reflect.Proxy
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The tool layer of the WebSocket tools: what is registered, the enums the merged `websocket`
 * schema relies on, bad arguments as `isError` results with a parseable message, and a blocking
 * wait that a cancelled call interrupts. The bridge runs on a Montoya stand-in that fails any call.
 */
class WebSocketToolsTest {

    private val api = Proxy.newProxyInstance(MontoyaApi::class.java.classLoader, arrayOf(MontoyaApi::class.java)) { proxy, method, args ->
        when (method.name) {
            "hashCode" -> System.identityHashCode(proxy)
            "equals" -> proxy === args?.firstOrNull()
            "toString" -> "MontoyaApi"
            else -> error("unexpected Burp call MontoyaApi.${method.name}")
        }
    } as MontoyaApi

    private val state = StateManager()
    private val bridge = WebSocketBridge(api, EventBus(), state)
    private val server = Server(
        Implementation("t", "0"),
        ServerOptions(ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false)))
    ).also { WebSocketTools.register(it, bridge, state) }

    @AfterTest
    fun shutDown() = bridge.shutdown()

    private fun request(tool: String, args: JsonObjectBuilder.() -> Unit) =
        CallToolRequest(CallToolRequestParams(tool, buildJsonObject(args)))

    private fun call(tool: String, args: JsonObjectBuilder.() -> Unit = {}): CallToolResult = runBlocking {
        server.tools.getValue(tool).handler(testClientConnection, request(tool, args))
    }

    private fun json(result: CallToolResult): JsonObject =
        Json.parseToJsonElement((result.content.first() as TextContent).text).jsonObject

    /** The error message of a call that must have been rejected. */
    private fun rejection(tool: String, args: JsonObjectBuilder.() -> Unit = {}): String {
        val result = call(tool, args)
        val body = json(result)
        assertEquals(true, result.isError, "$tool: $body")
        return body.getValue("error").jsonPrimitive.content
    }

    private fun schema(tool: String): JsonObject = server.tools.getValue(tool).tool.inputSchema.properties ?: JsonObject(emptyMap())

    /** A connection as a Burp tool would have opened it: tracked, with no handle to send on. */
    private fun tracked(): WebSocketConnection =
        WebSocketConnection("ws-900", "wss://chat.test/ws", "2026-11-17T00:00:00Z").also { state.websocketConnections[it.connectionId] = it }

    @Test
    fun `the websocket tools are registered, wait, fuzz and rule management among them`() {
        assertEquals(
            setOf(
                "websocket_create", "websocket_send_text", "websocket_send_binary", "websocket_close", "websocket_list",
                "websocket_get_messages", "websocket_wait_message", "websocket_fuzz", "websocket_set_intercept_rule",
                "websocket_list_intercept_rules", "websocket_remove_intercept_rule",
            ),
            server.tools.keys,
        )
    }

    @Test
    fun `every direction and message_type parameter shares one enum, so the merged schema fits all of them`() {
        val directions = server.tools.keys.mapNotNull { schema(it)["direction"]?.jsonObject?.get("enum") }
        val types = server.tools.keys.mapNotNull { schema(it)["message_type"]?.jsonObject?.get("enum") }

        assertEquals(3, directions.size)
        assertEquals(1, directions.toSet().size)
        assertEquals(listOf("client_to_server", "server_to_client", "both"), directions.first().jsonArray.map { it.jsonPrimitive.content })
        assertEquals(3, types.size)
        assertEquals(listOf("TEXT", "BINARY"), types.toSet().single().jsonArray.map { it.jsonPrimitive.content })
    }

    @Test
    fun `wait_message returns a buffered frame, and a timeout is a result rather than an error`() {
        val connection = tracked()
        connection.append("server_to_client", "TEXT", "hello", 5)

        val found = call("websocket_wait_message") {
            put("connection_id", connection.connectionId)
            put("since_index", -1)
        }
        assertEquals(false, found.isError)
        assertEquals("hello", json(found).getValue("message").jsonObject.getValue("payload").jsonPrimitive.content)

        val nothing = call("websocket_wait_message") {
            put("connection_id", connection.connectionId)
            put("timeout_ms", 0)
        }
        assertEquals(false, nothing.isError)
        assertEquals("timeout", json(nothing).getValue("reason").jsonPrimitive.content)
    }

    @Test
    fun `wait_message rejects bad arguments`() {
        val connection = tracked()
        assertTrue(rejection("websocket_wait_message").contains("connection_id"))
        assertTrue(rejection("websocket_wait_message") { put("connection_id", "ws-missing") }.contains("not found"))
        assertTrue(rejection("websocket_wait_message") { put("connection_id", connection.connectionId); put("timeout_ms", "soon") }.contains("integer"))
        assertTrue(rejection("websocket_wait_message") { put("connection_id", connection.connectionId); put("message_type", "json") }.contains("message_type"))
        assertTrue(rejection("websocket_wait_message") { put("connection_id", connection.connectionId); put("pattern", "(") }.contains("pattern"))
    }

    @Test
    fun `a cancelled wait stops at once instead of running out its timeout`() {
        val connection = tracked()
        val started = System.nanoTime()

        runBlocking {
            val waiting = launch(Dispatchers.Default) {
                server.tools.getValue("websocket_wait_message").handler(
                    testClientConnection,
                    request("websocket_wait_message") {
                        put("connection_id", connection.connectionId)
                        put("timeout_ms", 120_000)
                    },
                )
            }
            delay(300)
            waiting.cancelAndJoin()
        }

        val elapsed = System.nanoTime() - started
        assertTrue(elapsed < TimeUnit.SECONDS.toNanos(10), "took ${TimeUnit.NANOSECONDS.toMillis(elapsed)} ms")
    }

    @Test
    fun `fuzz checks its arguments before sending anything`() {
        val connection = tracked()
        assertTrue(rejection("websocket_fuzz") { put("payload_library", "nope"); put("connection_id", connection.connectionId) }.contains("payload_library"))
        assertTrue(rejection("websocket_fuzz") { putJsonArray("payloads") { add("a") } }.contains("connection_id"))
        assertTrue(rejection("websocket_fuzz") { put("url", "wss://x.test/ws"); put("headers", "nonsense") }.contains("headers"))
        assertTrue(rejection("websocket_fuzz") { put("connection_id", connection.connectionId) }.contains("No payloads"))
        // The library resolved to payloads: what stops the run is the connection, which Raijin can only read.
        assertTrue(rejection("websocket_fuzz") { put("payload_library", "XSS"); put("connection_id", connection.connectionId) }.contains("handle unavailable"))
    }

    @Test
    fun `intercept rules are set, listed and removed through the tools`() {
        val set = json(call("websocket_set_intercept_rule") {
            put("rule_id", "r1")
            put("action", "drop")
            put("message_type", "binary")
            put("enabled", "false")
        })
        assertEquals("BINARY", set.getValue("message_type").jsonPrimitive.content)

        val rule = json(call("websocket_list_intercept_rules")).getValue("rules").jsonArray.single().jsonObject
        assertEquals("r1", rule.getValue("rule_id").jsonPrimitive.content)
        assertEquals(false, rule.getValue("enabled").jsonPrimitive.boolean)

        val removed = json(call("websocket_remove_intercept_rule") { put("rule_id", "r1") })
        assertTrue(removed.getValue("removed").jsonPrimitive.boolean)
        assertTrue(rejection("websocket_remove_intercept_rule").contains("rule_id"))
        assertTrue(state.websocketInterceptRules.isEmpty())
    }

    @Test
    fun `get_messages clamps since_index and rejects a negative max_results`() {
        val connection = tracked()
        connection.append("server_to_client", "TEXT", "hello", 5)

        val page = json(call("websocket_get_messages") {
            put("connection_id", connection.connectionId)
            put("since_index", -5)
            put("max_results", Long.MAX_VALUE)
        })
        assertEquals(-1L, page.getValue("clamped").jsonObject.getValue("since_index").jsonPrimitive.long)
        assertEquals(1, page.getValue("messages").jsonArray.size)

        assertTrue(rejection("websocket_get_messages") { put("connection_id", connection.connectionId); put("max_results", -1) }.contains("max_results"))
    }
}
