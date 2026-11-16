package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.core.Registration
import burp.api.montoya.core.ToolSource
import burp.api.montoya.core.ToolType
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import burp.api.montoya.websocket.BinaryMessage
import burp.api.montoya.websocket.BinaryMessageAction
import burp.api.montoya.websocket.Direction
import burp.api.montoya.websocket.MessageAction
import burp.api.montoya.websocket.MessageHandler
import burp.api.montoya.websocket.TextMessage
import burp.api.montoya.websocket.TextMessageAction
import burp.api.montoya.websocket.WebSocket
import burp.api.montoya.websocket.WebSocketCreated
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.state.WebSocketConnection
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.lang.reflect.Proxy
import java.util.Base64
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Lifecycle of sockets Burp tools create (Proxy, Repeater, ...): tracking, single close,
 * eviction of closed connections at the cap, and handler deregistration on extension unload; and
 * what the tap does to their frames: intercept rules on text and binary frames, the records a
 * wait or a poll reads.
 */
class WebSocketBridgeTrackingTest {

    private class FakeRegistration : Registration {
        var deregistered = false
        override fun isRegistered(): Boolean = !deregistered
        override fun deregister() {
            deregistered = true
        }
    }

    /** What the bridge registered on one Burp-created socket. */
    private class Socket {
        val registration = FakeRegistration()
        var handler: MessageHandler? = null
    }

    private fun <T> fake(type: Class<T>, answer: (method: String, args: Array<Any?>) -> Any?): T =
        type.cast(Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { self, m, args ->
            when (m.name) {
                "hashCode" -> System.identityHashCode(self)
                "equals" -> self === args?.get(0)
                else -> answer(m.name, args ?: emptyArray())
            }
        })

    private fun created(url: String, socket: Socket): WebSocketCreated {
        val upgrade = fake(HttpRequest::class.java) { name, _ -> if (name == "url") url else null }
        val webSocket = fake(WebSocket::class.java) { name, args ->
            if (name == "registerMessageHandler") {
                socket.handler = args[0] as MessageHandler
                socket.registration
            } else {
                null
            }
        }
        val source = fake(ToolSource::class.java) { name, _ -> if (name == "toolType") ToolType.PROXY else null }
        return fake(WebSocketCreated::class.java) { name, _ ->
            when (name) {
                "upgradeRequest" -> upgrade
                "webSocket" -> webSocket
                "toolSource" -> source
                else -> null
            }
        }
    }

    private fun burpBytes(bytes: ByteArray): BurpByteArray = fake(BurpByteArray::class.java) { name, _ ->
        when (name) {
            "getBytes" -> bytes.copyOf()
            "length" -> bytes.size
            "toString" -> "ByteArray(${bytes.size})"
            else -> error("unexpected ByteArray.$name")
        }
    }

    private fun textMessage(payload: String, direction: Direction): TextMessage = fake(TextMessage::class.java) { name, _ ->
        when (name) {
            "payload" -> payload
            "direction" -> direction
            else -> null
        }
    }

    private fun binaryMessage(bytes: ByteArray, direction: Direction): BinaryMessage = fake(BinaryMessage::class.java) { name, _ ->
        when (name) {
            "payload" -> burpBytes(bytes)
            "direction" -> direction
            else -> null
        }
    }

    /** What Burp's object factory does for the frame actions and byte arrays the tap creates. */
    private val factory: MontoyaObjectFactory = fake(MontoyaObjectFactory::class.java) { name, args ->
        when (name) {
            "byteArray" -> burpBytes(args[0] as ByteArray)
            "continueWithBinaryMessage" -> binaryAction(MessageAction.CONTINUE, args[0] as BurpByteArray)
            "dropBinaryMessage" -> binaryAction(MessageAction.DROP, null)
            "continueWithTextMessage" -> textAction(MessageAction.CONTINUE, args[0] as String)
            "dropTextMessage" -> textAction(MessageAction.DROP, null)
            else -> error("unexpected MontoyaObjectFactory.$name")
        }
    }

    private fun binaryAction(action: MessageAction, payload: BurpByteArray?): BinaryMessageAction =
        fake(BinaryMessageAction::class.java) { name, _ ->
            when (name) {
                "action" -> action
                "payload" -> payload
                else -> null
            }
        }

    private fun textAction(action: MessageAction, payload: String?): TextMessageAction =
        fake(TextMessageAction::class.java) { name, _ ->
            when (name) {
                "action" -> action
                "payload" -> payload
                else -> null
            }
        }

    private val state = StateManager()
    private val events = EventBus()
    private val bridge = WebSocketBridge(fake(MontoyaApi::class.java) { _, _ -> null }, events, state)
    private var previousFactory: MontoyaObjectFactory? = null

    @BeforeTest
    fun installFactory() {
        previousFactory = ObjectFactoryLocator.FACTORY
        ObjectFactoryLocator.FACTORY = factory
    }

    @AfterTest
    fun shutDown() {
        bridge.shutdown()
        ObjectFactoryLocator.FACTORY = previousFactory
    }

    /** Reports one Burp-created socket to the bridge and returns the connection it tracks for it. */
    private fun tracked(socket: Socket = Socket()): WebSocketConnection {
        bridge.createWebSocketHandler().handleWebSocketCreated(created("wss://chat.test/ws", socket))
        return state.websocketConnections.values.single()
    }

    private fun base64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    private fun bytes(vararg values: Int) = ByteArray(values.size) { values[it].toByte() }

    @Test
    fun `a Burp-created socket is tracked and its handler is deregistered on unload`() {
        val socket = Socket()
        bridge.createWebSocketHandler().handleWebSocketCreated(created("wss://chat.test/ws", socket))

        val connection = state.websocketConnections.values.single()
        assertEquals("wss://chat.test/ws", connection.url)
        assertEquals("connected", connection.status)
        assertNotNull(socket.handler)

        bridge.shutdown()
        assertTrue(socket.registration.deregistered)
    }

    @Test
    fun `close is reported once even when onClose fires twice`() {
        val socket = Socket()
        bridge.createWebSocketHandler().handleWebSocketCreated(created("wss://chat.test/ws", socket))

        socket.handler!!.onClose()
        socket.handler!!.onClose()

        assertEquals("closed", state.websocketConnections.values.single().status)
        assertEquals(1, events.getRecentEvents(100).count { it.type == "websocket.closed" })
        // A closed socket's registration is dropped at close, so unload has nothing left to deregister.
        bridge.shutdown()
        assertFalse(socket.registration.deregistered)
    }

    @Test
    fun `closed connections are evicted once the cap is reached, open ones never`() {
        val handler = bridge.createWebSocketHandler()
        val sockets = (0 until WebSocketBridge.MAX_CONNECTIONS).map { i ->
            Socket().also { handler.handleWebSocketCreated(created("wss://h.test/$i", it)) }
        }
        sockets.take(3).forEach { it.handler!!.onClose() }

        handler.handleWebSocketCreated(created("wss://h.test/new", Socket()))

        val connections = state.websocketConnections.values
        assertEquals(WebSocketBridge.MAX_CONNECTIONS, connections.size)
        assertEquals(2, connections.count { it.status == "closed" })
        assertEquals(WebSocketBridge.MAX_CONNECTIONS - 2, connections.count { it.status == "connected" })
        assertTrue(connections.any { it.url == "wss://h.test/new" })
    }

    @Test
    fun `get_messages pages by since_index and reports the window`() {
        bridge.createWebSocketHandler().handleWebSocketCreated(created("wss://chat.test/ws", Socket()))
        val connection = state.websocketConnections.values.single()
        repeat(5) { connection.append(if (it % 2 == 0) "client_to_server" else "server_to_client", "TEXT", "m$it", 2) }

        val page = bridge.getMessages(connection.connectionId, "server_to_client", 1, 100)
        assertEquals(listOf(3L), page["messages"]!!.jsonArray.map { it.jsonObject["index"]!!.jsonPrimitive.long })
        assertEquals(0L, page["oldest_index"]!!.jsonPrimitive.long)
        assertEquals(5L, page["next_index"]!!.jsonPrimitive.long)
        assertFalse(page["has_more"]!!.jsonPrimitive.boolean)

        assertEquals(5, bridge.getMessages(connection.connectionId, "BOTH", -1, 100)["returned_messages"]!!.jsonPrimitive.int)
        // An index below -1 means the same as -1: everything retained, and the result says so.
        val all = bridge.getMessages(connection.connectionId, null, -2, 100)
        assertNull(all["error"])
        assertEquals(5, all["returned_messages"]!!.jsonPrimitive.int)
        assertEquals(-1L, all["clamped"]!!.jsonObject["since_index"]!!.jsonPrimitive.long)
    }

    @Test
    fun `unload releases a caller blocked in wait_message`() {
        val connection = tracked()
        val unloader = thread {
            Thread.sleep(150)
            bridge.shutdown()
        }

        val result = bridge.waitForMessage(connection.connectionId, -1, null, null, null, 30_000)
        unloader.join()

        assertFalse(result["matched"]!!.jsonPrimitive.boolean)
        assertEquals("connection_closed", result["reason"]!!.jsonPrimitive.content)
        assertTrue(result["waited_ms"]!!.jsonPrimitive.long < 15_000)
    }

    @Test
    fun `intercept rules are listed in evaluation order and can be removed`() {
        assertNull(bridge.setInterceptRule("r1", "chat", null, "both", "tag", null, null, "seen", true)["error"])
        val second = bridge.setInterceptRule("r2", null, "\\x00", "server_to_client", "drop", null, null, null, false, messageType = "binary")
        assertEquals("BINARY", second["message_type"]!!.jsonPrimitive.content)
        // Updating r1 keeps its place in the evaluation order.
        bridge.setInterceptRule("r1", "chat2", null, "both", "tag", null, null, "seen again", true)

        val listed = bridge.listInterceptRules()
        assertEquals(2, listed["total"]!!.jsonPrimitive.int)
        val rules = listed["rules"]!!.jsonArray.map { it.jsonObject }
        assertEquals(listOf("r1", "r2"), rules.map { it["rule_id"]!!.jsonPrimitive.content })
        assertEquals("chat2", rules[0]["match_url"]!!.jsonPrimitive.content)
        assertEquals("seen again", rules[0]["tag_comment"]!!.jsonPrimitive.content)
        assertNull(rules[0]["message_type"])
        assertEquals("BINARY", rules[1]["message_type"]!!.jsonPrimitive.content)
        assertEquals("drop", rules[1]["action"]!!.jsonPrimitive.content)
        assertFalse(rules[1]["enabled"]!!.jsonPrimitive.boolean)

        val removed = bridge.removeInterceptRule("r1")
        assertTrue(removed["removed"]!!.jsonPrimitive.boolean)
        assertEquals(1, removed["remaining_rules"]!!.jsonPrimitive.int)
        assertFalse(bridge.removeInterceptRule("r1")["removed"]!!.jsonPrimitive.boolean)
        assertEquals(listOf("r2"), state.websocketInterceptRules.map { it.ruleId })
        assertEquals(1, events.getRecentEvents(100).count { it.type == "websocket.rule_removed" })
    }

    @Test
    fun `a rule with an unknown message type is rejected and a blank rule id gets a generated one`() {
        assertNotNull(bridge.setInterceptRule(null, null, null, "both", "tag", null, null, null, true, messageType = "json")["error"])
        assertTrue(state.websocketInterceptRules.isEmpty())

        val set = bridge.setInterceptRule("  ", null, null, "both", "tag", null, null, null, true)
        assertTrue(set["rule_id"]!!.jsonPrimitive.content.startsWith("wsrule-"), "$set")
    }

    @Test
    fun `a binary rule rewrites a proxied frame byte for byte and the record shows what was forwarded`() {
        val socket = Socket()
        val connection = tracked(socket)
        bridge.setInterceptRule(null, null, null, "client_to_server", "modify", "\\x01\\xFF", "\u00AB\u00CD", null, true, messageType = "BINARY")

        val action = socket.handler!!.handleBinaryMessage(binaryMessage(bytes(0x00, 0x01, 0xFF, 0x41), Direction.CLIENT_TO_SERVER))

        val expected = bytes(0x00, 0xAB, 0xCD, 0x41)
        assertEquals(MessageAction.CONTINUE, action.action())
        assertContentEquals(expected, action.payload().getBytes())
        val recorded = connection.page(-1, 10).messages.single()
        assertEquals("BINARY", recorded.type)
        assertEquals(base64(expected), recorded.payload)
        assertEquals(4, recorded.length)
        assertEquals(1L, connection.messagesSent.get())

        // A text frame with the same characters is outside a BINARY rule.
        val text = socket.handler!!.handleTextMessage(textMessage("\u0001\u00FF", Direction.CLIENT_TO_SERVER))
        assertEquals(MessageAction.CONTINUE, text.action())
        assertEquals("\u0001\u00FF", text.payload())
    }

    @Test
    fun `a dropped binary frame keeps its original bytes and is marked dropped`() {
        val socket = Socket()
        val connection = tracked(socket)
        // No message_type: the content pattern applies to binary frames as their bytes.
        bridge.setInterceptRule(null, null, "^\\x00", "both", "drop", null, null, null, true)

        val original = bytes(0x00, 0x10, 0x80)
        val action = socket.handler!!.handleBinaryMessage(binaryMessage(original, Direction.SERVER_TO_CLIENT))

        assertEquals(MessageAction.DROP, action.action())
        val recorded = connection.page(-1, 10).messages.single()
        assertEquals("BINARY_DROPPED", recorded.type)
        assertEquals(base64(original), recorded.payload)
        assertEquals(3, recorded.length)
        assertEquals(0L, connection.messagesReceived.get(), "a dropped frame was not delivered")

        // A frame the rule does not match goes through untouched.
        val passed = socket.handler!!.handleBinaryMessage(binaryMessage(bytes(0x10, 0x00), Direction.SERVER_TO_CLIENT))
        assertEquals(MessageAction.CONTINUE, passed.action())
        assertContentEquals(bytes(0x10, 0x00), passed.payload().getBytes())
    }

    @Test
    fun `wait_message finds a proxied binary frame by its bytes and skips the text one`() {
        val socket = Socket()
        val connection = tracked(socket)
        val result = AtomicReference<JsonObject>()
        val waiter = thread {
            result.set(bridge.waitForMessage(connection.connectionId, -1, "server_to_client", "binary", "\\xCA\\xFE", 20_000))
        }
        Thread.sleep(100)
        socket.handler!!.handleTextMessage(textMessage("\u00CA\u00FE as text", Direction.SERVER_TO_CLIENT))
        socket.handler!!.handleBinaryMessage(binaryMessage(bytes(0x01, 0xCA, 0xFE), Direction.SERVER_TO_CLIENT))
        waiter.join(20_000)

        val waited = result.get()
        assertTrue(waited["matched"]!!.jsonPrimitive.boolean, "$waited")
        val message = waited["message"]!!.jsonObject
        assertEquals(1L, message["index"]!!.jsonPrimitive.long)
        assertEquals("BINARY", message["type"]!!.jsonPrimitive.content)
        assertEquals(base64(bytes(0x01, 0xCA, 0xFE)), message["payload"]!!.jsonPrimitive.content)
        assertEquals(1L, waited["next_since_index"]!!.jsonPrimitive.long)
        assertEquals(2, waited["scanned"]!!.jsonPrimitive.int)
    }

    @Test
    fun `wait_message reports a bad filter and an unknown connection as errors`() {
        val connection = tracked()
        assertNotNull(bridge.waitForMessage(connection.connectionId, -1, "sideways", null, null, 0)["error"])
        assertNotNull(bridge.waitForMessage(connection.connectionId, -1, null, "json", null, 0)["error"])
        assertNotNull(bridge.waitForMessage(connection.connectionId, -1, null, null, "(", 0)["error"])
        assertNotNull(bridge.waitForMessage("ws-missing", -1, null, null, null, 0)["error"])
    }

    @Test
    fun `wait_message clamps its numbers and says so`() {
        val connection = tracked()
        connection.append("server_to_client", "TEXT", "hello", 5)

        val waited = bridge.waitForMessage(connection.connectionId, 99, null, null, null, -5)

        assertFalse(waited["matched"]!!.jsonPrimitive.boolean)
        assertEquals("timeout", waited["reason"]!!.jsonPrimitive.content)
        val clamped = waited["clamped"]!!.jsonObject
        assertEquals(0L, clamped["timeout_ms"]!!.jsonPrimitive.long)
        assertEquals(0L, clamped["since_index"]!!.jsonPrimitive.long)
    }
}
