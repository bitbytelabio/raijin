package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Registration
import burp.api.montoya.core.ToolSource
import burp.api.montoya.core.ToolType
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.websocket.MessageHandler
import burp.api.montoya.websocket.WebSocket
import burp.api.montoya.websocket.WebSocketCreated
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.lang.reflect.Proxy
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Lifecycle of sockets Burp tools create (Proxy, Repeater, ...): tracking, single close,
 * eviction of closed connections at the cap, and handler deregistration on extension unload.
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

    private val state = StateManager()
    private val events = EventBus()
    private val bridge = WebSocketBridge(fake(MontoyaApi::class.java) { _, _ -> null }, events, state)

    @AfterTest
    fun shutDown() = bridge.shutdown()

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
        assertNotNull(bridge.getMessages(connection.connectionId, null, -2, 100)["error"])
    }
}
