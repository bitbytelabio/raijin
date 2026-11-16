package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.core.Registration
import burp.api.montoya.core.ToolSource
import burp.api.montoya.core.ToolType
import burp.api.montoya.http.HttpService
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
import burp.api.montoya.websocket.WebSockets
import burp.api.montoya.websocket.extension.ExtensionWebSocket
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreation
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreationStatus
import burp.api.montoya.websocket.extension.ExtensionWebSocketMessageHandler
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.lang.reflect.Proxy
import java.util.Base64
import java.util.Optional
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Sockets Raijin opens itself ([WebSocketBridge.createConnection]), end to end against an in-memory
 * server behind Montoya's `ExtensionWebSocket`: frames pushed right after the upgrade, binary
 * frames byte for byte, waiting for replies, failed sends, and fuzz runs over one connection or a
 * fresh one per payload.
 */
class WebSocketBridgeSocketTest {

    private fun <T> fake(type: Class<T>, answer: (method: String, args: Array<Any?>) -> Any?): T =
        type.cast(Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { self, m, args ->
            when (m.name) {
                "hashCode" -> System.identityHashCode(self)
                "equals" -> self === args?.get(0)
                else -> answer(m.name, args ?: emptyArray())
            }
        })

    private fun registration(): Registration = fake(Registration::class.java) { name, _ -> if (name == "isRegistered") true else null }

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

    /** The upgrade request Raijin builds; only what the bridge reads back from it. */
    private fun upgradeRequest(raw: String): HttpRequest = fake(HttpRequest::class.java) { name, args ->
        when (name) {
            "headerValue" -> raw.lineSequence().map { it.trimEnd('\r') }
                .firstOrNull { it.startsWith("${args[0]}:", ignoreCase = true) }
                ?.substringAfter(':')?.trim()
            "toString" -> raw
            else -> null
        }
    }

    private val factory: MontoyaObjectFactory = fake(MontoyaObjectFactory::class.java) { name, args ->
        when (name) {
            "httpService" -> fake(HttpService::class.java) { field, _ ->
                when (field) {
                    "host" -> args[0]
                    "port" -> args[1]
                    "secure" -> args[2]
                    else -> null
                }
            }
            "httpRequest" -> upgradeRequest(args[1] as String)
            "byteArray" -> burpBytes(args[0] as ByteArray)
            "continueWithTextMessage" -> fake(TextMessageAction::class.java) { field, _ ->
                if (field == "action") MessageAction.CONTINUE else if (field == "payload") args[0] else null
            }
            "continueWithBinaryMessage" -> fake(BinaryMessageAction::class.java) { field, _ ->
                if (field == "action") MessageAction.CONTINUE else if (field == "payload") args[0] else null
            }
            else -> error("unexpected MontoyaObjectFactory.$name")
        }
    }

    /**
     * One server-side socket. [push] delivers a frame the way Burp does: to the tap Burp's
     * created-handler path attached, if any, and to the extension's handler.
     */
    private inner class Server {
        @Volatile var handler: ExtensionWebSocketMessageHandler? = null
        @Volatile var tap: MessageHandler? = null
        val receivedText = CopyOnWriteArrayList<String>()
        val receivedBytes = CopyOnWriteArrayList<ByteArray>()
        val closes = AtomicInteger()

        val socket: ExtensionWebSocket = fake(ExtensionWebSocket::class.java) { name, args ->
            when (name) {
                "registerMessageHandler" -> {
                    handler = args[0] as ExtensionWebSocketMessageHandler
                    onConnect(this)
                    registration()
                }
                "sendTextMessage" -> {
                    val message = args[0] as String
                    tap?.handleTextMessage(textMessage(message, Direction.CLIENT_TO_SERVER))
                    receivedText += message
                    onText(this, message)
                    null
                }
                "sendBinaryMessage" -> {
                    val bytes = (args[0] as BurpByteArray).getBytes()
                    tap?.handleBinaryMessage(binaryMessage(bytes, Direction.CLIENT_TO_SERVER))
                    receivedBytes += bytes
                    onBinary(this, bytes)
                    null
                }
                "close" -> {
                    closes.incrementAndGet()
                    closeFromServer()
                    null
                }
                else -> null
            }
        }

        fun push(text: String) {
            tap?.handleTextMessage(textMessage(text, Direction.SERVER_TO_CLIENT))
            handler?.textMessageReceived(textMessage(text, Direction.SERVER_TO_CLIENT))
        }

        fun pushBinary(bytes: ByteArray) {
            tap?.handleBinaryMessage(binaryMessage(bytes, Direction.SERVER_TO_CLIENT))
            handler?.binaryMessageReceived(binaryMessage(bytes, Direction.SERVER_TO_CLIENT))
        }

        fun closeFromServer() {
            tap?.onClose()
            handler?.onClose()
        }

        /** How Burp reports this socket to a [burp.api.montoya.websocket.WebSocketCreatedHandler]. */
        fun created(upgrade: HttpRequest): WebSocketCreated {
            val burpSide = fake(WebSocket::class.java) { name, args ->
                if (name == "registerMessageHandler") {
                    tap = args[0] as MessageHandler
                    registration()
                } else {
                    null
                }
            }
            val source = fake(ToolSource::class.java) { name, _ -> if (name == "toolType") ToolType.EXTENSIONS else null }
            return fake(WebSocketCreated::class.java) { name, _ ->
                when (name) {
                    "upgradeRequest" -> upgrade
                    "webSocket" -> burpSide
                    "toolSource" -> source
                    else -> null
                }
            }
        }
    }

    @Volatile private var onConnect: (Server) -> Unit = {}
    @Volatile private var onText: (Server, String) -> Unit = { _, _ -> }
    @Volatile private var onBinary: (Server, ByteArray) -> Unit = { server, bytes -> server.pushBinary(bytes) }

    /** Burp also reports Raijin's own sockets to the created handler, before any frame flows. */
    @Volatile private var reportToCreatedHandler = false

    private val servers = CopyOnWriteArrayList<Server>()
    private val upgrades = CopyOnWriteArrayList<String>()

    private val websockets: WebSockets = fake(WebSockets::class.java) { name, args ->
        if (name == "createWebSocket" && args.size == 1) createWebSocket(args[0] as HttpRequest) else error("unexpected WebSockets.$name")
    }

    private val api: MontoyaApi = fake(MontoyaApi::class.java) { name, _ ->
        if (name == "websockets") websockets else error("unexpected MontoyaApi.$name")
    }

    private val state = StateManager()
    private val bridge = WebSocketBridge(api, EventBus(), state)

    private fun createWebSocket(upgrade: HttpRequest): ExtensionWebSocketCreation {
        upgrades += upgrade.toString()
        val server = Server()
        servers += server
        if (reportToCreatedHandler) bridge.createWebSocketHandler().handleWebSocketCreated(server.created(upgrade))
        return fake(ExtensionWebSocketCreation::class.java) { name, _ ->
            when (name) {
                "status" -> ExtensionWebSocketCreationStatus.SUCCESS
                "webSocket" -> Optional.of(server.socket)
                "upgradeResponse" -> Optional.empty<Any>()
                else -> null
            }
        }
    }

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

    private fun open(url: String = "wss://echo.test/ws"): String {
        val created = bridge.createConnection(url, null, null)
        assertNull(created["error"], "$created")
        return created.text("connection_id")
    }

    private fun messages(id: String): List<JsonObject> =
        bridge.getMessages(id, null, -1, 100).getValue("messages").jsonArray.map { it.jsonObject }

    private fun JsonObject.text(key: String) = getValue(key).jsonPrimitive.content

    private val allBytes = ByteArray(256) { it.toByte() }

    @Test
    fun `a frame the server pushes right after the upgrade is recorded`() {
        onConnect = { it.push("hello") }

        val id = open()

        val recorded = messages(id).single()
        assertEquals("hello", recorded.text("payload"))
        assertEquals("server_to_client", recorded.text("direction"))
        assertEquals(1L, state.websocketConnections.getValue(id).messagesReceived.get())
    }

    @Test
    fun `a binary payload round-trips byte for byte`() {
        val id = open()

        val sent = bridge.sendBinary(id, Base64.getUrlEncoder().withoutPadding().encodeToString(allBytes))

        assertEquals("sent", sent.text("status"))
        assertEquals("BINARY", sent.text("type"))
        assertEquals(256, sent["length"]!!.jsonPrimitive.int)
        assertContentEquals(allBytes, servers.single().receivedBytes.single())
        val canonical = Base64.getEncoder().encodeToString(allBytes)
        val recorded = messages(id)
        assertEquals(listOf("client_to_server", "server_to_client"), recorded.map { it.text("direction") })
        for (frame in recorded) {
            assertEquals("BINARY", frame.text("type"))
            assertEquals(canonical, frame.text("payload"))
            assertEquals(256, frame["length"]!!.jsonPrimitive.int)
        }

        val index = sent["message_index"]!!.jsonPrimitive.long
        val echo = bridge.waitForMessage(id, index, "server_to_client", "BINARY", "(?-i)\\x00\\x01\\x02", 5_000)
        assertTrue(echo["matched"]!!.jsonPrimitive.boolean, "$echo")
        val message = echo.getValue("message").jsonObject
        assertEquals(index + 1, message["index"]!!.jsonPrimitive.long)
        assertContentEquals(allBytes, Base64.getDecoder().decode(message.text("payload")))
    }

    @Test
    fun `data that is not base64 is refused before anything is sent`() {
        val id = open()

        val refused = bridge.sendBinary(id, "not base64!")

        assertTrue(refused.text("error").contains("base64"), "$refused")
        assertTrue(servers.single().receivedBytes.isEmpty())
        assertTrue(messages(id).isEmpty())
    }

    @Test
    fun `wait_message returns a reply that came before the call and one that comes after it`() {
        onText = { server, message ->
            if (message == "sync") {
                server.push("reply to sync")
            } else {
                thread {
                    Thread.sleep(200)
                    server.push("reply to $message")
                }
            }
        }
        val id = open()

        val first = bridge.sendText(id, "sync")["message_index"]!!.jsonPrimitive.long
        val found = bridge.waitForMessage(id, first, "server_to_client", null, null, 5_000)
        assertTrue(found["matched"]!!.jsonPrimitive.boolean, "$found")
        assertEquals("reply to sync", found.getValue("message").jsonObject.text("payload"))

        val second = bridge.sendText(id, "async")["message_index"]!!.jsonPrimitive.long
        val awaited = bridge.waitForMessage(id, second, "server_to_client", null, null, 10_000)
        assertTrue(awaited["matched"]!!.jsonPrimitive.boolean, "$awaited")
        val reply = awaited.getValue("message").jsonObject
        assertEquals("reply to async", reply.text("payload"))
        assertEquals(reply["index"]!!.jsonPrimitive.long, awaited["next_since_index"]!!.jsonPrimitive.long)
    }

    @Test
    fun `without since_index only frames that arrive after the call count`() {
        onConnect = { it.push("hello") }
        val id = open()

        val later = bridge.waitForMessage(id, null, "server_to_client", null, null, 200)
        assertFalse(later["matched"]!!.jsonPrimitive.boolean)
        assertEquals("timeout", later.text("reason"))
        assertEquals(0L, later["since_index"]!!.jsonPrimitive.long)

        val any = bridge.waitForMessage(id, -1, "server_to_client", null, null, 200)
        assertEquals("hello", any.getValue("message").jsonObject.text("payload"))
    }

    @Test
    fun `a send that fails is kept as UNSENT and the error reaches the caller`() {
        onText = { _, message -> if (message == "boom") throw IllegalStateException("socket write failed") }
        val id = open()

        val failure = assertFailsWith<IllegalStateException> { bridge.sendText(id, "boom") }

        assertEquals("socket write failed", failure.message)
        assertEquals("TEXT_UNSENT", messages(id).single().text("type"))
        assertEquals(0L, state.websocketConnections.getValue(id).messagesSent.get())
    }

    @Test
    fun `a server close releases a waiter and ends sending`() {
        val id = open()
        val server = servers.single()
        val closer = thread {
            Thread.sleep(150)
            server.closeFromServer()
        }

        val waited = bridge.waitForMessage(id, null, "server_to_client", null, null, 20_000)
        closer.join()

        assertFalse(waited["matched"]!!.jsonPrimitive.boolean)
        assertEquals("connection_closed", waited.text("reason"))
        assertEquals("closed", waited.text("status"))
        assertNotNull(bridge.sendText(id, "too late")["error"])
    }

    @Test
    fun `a socket Burp also reports to the created handler is tracked once and records each frame once`() {
        reportToCreatedHandler = true
        val id = open()
        val server = servers.single()
        assertNotNull(server.tap, "the created-handler path attached its tap")

        server.push("one")
        bridge.sendText(id, "two")

        assertEquals(listOf("one", "two"), messages(id).map { it.text("payload") })
        assertEquals(1, state.websocketConnections.size)
    }

    @Test
    fun `fuzz over an open connection credits each payload with its reply`() {
        onText = { server, message -> server.push(if (message.contains("'")) "error: unterminated string" else "ok $message") }
        val id = open()

        val result = bridge.fuzz(WebSocketFuzzRequest(listOf("alpha", "bravo", "char'lie"), connectionId = id, idleMs = 50))

        assertEquals(3, result["sent"]!!.jsonPrimitive.int)
        val frames = result.getValue("results").jsonArray.map { entry ->
            entry.jsonObject.getValue("frames").jsonArray.map { it.jsonObject.text("payload") }
        }
        assertEquals(listOf(listOf("ok alpha"), listOf("ok bravo"), listOf("error: unterminated string")), frames)
        assertEquals(listOf(2, 1), result.getValue("clusters").jsonArray.map { it.jsonObject["count"]!!.jsonPrimitive.int })
        assertEquals(listOf("alpha", "bravo", "char'lie"), servers.single().receivedText)
    }

    @Test
    fun `fuzz with a url opens a socket per payload, with the given headers, and closes each one`() {
        onConnect = { it.push("welcome") }
        onText = { server, message -> server.push("echo $message") }

        val result = bridge.fuzz(
            WebSocketFuzzRequest(listOf("one", "two"), url = "wss://echo.test/ws", headers = mapOf("Cookie" to "session=abc"), idleMs = 50)
        )

        assertEquals(2, servers.size)
        assertTrue(upgrades.all { it.contains("Cookie: session=abc\r\n") }, "$upgrades")
        val results = result.getValue("results").jsonArray.map { it.jsonObject }
        assertEquals(
            listOf(listOf("echo one"), listOf("echo two")),
            results.map { entry -> entry.getValue("frames").jsonArray.map { it.jsonObject.text("payload") } },
        )
        val ids = results.map { it.text("connection_id") }
        assertEquals(2, ids.toSet().size)
        assertTrue(ids.all { state.websocketConnections.getValue(it).status == "closed" })
        assertTrue(servers.all { it.closes.get() == 1 })
    }
}
