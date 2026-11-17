package io.bitbytelab.raijin.bridge

import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.core.Registration
import burp.api.montoya.websocket.BinaryMessage
import burp.api.montoya.websocket.BinaryMessageAction
import burp.api.montoya.websocket.Direction
import burp.api.montoya.websocket.MessageHandler
import burp.api.montoya.websocket.TextMessage
import burp.api.montoya.websocket.TextMessageAction
import burp.api.montoya.websocket.WebSocketCreated
import burp.api.montoya.websocket.WebSocketCreatedHandler
import io.bitbytelab.raijin.bridge.WebSocketBridge.Companion.MAX_CONNECTIONS
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.state.WebSocketConnection
import io.bitbytelab.raijin.state.WebSocketMessage
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

/**
 * The [WebSocketCreatedHandler] of [WebSocketBridge]: tracks each socket a Burp tool opens (Proxy,
 * Repeater, ...), applies the intercept rules to its frames and records them. A socket
 * [WebSocketConnections] opened is recognised by its Sec-WebSocket-Key and left to [tapIfOwn], so
 * it is never tracked twice.
 *
 * Also keeps what both kinds of socket share: the message-handler registrations deregistered on
 * unload, the "websocket.message" and "websocket.closed" events, and the eviction of closed
 * connections.
 *
 * @param tapIfOwn [WebSocketConnections.tapIfOwn]: taps a reported socket Raijin opened itself;
 *   false for any other socket.
 * @param closeHandle [WebSocketConnections.closeHandle]: closes the send handle of an evicted connection.
 */
internal class WebSocketBurpTap(
    private val eventBus: EventBus,
    private val stateManager: StateManager,
    private val isShutDown: () -> Boolean,
    private val evaluateRules: (url: String?, direction: String, binary: Boolean, content: () -> String) -> WebSocketInterceptRules.Outcome,
    private val tapIfOwn: (key: String, created: WebSocketCreated) -> Boolean,
    private val closeHandle: (connectionId: String) -> Unit,
) {
    /** Message-handler registrations on Burp-created sockets, by connection ID; deregistered on unload. */
    private val handlerRegistrations = ConcurrentHashMap<String, Registration>()

    /**
     * Creates a WebSocketCreatedHandler that monitors all WebSocket connections
     * initiated through Burp's proxy (or any other Burp component). Each new
     * connection is tracked in StateManager and emits lifecycle events. Sockets
     * opened by [WebSocketConnections.createConnection] are recognised by their Sec-WebSocket-Key and
     * tapped for that connection instead of being tracked a second time.
     *
     * @return A WebSocketCreatedHandler to register with the Montoya API.
     */
    fun createWebSocketHandler(): WebSocketCreatedHandler {
        return WebSocketCreatedHandler { webSocketCreated: WebSocketCreated ->
            try {
                onWebSocketCreated(webSocketCreated)
            } catch (_: Exception) {
                // Tracking is best-effort; it must never interfere with the socket itself.
            }
        }
    }

    private fun onWebSocketCreated(created: WebSocketCreated) {
        if (isShutDown()) return
        val upgradeRequest = created.upgradeRequest()
        val key = try { upgradeRequest.headerValue("Sec-WebSocket-Key") } catch (_: Exception) { null }
        // One of Raijin's own sockets: recorded for its connection, never tracked a second time.
        if (key != null && tapIfOwn(key, created)) return

        val url = try { upgradeRequest.url() } catch (_: Exception) { "" }
        val source = try { created.toolSource().toolType().name.lowercase() } catch (_: Exception) { "proxy" }
        val connection = WebSocketConnection(
            connectionId = stateManager.generateId("ws"),
            url = url,
            createdAt = Instant.now().toString(),
        )
        evictClosedConnectionsIfNeeded()
        stateManager.websocketConnections[connection.connectionId] = connection

        // Emit creation event
        eventBus.emit("websocket.created", buildJsonObject {
            put("connection_id", connection.connectionId)
            put("url", url)
            put("source", source)
            put("timestamp", Instant.now().toString())
        })

        keepRegistration(connection.connectionId, created.webSocket().registerMessageHandler(burpSocketTap(connection)))
    }

    /** Keeps [registration] for deregistration on unload, or deregisters it now if the unload has begun. */
    fun keepRegistration(connectionId: String, registration: Registration) {
        handlerRegistrations[connectionId] = registration
        if (isShutDown()) handlerRegistrations.remove(connectionId)?.let { runCatching { it.deregister() } }
    }

    /** Forgets the registration kept for [connectionId] without deregistering it: its socket has closed. */
    fun dropRegistration(connectionId: String) {
        handlerRegistrations.remove(connectionId)
    }

    /**
     * Tap for a socket created by a Burp tool (Proxy, Repeater, ...): applies intercept rules and
     * records each frame as it was actually forwarded — the rewritten payload for "modify", the
     * original marked *_DROPPED for "drop". Text and binary frames are treated alike. A failure
     * here forwards the frame unchanged.
     */
    private fun burpSocketTap(connection: WebSocketConnection): MessageHandler = object : MessageHandler {
        override fun handleTextMessage(textMessage: TextMessage): TextMessageAction = try {
            tapText(connection, textMessage)
        } catch (_: Exception) {
            TextMessageAction.continueWith(textMessage)
        }

        override fun handleBinaryMessage(binaryMessage: BinaryMessage): BinaryMessageAction = try {
            tapBinary(connection, binaryMessage)
        } catch (_: Exception) {
            BinaryMessageAction.continueWith(binaryMessage)
        }

        override fun onClose() {
            handlerRegistrations.remove(connection.connectionId)
            markClosed(connection)
        }
    }

    private fun tapText(connection: WebSocketConnection, textMessage: TextMessage): TextMessageAction {
        val direction = directionName(textMessage.direction())
        val originalPayload = textMessage.payload()
        val outcome = evaluateRules(connection.url, direction, false) { originalPayload }
        val dropped = outcome === WebSocketInterceptRules.Outcome.Drop
        val forwarded = (outcome as? WebSocketInterceptRules.Outcome.Modify)?.content ?: originalPayload

        if (!dropped) countFrame(connection, direction)
        val message = connection.append(
            direction, if (dropped) "TEXT_DROPPED" else "TEXT", forwarded, WebSocketFrames.utf8Length(forwarded)
        )
        emitMessageEvent(connection.connectionId, message)

        return when (outcome) {
            WebSocketInterceptRules.Outcome.Drop -> TextMessageAction.drop()
            is WebSocketInterceptRules.Outcome.Modify -> TextMessageAction.continueWith(outcome.content)
            WebSocketInterceptRules.Outcome.Continue -> TextMessageAction.continueWith(textMessage)
        }
    }

    private fun tapBinary(connection: WebSocketConnection, binaryMessage: BinaryMessage): BinaryMessageAction {
        val direction = directionName(binaryMessage.direction())
        val originalBytes = binaryMessage.payload().getBytes()
        val outcome = evaluateRules(connection.url, direction, true) { WebSocketFrames.latin1(originalBytes) }
        val dropped = outcome === WebSocketInterceptRules.Outcome.Drop
        val forwarded = (outcome as? WebSocketInterceptRules.Outcome.Modify)
            ?.let { WebSocketFrames.latin1Bytes(it.content) } ?: originalBytes

        if (!dropped) countFrame(connection, direction)
        val message = connection.append(
            direction, if (dropped) "BINARY_DROPPED" else "BINARY", WebSocketFrames.encodeBase64(forwarded), forwarded.size
        )
        emitMessageEvent(connection.connectionId, message)

        return when (outcome) {
            WebSocketInterceptRules.Outcome.Drop -> BinaryMessageAction.drop()
            is WebSocketInterceptRules.Outcome.Modify -> BinaryMessageAction.continueWith(BurpByteArray.byteArray(*forwarded))
            WebSocketInterceptRules.Outcome.Continue -> BinaryMessageAction.continueWith(binaryMessage)
        }
    }

    private fun countFrame(connection: WebSocketConnection, direction: String) {
        if (direction == "server_to_client") connection.messagesReceived.incrementAndGet()
        else connection.messagesSent.incrementAndGet()
    }

    private fun directionName(direction: Direction?): String = when (direction) {
        Direction.CLIENT_TO_SERVER -> "client_to_server"
        Direction.SERVER_TO_CLIENT -> "server_to_client"
        else -> "unknown"
    }

    fun emitMessageEvent(connectionId: String, message: WebSocketMessage) {
        eventBus.emit("websocket.message", buildJsonObject {
            put("connection_id", connectionId)
            put("direction", message.direction)
            put("type", message.type)
            put("index", message.index)
            put("length", message.length)
            put("timestamp", message.timestamp)
        })
    }

    /** Marks [connection] closed and emits "websocket.closed" once, whichever close path gets there first. */
    fun markClosed(connection: WebSocketConnection) {
        if (!connection.markClosed()) return
        eventBus.emit("websocket.closed", buildJsonObject {
            put("connection_id", connection.connectionId)
            put("url", connection.url)
            put("messages_sent", connection.messagesSent.get())
            put("messages_received", connection.messagesReceived.get())
            put("timestamp", Instant.now().toString())
        })
    }

    /** Once [MAX_CONNECTIONS] are tracked, drops the oldest closed connections (and anything they still hold). */
    fun evictClosedConnectionsIfNeeded() {
        val connections = stateManager.websocketConnections
        if (connections.size < MAX_CONNECTIONS) return
        val closedOldest = connections.values
            .filter { it.status == "closed" }
            .sortedBy { runCatching { Instant.parse(it.createdAt) }.getOrDefault(Instant.EPOCH) }
        for (connection in closedOldest) {
            if (connections.size < MAX_CONNECTIONS) break
            val id = connection.connectionId
            connections.remove(id)
            closeHandle(id)
            handlerRegistrations.remove(id)?.let { runCatching { it.deregister() } }
        }
    }

    /** On unload: deregisters every message handler still attached, so none keeps calling into unloaded code. */
    fun shutdown() {
        handlerRegistrations.values.forEach { reg -> runCatching { reg.deregister() } }
        handlerRegistrations.clear()
    }
}
