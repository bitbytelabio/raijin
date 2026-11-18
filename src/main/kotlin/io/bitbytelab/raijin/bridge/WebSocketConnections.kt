package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.websocket.BinaryMessage
import burp.api.montoya.websocket.BinaryMessageAction
import burp.api.montoya.websocket.Direction
import burp.api.montoya.websocket.MessageHandler
import burp.api.montoya.websocket.TextMessage
import burp.api.montoya.websocket.TextMessageAction
import burp.api.montoya.websocket.WebSocketCreated
import burp.api.montoya.websocket.WebSocketCreatedHandler
import burp.api.montoya.websocket.extension.ExtensionWebSocket
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreation
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreationStatus
import burp.api.montoya.websocket.extension.ExtensionWebSocketMessageHandler
import io.bitbytelab.raijin.bridge.WebSocketBridge.Companion.CONNECT_TIMEOUT_MS
import io.bitbytelab.raijin.bridge.WebSocketBridge.Companion.buildErrorJson
import io.bitbytelab.raijin.bridge.WebSocketBridge.Companion.validateScheme
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.safety.HeaderSafety
import io.bitbytelab.raijin.safety.ScopeGate
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.state.WebSocketConnection
import io.bitbytelab.raijin.state.WebSocketMessage
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.Base64
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicReference

/**
 * The sockets [WebSocketBridge] opens itself. [createConnection] upgrades one through Montoya's
 * [ExtensionWebSocket] API and records its server frames from the moment it exists (see
 * [OwnSocket]); [sendText] and [sendBinary] send on it. [close] and [listConnections] cover every
 * tracked connection, including those of sockets Burp tools open, which [tap] tracks; [tap] also
 * keeps the events, handler registrations and eviction both kinds of socket share.
 */
internal class WebSocketConnections(
    private val api: MontoyaApi,
    private val eventBus: EventBus,
    private val stateManager: StateManager,
    private val tap: WebSocketBurpTap,
    private val isShutDown: () -> Boolean,
    private val adviseIncomingRules: (url: String?, direction: String, binary: Boolean, content: () -> String) -> Unit,
) {
    /** Advisory only: an out-of-scope socket is flagged, never refused. */
    private val scopeGate = ScopeGate(api)

    /** Maps connection IDs to the Montoya ExtensionWebSocket object for sending messages. */
    private val webSocketHandles = ConcurrentHashMap<String, ExtensionWebSocket>()

    /** Sockets opened by [createConnection], keyed by the Sec-WebSocket-Key of their upgrade request. */
    private val ownSockets = ConcurrentHashMap<String, OwnSocket>()

    /** Runs the blocking createWebSocket call so a stalled upgrade cannot wedge the tool call. */
    private val createExecutor: ExecutorService = Executors.newCachedThreadPool { task ->
        Thread(task, "raijin-ws-create").apply { isDaemon = true }
    }

    /** Which handler records the server frames of an [OwnSocket]. */
    private enum class Capture { PENDING, CREATED_HANDLER, EXTENSION_HANDLER }

    /**
     * A socket opened by [createConnection]. Its server frames are recorded by exactly one handler:
     * the [WebSocketCreatedHandler] tap when Burp reports the socket there (attached before any frame
     * flows), otherwise the [ExtensionWebSocketMessageHandler] registered as soon as createWebSocket
     * returns. [capture] holds the winner, so a frame is never recorded twice.
     */
    private class OwnSocket(val key: String, val connection: WebSocketConnection) {
        val capture = AtomicReference(Capture.PENDING)
    }

    /**
     * Creates a new WebSocket connection by constructing an HTTP upgrade
     * request and using the Montoya WebSocket API.
     *
     * The returned connection is stored in StateManager. Server frames are captured
     * from the moment the socket exists: by the created-socket tap when Burp reports
     * the socket there, otherwise by a handler attached on the creating thread before
     * the socket is handed back (see [OwnSocket]).
     *
     * @param url The WebSocket URL (e.g. "wss://example.com/ws").
     * @param headers Optional map of additional HTTP headers for the upgrade request.
     * @param subprotocol Optional WebSocket subprotocol to request.
     * @return JSON object with the connection ID and status.
     */
    fun createConnection(url: String, headers: Map<String, String>?, subprotocol: String?): JsonObject {
        // Split leniently (hosts with '_', paths with '|', spaces or '{' are a test's business).
        val parts = HttpRequestBuilder.splitUrl(url)
            ?: return buildErrorJson("Invalid URL: expected ws://host/path or wss://host/path, got '$url'")

        // Reject obviously non-WebSocket schemes before attempting an upgrade so
        // callers get a clear message instead of a generic connection failure.
        validateScheme(parts.scheme)?.let { return buildErrorJson(it) }

        val (host, urlPort) = HttpRequestBuilder.parseHostValue(parts.authority)
            ?: return buildErrorJson("Invalid URL: missing host")
        val useTls = parts.scheme.equals("wss", ignoreCase = true) || parts.scheme.equals("https", ignoreCase = true)
        val port = urlPort ?: if (useTls) 443 else 80
        val hostLiteral = if (host.contains(':') && !host.startsWith("[")) "[$host]" else host
        val scope = scopeGate.advise("${if (useTls) "https" else "http"}://$hostLiteral:$port${parts.target}", "websocket")

        // The handshake goes out exactly as given; a raw CR/LF is reported, never removed.
        val warnings = buildList {
            val path = parts.target.substringBefore('?')
            val query = parts.target.substring(path.length)
            if (HeaderSafety.containsCrlf(path)) add("raw CR/LF in path sent as written")
            if (HeaderSafety.containsCrlf(query)) add("raw CR/LF in query sent as written")
            headers?.forEach { (name, value) ->
                if (HeaderSafety.containsCrlf(name)) add("raw CR/LF in header name '$name' sent as written")
                if (HeaderSafety.containsCrlf(value)) add("raw CR/LF in header '$name' value sent as written")
            }
        }
        var result = openConnection(url, host, port, useTls, parts.authority, parts.target, headers, subprotocol)
        if (warnings.isNotEmpty()) result = JsonObject(result + ("warnings" to JsonArray(warnings.map { JsonPrimitive(it) })))
        return scope.annotate(result)
    }

    private fun openConnection(
        url: String,
        host: String,
        port: Int,
        useTls: Boolean,
        authority: String,
        target: String,
        headers: Map<String, String>?,
        subprotocol: String?,
    ): JsonObject {
        // Build the HTTP upgrade request. Its Sec-WebSocket-Key identifies the socket when Burp
        // reports it to createWebSocketHandler.
        val wsKey = generateWebSocketKey()
        val httpService = HttpService.httpService(host, port, useTls)
        val requestBuilder = StringBuilder()
        requestBuilder.append("GET $target HTTP/1.1\r\n")
        requestBuilder.append("Host: $authority\r\n")
        requestBuilder.append("Upgrade: websocket\r\n")
        requestBuilder.append("Connection: Upgrade\r\n")
        requestBuilder.append("Sec-WebSocket-Version: 13\r\n")
        requestBuilder.append("Sec-WebSocket-Key: $wsKey\r\n")

        if (subprotocol != null) {
            requestBuilder.append("Sec-WebSocket-Protocol: $subprotocol\r\n")
        }

        headers?.forEach { (name, value) ->
            requestBuilder.append("$name: $value\r\n")
        }

        requestBuilder.append("\r\n")

        val httpRequest = HttpRequest.httpRequest(httpService, requestBuilder.toString())

        val connection = WebSocketConnection(
            connectionId = stateManager.generateId("ws"),
            url = url,
            createdAt = Instant.now().toString(),
        )
        val own = OwnSocket(wsKey, connection)
        ownSockets[wsKey] = own

        // Create the WebSocket connection through the Montoya API. The call is
        // blocking and can hang indefinitely when a host accepts the TCP
        // connection but never completes the upgrade (common with plaintext
        // ws:// against a TLS port, or a silently-dropping middlebox). Bound it
        // on a worker thread so the tool call always returns promptly.
        val future = try {
            CompletableFuture.supplyAsync({ openSocket(httpRequest, own) }, createExecutor)
        } catch (e: Exception) {
            ownSockets.remove(wsKey)
            return buildErrorJson("WebSocket creation failed: ${e.message ?: e.javaClass.simpleName}")
        }
        // The blocking create may still succeed after the caller stopped waiting for it: close that
        // socket instead of leaking it.
        fun closeWhenCreated() {
            future.whenComplete { late, _ ->
                late?.webSocket()?.ifPresent { ws -> runCatching { ws.close() } }
                ownSockets.remove(wsKey)
            }
        }
        val creation: ExtensionWebSocketCreation = try {
            future.get(CONNECT_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            closeWhenCreated()
            return buildErrorJson(
                "WebSocket upgrade timed out after $CONNECT_TIMEOUT_MS ms " +
                    "(host accepted the connection but did not complete the upgrade)"
            )
        } catch (e: InterruptedException) {
            // A cancelled tool call (or fuzz run). The interrupt stays set so the caller stops as well.
            closeWhenCreated()
            Thread.currentThread().interrupt()
            return buildErrorJson("WebSocket creation interrupted")
        } catch (e: Exception) {
            ownSockets.remove(wsKey)
            val cause = e.cause ?: e
            return buildErrorJson("WebSocket creation failed: ${cause.message ?: cause.javaClass.simpleName}")
        }

        val webSocket = creation.webSocket().orElse(null)
        if (webSocket == null) {
            ownSockets.remove(wsKey)
            // Surface the real failure reason from the creation status rather
            // than a single generic message, so scheme/port mismatches are
            // distinguishable from DNS and connection failures.
            val status = creation.status()
            val upgradeResponseOpt = creation.upgradeResponse()
            val upgradeStatusCode: Int? =
                if (upgradeResponseOpt.isPresent) upgradeResponseOpt.get().statusCode().toInt() else null
            return buildJsonObject {
                put("error", describeCreationStatus(status, upgradeStatusCode))
                put("status", status?.name ?: "UNKNOWN")
                if (upgradeStatusCode != null) put("upgrade_status_code", upgradeStatusCode)
            }
        }
        if (isShutDown()) {
            runCatching { webSocket.close() }
            ownSockets.remove(wsKey)
            return buildErrorJson("WebSocket bridge is shut down (extension unloading)")
        }

        val connectionId = connection.connectionId
        tap.evictClosedConnectionsIfNeeded()
        stateManager.websocketConnections[connectionId] = connection
        webSocketHandles[connectionId] = webSocket
        // Re-check after publishing the handle: an unload or an early server close may have run meanwhile.
        if (isShutDown()) {
            webSocketHandles.remove(connectionId)
            runCatching { webSocket.close() }
        } else if (connection.status == "closed") {
            webSocketHandles.remove(connectionId)
        }

        // Emit connection created event
        eventBus.emit("websocket.created", buildJsonObject {
            put("connection_id", connectionId)
            put("url", url)
            put("host", host)
            put("port", port)
            put("use_tls", useTls)
            put("timestamp", Instant.now().toString())
        })

        return buildJsonObject {
            put("connection_id", connectionId)
            put("url", url)
            put("host", host)
            put("port", port)
            put("use_tls", useTls)
            put("status", connection.status)
        }
    }

    /**
     * Runs on [createExecutor]. Attaches the capture handler before handing the socket back, so
     * frames the server pushes right after the 101 are recorded rather than arriving unobserved.
     */
    private fun openSocket(request: HttpRequest, own: OwnSocket): ExtensionWebSocketCreation {
        val creation = api.websockets().createWebSocket(request)
        creation.webSocket().ifPresent { ws -> attachExtensionHandler(ws, own) }
        return creation
    }

    private fun attachExtensionHandler(webSocket: ExtensionWebSocket, own: OwnSocket) {
        val recordFrames = own.capture.compareAndSet(Capture.PENDING, Capture.EXTENSION_HANDLER)
        val connection = own.connection
        webSocket.registerMessageHandler(object : ExtensionWebSocketMessageHandler {
            override fun textMessageReceived(textMessage: TextMessage) {
                if (recordFrames) recordServerText(connection, textMessage.payload())
            }

            override fun binaryMessageReceived(binaryMessage: BinaryMessage) {
                if (recordFrames) recordServerBinary(connection, binaryMessage.payload().getBytes())
            }

            override fun onClose() = onOwnSocketClosed(own)
        })
    }

    /**
     * Called by [tap] for each socket Burp reports. True when [key], the Sec-WebSocket-Key of its
     * upgrade request, is that of a socket [createConnection] opened: that socket is tapped here for
     * its connection, unless the extension handler records it already, and must not be tracked again.
     */
    fun tapIfOwn(key: String, created: WebSocketCreated): Boolean {
        val own = ownSockets[key] ?: return false
        // Burp reports the socket before any frame flows, so tapping here loses nothing.
        if (own.capture.compareAndSet(Capture.PENDING, Capture.CREATED_HANDLER)) {
            try {
                tap.keepRegistration(own.connection.connectionId, created.webSocket().registerMessageHandler(ownSocketTap(own)))
            } catch (_: Exception) {
                // Let the extension handler record the frames instead.
                own.capture.set(Capture.PENDING)
            }
        }
        return true
    }

    /** Tap for an [OwnSocket] attached from [tapIfOwn]; client frames are recorded by the send methods. */
    private fun ownSocketTap(own: OwnSocket): MessageHandler = object : MessageHandler {
        override fun handleTextMessage(textMessage: TextMessage): TextMessageAction {
            if (textMessage.direction() == Direction.SERVER_TO_CLIENT) recordServerText(own.connection, textMessage.payload())
            return TextMessageAction.continueWith(textMessage)
        }

        override fun handleBinaryMessage(binaryMessage: BinaryMessage): BinaryMessageAction {
            if (binaryMessage.direction() == Direction.SERVER_TO_CLIENT) {
                recordServerBinary(own.connection, binaryMessage.payload().getBytes())
            }
            return BinaryMessageAction.continueWith(binaryMessage)
        }

        override fun onClose() = onOwnSocketClosed(own)
    }

    /**
     * Records a server text frame on a socket opened by [createConnection]. That socket's receive
     * callback cannot drop or rewrite frames, so matching intercept rules are reported, not applied.
     */
    private fun recordServerText(connection: WebSocketConnection, payload: String) {
        try {
            connection.messagesReceived.incrementAndGet()
            val message = connection.append("server_to_client", "TEXT", payload, WebSocketFrames.utf8Length(payload))
            tap.emitMessageEvent(connection.connectionId, message)
            adviseIncomingRules(connection.url, "server_to_client", false) { payload }
        } catch (_: Exception) {
            // Recording is best-effort; it must never break the socket's callback thread.
        }
    }

    /** Binary counterpart of [recordServerText]; the payload is stored base64-encoded. */
    private fun recordServerBinary(connection: WebSocketConnection, bytes: ByteArray) {
        try {
            connection.messagesReceived.incrementAndGet()
            val message = connection.append("server_to_client", "BINARY", WebSocketFrames.encodeBase64(bytes), bytes.size)
            tap.emitMessageEvent(connection.connectionId, message)
            adviseIncomingRules(connection.url, "server_to_client", true) { WebSocketFrames.latin1(bytes) }
        } catch (_: Exception) {
            // See recordServerText.
        }
    }

    private fun onOwnSocketClosed(own: OwnSocket) {
        val connectionId = own.connection.connectionId
        ownSockets.remove(own.key)
        webSocketHandles.remove(connectionId)
        tap.dropRegistration(connectionId)
        tap.markClosed(own.connection)
    }

    /**
     * The socket frames for [connection] are sent on. Null when the connection is not open, or has
     * no handle: its socket was closed under us, or a Burp tool opened it and Raijin only reads it.
     */
    fun liveSocket(connection: WebSocketConnection): ExtensionWebSocket? =
        if (connection.status == "connected") webSocketHandles[connection.connectionId] else null

    /** Why [liveSocket] has no socket for [connection]. */
    fun describeUnsendable(connection: WebSocketConnection): String =
        if (connection.status != "connected") {
            "Connection is not active: status=${connection.status}"
        } else {
            "Connection handle unavailable (connection may be closed, or a Burp tool opened it and " +
                "Raijin can only read it): ${connection.connectionId}"
        }

    private fun unsendableJson(connection: WebSocketConnection): JsonObject = buildJsonObject {
        val status = connection.status
        put("error", describeUnsendable(connection))
        if (status != "connected") put("status", status)
    }

    /** Records a text frame on [connection] and sends it on [webSocket] (see [deliver]). */
    fun deliverText(connection: WebSocketConnection, webSocket: ExtensionWebSocket, message: String): WebSocketMessage =
        deliver(connection, "TEXT", message, WebSocketFrames.utf8Length(message)) { webSocket.sendTextMessage(message) }

    /** Binary counterpart of [deliverText]; the record holds the canonical base64 of [bytes]. */
    fun deliverBinary(connection: WebSocketConnection, webSocket: ExtensionWebSocket, bytes: ByteArray): WebSocketMessage =
        deliver(connection, "BINARY", WebSocketFrames.encodeBase64(bytes), bytes.size) {
            webSocket.sendBinaryMessage(BurpByteArray.byteArray(*bytes))
        }

    /**
     * Records a client frame, then sends it. The record comes first so that the frame's index is
     * lower than the index of any reply, however fast the reply is: a wait or a poll from the
     * returned index sees exactly what followed. A frame whose send throws is relabelled
     * `<type>_UNSENT` and the exception reaches the caller.
     */
    private inline fun deliver(
        connection: WebSocketConnection,
        type: String,
        payload: String,
        length: Int,
        send: () -> Unit
    ): WebSocketMessage {
        val recorded = connection.append("client_to_server", type, payload, length)
        try {
            send()
        } catch (e: Exception) {
            connection.relabel(recorded.index, "${type}_UNSENT")
            throw e
        }
        connection.messagesSent.incrementAndGet()
        tap.emitMessageEvent(connection.connectionId, recorded)
        return recorded
    }

    private fun sentJson(recorded: WebSocketMessage, connectionId: String): JsonObject = buildJsonObject {
        put("connection_id", connectionId)
        put("status", "sent")
        put("type", recorded.type)
        put("message_index", recorded.index)
        put("length", recorded.length)
    }

    /**
     * Sends a text message on an existing WebSocket connection.
     *
     * @param connectionId The connection ID to send on.
     * @param message The text message to send.
     * @return JSON object confirming the message was sent, with its `message_index`: pass it to
     *   [WebSocketBridge.waitForMessage] as `since_index` to get what followed.
     */
    fun sendText(connectionId: String, message: String): JsonObject {
        // Consult the connection record first: it is the source of truth for
        // what websocket_list advertises. Looking up the live handle first
        // reports a misleading "Connection not found" for listed-but-closed
        // connections.
        val connection = stateManager.websocketConnections[connectionId]
            ?: return buildErrorJson("Connection not found: $connectionId")
        val webSocket = liveSocket(connection) ?: return unsendableJson(connection)

        return sentJson(deliverText(connection, webSocket, message), connectionId)
    }

    /**
     * Sends a binary message on an existing WebSocket connection.
     *
     * @param connectionId The connection ID to send on.
     * @param data The bytes to send as base64: standard or URL-safe alphabet, padding optional,
     *   whitespace ignored. The frame is recorded as the canonical base64 of the bytes sent.
     * @return JSON object confirming the message was sent.
     */
    fun sendBinary(connectionId: String, data: String): JsonObject {
        // State-record first (see sendText): reserves "Connection not found" for
        // ids that are genuinely absent from websocket_list.
        val connection = stateManager.websocketConnections[connectionId]
            ?: return buildErrorJson("Connection not found: $connectionId")
        val webSocket = liveSocket(connection) ?: return unsendableJson(connection)

        val bytes = WebSocketFrames.decodeBase64(data)
            ?: return buildErrorJson("Invalid base64 in 'data' (standard or URL-safe alphabet; whitespace is ignored)")
        return sentJson(deliverBinary(connection, webSocket, bytes), connectionId)
    }

    /**
     * Closes an existing WebSocket connection and updates its state.
     *
     * @param connectionId The connection ID to close.
     * @return JSON object confirming the closure.
     */
    fun close(connectionId: String): JsonObject {
        // State-first lookup so every list-visible id is actionable. The only
        // true "not found" case is an id that is absent from the connection map.
        val connection = stateManager.websocketConnections[connectionId]
            ?: return buildErrorJson("Connection not found: $connectionId")

        // Already closed (e.g. a proxy-observed connection the peer shut down):
        // report an idempotent no-op instead of a misleading error.
        if (connection.status == "closed") {
            return buildJsonObject {
                put("connection_id", connectionId)
                put("status", "already_closed")
                put("messages_sent", connection.messagesSent.get())
                put("messages_received", connection.messagesReceived.get())
            }
        }

        // Only extension-created connections have a live handle we can drive.
        // Proxy-observed / shadow entries have none; that is not an error — we
        // simply mark the tracked state as closed.
        webSocketHandles.remove(connectionId)?.let { runCatching { it.close() } }
        tap.markClosed(connection)

        return buildJsonObject {
            put("connection_id", connectionId)
            put("status", "closed")
            put("messages_sent", connection.messagesSent.get())
            put("messages_received", connection.messagesReceived.get())
        }
    }

    /**
     * Lists all WebSocket connections currently tracked in the StateManager.
     *
     * @return JSON object containing an array of connection summaries.
     */
    fun listConnections(): JsonObject {
        val connections = stateManager.websocketConnections.values.toList()
        return buildJsonObject {
            put("total_connections", connections.size)
            putJsonArray("connections") {
                for (conn in connections) {
                    addJsonObject {
                        put("connection_id", conn.connectionId)
                        put("url", conn.url)
                        put("status", conn.status)
                        put("created_at", conn.createdAt)
                        put("messages_sent", conn.messagesSent.get())
                        put("messages_received", conn.messagesReceived.get())
                        put("total_messages", conn.messageCount())
                    }
                }
            }
        }
    }

    /** Closes and forgets the send handle of [connectionId], if it has one; for [tap]'s eviction of a closed connection. */
    fun closeHandle(connectionId: String) {
        webSocketHandles.remove(connectionId)?.let { runCatching { it.close() } }
    }

    /** On unload: stops the creation worker, closes every socket [createConnection] opened and forgets them. */
    fun shutdown() {
        createExecutor.shutdownNow()
        webSocketHandles.values.forEach { ws -> runCatching { ws.close() } }
        webSocketHandles.clear()
        ownSockets.clear()
    }

    /**
     * Generates a random Sec-WebSocket-Key for the upgrade request.
     */
    private fun generateWebSocketKey(): String {
        val bytes = ByteArray(16)
        java.security.SecureRandom().nextBytes(bytes)
        return Base64.getEncoder().encodeToString(bytes)
    }

    /**
     * Maps a Montoya [ExtensionWebSocketCreationStatus] to a human-readable
     * failure reason. Delegates to the pure, enum-name-keyed
     * [WebSocketBridge.describeCreationStatus] so the mapping is unit-testable without the
     * compileOnly Montoya API.
     */
    private fun describeCreationStatus(
        status: ExtensionWebSocketCreationStatus?,
        upgradeStatusCode: Int?
    ): String = WebSocketBridge.describeCreationStatus(status?.name, upgradeStatusCode)
}
