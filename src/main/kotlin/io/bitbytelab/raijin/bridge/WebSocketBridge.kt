package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.core.Registration
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.HttpService
import io.bitbytelab.raijin.safety.RequestHygiene
import burp.api.montoya.websocket.BinaryMessage
import burp.api.montoya.websocket.BinaryMessageAction
import burp.api.montoya.websocket.MessageHandler
import burp.api.montoya.websocket.TextMessage
import burp.api.montoya.websocket.TextMessageAction
import burp.api.montoya.websocket.WebSocketCreated
import burp.api.montoya.websocket.WebSocketCreatedHandler
import burp.api.montoya.websocket.Direction
import burp.api.montoya.websocket.extension.ExtensionWebSocket
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreation
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreationStatus
import burp.api.montoya.websocket.extension.ExtensionWebSocketMessageHandler
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.state.WebSocketConnection
import io.bitbytelab.raijin.state.WebSocketInterceptRule
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

class WebSocketBridge(
    private val api: MontoyaApi,
    private val eventBus: EventBus,
    private val stateManager: StateManager
) {
    /** Maps connection IDs to the Montoya ExtensionWebSocket object for sending messages. */
    private val webSocketHandles = ConcurrentHashMap<String, ExtensionWebSocket>()

    /** Message-handler registrations on Burp-created sockets, by connection ID; deregistered on unload. */
    private val handlerRegistrations = ConcurrentHashMap<String, Registration>()

    /** Sockets opened by [createConnection], keyed by the Sec-WebSocket-Key of their upgrade request. */
    private val ownSockets = ConcurrentHashMap<String, OwnSocket>()

    /** Runs the blocking createWebSocket call so a stalled upgrade cannot wedge the tool call. */
    private val createExecutor: ExecutorService = Executors.newCachedThreadPool { task ->
        Thread(task, "raijin-ws-create").apply { isDaemon = true }
    }

    /** Serialises intercept-rule writes so concurrent sets of one id cannot both append. */
    private val ruleLock = Any()

    @Volatile
    private var shutDown = false

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
        // Parse URL to extract host, port, and path
        val parsedUrl = try {
            java.net.URI(url)
        } catch (e: Exception) {
            return buildErrorJson("Invalid URL: ${e.message}")
        }
        val scheme = parsedUrl.scheme ?: "wss"

        // Reject obviously non-WebSocket schemes before attempting an upgrade so
        // callers get a clear message instead of a generic connection failure.
        validateScheme(scheme)?.let { return buildErrorJson(it) }

        val host = parsedUrl.host ?: return buildErrorJson("Invalid URL: missing host")
        val useTls = scheme.equals("wss", ignoreCase = true) || scheme.equals("https", ignoreCase = true)
        val defaultPort = if (useTls) 443 else 80
        val port = if (parsedUrl.port > 0) parsedUrl.port else defaultPort
        // Strip control chars so a stray newline in the path/query can't fold into the
        // request line and kettle the upgrade (issue #7).
        val path = RequestHygiene.stripControl(if (parsedUrl.rawPath.isNullOrEmpty()) "/" else parsedUrl.rawPath)
        val query = RequestHygiene.stripControl(if (parsedUrl.rawQuery != null) "?${parsedUrl.rawQuery}" else "")

        // Build the HTTP upgrade request. Its Sec-WebSocket-Key identifies the socket when Burp
        // reports it to createWebSocketHandler.
        val wsKey = generateWebSocketKey()
        val httpService = HttpService.httpService(host, port, useTls)
        val requestBuilder = StringBuilder()
        requestBuilder.append("GET $path$query HTTP/1.1\r\n")
        requestBuilder.append("Host: $host${if (port != defaultPort) ":$port" else ""}\r\n")
        requestBuilder.append("Upgrade: websocket\r\n")
        requestBuilder.append("Connection: Upgrade\r\n")
        requestBuilder.append("Sec-WebSocket-Version: 13\r\n")
        requestBuilder.append("Sec-WebSocket-Key: $wsKey\r\n")

        if (subprotocol != null) {
            requestBuilder.append("Sec-WebSocket-Protocol: $subprotocol\r\n")
        }

        headers?.forEach { (name, value) ->
            requestBuilder.append("${RequestHygiene.stripControl(name)}: ${RequestHygiene.stripControl(value)}\r\n")
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
        val creation: ExtensionWebSocketCreation = try {
            future.get(CONNECT_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            // The blocking create may still succeed later: close that socket instead of leaking it.
            future.whenComplete { late, _ ->
                late?.webSocket()?.ifPresent { ws -> runCatching { ws.close() } }
                ownSockets.remove(wsKey)
            }
            return buildErrorJson(
                "WebSocket upgrade timed out after $CONNECT_TIMEOUT_MS ms " +
                    "(host accepted the connection but did not complete the upgrade)"
            )
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
        if (shutDown) {
            runCatching { webSocket.close() }
            ownSockets.remove(wsKey)
            return buildErrorJson("WebSocket bridge is shut down (extension unloading)")
        }

        val connectionId = connection.connectionId
        evictClosedConnectionsIfNeeded()
        stateManager.websocketConnections[connectionId] = connection
        webSocketHandles[connectionId] = webSocket
        // Re-check after publishing the handle: an unload or an early server close may have run meanwhile.
        if (shutDown) {
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

    /** Tap for an [OwnSocket] attached from [createWebSocketHandler]; client frames are recorded by the send methods. */
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
            val message = connection.append("server_to_client", "TEXT", payload, payload.toByteArray().size)
            emitMessageEvent(connection.connectionId, message)
            applyIncomingRulesAdvisory(connection.url, "server_to_client", payload)
        } catch (_: Exception) {
            // Recording is best-effort; it must never break the socket's callback thread.
        }
    }

    /** Binary counterpart of [recordServerText]; the payload is stored base64-encoded. */
    private fun recordServerBinary(connection: WebSocketConnection, bytes: ByteArray) {
        try {
            connection.messagesReceived.incrementAndGet()
            val message = connection.append("server_to_client", "BINARY", Base64.getEncoder().encodeToString(bytes), bytes.size)
            emitMessageEvent(connection.connectionId, message)
            applyIncomingBinaryRulesAdvisory(connection.url, "server_to_client")
        } catch (_: Exception) {
            // See recordServerText.
        }
    }

    private fun onOwnSocketClosed(own: OwnSocket) {
        val connectionId = own.connection.connectionId
        ownSockets.remove(own.key)
        webSocketHandles.remove(connectionId)
        handlerRegistrations.remove(connectionId)
        markClosed(own.connection)
    }

    /**
     * Sends a text message on an existing WebSocket connection.
     *
     * @param connectionId The connection ID to send on.
     * @param message The text message to send.
     * @return JSON object confirming the message was sent.
     */
    fun sendText(connectionId: String, message: String): JsonObject {
        // Consult the connection record first: it is the source of truth for
        // what websocket_list advertises. Looking up the live handle first
        // reports a misleading "Connection not found" for listed-but-closed
        // connections.
        val connection = stateManager.websocketConnections[connectionId]
            ?: return buildErrorJson("Connection not found: $connectionId")

        if (connection.status != "connected") {
            return buildJsonObject {
                put("error", "Connection is not active: status=${connection.status}")
                put("status", connection.status)
            }
        }

        // Only a genuinely-connected record should still hold a live handle; if
        // it is gone the socket was closed out from under us.
        val webSocket = webSocketHandles[connectionId]
            ?: return buildErrorJson("Connection handle unavailable (connection may be closed): $connectionId")

        webSocket.sendTextMessage(message)

        connection.messagesSent.incrementAndGet()
        val wsMessage = connection.append("client_to_server", "TEXT", message, message.toByteArray().size)
        emitMessageEvent(connectionId, wsMessage)

        return buildJsonObject {
            put("connection_id", connectionId)
            put("status", "sent")
            put("type", "TEXT")
            put("message_index", wsMessage.index)
            put("length", wsMessage.length)
        }
    }

    /**
     * Sends a binary message on an existing WebSocket connection.
     *
     * @param connectionId The connection ID to send on.
     * @param data Base64-encoded binary data to send.
     * @return JSON object confirming the message was sent.
     */
    fun sendBinary(connectionId: String, data: String): JsonObject {
        // State-record first (see sendText): reserves "Connection not found" for
        // ids that are genuinely absent from websocket_list.
        val connection = stateManager.websocketConnections[connectionId]
            ?: return buildErrorJson("Connection not found: $connectionId")

        if (connection.status != "connected") {
            return buildJsonObject {
                put("error", "Connection is not active: status=${connection.status}")
                put("status", connection.status)
            }
        }

        val webSocket = webSocketHandles[connectionId]
            ?: return buildErrorJson("Connection handle unavailable (connection may be closed): $connectionId")

        val decodedBytes = try {
            Base64.getDecoder().decode(data)
        } catch (e: IllegalArgumentException) {
            return buildErrorJson("Invalid base64 in 'data': ${e.message}")
        }
        webSocket.sendBinaryMessage(BurpByteArray.byteArray(*decodedBytes))

        connection.messagesSent.incrementAndGet()
        val wsMessage = connection.append("client_to_server", "BINARY", data, decodedBytes.size)
        emitMessageEvent(connectionId, wsMessage)

        return buildJsonObject {
            put("connection_id", connectionId)
            put("status", "sent")
            put("type", "BINARY")
            put("message_index", wsMessage.index)
            put("length", decodedBytes.size)
        }
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
        markClosed(connection)

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

    /**
     * Retrieves messages from a specific WebSocket connection with optional
     * filtering by direction and pagination support.
     *
     * Polling contract: pass the index of the last message you read as [sinceIndex]. Indices are
     * allocated and stored atomically, so no frame is ever skipped; `missed_messages` reports frames
     * that were evicted from the bounded buffer before this call could read them.
     *
     * @param connectionId The connection to retrieve messages from.
     * @param direction Optional direction filter: "client_to_server", "server_to_client", "both" or null for all.
     * @param sinceIndex Only return messages with index greater than this value (-1 for all).
     * @param maxResults Maximum number of messages to return.
     * @return JSON object containing the matching messages.
     */
    fun getMessages(
        connectionId: String,
        direction: String?,
        sinceIndex: Long,
        maxResults: Int
    ): JsonObject {
        // Validate direction against the known enum so an unrecognised value
        // yields a clear error instead of silently matching nothing.
        validateDirectionFilter(direction)?.let { return buildErrorJson(it) }

        // Validate max_results: a negative value would make List.take() throw an
        // IllegalArgumentException that leaks as an opaque stdlib error.
        validateMaxResults(maxResults)?.let { return buildErrorJson(it) }
        validateSinceIndex(sinceIndex)?.let { return buildErrorJson(it) }

        val connection = stateManager.websocketConnections[connectionId]
            ?: return buildErrorJson("Connection not found: $connectionId")

        val directionFilter = direction?.trim()?.lowercase()?.takeUnless { it == "both" }
        val page = connection.page(sinceIndex, maxResults, directionFilter)

        return buildJsonObject {
            put("connection_id", connectionId)
            put("status", connection.status)
            put("total_messages", page.retained)
            put("returned_messages", page.messages.size)
            put("oldest_index", page.oldestIndex)
            put("next_index", page.nextIndex)
            if (page.missed > 0) put("missed_messages", page.missed)
            put("has_more", page.hasMore)
            putJsonArray("messages") {
                for (msg in page.messages) {
                    addJsonObject {
                        put("index", msg.index)
                        put("direction", msg.direction)
                        put("type", msg.type)
                        put("payload", msg.payload)
                        put("length", msg.length)
                        put("timestamp", msg.timestamp)
                    }
                }
            }
        }
    }

    /**
     * Creates a WebSocketCreatedHandler that monitors all WebSocket connections
     * initiated through Burp's proxy (or any other Burp component). Each new
     * connection is tracked in StateManager and emits lifecycle events. Sockets
     * opened by [createConnection] are recognised by their Sec-WebSocket-Key and
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
        if (shutDown) return
        val upgradeRequest = created.upgradeRequest()
        val key = try { upgradeRequest.headerValue("Sec-WebSocket-Key") } catch (_: Exception) { null }
        val own = key?.let { ownSockets[it] }
        if (own != null) {
            // Burp reports the socket before any frame flows, so tapping here loses nothing.
            if (own.capture.compareAndSet(Capture.PENDING, Capture.CREATED_HANDLER)) {
                try {
                    keepRegistration(own.connection.connectionId, created.webSocket().registerMessageHandler(ownSocketTap(own)))
                } catch (_: Exception) {
                    // Let the extension handler record the frames instead.
                    own.capture.set(Capture.PENDING)
                }
            }
            return
        }

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
    private fun keepRegistration(connectionId: String, registration: Registration) {
        handlerRegistrations[connectionId] = registration
        if (shutDown) handlerRegistrations.remove(connectionId)?.let { runCatching { it.deregister() } }
    }

    /**
     * Tap for a socket created by a Burp tool (Proxy, Repeater, ...): applies intercept rules and
     * records each frame as it was actually forwarded — the rewritten payload for "modify", the
     * original marked *_DROPPED for "drop". A failure here forwards the frame unchanged.
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
        val outcome = evaluateTextRules(connection.url, direction, originalPayload)
        val dropped = outcome is TextRuleOutcome.Drop
        val forwarded = (outcome as? TextRuleOutcome.Modify)?.payload ?: originalPayload

        if (!dropped) countFrame(connection, direction)
        val message = connection.append(
            direction, if (dropped) "TEXT_DROPPED" else "TEXT", forwarded, forwarded.toByteArray().size
        )
        emitMessageEvent(connection.connectionId, message)

        return when (outcome) {
            is TextRuleOutcome.Drop -> TextMessageAction.drop()
            is TextRuleOutcome.Modify -> TextMessageAction.continueWith(outcome.payload)
            is TextRuleOutcome.Continue -> TextMessageAction.continueWith(textMessage)
        }
    }

    private fun tapBinary(connection: WebSocketConnection, binaryMessage: BinaryMessage): BinaryMessageAction {
        val direction = directionName(binaryMessage.direction())
        val dropped = shouldDropBinary(connection.url, direction)
        val rawBytes = binaryMessage.payload().getBytes()

        if (!dropped) countFrame(connection, direction)
        val message = connection.append(
            direction, if (dropped) "BINARY_DROPPED" else "BINARY", Base64.getEncoder().encodeToString(rawBytes), rawBytes.size
        )
        emitMessageEvent(connection.connectionId, message)

        return if (dropped) BinaryMessageAction.drop() else BinaryMessageAction.continueWith(binaryMessage)
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

    private fun emitMessageEvent(connectionId: String, message: WebSocketMessage) {
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
    private fun markClosed(connection: WebSocketConnection) {
        if (!connection.markClosed()) return
        eventBus.emit("websocket.closed", buildJsonObject {
            put("connection_id", connection.connectionId)
            put("url", connection.url)
            put("messages_sent", connection.messagesSent.get())
            put("messages_received", connection.messagesReceived.get())
            put("timestamp", Instant.now().toString())
        })
    }

    /**
     * Creates or updates a WebSocket message interception rule. Rules are
     * evaluated by the WebSocket handler to modify, drop, or tag messages
     * matching specified criteria.
     *
     * @param ruleId Unique identifier for the rule.
     * @param matchUrl Optional URL regex to match against the WebSocket URL.
     * @param matchMessage Optional regex to match against message content.
     * @param direction Direction filter: "client_to_server", "server_to_client", or "both".
     * @param action What to do: "modify", "drop", or "tag".
     * @param modifyRegex Regex for message content replacement.
     * @param modifyReplacement Replacement string for regex matches.
     * @param tagComment Comment to attach to the matched message.
     * @param enabled Whether this rule is active.
     * @return JSON object confirming the rule was set.
     */
    fun setInterceptRule(
        ruleId: String?,
        matchUrl: String?,
        matchMessage: String?,
        direction: String,
        action: String,
        modifyRegex: String?,
        modifyReplacement: String?,
        tagComment: String?,
        enabled: Boolean
    ): JsonObject {
        val ruleDirection = direction.trim().lowercase()
        if (ruleDirection !in RULE_DIRECTIONS) {
            return buildErrorJson("Invalid direction: '$direction'. Must be 'client_to_server', 'server_to_client' or 'both'")
        }
        val ruleAction = action.trim().lowercase()
        if (ruleAction !in RULE_ACTIONS) {
            return buildErrorJson("Invalid action: '$action'. Must be 'modify', 'drop', or 'tag'")
        }
        if (ruleAction == "modify" && modifyRegex == null) {
            return buildErrorJson("action 'modify' requires modify_regex")
        }
        if (matchUrl != null) {
            SafeRegex.validate(matchUrl)?.let { err ->
                return buildJsonObject { put("error", "Invalid match_url regex: $err") }
            }
        }
        if (matchMessage != null) {
            SafeRegex.validate(matchMessage)?.let { err ->
                return buildJsonObject { put("error", "Invalid match_message regex: $err") }
            }
        }
        if (modifyRegex != null) {
            SafeRegex.validate(modifyRegex)?.let { err ->
                return buildJsonObject { put("error", "Invalid modify_regex regex: $err") }
            }
        }

        val actualRuleId = ruleId ?: stateManager.generateId("wsrule")

        val rule = WebSocketInterceptRule(
            ruleId = actualRuleId,
            matchUrl = matchUrl,
            matchMessage = matchMessage,
            direction = ruleDirection,
            action = ruleAction,
            modifyRegex = modifyRegex,
            modifyReplacement = modifyReplacement,
            tagComment = tagComment,
            enabled = enabled
        )

        // Replace an existing rule with the same ID in place (keeping its evaluation order), or add.
        synchronized(ruleLock) {
            var replaced = false
            stateManager.websocketInterceptRules.replaceAll { existing ->
                if (existing.ruleId == actualRuleId) {
                    replaced = true
                    rule
                } else {
                    existing
                }
            }
            if (!replaced) stateManager.websocketInterceptRules.add(rule)
        }

        // Emit rule change event
        eventBus.emit("websocket.rule_set", buildJsonObject {
            put("rule_id", actualRuleId)
            put("action", ruleAction)
            put("direction", ruleDirection)
            put("enabled", enabled)
            put("timestamp", Instant.now().toString())
        })

        return buildJsonObject {
            put("rule_id", actualRuleId)
            put("status", "rule_set")
            put("action", ruleAction)
            put("direction", ruleDirection)
            put("enabled", enabled)
            put("total_rules", stateManager.websocketInterceptRules.size)
        }
    }

    /**
     * The outcome of evaluating intercept rules against a text message.
     *
     * - [Continue]: forward the message unchanged.
     * - [Drop]: discard the message entirely.
     * - [Modify]: forward the message with [payload] substituted as the new text.
     */
    private sealed class TextRuleOutcome {
        object Continue : TextRuleOutcome()
        object Drop : TextRuleOutcome()
        data class Modify(val payload: String) : TextRuleOutcome()
    }

    /**
     * Returns true if [rule] applies to a message with the given [url] and
     * [direction] ("client_to_server" / "server_to_client"), and whose textual
     * [content] satisfies the rule's matchMessage pattern.
     *
     * Null match fields mean "match any". A rule direction of "both" matches
     * either direction. Regex compilation failures are treated as non-matches so
     * a malformed pattern can never crash the message handler.
     */
    private fun ruleMatches(
        rule: WebSocketInterceptRule,
        url: String?,
        direction: String,
        content: String
    ): Boolean {
        // Direction filter ("both" or matching the message direction).
        if (rule.direction != "both" && rule.direction != direction) {
            return false
        }

        // URL filter (regex against the connection URL, if one is available).
        rule.matchUrl?.let { pattern ->
            val target = url ?: return false
            if (!SafeRegex.containsMatchIn(pattern, target)) return false
        }

        // Message-content filter (regex against the text payload).
        rule.matchMessage?.let { pattern ->
            if (!SafeRegex.containsMatchIn(pattern, content)) return false
        }

        return true
    }

    /**
     * Evaluates all enabled intercept rules against a text message and returns
     * the resulting action. The first matching "drop" wins; otherwise "modify"
     * rules are applied in order to the payload, and "tag" rules emit an event.
     *
     * @param url The WebSocket connection URL, or null if unknown.
     * @param direction "client_to_server" or "server_to_client".
     * @param payload The original text payload.
     * @return A [TextRuleOutcome] describing what the caller should do.
     */
    private fun evaluateTextRules(
        url: String?,
        direction: String,
        payload: String
    ): TextRuleOutcome {
        var current = payload
        var modified = false

        // Iterating the copy-on-write list directly walks its current snapshot without copying it.
        for (rule in stateManager.websocketInterceptRules) {
            if (!rule.enabled) continue
            if (!ruleMatches(rule, url, direction, current)) continue

            when (rule.action) {
                "drop" -> return TextRuleOutcome.Drop

                "modify" -> {
                    val regex = rule.modifyRegex
                    val replacement = rule.modifyReplacement ?: ""
                    if (regex != null) {
                        val updated = SafeRegex.replace(regex, current, replacement)
                        if (updated !== current && updated != current) {
                            current = updated
                            modified = true
                        }
                    }
                }

                "tag" -> {
                    eventBus.emit("websocket.message_tagged", buildJsonObject {
                        put("rule_id", rule.ruleId)
                        put("direction", direction)
                        if (url != null) put("url", url)
                        if (rule.tagComment != null) put("comment", rule.tagComment)
                        put("timestamp", Instant.now().toString())
                    })
                }
            }
        }

        return if (modified) TextRuleOutcome.Modify(current) else TextRuleOutcome.Continue
    }

    /**
     * Evaluates enabled intercept rules against a binary message. Binary payloads
     * cannot be regex-modified, so only "drop" (and "tag", which emits an event)
     * are honoured; everything else passes through unchanged.
     *
     * Rules that carry a matchMessage pattern are skipped for binary frames since
     * there is no meaningful text content to match against.
     *
     * @param url The WebSocket connection URL, or null if unknown.
     * @param direction "client_to_server" or "server_to_client".
     * @return true if the binary message should be dropped, false to continue.
     */
    private fun shouldDropBinary(url: String?, direction: String): Boolean {
        for (rule in stateManager.websocketInterceptRules) {
            if (!rule.enabled) continue
            // Binary frames have no text content; matchMessage cannot apply.
            if (rule.matchMessage != null) continue
            if (!ruleMatches(rule, url, direction, "")) continue

            when (rule.action) {
                "drop" -> return true
                "tag" -> {
                    eventBus.emit("websocket.message_tagged", buildJsonObject {
                        put("rule_id", rule.ruleId)
                        put("direction", direction)
                        put("type", "BINARY")
                        if (url != null) put("url", url)
                        if (rule.tagComment != null) put("comment", rule.tagComment)
                        put("timestamp", Instant.now().toString())
                    })
                }
                // "modify" is not supported for binary frames; pass through.
            }
        }
        return false
    }

    /**
     * Applies intercept rules to an incoming text frame received on a
     * programmatically created ExtensionWebSocket. Because that callback is
     * receive-only (returns void), drop/modify cannot be enforced by the API;
     * "tag" rules are fully honoured (they emit their own event), and any
     * matching drop/modify rule produces an advisory event so it remains
     * observable.
     */
    private fun applyIncomingRulesAdvisory(url: String?, direction: String, payload: String) {
        when (evaluateTextRules(url, direction, payload)) {
            is TextRuleOutcome.Drop -> eventBus.emit("websocket.rule_unenforceable", buildJsonObject {
                put("direction", direction)
                put("action", "drop")
                put("reason", "extension_websocket_receive_only")
                if (url != null) put("url", url)
                put("timestamp", Instant.now().toString())
            })
            is TextRuleOutcome.Modify -> eventBus.emit("websocket.rule_unenforceable", buildJsonObject {
                put("direction", direction)
                put("action", "modify")
                put("reason", "extension_websocket_receive_only")
                if (url != null) put("url", url)
                put("timestamp", Instant.now().toString())
            })
            is TextRuleOutcome.Continue -> { /* nothing to do */ }
        }
    }

    /**
     * Binary-frame counterpart to [applyIncomingRulesAdvisory]. Honours "tag"
     * rules and emits an advisory event when a drop rule matches but cannot be
     * enforced on the receive-only extension callback.
     */
    private fun applyIncomingBinaryRulesAdvisory(url: String?, direction: String) {
        if (shouldDropBinary(url, direction)) {
            eventBus.emit("websocket.rule_unenforceable", buildJsonObject {
                put("direction", direction)
                put("action", "drop")
                put("type", "BINARY")
                put("reason", "extension_websocket_receive_only")
                if (url != null) put("url", url)
                put("timestamp", Instant.now().toString())
            })
        }
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
     * [describeCreationStatus] so the mapping is unit-testable without the
     * compileOnly Montoya API.
     */
    private fun describeCreationStatus(
        status: ExtensionWebSocketCreationStatus?,
        upgradeStatusCode: Int?
    ): String = describeCreationStatus(status?.name, upgradeStatusCode)

    /**
     * Releases everything this bridge holds on extension unload: stops the creation worker,
     * closes every socket opened by [createConnection], and deregisters the message handlers
     * attached to Burp-created sockets so none of them keeps calling into unloaded code.
     */
    fun shutdown() {
        shutDown = true
        createExecutor.shutdownNow()
        webSocketHandles.values.forEach { ws -> runCatching { ws.close() } }
        webSocketHandles.clear()
        handlerRegistrations.values.forEach { reg -> runCatching { reg.deregister() } }
        handlerRegistrations.clear()
        ownSockets.clear()
    }

    /** Once [MAX_CONNECTIONS] are tracked, drops the oldest closed connections (and anything they still hold). */
    private fun evictClosedConnectionsIfNeeded() {
        val connections = stateManager.websocketConnections
        if (connections.size < MAX_CONNECTIONS) return
        val closedOldest = connections.values
            .filter { it.status == "closed" }
            .sortedBy { runCatching { Instant.parse(it.createdAt) }.getOrDefault(Instant.EPOCH) }
        for (connection in closedOldest) {
            if (connections.size < MAX_CONNECTIONS) break
            val id = connection.connectionId
            connections.remove(id)
            webSocketHandles.remove(id)?.let { runCatching { it.close() } }
            handlerRegistrations.remove(id)?.let { runCatching { it.deregister() } }
        }
    }

    /**
     * Builds a standardized error JSON object.
     */
    private fun buildErrorJson(message: String): JsonObject {
        return buildJsonObject {
            put("error", message)
        }
    }

    companion object {
        const val MAX_CONNECTIONS = 200
        /**
         * Upper bound on how long the blocking [MontoyaApi] createWebSocket call
         * may take before the tool call returns a timeout error. A
         * non-responsive host must fail fast instead of hanging forever.
         */
        const val CONNECT_TIMEOUT_MS = 12_000L

        /** Schemes accepted for a WebSocket upgrade attempt. */
        private val ALLOWED_SCHEMES = setOf("ws", "wss", "http", "https")

        /** Accepted direction values (case-insensitive); "both" means no direction filter. */
        private val RULE_DIRECTIONS = setOf("client_to_server", "server_to_client", "both")

        private val RULE_ACTIONS = setOf("modify", "drop", "tag")

        /**
         * Returns an error message if [scheme] is not a WebSocket-capable
         * scheme, or null if it is acceptable. Comparison is case-insensitive.
         */
        internal fun validateScheme(scheme: String?): String? {
            val normalized = scheme?.lowercase()
            if (normalized == null || normalized !in ALLOWED_SCHEMES) {
                return "Unsupported scheme '${scheme ?: ""}': expected ws, wss, http, or https"
            }
            return null
        }

        /**
         * Returns an error message if [direction] is a non-null value that is
         * not a recognised direction filter, or null if it is acceptable (null
         * or "both" means "no filter"). Comparison is case-insensitive.
         */
        internal fun validateDirectionFilter(direction: String?): String? {
            if (direction != null && direction.trim().lowercase() !in RULE_DIRECTIONS) {
                return "Invalid direction: '$direction'. Must be 'client_to_server', 'server_to_client' or 'both'"
            }
            return null
        }

        /**
         * Returns an error message if [maxResults] is negative (which would make
         * List.take() throw), or null if it is acceptable. Zero is allowed and
         * yields an empty result.
         */
        internal fun validateMaxResults(maxResults: Int): String? {
            if (maxResults < 0) {
                return "Invalid max_results: $maxResults. Must be zero or a positive integer"
            }
            return null
        }

        /** Returns an error message if [sinceIndex] is below -1 (-1 means "from the oldest retained message"). */
        internal fun validateSinceIndex(sinceIndex: Long): String? {
            if (sinceIndex < -1) {
                return "Invalid since_index: $sinceIndex. Use -1 for all retained messages, or the index of the last message read"
            }
            return null
        }

        /**
         * Pure mapping from an [ExtensionWebSocketCreationStatus] enum name to a
         * specific, human-readable failure reason. Keyed by name (not the enum
         * type) so it is testable without the compileOnly Montoya API.
         */
        internal fun describeCreationStatus(statusName: String?, upgradeStatusCode: Int?): String {
            val base = when (statusName) {
                "UNKNOWN_HOST" -> "DNS resolution failed (unknown host)"
                "INVALID_HOST" -> "Invalid host in the upgrade request"
                "INVALID_PORT" -> "Invalid port in the upgrade request"
                "INVALID_REQUEST" -> "The upgrade request was rejected as invalid"
                "CONNECTION_FAILED" -> "Connection failed (could not reach the host)"
                "NON_UPGRADE_RESPONSE" ->
                    "Server did not accept the WebSocket upgrade (possible scheme/port mismatch)"
                "STREAMING_RESPONSE" ->
                    "Server returned a streaming response instead of a WebSocket upgrade"
                null -> "Failed to create WebSocket connection: no status reported"
                else -> "Failed to create WebSocket connection (status=$statusName)"
            }
            return if (upgradeStatusCode != null) "$base [upgrade HTTP $upgradeStatusCode]" else base
        }
    }
}
