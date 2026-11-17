package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.websocket.WebSocketCreatedHandler
import burp.api.montoya.websocket.extension.ExtensionWebSocket
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreationStatus
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.state.WebSocketConnection
import io.bitbytelab.raijin.state.WebSocketInterceptRule
import io.bitbytelab.raijin.state.WebSocketMessage
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.concurrent.TimeUnit

/**
 * Bridge for WebSocket connections. Sockets Raijin opens itself are created, sent on and closed by
 * [WebSocketConnections]; sockets Burp tools open are tracked by [WebSocketBurpTap]. Reading and
 * waiting for frames, fuzzing and the intercept rules are handled here.
 */
class WebSocketBridge(
    api: MontoyaApi,
    private val eventBus: EventBus,
    private val stateManager: StateManager
) {
    /** Serialises intercept-rule writes so concurrent sets of one id cannot both append. */
    private val ruleLock = Any()

    @Volatile
    private var shutDown = false

    // Lambdas, not `connections::` references: connections is initialised after tap, which calls them only later.
    private val tap: WebSocketBurpTap = WebSocketBurpTap(
        eventBus,
        stateManager,
        isShutDown = { shutDown },
        evaluateRules = this::evaluateRules,
        tapIfOwn = { key, created -> connections.tapIfOwn(key, created) },
        closeHandle = { connectionId -> connections.closeHandle(connectionId) },
    )

    private val connections: WebSocketConnections = WebSocketConnections(
        api,
        eventBus,
        stateManager,
        tap,
        isShutDown = { shutDown },
        adviseIncomingRules = this::adviseIncomingRules,
    )

    /** Opens a WebSocket connection of Raijin's own; see [WebSocketConnections.createConnection]. */
    fun createConnection(url: String, headers: Map<String, String>?, subprotocol: String?): JsonObject =
        connections.createConnection(url, headers, subprotocol)

    /** Sends a text frame on a connection Raijin opened; see [WebSocketConnections.sendText]. */
    fun sendText(connectionId: String, message: String): JsonObject = connections.sendText(connectionId, message)

    /** Sends a binary frame, given as base64, on a connection Raijin opened; see [WebSocketConnections.sendBinary]. */
    fun sendBinary(connectionId: String, data: String): JsonObject = connections.sendBinary(connectionId, data)

    /** Closes a tracked connection; see [WebSocketConnections.close]. */
    fun close(connectionId: String): JsonObject = connections.close(connectionId)

    /** Lists every tracked connection; see [WebSocketConnections.listConnections]. */
    fun listConnections(): JsonObject = connections.listConnections()

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
     * @param sinceIndex Only return messages with index greater than this value (-1 for all; a lower
     *   value is clamped to -1 and reported under `clamped`).
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

        val connection = stateManager.websocketConnections[connectionId]
            ?: return buildErrorJson("Connection not found: $connectionId")

        val since = maxOf(sinceIndex, -1L)
        val directionFilter = direction?.trim()?.lowercase()?.takeUnless { it == "both" }
        val page = connection.page(since, maxResults, directionFilter)

        return buildJsonObject {
            put("connection_id", connectionId)
            put("status", connection.status)
            put("total_messages", page.retained)
            put("returned_messages", page.messages.size)
            put("oldest_index", page.oldestIndex)
            put("next_index", page.nextIndex)
            if (page.missed > 0) put("missed_messages", page.missed)
            put("has_more", page.hasMore)
            if (since != sinceIndex) putJsonObject("clamped") { put("since_index", since) }
            putJsonArray("messages") { page.messages.forEach { add(WebSocketFrames.toJson(it)) } }
        }
    }

    /**
     * Blocks until a frame recorded on [connectionId] after [sinceIndex] passes the filters, the
     * connection closes, or [timeoutMs] have passed, so a caller does not have to poll
     * [getMessages]. Frames already buffered after [sinceIndex] count, so a reply that arrived
     * before the call is found at once; later ones are awaited on the connection's buffer
     * ([WebSocketWait.collect]), which cannot miss a frame recorded while the wait begins.
     *
     * @param sinceIndex Only frames with a greater index count; null means the newest index when the
     *   call starts (only frames that arrive later). Clamped to -1..(newest index), so a cursor past
     *   the newest frame cannot pass over the frames recorded next.
     * @param direction "client_to_server", "server_to_client", "both" or null for either.
     * @param messageType "TEXT", "BINARY", or null for either.
     * @param pattern Case-insensitive regex the frame must contain; a binary frame is matched as
     *   ISO-8859-1 text.
     * @param timeoutMs How long to wait; clamped to 0..[MAX_WAIT_MS]; 0 only checks what is buffered.
     * @return JSON object with `matched` and the `message`, or the `reason` nothing matched
     *   ("timeout", "connection_closed"), and `next_since_index` to continue from.
     * @throws InterruptedException when the calling thread is interrupted while waiting.
     */
    fun waitForMessage(
        connectionId: String,
        sinceIndex: Long?,
        direction: String?,
        messageType: String?,
        pattern: String?,
        timeoutMs: Long
    ): JsonObject {
        validateDirectionFilter(direction)?.let { return buildErrorJson(it) }
        WebSocketFrames.messageTypeError(messageType)?.let { return buildErrorJson(it) }
        if (pattern != null) {
            SafeRegex.validate(pattern, ignoreCase = true)?.let { return buildErrorJson("Invalid pattern regex: $it") }
        }
        val connection = stateManager.websocketConnections[connectionId]
            ?: return buildErrorJson("Connection not found: $connectionId")

        val clamped = LinkedHashMap<String, Long>()
        val timeout = timeoutMs.coerceIn(0, MAX_WAIT_MS).also { if (it != timeoutMs) clamped["timeout_ms"] = it }
        val newest = connection.lastIndex()
        // A cursor past the newest frame would pass over the frames recorded next.
        val since = sinceIndex?.let { requested ->
            requested.coerceIn(-1, newest).also { if (it != requested) clamped["since_index"] = it }
        } ?: newest
        val filter = WebSocketFrameFilter(
            direction = direction?.trim()?.lowercase()?.takeUnless { it == "both" },
            binary = WebSocketFrames.normalizeMessageType(messageType)?.let { it == "BINARY" },
            pattern = pattern,
        )
        val waited = WebSocketWait.collect(connection, since, filter, TimeUnit.MILLISECONDS.toNanos(timeout), maxFrames = 1)
        val match = waited.frames.firstOrNull()

        return buildJsonObject {
            put("connection_id", connectionId)
            put("matched", match != null)
            if (match != null) put("message", WebSocketFrames.toJson(match))
            else put("reason", if (waited.closed) "connection_closed" else "timeout")
            put("since_index", since)
            put("next_since_index", waited.cursor)
            put("scanned", waited.scanned)
            if (waited.missed > 0) put("missed_messages", waited.missed)
            put("waited_ms", TimeUnit.NANOSECONDS.toMillis(waited.elapsedNanos))
            put("status", connection.status)
            if (clamped.isNotEmpty()) putJsonObject("clamped") { clamped.forEach { (name, value) -> put(name, value) } }
        }
    }

    /**
     * Fuzzes a WebSocket endpoint: sends each payload of [request] as one frame, over an open
     * connection or a fresh one per payload, and returns the frames each payload triggered together
     * with clusters of similar responses ([WebSocketFuzz.run]). Runs on the calling thread.
     *
     * @throws InterruptedException when the calling thread is interrupted during the run.
     */
    fun fuzz(request: WebSocketFuzzRequest): JsonObject = WebSocketFuzz.run(request, FuzzHost())

    /** The fuzz run's view of this bridge: sockets opened, sent on and closed as the tools do. */
    private inner class FuzzHost : WebSocketFuzzHost {
        override val stopping: Boolean get() = shutDown

        override fun find(connectionId: String): WebSocketConnection? = stateManager.websocketConnections[connectionId]

        override fun unsendableReason(connection: WebSocketConnection): String? =
            if (connections.liveSocket(connection) != null) null else connections.describeUnsendable(connection)

        override fun open(url: String, headers: Map<String, String>?, subprotocol: String?): WebSocketFuzzHost.Opened {
            val created = createConnection(url, headers, subprotocol)
            val connection = (created["connection_id"] as? JsonPrimitive)?.contentOrNull
                ?.let { stateManager.websocketConnections[it] }
            val error = if (connection != null) null else (created["error"] as? JsonPrimitive)?.contentOrNull
            return WebSocketFuzzHost.Opened(connection, error)
        }

        override fun sendText(connection: WebSocketConnection, message: String): WebSocketMessage =
            connections.deliverText(connection, socketFor(connection), message)

        override fun sendBinary(connection: WebSocketConnection, bytes: ByteArray): WebSocketMessage =
            connections.deliverBinary(connection, socketFor(connection), bytes)

        override fun close(connection: WebSocketConnection) {
            this@WebSocketBridge.close(connection.connectionId)
        }

        private fun socketFor(connection: WebSocketConnection): ExtensionWebSocket =
            connections.liveSocket(connection) ?: throw IllegalStateException(connections.describeUnsendable(connection))
    }

    /** The handler Burp reports every new WebSocket to; see [WebSocketBurpTap.createWebSocketHandler]. */
    fun createWebSocketHandler(): WebSocketCreatedHandler = tap.createWebSocketHandler()

    /**
     * Creates or updates a WebSocket message interception rule. Rules are
     * evaluated by the WebSocket handler to modify, drop, or tag messages
     * matching specified criteria. Text and binary frames are both covered; a binary frame is
     * matched and rewritten as ISO-8859-1 text (see [WebSocketInterceptRules]).
     *
     * @param ruleId Unique identifier for the rule; null or blank generates one.
     * @param matchUrl Optional URL regex to match against the WebSocket URL.
     * @param matchMessage Optional regex to match against message content.
     * @param direction Direction filter: "client_to_server", "server_to_client", or "both".
     * @param action What to do: "modify", "drop", or "tag".
     * @param modifyRegex Regex for message content replacement.
     * @param modifyReplacement Replacement string for regex matches.
     * @param tagComment Comment to attach to the matched message.
     * @param enabled Whether this rule is active.
     * @param messageType Limits the rule to "TEXT" or "BINARY" frames; null or blank for both.
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
        enabled: Boolean,
        messageType: String? = null
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
        WebSocketFrames.messageTypeError(messageType)?.let { return buildErrorJson(it) }
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

        val actualRuleId = ruleId?.takeIf { it.isNotBlank() } ?: stateManager.generateId("wsrule")

        val rule = WebSocketInterceptRule(
            ruleId = actualRuleId,
            matchUrl = matchUrl,
            matchMessage = matchMessage,
            direction = ruleDirection,
            action = ruleAction,
            modifyRegex = modifyRegex,
            modifyReplacement = modifyReplacement,
            tagComment = tagComment,
            enabled = enabled,
            messageType = WebSocketFrames.normalizeMessageType(messageType)
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
            if (rule.messageType != null) put("message_type", rule.messageType)
            put("enabled", enabled)
            put("total_rules", stateManager.websocketInterceptRules.size)
        }
    }

    /** Lists the intercept rules in the order they are evaluated. */
    fun listInterceptRules(): JsonObject {
        val rules = stateManager.websocketInterceptRules.toList()
        return buildJsonObject {
            put("total", rules.size)
            putJsonArray("rules") { rules.forEach { add(WebSocketInterceptRules.toJson(it)) } }
        }
    }

    /** Removes the rule with [ruleId]; `removed` is false when there was none. */
    fun removeInterceptRule(ruleId: String): JsonObject {
        val removed = synchronized(ruleLock) { stateManager.websocketInterceptRules.removeIf { it.ruleId == ruleId } }
        if (removed) {
            eventBus.emit("websocket.rule_removed", buildJsonObject {
                put("rule_id", ruleId)
                put("timestamp", Instant.now().toString())
            })
        }
        return buildJsonObject {
            put("rule_id", ruleId)
            put("removed", removed)
            put("remaining_rules", stateManager.websocketInterceptRules.size)
        }
    }

    /**
     * Evaluates the intercept rules against one frame ([WebSocketInterceptRules.evaluate]); a
     * matching "tag" rule emits its "websocket.message_tagged" event from here.
     *
     * @param content the frame as text, read only when a rule looks at the content.
     */
    private fun evaluateRules(
        url: String?,
        direction: String,
        binary: Boolean,
        content: () -> String
    ): WebSocketInterceptRules.Outcome =
        // Iterating the copy-on-write list directly walks its current snapshot without copying it.
        WebSocketInterceptRules.evaluate(stateManager.websocketInterceptRules, url, direction, binary, content) { rule ->
            eventBus.emit("websocket.message_tagged", buildJsonObject {
                put("rule_id", rule.ruleId)
                put("direction", direction)
                if (binary) put("type", "BINARY")
                if (url != null) put("url", url)
                if (rule.tagComment != null) put("comment", rule.tagComment)
                put("timestamp", Instant.now().toString())
            })
        }

    /**
     * Applies intercept rules to a frame received on a programmatically created
     * ExtensionWebSocket. Because that callback is receive-only (returns void), drop/modify cannot
     * be enforced by the API; "tag" rules are fully honoured (they emit their own event), and a
     * matching drop/modify rule produces an advisory event so it remains observable.
     */
    private fun adviseIncomingRules(url: String?, direction: String, binary: Boolean, content: () -> String) {
        val unenforced = when (evaluateRules(url, direction, binary, content)) {
            WebSocketInterceptRules.Outcome.Continue -> return
            WebSocketInterceptRules.Outcome.Drop -> "drop"
            is WebSocketInterceptRules.Outcome.Modify -> "modify"
        }
        eventBus.emit("websocket.rule_unenforceable", buildJsonObject {
            put("direction", direction)
            put("action", unenforced)
            if (binary) put("type", "BINARY")
            put("reason", "extension_websocket_receive_only")
            if (url != null) put("url", url)
            put("timestamp", Instant.now().toString())
        })
    }

    /**
     * Releases everything this bridge holds on extension unload: stops the creation worker,
     * closes every socket opened by [createConnection], and deregisters the message handlers
     * attached to Burp-created sockets so none of them keeps calling into unloaded code. Nothing
     * records frames afterwards, so every tracked connection is marked closed, which releases the
     * callers still blocked in [waitForMessage] or [fuzz].
     */
    fun shutdown() {
        shutDown = true
        connections.shutdown()
        tap.shutdown()
        stateManager.websocketConnections.values.forEach { it.markClosed() }
    }

    companion object {
        const val MAX_CONNECTIONS = 200
        /**
         * Upper bound on how long the blocking [MontoyaApi] createWebSocket call
         * may take before the tool call returns a timeout error. A
         * non-responsive host must fail fast instead of hanging forever.
         */
        const val CONNECT_TIMEOUT_MS = 12_000L

        /** Longest a single [waitForMessage] call blocks; a longer `timeout_ms` is clamped to it. */
        const val MAX_WAIT_MS = 300_000L

        /** How long `websocket_wait_message` waits when the caller gives no timeout. */
        const val DEFAULT_WAIT_MS = 10_000L

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

        /**
         * Builds a standardized error JSON object.
         */
        internal fun buildErrorJson(message: String): JsonObject {
            return buildJsonObject {
                put("error", message)
            }
        }
    }
}
