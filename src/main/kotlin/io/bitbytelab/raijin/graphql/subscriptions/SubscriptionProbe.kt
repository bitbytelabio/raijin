package io.bitbytelab.raijin.graphql.subscriptions

import io.bitbytelab.raijin.core.BodyText
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** The slice of a WebSocket the probe drives: the bridge adapts a Montoya socket, tests script one. */
interface ProbeSocket {
    /** Sends a text frame; throws when the socket is no longer open. */
    fun send(text: String)

    /** The next server event, or null when none arrives within [timeoutMs]. */
    fun receive(timeoutMs: Long): ProbeEvent?

    fun close()
}

sealed interface ProbeEvent {
    data class Text(val payload: String) : ProbeEvent

    /** The socket closed (by either side); nothing follows. */
    data object Closed : ProbeEvent
}

/** Outcome of the WebSocket upgrade that starts one session. */
sealed interface OpenResult {
    class Opened(val socket: ProbeSocket, val httpStatus: Int?, val selectedSubprotocol: String?) : OpenResult

    /**
     * No socket. [unreachable] tells "the target gave no usable answer" (DNS, connect, timeout),
     * after which another protocol or identity cannot do better, from "the server answered and
     * declined this upgrade".
     */
    data class Refused(val status: String, val httpStatus: Int?, val reason: String, val unreachable: Boolean) : OpenResult {
        companion object {
            const val TIMEOUT = "TIMEOUT"
            const val ERROR = "ERROR"

            private val NO_ANSWER = setOf(
                "UNKNOWN_HOST", "INVALID_HOST", "INVALID_PORT", "CONNECTION_FAILED", "INVALID_REQUEST", TIMEOUT, ERROR,
            )

            /**
             * From the name of a Montoya `ExtensionWebSocketCreationStatus`, or [TIMEOUT] / [ERROR]
             * when the create call never returned one ([detail] then says what happened).
             */
            fun of(status: String, httpStatus: Int? = null, detail: String? = null): Refused {
                val base = when (status) {
                    "UNKNOWN_HOST" -> "DNS resolution failed (unknown host)"
                    "INVALID_HOST" -> "invalid host in the upgrade request"
                    "INVALID_PORT" -> "invalid port in the upgrade request"
                    "INVALID_REQUEST" -> "the upgrade request was rejected as invalid"
                    "CONNECTION_FAILED" -> "connection failed (could not reach the host)"
                    "NON_UPGRADE_RESPONSE" -> "the server answered without upgrading to WebSocket"
                    "STREAMING_RESPONSE" -> "the server returned a streaming response instead of a WebSocket upgrade"
                    TIMEOUT -> "the WebSocket upgrade did not complete in time"
                    else -> "the WebSocket could not be created (status $status)"
                }
                val reason = buildString {
                    append(base)
                    if (detail != null) append(": ").append(detail)
                    if (httpStatus != null) append(" [HTTP ").append(httpStatus).append(']')
                }
                return Refused(status, httpStatus, reason, unreachable = status in NO_ANSWER)
            }
        }
    }
}

/** What introspection over an open socket says about the subscription root type. */
sealed interface SubscriptionCatalog {
    /** [query] starts [field], a subscription that needs no arguments; [fields] are all subscription fields. */
    data class Runnable(val query: String, val field: String, val fields: List<String>) : SubscriptionCatalog

    /** Subscriptions exist, but each needs arguments the probe cannot guess. */
    data class ArgumentsRequired(val fields: List<String>) : SubscriptionCatalog

    /** The schema defines no subscription type. */
    data object NoSubscriptions : SubscriptionCatalog

    /** Introspection was refused, went unanswered, or returned something else. */
    data object Unavailable : SubscriptionCatalog

    companion object {
        /** Asks only for what [read] needs: each subscription field's arguments and the kind of its type. */
        const val QUERY = "query { __schema { subscriptionType { fields { name args { name defaultValue type { kind } } " +
            "type { kind ofType { kind ofType { kind ofType { kind } } } } } } } }"

        /** Reads the `data` of a [QUERY] result. */
        fun read(data: JsonObject?): SubscriptionCatalog {
            val schema = data?.get("__schema") as? JsonObject ?: return Unavailable
            if ("subscriptionType" !in schema) return Unavailable
            val root = schema["subscriptionType"] as? JsonObject ?: return NoSubscriptions
            val fields = (root["fields"] as? JsonArray).orEmpty().filterIsInstance<JsonObject>()
            val names = fields.mapNotNull { it.text("name") }
            if (names.isEmpty()) return NoSubscriptions
            val (name, definition) = fields.firstNotNullOfOrNull { field ->
                field.text("name")?.takeUnless { requiresArguments(field) }?.let { it to field }
            } ?: return ArgumentsRequired(names)
            val selection = if (isLeaf(definition["type"] as? JsonObject)) "" else " { __typename }"
            return Runnable("subscription { $name$selection }", name, names)
        }

        /** The string at [key], or null when it is absent, JSON null or not a string. */
        private fun JsonObject.text(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content

        /** An argument is required when its type is non-null and it has no default value. */
        private fun requiresArguments(field: JsonObject): Boolean =
            (field["args"] as? JsonArray).orEmpty().filterIsInstance<JsonObject>().any { arg ->
                (arg["type"] as? JsonObject)?.text("kind") == "NON_NULL" && arg.text("defaultValue") == null
            }

        /** True for a scalar or enum under any list/non-null wrappers: such a field takes no selection set. */
        private fun isLeaf(type: JsonObject?): Boolean {
            var current = type
            while (current != null) {
                when (current.text("kind")) {
                    "NON_NULL", "LIST" -> current = current["ofType"] as? JsonObject
                    "SCALAR", "ENUM" -> return true
                    else -> return false
                }
            }
            return false
        }
    }
}

/**
 * Probes GraphQL subscriptions over WebSocket. For each [SubscriptionProtocol] it opens a socket
 * without credentials, sends `connection_init`, and on `connection_ack` starts one operation; when
 * the caller has credentials and the anonymous session did not get all the way, a second session
 * repeats the steps with them. Together the two say which handshake the server accepts, whether
 * `connection_init` needs authentication, and whether a subscription can be started.
 *
 * Every wait is bounded by [waitMs] and every socket is closed before its session returns.
 *
 * @param open performs the WebSocket upgrade for a protocol, with (`true`) or without the
 *   caller's credential headers.
 * @param operation the operation to start; when null a no-argument subscription field is looked
 *   up by introspection over the socket, with [DEFAULT_OPERATION] as the fallback.
 * @param connectionPayload `connection_init` payload of the authenticated session.
 * @param hasCredentials whether an authenticated session differs from the anonymous one at all.
 */
class SubscriptionProbe(
    private val open: (protocol: SubscriptionProtocol, authenticated: Boolean) -> OpenResult,
    private val operation: String? = null,
    private val connectionPayload: JsonObject? = null,
    private val hasCredentials: Boolean = false,
    private val waitMs: Long = DEFAULT_WAIT_MS,
) {
    enum class InitOutcome(val label: String) {
        ACKNOWLEDGED("acknowledged"),

        /** The server answered `connection_init` with an error. */
        REJECTED("rejected"),

        /** The socket closed instead of an acknowledgement (how the current protocol refuses). */
        CLOSED("closed"),
        TIMED_OUT("timed_out"),

        /** The upgrade produced no socket. */
        NOT_SENT("not_sent"),
    }

    /** [accepted] is null when no operation could be tried; [meaning] is the outcome spelled out for the result. */
    enum class SubscriptionOutcome(val label: String, val accepted: Boolean?, val meaning: String) {
        DATA("data", true, "the server returned a result for the operation"),
        COMPLETE("complete", true, "the server completed the operation without a result"),
        OPEN_NO_EVENTS(
            "open_no_events", true,
            "no reply within the wait: a refused operation is answered at once, so the stream was accepted and is idle",
        ),
        ERROR("error", false, "the server answered the operation with errors"),
        CLOSED("closed", false, "the socket closed before the operation was answered"),
        NO_SUBSCRIPTION_TYPE("no_subscription_type", false, "introspection over the socket shows a schema without a subscription type"),
        NEEDS_ARGUMENTS(
            "needs_arguments", null,
            "every subscription field takes required arguments: pass an operation in 'subscription_query'",
        ),
    }

    class Subscription(
        val query: String?,
        /** `caller`, `introspection` or `default`. */
        val source: String,
        val outcome: SubscriptionOutcome,
        val errors: List<String> = emptyList(),
        /** Subscription fields introspection listed, when it ran. */
        val fields: List<String> = emptyList(),
    )

    class Frame(val sent: Boolean, val text: String)

    /** One WebSocket session: its upgrade, its `connection_init`, and the operation it tried. */
    class Session(
        val authenticated: Boolean,
        /** Why there was no socket, or null when the upgrade succeeded. */
        val refused: OpenResult.Refused?,
        val httpStatus: Int?,
        val selectedSubprotocol: String?,
        val connectionInit: InitOutcome,
        val connectionErrors: List<String>,
        val subscription: Subscription?,
        val frames: List<Frame>,
    ) {
        val acknowledged: Boolean get() = connectionInit == InitOutcome.ACKNOWLEDGED

        fun toJson(): JsonObject = buildJsonObject {
            put("upgrade", buildJsonObject {
                put("accepted", refused == null)
                if (refused != null) {
                    put("status", refused.status)
                    put("reason", refused.reason)
                }
                if (httpStatus != null) put("http_status", httpStatus)
                if (selectedSubprotocol != null) put("selected_subprotocol", selectedSubprotocol)
            })
            put("connection_init", connectionInit.label)
            if (connectionErrors.isNotEmpty()) put("connection_errors", buildJsonArray { connectionErrors.forEach { add(it) } })
            if (subscription != null) {
                put("subscription", buildJsonObject {
                    if (subscription.query != null) put("query", subscription.query)
                    put("query_source", subscription.source)
                    put("outcome", subscription.outcome.label)
                    put("meaning", subscription.outcome.meaning)
                    put("accepted", subscription.outcome.accepted)
                    if (subscription.errors.isNotEmpty()) put("errors", buildJsonArray { subscription.errors.forEach { add(it) } })
                    if (subscription.fields.isNotEmpty()) {
                        put("subscription_fields", buildJsonArray { subscription.fields.forEach { add(it) } })
                    }
                })
            }
            if (frames.isNotEmpty()) {
                put("frames", buildJsonArray {
                    frames.forEach { frame ->
                        add(buildJsonObject {
                            put("direction", if (frame.sent) "sent" else "received")
                            put("text", frame.text)
                        })
                    }
                })
            }
        }
    }

    class ProtocolReport(val protocol: SubscriptionProtocol, val anonymous: Session, val authenticated: Session?) {
        /** `connection_init` was acknowledged in at least one session. */
        val handshakeAccepted: Boolean get() = anonymous.acknowledged || authenticated?.acknowledged == true

        /** False when an anonymous `connection_init` is acknowledged, true when only the authenticated one is, null when neither. */
        val initRequiresAuth: Boolean?
            get() = when {
                anonymous.acknowledged -> false
                authenticated?.acknowledged == true -> true
                else -> null
            }

        /** Whether the operation was accepted in any session; null when none got to try one. */
        val subscriptionAccepted: Boolean?
            get() {
                val verdicts = listOfNotNull(anonymous.subscription?.outcome?.accepted, authenticated?.subscription?.outcome?.accepted)
                return if (verdicts.isEmpty()) null else verdicts.any { it }
            }

        /** False when an anonymous session can start the operation, true when only the authenticated one can, null otherwise. */
        val subscriptionRequiresAuth: Boolean?
            get() = when {
                anonymous.subscription?.outcome?.accepted == true -> false
                authenticated?.subscription?.outcome?.accepted == true -> true
                else -> null
            }

        fun toJson(): JsonObject = buildJsonObject {
            put("subprotocol", protocol.subprotocol)
            put("handshake_accepted", handshakeAccepted)
            put("init_requires_auth", initRequiresAuth)
            put("subscription_accepted", subscriptionAccepted)
            put("subscription_requires_auth", subscriptionRequiresAuth)
            put("anonymous", anonymous.toJson())
            if (authenticated != null) put("authenticated", authenticated.toJson())
        }
    }

    /** [unreachable] is set when the target stopped answering upgrades; [protocols] then holds what was probed before. */
    class Report(val protocols: List<ProtocolReport>, val unreachable: String?) {
        fun toJson(endpoint: String): JsonObject = buildJsonObject {
            put("endpoint", endpoint)
            if (protocols.isEmpty() && unreachable != null) {
                put("error", "Could not open a WebSocket to $endpoint: $unreachable.")
                return@buildJsonObject
            }
            put("supported_protocols", buildJsonArray { protocols.filter { it.handshakeAccepted }.forEach { add(it.protocol.protocolName) } })
            put("protocols", buildJsonObject { protocols.forEach { put(it.protocol.protocolName, it.toJson()) } })
            if (unreachable != null) put("warning", "Stopped early, the target no longer answered: $unreachable.")
            put("note", note())
        }

        private fun note(): String {
            val accepted = protocols.filter { it.handshakeAccepted }
            if (accepted.isEmpty()) {
                return "Neither GraphQL-over-WebSocket handshake was acknowledged here. Subscriptions may be served on " +
                    "another path (e.g. /subscriptions, /graphql/ws) or need credentials ('headers' / 'connection_payload')."
            }
            return accepted.joinToString(" ") { report ->
                val handshake = when (report.initRequiresAuth) {
                    false -> "connection_init is acknowledged without credentials"
                    else -> "connection_init is acknowledged only with credentials"
                }
                val operation = when {
                    report.subscriptionRequiresAuth == false ->
                        " and an anonymous client can start the operation — compare with what the HTTP endpoint enforces"
                    report.subscriptionRequiresAuth == true -> " and starting the operation needs credentials"
                    report.subscriptionAccepted == false ->
                        "; the operation tried was not accepted (see 'errors'; pass 'subscription_query' to try another)"
                    else -> ""
                }
                "${report.protocol.protocolName}: $handshake$operation."
            }
        }
    }

    companion object {
        const val DEFAULT_WAIT_MS = 3_000L
        const val MIN_WAIT_MS = 250L
        const val MAX_WAIT_MS = 30_000L

        /** Valid against any schema with a subscription type, though many servers refuse an introspection root field here. */
        const val DEFAULT_OPERATION = "subscription { __typename }"

        private const val DISCOVERY_ID = "raijin-discover"
        private const val OPERATION_ID = "raijin-1"
        private const val MAX_FRAMES = 16
        private const val MAX_FRAME_CHARS = 400
    }

    /** A session's socket together with the record of what crossed it. */
    private class Wire(val protocol: SubscriptionProtocol, val socket: ProbeSocket) {
        val frames = ArrayList<Frame>()

        /** False when the socket would not take the frame, which is how a close shows up on the sending side. */
        fun send(text: String): Boolean {
            record(sent = true, text = text)
            return try {
                socket.send(text)
                true
            } catch (_: Exception) {
                false
            }
        }

        fun record(sent: Boolean, text: String) {
            if (frames.size < MAX_FRAMES) frames.add(Frame(sent, BodyText.render(text, MAX_FRAME_CHARS).text))
        }
    }

    private enum class Silence { CLOSED, TIMED_OUT }

    private class Init(val outcome: InitOutcome, val errors: List<String> = emptyList())

    fun run(): Report {
        val reports = ArrayList<ProtocolReport>()
        for (protocol in SubscriptionProtocol.entries) {
            val anonymous = session(protocol, authenticated = false)
            anonymous.refused?.takeIf { it.unreachable }?.let { return Report(reports, it.reason) }

            // Credentials only add something where the anonymous session stopped short.
            val wideOpen = anonymous.acknowledged && anonymous.subscription?.outcome?.accepted == true
            val authenticated = if (hasCredentials && !wideOpen) session(protocol, authenticated = true) else null
            reports.add(ProtocolReport(protocol, anonymous, authenticated))
            authenticated?.refused?.takeIf { it.unreachable }?.let { return Report(reports, it.reason) }
        }
        return Report(reports, null)
    }

    private fun session(protocol: SubscriptionProtocol, authenticated: Boolean): Session {
        val opened = when (val result = open(protocol, authenticated)) {
            is OpenResult.Refused ->
                return Session(authenticated, result, result.httpStatus, null, InitOutcome.NOT_SENT, emptyList(), null, emptyList())
            is OpenResult.Opened -> result
        }
        val wire = Wire(protocol, opened.socket)
        try {
            val connection = handshake(wire, if (authenticated) connectionPayload else null)
            var subscription: Subscription? = null
            if (connection.outcome == InitOutcome.ACKNOWLEDGED) {
                subscription = subscribe(wire)
                // The legacy protocol ends an established session with a message of its own.
                if (subscription.outcome != SubscriptionOutcome.CLOSED) protocol.terminate()?.let { wire.send(it) }
            }
            return Session(
                authenticated, null, opened.httpStatus, opened.selectedSubprotocol,
                connection.outcome, connection.errors, subscription, wire.frames,
            )
        } finally {
            runCatching { opened.socket.close() }
        }
    }

    private fun handshake(wire: Wire, payload: JsonObject?): Init {
        if (!wire.send(wire.protocol.connectionInit(payload))) return Init(InitOutcome.CLOSED)
        return await(
            wire,
            decide = { message ->
                when (message) {
                    is ServerMessage.ConnectionAck -> Init(InitOutcome.ACKNOWLEDGED)
                    is ServerMessage.ConnectionError -> Init(InitOutcome.REJECTED, message.messages)
                    is ServerMessage.OperationError -> Init(InitOutcome.REJECTED, message.messages)
                    else -> null
                }
            },
            onSilence = { Init(if (it == Silence.CLOSED) InitOutcome.CLOSED else InitOutcome.TIMED_OUT) },
        )
    }

    private fun subscribe(wire: Wire): Subscription {
        val catalog = if (operation == null) discover(wire) else null
        val fields = when (catalog) {
            is SubscriptionCatalog.Runnable -> catalog.fields
            is SubscriptionCatalog.ArgumentsRequired -> catalog.fields
            else -> emptyList()
        }
        val (query, source) = when {
            operation != null -> operation to "caller"
            catalog is SubscriptionCatalog.Runnable -> catalog.query to "introspection"
            catalog is SubscriptionCatalog.NoSubscriptions ->
                return Subscription(null, "introspection", SubscriptionOutcome.NO_SUBSCRIPTION_TYPE)
            catalog is SubscriptionCatalog.ArgumentsRequired ->
                return Subscription(null, "introspection", SubscriptionOutcome.NEEDS_ARGUMENTS, fields = fields)
            catalog == null -> return Subscription(
                null, "introspection", SubscriptionOutcome.CLOSED,
                listOf("The socket closed during the introspection query that looks for a subscription field; pass 'subscription_query' to skip it."),
            )
            else -> DEFAULT_OPERATION to "default"
        }

        if (!wire.send(wire.protocol.start(OPERATION_ID, query))) {
            return Subscription(query, source, SubscriptionOutcome.CLOSED, fields = fields)
        }
        val reply = await(
            wire,
            decide = { message ->
                when {
                    message is ServerMessage.Data && concerns(message.id, OPERATION_ID) ->
                        if (!message.hasData && message.errors.isNotEmpty()) {
                            Subscription(query, source, SubscriptionOutcome.ERROR, message.errors, fields)
                        } else {
                            Subscription(query, source, SubscriptionOutcome.DATA, message.errors, fields)
                        }
                    message is ServerMessage.OperationError && concerns(message.id, OPERATION_ID) ->
                        Subscription(query, source, SubscriptionOutcome.ERROR, message.messages, fields)
                    message is ServerMessage.ConnectionError ->
                        Subscription(query, source, SubscriptionOutcome.ERROR, message.messages, fields)
                    message is ServerMessage.Complete && concerns(message.id, OPERATION_ID) ->
                        Subscription(query, source, SubscriptionOutcome.COMPLETE, fields = fields)
                    else -> null
                }
            },
            onSilence = {
                val outcome = if (it == Silence.CLOSED) SubscriptionOutcome.CLOSED else SubscriptionOutcome.OPEN_NO_EVENTS
                Subscription(query, source, outcome, fields = fields)
            },
        )
        // A stream that may still be running is stopped before the session ends.
        if (reply.outcome == SubscriptionOutcome.DATA || reply.outcome == SubscriptionOutcome.OPEN_NO_EVENTS) {
            wire.send(wire.protocol.stop(OPERATION_ID))
        }
        return reply
    }

    /** Introspects the subscription root over the socket; null when the socket closed meanwhile. */
    private fun discover(wire: Wire): SubscriptionCatalog? {
        if (!wire.send(wire.protocol.start(DISCOVERY_ID, SubscriptionCatalog.QUERY))) return null
        var closed = false
        val catalog = await<SubscriptionCatalog>(
            wire,
            decide = { message ->
                when {
                    message is ServerMessage.Data && concerns(message.id, DISCOVERY_ID) ->
                        SubscriptionCatalog.read(message.payload?.get("data") as? JsonObject)
                    message is ServerMessage.OperationError && concerns(message.id, DISCOVERY_ID) -> SubscriptionCatalog.Unavailable
                    message is ServerMessage.Complete && concerns(message.id, DISCOVERY_ID) -> SubscriptionCatalog.Unavailable
                    else -> null
                }
            },
            onSilence = {
                closed = it == Silence.CLOSED
                SubscriptionCatalog.Unavailable
            },
        )
        return if (closed) null else catalog
    }

    /** A frame without an id can only be about the one operation in flight. */
    private fun concerns(id: String?, operationId: String): Boolean = id == null || id == operationId

    /**
     * Reads frames until [decide] returns a verdict, the socket closes, or [waitMs] has passed in
     * total: keep-alives and frames about other operations do not extend the wait. Pings are answered.
     */
    private fun <T : Any> await(wire: Wire, decide: (ServerMessage) -> T?, onSilence: (Silence) -> T): T {
        val deadline = System.nanoTime() + waitMs * 1_000_000
        while (true) {
            val remainingMs = (deadline - System.nanoTime()) / 1_000_000
            if (remainingMs <= 0) return onSilence(Silence.TIMED_OUT)
            when (val event = wire.socket.receive(remainingMs)) {
                null -> return onSilence(Silence.TIMED_OUT)
                is ProbeEvent.Closed -> return onSilence(Silence.CLOSED)
                is ProbeEvent.Text -> {
                    wire.record(sent = false, event.payload)
                    val message = SubscriptionProtocol.parse(event.payload)
                    if (message is ServerMessage.Ping) wire.send(SubscriptionProtocol.PONG)
                    decide(message)?.let { return it }
                }
            }
        }
    }
}
