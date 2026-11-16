package io.bitbytelab.raijin.graphql.subscriptions

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put

/**
 * The two GraphQL-over-WebSocket protocols in use, and how each frames its client messages. Both
 * open with `connection_init` / `connection_ack`; they differ in the WebSocket subprotocol that
 * selects them and in the message that starts and stops an operation.
 */
enum class SubscriptionProtocol(
    /** Name used in results. */
    val protocolName: String,
    /** `Sec-WebSocket-Protocol` token that selects it. */
    val subprotocol: String,
    private val startType: String,
    private val stopType: String,
) {
    /** The current protocol, implemented by the `graphql-ws` library. */
    GRAPHQL_TRANSPORT_WS("graphql-transport-ws", "graphql-transport-ws", "subscribe", "complete"),

    /**
     * The legacy protocol of the unmaintained `subscriptions-transport-ws` library. Its subprotocol
     * token is `graphql-ws`, which is also the name of the library implementing the other protocol.
     */
    SUBSCRIPTIONS_TRANSPORT_WS("subscriptions-transport-ws", "graphql-ws", "start", "stop");

    /**
     * `connection_init`, carrying [payload] (the client's connection params, where credentials go).
     * Without one the legacy client still sends an empty object and the current one leaves it out;
     * each is mirrored, so a server sees what its own client library would send.
     */
    fun connectionInit(payload: JsonObject? = null): String {
        val body = payload ?: if (this == SUBSCRIPTIONS_TRANSPORT_WS) JsonObject(emptyMap()) else null
        return buildJsonObject {
            put("type", "connection_init")
            if (body != null) put("payload", body)
        }.toString()
    }

    /** Starts operation [id]: `subscribe` in the current protocol, `start` in the legacy one. */
    fun start(id: String, query: String): String = buildJsonObject {
        put("id", id)
        put("type", startType)
        put("payload", buildJsonObject { put("query", query) })
    }.toString()

    /** Ends operation [id] from the client side: `complete` in the current protocol, `stop` in the legacy one. */
    fun stop(id: String): String = buildJsonObject {
        put("id", id)
        put("type", stopType)
    }.toString()

    /** The message that ends the session before the socket closes; only the legacy protocol has one. */
    fun terminate(): String? = if (this == SUBSCRIPTIONS_TRANSPORT_WS) CONNECTION_TERMINATE else null

    companion object {
        /** Answer to a server `ping` (current protocol). */
        const val PONG = """{"type":"pong"}"""

        private const val CONNECTION_TERMINATE = """{"type":"connection_terminate"}"""

        /**
         * Reads a server frame. The two protocols use disjoint names for what differs (`next` /
         * `data`, `ping` / `ka`), so one parser serves both.
         */
        fun parse(frame: String): ServerMessage {
            val message = try { Json.parseToJsonElement(frame) as? JsonObject } catch (_: Exception) { null }
                ?: return ServerMessage.Unknown(null)
            val type = (message["type"] as? JsonPrimitive)?.contentOrNull
            val id = (message["id"] as? JsonPrimitive)?.contentOrNull
            val payload = message["payload"]
            return when (type) {
                "connection_ack" -> ServerMessage.ConnectionAck
                "connection_error" -> ServerMessage.ConnectionError(errorMessages(payload))
                "ka" -> ServerMessage.KeepAlive
                "ping" -> ServerMessage.Ping
                "pong" -> ServerMessage.Pong
                "next", "data" -> {
                    val result = payload as? JsonObject
                    ServerMessage.Data(id, result?.get("data") is JsonObject, errorMessages(result?.get("errors")), result)
                }
                "error" -> ServerMessage.OperationError(id, errorMessages(payload))
                "complete" -> ServerMessage.Complete(id)
                else -> ServerMessage.Unknown(type)
            }
        }

        /**
         * Error texts from any of the payload shapes servers use: an array of errors (current
         * protocol), one error object (legacy), `{"errors": [...]}`, or a bare string.
         */
        fun errorMessages(payload: JsonElement?): List<String> = when (payload) {
            null, is JsonNull -> emptyList()
            is JsonArray -> payload.flatMap { errorMessages(it) }
            is JsonObject -> {
                val nested = payload["errors"]
                val message = (payload["message"] as? JsonPrimitive)?.contentOrNull
                when {
                    nested is JsonArray -> errorMessages(nested)
                    message != null -> listOf(message)
                    else -> listOf(payload.toString())
                }
            }
            is JsonPrimitive -> listOf(payload.content)
        }
    }
}

/** A server frame, reduced to what the probe acts on. */
sealed interface ServerMessage {
    data object ConnectionAck : ServerMessage

    /** Legacy `connection_error`: the server refused `connection_init`. */
    data class ConnectionError(val messages: List<String>) : ServerMessage

    /** Legacy keep-alive (`ka`). */
    data object KeepAlive : ServerMessage

    data object Ping : ServerMessage

    data object Pong : ServerMessage

    /**
     * `next` (current) or `data` (legacy): an execution result for operation [id]. [hasData] is
     * false when the result carries no `data` object, which with [errors] means the operation failed.
     */
    data class Data(val id: String?, val hasData: Boolean, val errors: List<String>, val payload: JsonObject?) : ServerMessage

    /** `error`: operation [id] was refused before it produced a result. */
    data class OperationError(val id: String?, val messages: List<String>) : ServerMessage

    data class Complete(val id: String?) : ServerMessage

    /** Not a JSON object, or a `type` neither protocol defines. */
    data class Unknown(val type: String?) : ServerMessage
}
