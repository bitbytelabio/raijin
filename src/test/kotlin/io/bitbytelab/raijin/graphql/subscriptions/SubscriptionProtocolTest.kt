package io.bitbytelab.raijin.graphql.subscriptions

import io.bitbytelab.raijin.graphql.subscriptions.SubscriptionProtocol.GRAPHQL_TRANSPORT_WS
import io.bitbytelab.raijin.graphql.subscriptions.SubscriptionProtocol.SUBSCRIPTIONS_TRANSPORT_WS
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SubscriptionProtocolTest {

    @Test
    fun `each protocol is selected by its own subprotocol token`() {
        assertEquals("graphql-transport-ws", GRAPHQL_TRANSPORT_WS.subprotocol)
        // The legacy protocol's token is the name of the library that implements the other one.
        assertEquals("graphql-ws", SUBSCRIPTIONS_TRANSPORT_WS.subprotocol)
        assertEquals(
            listOf("graphql-transport-ws", "subscriptions-transport-ws"),
            SubscriptionProtocol.entries.map { it.protocolName },
        )
    }

    @Test
    fun `connection_init without a payload mirrors each reference client`() {
        assertEquals("""{"type":"connection_init"}""", GRAPHQL_TRANSPORT_WS.connectionInit())
        assertEquals("""{"type":"connection_init","payload":{}}""", SUBSCRIPTIONS_TRANSPORT_WS.connectionInit())
    }

    @Test
    fun `connection_init carries the credentials payload in both protocols`() {
        val payload = buildJsonObject { put("Authorization", "Bearer abc") }
        val expected = """{"type":"connection_init","payload":{"Authorization":"Bearer abc"}}"""
        assertEquals(expected, GRAPHQL_TRANSPORT_WS.connectionInit(payload))
        assertEquals(expected, SUBSCRIPTIONS_TRANSPORT_WS.connectionInit(payload))
    }

    @Test
    fun `an operation is started with subscribe in the current protocol and start in the legacy one`() {
        val query = "subscription { messageAdded { id } }"
        assertEquals(
            """{"id":"1","type":"subscribe","payload":{"query":"subscription { messageAdded { id } }"}}""",
            GRAPHQL_TRANSPORT_WS.start("1", query),
        )
        assertEquals(
            """{"id":"1","type":"start","payload":{"query":"subscription { messageAdded { id } }"}}""",
            SUBSCRIPTIONS_TRANSPORT_WS.start("1", query),
        )
    }

    @Test
    fun `a query with quotes and newlines survives the framing`() {
        val query = "subscription {\n  search(text: \"a \\\"quoted\\\" word\") { id }\n}"
        for (protocol in SubscriptionProtocol.entries) {
            val frame = Json.parseToJsonElement(protocol.start("op-7", query)).jsonObject
            assertEquals("op-7", frame.getValue("id").jsonPrimitive.content)
            assertEquals(query, frame.getValue("payload").jsonObject.getValue("query").jsonPrimitive.content)
        }
    }

    @Test
    fun `an operation is stopped with complete in the current protocol and stop in the legacy one`() {
        assertEquals("""{"id":"1","type":"complete"}""", GRAPHQL_TRANSPORT_WS.stop("1"))
        assertEquals("""{"id":"1","type":"stop"}""", SUBSCRIPTIONS_TRANSPORT_WS.stop("1"))
    }

    @Test
    fun `only the legacy protocol ends a session with a message`() {
        assertNull(GRAPHQL_TRANSPORT_WS.terminate())
        assertEquals("""{"type":"connection_terminate"}""", SUBSCRIPTIONS_TRANSPORT_WS.terminate())
        assertEquals("""{"type":"pong"}""", SubscriptionProtocol.PONG)
    }

    @Test
    fun `the handshake replies of both protocols are parsed`() {
        assertEquals(ServerMessage.ConnectionAck, SubscriptionProtocol.parse("""{"type":"connection_ack"}"""))
        assertEquals(ServerMessage.ConnectionAck, SubscriptionProtocol.parse("""{"type":"connection_ack","payload":{"ttl":30}}"""))
        assertEquals(
            ServerMessage.ConnectionError(listOf("Unauthorized")),
            SubscriptionProtocol.parse("""{"type":"connection_error","payload":{"message":"Unauthorized"}}"""),
        )
        assertEquals(ServerMessage.KeepAlive, SubscriptionProtocol.parse("""{"type":"ka"}"""))
        assertEquals(ServerMessage.Ping, SubscriptionProtocol.parse("""{"type":"ping"}"""))
        assertEquals(ServerMessage.Pong, SubscriptionProtocol.parse("""{"type":"pong"}"""))
    }

    @Test
    fun `next and data are the same result message`() {
        for (type in listOf("next", "data")) {
            val message = SubscriptionProtocol.parse("""{"id":"1","type":"$type","payload":{"data":{"messageAdded":{"id":"7"}}}}""")
            assertTrue(message is ServerMessage.Data, "$type: $message")
            assertEquals("1", message.id)
            assertTrue(message.hasData)
            assertEquals(emptyList(), message.errors)
            assertEquals("7", message.payload!!.getValue("data").jsonObject.getValue("messageAdded").jsonObject.getValue("id").jsonPrimitive.content)
        }
    }

    @Test
    fun `a result that carries only errors has no data`() {
        val message = SubscriptionProtocol.parse(
            """{"id":"1","type":"data","payload":{"data":null,"errors":[{"message":"Not authorised"},{"message":"Second"}]}}"""
        )
        assertTrue(message is ServerMessage.Data)
        assertFalse(message.hasData)
        assertEquals(listOf("Not authorised", "Second"), message.errors)
    }

    @Test
    fun `operation errors are read from every payload shape in use`() {
        fun errors(payload: String) =
            (SubscriptionProtocol.parse("""{"id":"1","type":"error","payload":$payload}""") as ServerMessage.OperationError).messages

        // Current protocol: an array of GraphQL errors.
        assertEquals(listOf("Cannot query field \"x\"", "Second"), errors("""[{"message":"Cannot query field \"x\""},{"message":"Second"}]"""))
        // Legacy protocol: one error object.
        assertEquals(listOf("Subscription field must return Async Iterable"), errors("""{"message":"Subscription field must return Async Iterable"}"""))
        // Hasura: an object wrapping the usual errors array.
        assertEquals(listOf("field not found"), errors("""{"errors":[{"message":"field not found"}]}"""))
        assertEquals(listOf("plain text"), errors(""""plain text""""))
        assertEquals(listOf("""{"code":"FORBIDDEN"}"""), errors("""{"code":"FORBIDDEN"}"""))
        assertEquals(emptyList(), errors("null"))
    }

    @Test
    fun `complete and unknown frames are parsed, and ids need not be strings`() {
        assertEquals(ServerMessage.Complete("1"), SubscriptionProtocol.parse("""{"id":"1","type":"complete"}"""))
        assertEquals(ServerMessage.Complete("42"), SubscriptionProtocol.parse("""{"id":42,"type":"complete"}"""))
        assertEquals(ServerMessage.Complete(null), SubscriptionProtocol.parse("""{"type":"complete"}"""))
        assertEquals(ServerMessage.Unknown("connection_keep_alive"), SubscriptionProtocol.parse("""{"type":"connection_keep_alive"}"""))
        assertEquals(ServerMessage.Unknown(null), SubscriptionProtocol.parse("""{"id":"1"}"""))
        assertEquals(ServerMessage.Unknown(null), SubscriptionProtocol.parse("not json"))
        assertEquals(ServerMessage.Unknown(null), SubscriptionProtocol.parse("""["connection_ack"]"""))
        assertEquals(ServerMessage.Unknown(null), SubscriptionProtocol.parse(""))
    }
}
