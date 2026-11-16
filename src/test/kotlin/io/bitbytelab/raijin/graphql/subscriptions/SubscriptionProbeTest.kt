package io.bitbytelab.raijin.graphql.subscriptions

import io.bitbytelab.raijin.graphql.subscriptions.SubscriptionProbe.InitOutcome
import io.bitbytelab.raijin.graphql.subscriptions.SubscriptionProbe.SubscriptionOutcome
import io.bitbytelab.raijin.graphql.subscriptions.SubscriptionProtocol.GRAPHQL_TRANSPORT_WS
import io.bitbytelab.raijin.graphql.subscriptions.SubscriptionProtocol.SUBSCRIPTIONS_TRANSPORT_WS
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SubscriptionProbeTest {

    /** A socket driven by a script: [respond] maps each client frame to the server events it triggers. */
    private class ScriptedSocket(private val respond: (String) -> List<ProbeEvent>) : ProbeSocket {
        val sent = mutableListOf<String>()
        var closed = false
            private set
        private val pending = ArrayDeque<ProbeEvent>()

        override fun send(text: String) {
            check(!closed) { "send on a closed socket" }
            sent += text
            pending += respond(text)
        }

        // A script has no clock: once it has nothing left to say, the wait is over.
        override fun receive(timeoutMs: Long): ProbeEvent? = pending.removeFirstOrNull()

        override fun close() {
            closed = true
        }
    }

    /** Hands out scripted sockets; a null script is a server that answers the upgrade with HTTP 400. */
    private class Opener(private val script: (SubscriptionProtocol, authenticated: Boolean) -> ((String) -> List<ProbeEvent>)?) {
        val calls = mutableListOf<Pair<SubscriptionProtocol, Boolean>>()
        val sockets = mutableMapOf<Pair<SubscriptionProtocol, Boolean>, ScriptedSocket>()

        fun open(protocol: SubscriptionProtocol, authenticated: Boolean): OpenResult {
            calls += protocol to authenticated
            val respond = script(protocol, authenticated) ?: return OpenResult.Refused.of("NON_UPGRADE_RESPONSE", 400)
            val socket = ScriptedSocket(respond)
            sockets[protocol to authenticated] = socket
            return OpenResult.Opened(socket, 101, protocol.subprotocol)
        }

        fun sent(protocol: SubscriptionProtocol, authenticated: Boolean = false): List<String> =
            sockets.getValue(protocol to authenticated).sent
    }

    /**
     * A GraphQL-over-WebSocket server for one session. By default it acknowledges `connection_init`,
     * lists one subscription field on introspection and holds every operation open without events.
     */
    private fun server(
        protocol: SubscriptionProtocol,
        onInit: (payload: JsonObject?) -> List<ProbeEvent> = { listOf(ACK) },
        subscriptionType: String? = MESSAGE_ADDED,
        onOperation: (id: String, query: String) -> List<ProbeEvent> = { _, _ -> emptyList() },
    ): (String) -> List<ProbeEvent> = { frame ->
        val message = Json.parseToJsonElement(frame).jsonObject
        val id = message["id"]?.jsonPrimitive?.content
        val query = (message["payload"] as? JsonObject)?.get("query")?.jsonPrimitive?.content
        when (message.getValue("type").jsonPrimitive.content) {
            "connection_init" -> onInit(message["payload"] as? JsonObject)
            "subscribe", "start" -> when {
                query != SubscriptionCatalog.QUERY -> onOperation(id!!, query!!)
                subscriptionType == null -> listOf(protocol.error(id!!, """[{"message":"Introspection is disabled"}]"""))
                else -> listOf(
                    protocol.result(id!!, """{"data":{"__schema":{"subscriptionType":$subscriptionType}}}"""),
                    text("""{"id":"$id","type":"complete"}"""),
                )
            }
            else -> emptyList()
        }
    }

    private fun probe(opener: Opener, operation: String? = null, payload: JsonObject? = null, hasCredentials: Boolean = false) =
        SubscriptionProbe(opener::open, operation, payload, hasCredentials, waitMs = 5_000).run()

    private fun SubscriptionProbe.Report.of(protocol: SubscriptionProtocol) = protocols.single { it.protocol == protocol }

    @Test
    fun `a server speaking only the current protocol is told apart from the legacy one`() {
        val opener = Opener { protocol, _ ->
            when (protocol) {
                GRAPHQL_TRANSPORT_WS -> server(protocol)
                // graphql-ws closes a socket that asked for another subprotocol (4406).
                SUBSCRIPTIONS_TRANSPORT_WS -> server(protocol, onInit = { listOf(ProbeEvent.Closed) })
            }
        }
        val report = probe(opener)

        val current = report.of(GRAPHQL_TRANSPORT_WS)
        assertTrue(current.handshakeAccepted)
        assertEquals(false, current.initRequiresAuth)
        assertEquals(true, current.subscriptionAccepted)
        val subscription = assertNotNull(current.anonymous.subscription)
        assertEquals(SubscriptionOutcome.OPEN_NO_EVENTS, subscription.outcome)
        assertEquals("introspection", subscription.source)
        assertEquals("subscription { messageAdded { __typename } }", subscription.query)
        assertEquals(listOf("messageAdded"), subscription.fields)

        val legacy = report.of(SUBSCRIPTIONS_TRANSPORT_WS)
        assertFalse(legacy.handshakeAccepted)
        assertNull(legacy.initRequiresAuth)
        assertNull(legacy.subscriptionAccepted)
        assertEquals(InitOutcome.CLOSED, legacy.anonymous.connectionInit)
        assertNull(legacy.anonymous.subscription)

        // Each session spoke its own dialect, and the idle stream was stopped before the socket closed.
        assertEquals(
            listOf(
                """{"type":"connection_init"}""",
                GRAPHQL_TRANSPORT_WS.start("raijin-discover", SubscriptionCatalog.QUERY),
                """{"id":"raijin-1","type":"subscribe","payload":{"query":"subscription { messageAdded { __typename } }"}}""",
                """{"id":"raijin-1","type":"complete"}""",
            ),
            opener.sent(GRAPHQL_TRANSPORT_WS),
        )
        assertEquals(listOf("""{"type":"connection_init","payload":{}}"""), opener.sent(SUBSCRIPTIONS_TRANSPORT_WS))
        assertTrue(opener.sockets.values.all { it.closed })
    }

    @Test
    fun `a server speaking only the legacy protocol is told apart from the current one`() {
        val opener = Opener { protocol, _ ->
            when (protocol) {
                GRAPHQL_TRANSPORT_WS -> null // the upgrade itself is refused
                SUBSCRIPTIONS_TRANSPORT_WS -> server(
                    protocol,
                    onInit = { listOf(ACK, text("""{"type":"ka"}""")) },
                    onOperation = { id, _ -> listOf(protocol.result(id, """{"data":{"messageAdded":{"__typename":"Message"}}}""")) },
                )
            }
        }
        val report = probe(opener)

        val current = report.of(GRAPHQL_TRANSPORT_WS)
        assertFalse(current.handshakeAccepted)
        assertEquals(InitOutcome.NOT_SENT, current.anonymous.connectionInit)
        assertEquals("NON_UPGRADE_RESPONSE", current.anonymous.refused?.status)
        assertEquals(400, current.anonymous.httpStatus)

        val legacy = report.of(SUBSCRIPTIONS_TRANSPORT_WS)
        assertTrue(legacy.handshakeAccepted)
        assertEquals(SubscriptionOutcome.DATA, legacy.anonymous.subscription?.outcome)
        assertEquals("graphql-ws", legacy.anonymous.selectedSubprotocol)
        assertEquals(
            listOf(
                """{"type":"connection_init","payload":{}}""",
                SUBSCRIPTIONS_TRANSPORT_WS.start("raijin-discover", SubscriptionCatalog.QUERY),
                """{"id":"raijin-1","type":"start","payload":{"query":"subscription { messageAdded { __typename } }"}}""",
                """{"id":"raijin-1","type":"stop"}""",
                """{"type":"connection_terminate"}""",
            ),
            opener.sent(SUBSCRIPTIONS_TRANSPORT_WS),
        )
        assertTrue(opener.sockets.values.all { it.closed })

        val json = report.toJson("wss://target.example/graphql")
        assertEquals(listOf("subscriptions-transport-ws"), json.getValue("supported_protocols").jsonArray.map { it.jsonPrimitive.content })
        val upgrade = json.getValue("protocols").jsonObject.getValue("graphql-transport-ws").jsonObject
            .getValue("anonymous").jsonObject.getValue("upgrade").jsonObject
        assertFalse(upgrade.getValue("accepted").jsonPrimitive.boolean)
        assertEquals(400, upgrade.getValue("http_status").jsonPrimitive.int)
    }

    @Test
    fun `connection_init that is only acknowledged with credentials needs auth`() {
        val credentials = buildJsonObject { put("token", "secret") }
        val opener = Opener { protocol, _ ->
            server(
                protocol,
                onInit = { payload ->
                    when {
                        payload?.get("token")?.jsonPrimitive?.content == "secret" -> listOf(ACK)
                        // The current protocol refuses by closing (4403); the legacy one says why.
                        protocol == GRAPHQL_TRANSPORT_WS -> listOf(ProbeEvent.Closed)
                        else -> listOf(text("""{"type":"connection_error","payload":{"message":"Unauthorized"}}"""))
                    }
                },
                onOperation = { id, _ -> listOf(protocol.result(id, """{"data":{"secrets":{"id":"1"}}}""")) },
            )
        }
        val report = probe(opener, operation = "subscription { secrets { id } }", payload = credentials, hasCredentials = true)

        for (protocol in SubscriptionProtocol.entries) {
            val result = report.of(protocol)
            assertTrue(result.handshakeAccepted, protocol.protocolName)
            assertEquals(true, result.initRequiresAuth, protocol.protocolName)
            assertEquals(true, result.subscriptionAccepted, protocol.protocolName)
            assertEquals(true, result.subscriptionRequiresAuth, protocol.protocolName)
            assertEquals(InitOutcome.ACKNOWLEDGED, result.authenticated?.connectionInit)
            assertEquals("caller", result.authenticated?.subscription?.source)

            // The anonymous session never carried the credentials.
            assertEquals(listOf(protocol.connectionInit()), opener.sent(protocol, authenticated = false))
            assertEquals(protocol.connectionInit(credentials), opener.sent(protocol, authenticated = true).first())
            // A caller-supplied operation is sent as is, with no introspection first.
            assertEquals(protocol.start("raijin-1", "subscription { secrets { id } }"), opener.sent(protocol, authenticated = true)[1])
        }
        assertEquals(InitOutcome.CLOSED, report.of(GRAPHQL_TRANSPORT_WS).anonymous.connectionInit)
        assertEquals(InitOutcome.REJECTED, report.of(SUBSCRIPTIONS_TRANSPORT_WS).anonymous.connectionInit)
        assertEquals(listOf("Unauthorized"), report.of(SUBSCRIPTIONS_TRANSPORT_WS).anonymous.connectionErrors)
        assertEquals(
            listOf(GRAPHQL_TRANSPORT_WS to false, GRAPHQL_TRANSPORT_WS to true, SUBSCRIPTIONS_TRANSPORT_WS to false, SUBSCRIPTIONS_TRANSPORT_WS to true),
            opener.calls,
        )
        assertTrue(opener.sockets.values.all { it.closed })
    }

    @Test
    fun `an anonymous session that gets all the way makes the authenticated one unnecessary`() {
        val opener = Opener { protocol, _ ->
            server(protocol, onOperation = { id, _ -> listOf(protocol.result(id, """{"data":{"messageAdded":null}}""")) })
        }
        val report = probe(opener, payload = buildJsonObject { put("token", "secret") }, hasCredentials = true)

        assertEquals(listOf(GRAPHQL_TRANSPORT_WS to false, SUBSCRIPTIONS_TRANSPORT_WS to false), opener.calls)
        for (result in report.protocols) {
            assertNull(result.authenticated)
            assertEquals(false, result.initRequiresAuth)
            assertEquals(false, result.subscriptionRequiresAuth)
        }
    }

    @Test
    fun `an operation refused anonymously and accepted with credentials needs auth, though connection_init does not`() {
        val opener = Opener { protocol, authenticated ->
            server(
                protocol,
                onOperation = { id, _ ->
                    if (authenticated) listOf(protocol.result(id, """{"data":{"messageAdded":null}}"""))
                    else listOf(protocol.error(id, """[{"message":"Not authorised"}]"""))
                },
            )
        }
        val report = probe(opener, hasCredentials = true)

        for (result in report.protocols) {
            assertEquals(false, result.initRequiresAuth)
            assertEquals(true, result.subscriptionAccepted)
            assertEquals(true, result.subscriptionRequiresAuth)
            assertEquals(SubscriptionOutcome.ERROR, result.anonymous.subscription?.outcome)
            assertEquals(listOf("Not authorised"), result.anonymous.subscription?.errors)
            assertEquals(SubscriptionOutcome.DATA, result.authenticated?.subscription?.outcome)
        }
    }

    @Test
    fun `without credentials only the anonymous sessions run`() {
        val opener = Opener { protocol, _ -> server(protocol, onInit = { listOf(ProbeEvent.Closed) }) }
        val report = probe(opener)

        assertEquals(listOf(GRAPHQL_TRANSPORT_WS to false, SUBSCRIPTIONS_TRANSPORT_WS to false), opener.calls)
        assertTrue(report.protocols.none { it.handshakeAccepted })
        assertTrue(report.protocols.all { it.initRequiresAuth == null && it.authenticated == null })
        val json = report.toJson("wss://target.example/graphql")
        assertEquals(0, json.getValue("supported_protocols").jsonArray.size)
        assertTrue("Neither" in json.getValue("note").jsonPrimitive.content)
    }

    @Test
    fun `an unreachable target ends the probe at the first upgrade with one error`() {
        var opens = 0
        val report = SubscriptionProbe(
            open = { _, _ ->
                opens++
                OpenResult.Refused.of("CONNECTION_FAILED")
            },
            hasCredentials = true,
        ).run()

        assertEquals(1, opens)
        assertTrue(report.protocols.isEmpty())
        val json = report.toJson("wss://down.example/graphql")
        assertEquals(setOf("endpoint", "error"), json.keys)
        assertTrue("wss://down.example/graphql" in json.getValue("error").jsonPrimitive.content)
        assertTrue("could not reach the host" in json.getValue("error").jsonPrimitive.content)
    }

    @Test
    fun `a target that stops answering later keeps what was probed and says so`() {
        val opener = Opener { protocol, _ -> server(protocol) }
        val report = SubscriptionProbe(
            open = { protocol, authenticated ->
                if (protocol == GRAPHQL_TRANSPORT_WS) opener.open(protocol, authenticated)
                else OpenResult.Refused.of(OpenResult.Refused.TIMEOUT, detail = "no answer within 10000 ms")
            },
            waitMs = 5_000,
        ).run()

        assertEquals(listOf(GRAPHQL_TRANSPORT_WS), report.protocols.map { it.protocol })
        val json = report.toJson("wss://target.example/graphql")
        assertNull(json["error"])
        assertTrue("no answer within 10000 ms" in json.getValue("warning").jsonPrimitive.content)
        assertEquals(setOf("graphql-transport-ws"), json.getValue("protocols").jsonObject.keys)
    }

    @Test
    fun `an upgrade the server declines is not taken for an unreachable target`() {
        val refused = OpenResult.Refused.of("NON_UPGRADE_RESPONSE", 403)
        assertFalse(refused.unreachable)
        assertTrue("HTTP 403" in refused.reason)
        for (status in listOf("UNKNOWN_HOST", "CONNECTION_FAILED", "INVALID_HOST", OpenResult.Refused.TIMEOUT, OpenResult.Refused.ERROR)) {
            assertTrue(OpenResult.Refused.of(status).unreachable, status)
        }
    }

    @Test
    fun `pings are answered, and keep-alives and other operations' frames are not taken for the reply`() {
        val opener = Opener { protocol, _ ->
            if (protocol == SUBSCRIPTIONS_TRANSPORT_WS) null
            else server(
                protocol,
                onInit = { listOf(text("""{"type":"ping"}"""), ACK) },
                onOperation = { id, _ ->
                    listOf(
                        text("""{"type":"ka"}"""),
                        text("""{"id":"someone-else","type":"next","payload":{"data":{"x":1}}}"""),
                        text("""{"id":"raijin-discover","type":"complete"}"""),
                        text("""{"type":"ping"}"""),
                        protocol.error(id, """[{"message":"Subscription \"Anonymous\" must not select an introspection top level field."}]"""),
                    )
                },
            )
        }
        val report = probe(opener, operation = SubscriptionProbe.DEFAULT_OPERATION)

        val subscription = assertNotNull(report.of(GRAPHQL_TRANSPORT_WS).anonymous.subscription)
        assertEquals(SubscriptionOutcome.ERROR, subscription.outcome)
        assertEquals(listOf("Subscription \"Anonymous\" must not select an introspection top level field."), subscription.errors)
        assertEquals(false, report.of(GRAPHQL_TRANSPORT_WS).subscriptionAccepted)
        assertEquals(
            listOf(
                """{"type":"connection_init"}""",
                """{"type":"pong"}""",
                GRAPHQL_TRANSPORT_WS.start("raijin-1", "subscription { __typename }"),
                """{"type":"pong"}""",
            ),
            opener.sent(GRAPHQL_TRANSPORT_WS),
        )
    }

    @Test
    fun `a server that never answers connection_init times out and is closed`() {
        val opener = Opener { protocol, _ -> server(protocol, onInit = { emptyList() }) }
        val report = probe(opener)

        for (result in report.protocols) {
            assertEquals(InitOutcome.TIMED_OUT, result.anonymous.connectionInit)
            assertNull(result.anonymous.subscription)
            assertFalse(result.handshakeAccepted)
        }
        assertEquals(2, opener.sockets.size)
        assertTrue(opener.sockets.values.all { it.closed && it.sent.size == 1 })
    }

    @Test
    fun `the socket is closed when the session fails half-way`() {
        class Failing(private val failOnSend: Boolean) : ProbeSocket {
            var closed = false
            override fun send(text: String) {
                if (failOnSend) throw IllegalStateException("socket is closed")
            }
            override fun receive(timeoutMs: Long): ProbeEvent? {
                throw IllegalStateException("receive blew up")
            }
            override fun close() {
                closed = true
            }
        }

        // A frame the socket will not take reads as a closed connection.
        val unsendable = Failing(failOnSend = true)
        val report = SubscriptionProbe(open = { protocol, _ -> OpenResult.Opened(unsendable, 101, protocol.subprotocol) }).run()
        assertTrue(report.protocols.all { it.anonymous.connectionInit == InitOutcome.CLOSED })
        assertTrue(unsendable.closed)

        // Anything unexpected still leaves no socket open behind it.
        val broken = Failing(failOnSend = false)
        assertFailsWith<IllegalStateException> {
            SubscriptionProbe(open = { protocol, _ -> OpenResult.Opened(broken, 101, protocol.subprotocol) }).run()
        }
        assertTrue(broken.closed)
    }

    @Test
    fun `a schema without a subscription type is reported without starting an operation`() {
        val opener = Opener { protocol, _ -> server(protocol, subscriptionType = "null") }
        val report = probe(opener)

        for (result in report.protocols) {
            val subscription = assertNotNull(result.anonymous.subscription)
            assertEquals(SubscriptionOutcome.NO_SUBSCRIPTION_TYPE, subscription.outcome)
            assertNull(subscription.query)
            assertEquals(false, result.subscriptionAccepted)
            assertEquals(2, opener.sent(result.protocol).count { "__schema" in it || "connection_init" in it })
            assertTrue(opener.sent(result.protocol).none { "raijin-1" in it })
        }
    }

    @Test
    fun `subscriptions that all need arguments are listed instead of guessed at`() {
        val needsArguments = """{"fields":[
            {"name":"orderUpdated","args":[{"name":"id","defaultValue":null,"type":{"kind":"NON_NULL"}}],"type":{"kind":"OBJECT","ofType":null}},
            {"name":"priceChanged","args":[{"name":"sku","defaultValue":null,"type":{"kind":"NON_NULL"}}],"type":{"kind":"SCALAR","ofType":null}}
        ]}"""
        val opener = Opener { protocol, _ -> if (protocol == GRAPHQL_TRANSPORT_WS) server(protocol, subscriptionType = needsArguments) else null }
        val report = probe(opener)

        val result = report.of(GRAPHQL_TRANSPORT_WS)
        val subscription = assertNotNull(result.anonymous.subscription)
        assertEquals(SubscriptionOutcome.NEEDS_ARGUMENTS, subscription.outcome)
        assertEquals(listOf("orderUpdated", "priceChanged"), subscription.fields)
        assertNull(result.subscriptionAccepted)
        assertTrue(opener.sent(GRAPHQL_TRANSPORT_WS).none { "raijin-1" in it })
    }

    @Test
    fun `when introspection is refused the default operation is tried`() {
        val opener = Opener { protocol, _ ->
            if (protocol == GRAPHQL_TRANSPORT_WS) null
            else server(protocol, subscriptionType = null, onOperation = { id, _ -> listOf(text("""{"id":"$id","type":"complete"}""")) })
        }
        val report = probe(opener)

        val subscription = assertNotNull(report.of(SUBSCRIPTIONS_TRANSPORT_WS).anonymous.subscription)
        assertEquals("default", subscription.source)
        assertEquals(SubscriptionProbe.DEFAULT_OPERATION, subscription.query)
        assertEquals(SubscriptionOutcome.COMPLETE, subscription.outcome)
        assertEquals(true, report.of(SUBSCRIPTIONS_TRANSPORT_WS).subscriptionAccepted)
        // A completed operation needs no stop; the session is still ended properly.
        assertEquals("""{"type":"connection_terminate"}""", opener.sent(SUBSCRIPTIONS_TRANSPORT_WS).last())
        assertTrue(opener.sent(SUBSCRIPTIONS_TRANSPORT_WS).none { """"type":"stop"""" in it })
    }

    @Test
    fun `a legacy data frame that carries only errors is a refusal`() {
        val opener = Opener { protocol, _ ->
            if (protocol == GRAPHQL_TRANSPORT_WS) null
            else server(protocol, onOperation = { id, _ -> listOf(protocol.result(id, """{"data":null,"errors":[{"message":"Forbidden"}]}""")) })
        }
        val subscription = assertNotNull(probe(opener, operation = "subscription { secrets }").of(SUBSCRIPTIONS_TRANSPORT_WS).anonymous.subscription)

        assertEquals(SubscriptionOutcome.ERROR, subscription.outcome)
        assertEquals(listOf("Forbidden"), subscription.errors)
    }

    @Test
    fun `a socket closed in answer to the operation is a refusal`() {
        val opener = Opener { protocol, _ -> server(protocol, onOperation = { _, _ -> listOf(ProbeEvent.Closed) }) }
        val report = probe(opener, operation = "subscription { secrets }")

        for (result in report.protocols) {
            assertEquals(SubscriptionOutcome.CLOSED, result.anonymous.subscription?.outcome)
            assertEquals(false, result.subscriptionAccepted)
            assertTrue(result.handshakeAccepted)
        }
        // Nothing more is said on a connection the server has closed.
        assertEquals(2, opener.sent(SUBSCRIPTIONS_TRANSPORT_WS).size)
    }

    @Test
    fun `the report renders every fact the probe established`() {
        val opener = Opener { protocol, authenticated ->
            when {
                protocol == SUBSCRIPTIONS_TRANSPORT_WS -> null
                authenticated -> server(protocol)
                else -> server(protocol, onInit = { listOf(ProbeEvent.Closed) })
            }
        }
        val json = probe(opener, hasCredentials = true).toJson("wss://target.example/graphql")

        assertEquals("wss://target.example/graphql", json.getValue("endpoint").jsonPrimitive.content)
        assertEquals(listOf("graphql-transport-ws"), json.getValue("supported_protocols").jsonArray.map { it.jsonPrimitive.content })
        val current = json.getValue("protocols").jsonObject.getValue("graphql-transport-ws").jsonObject
        assertEquals("graphql-transport-ws", current.getValue("subprotocol").jsonPrimitive.content)
        assertTrue(current.getValue("handshake_accepted").jsonPrimitive.boolean)
        assertTrue(current.getValue("init_requires_auth").jsonPrimitive.boolean)
        assertTrue(current.getValue("subscription_accepted").jsonPrimitive.boolean)
        assertTrue(current.getValue("subscription_requires_auth").jsonPrimitive.boolean)
        assertEquals("closed", current.getValue("anonymous").jsonObject.getValue("connection_init").jsonPrimitive.content)

        val authenticated = current.getValue("authenticated").jsonObject
        assertEquals("acknowledged", authenticated.getValue("connection_init").jsonPrimitive.content)
        assertEquals(101, authenticated.getValue("upgrade").jsonObject.getValue("http_status").jsonPrimitive.int)
        assertEquals("graphql-transport-ws", authenticated.getValue("upgrade").jsonObject.getValue("selected_subprotocol").jsonPrimitive.content)
        val subscription = authenticated.getValue("subscription").jsonObject
        assertEquals("open_no_events", subscription.getValue("outcome").jsonPrimitive.content)
        assertEquals("introspection", subscription.getValue("query_source").jsonPrimitive.content)
        assertTrue(subscription.getValue("accepted").jsonPrimitive.boolean)
        assertEquals(listOf("messageAdded"), subscription.getValue("subscription_fields").jsonArray.map { it.jsonPrimitive.content })
        val frames = authenticated.getValue("frames").jsonArray.map { it.jsonObject.getValue("direction").jsonPrimitive.content }
        // init/ack, introspection/its result, the operation, the introspection's late "complete", then the stop.
        assertEquals(listOf("sent", "received", "sent", "received", "sent", "received", "sent"), frames)

        val legacy = json.getValue("protocols").jsonObject.getValue("subscriptions-transport-ws").jsonObject
        assertEquals("graphql-ws", legacy.getValue("subprotocol").jsonPrimitive.content)
        assertFalse(legacy.getValue("handshake_accepted").jsonPrimitive.boolean)
        assertEquals(JsonNull, legacy.getValue("init_requires_auth"))
        assertEquals(JsonNull, legacy.getValue("subscription_accepted"))
        assertTrue("graphql-transport-ws: connection_init is acknowledged only with credentials" in json.getValue("note").jsonPrimitive.content)
    }

    @Test
    fun `the catalog picks a subscription that needs no arguments and selects on it as its type requires`() {
        fun read(subscriptionType: String) = SubscriptionCatalog.read(
            Json.parseToJsonElement("""{"__schema":{"subscriptionType":$subscriptionType}}""").jsonObject
        )

        // The first field needs an argument; the second has a default for its non-null argument and returns a list of scalars.
        val catalog = read(
            """{"fields":[
                {"name":"orderUpdated","args":[{"name":"id","defaultValue":null,"type":{"kind":"NON_NULL"}}],"type":{"kind":"OBJECT","ofType":null}},
                {"name":"ticks","args":[{"name":"every","defaultValue":"1","type":{"kind":"NON_NULL"}},{"name":"label","defaultValue":null,"type":{"kind":"SCALAR"}}],
                 "type":{"kind":"NON_NULL","ofType":{"kind":"LIST","ofType":{"kind":"NON_NULL","ofType":{"kind":"SCALAR"}}}}},
                {"name":"messageAdded","args":[],"type":{"kind":"OBJECT","ofType":null}}
            ]}"""
        )
        assertEquals(
            SubscriptionCatalog.Runnable("subscription { ticks }", "ticks", listOf("orderUpdated", "ticks", "messageAdded")),
            catalog,
        )

        assertEquals(
            "subscription { feed { __typename } }",
            (read("""{"fields":[{"name":"feed","args":[],"type":{"kind":"LIST","ofType":{"kind":"UNION","ofType":null}}}]}""") as SubscriptionCatalog.Runnable).query,
        )
        assertEquals("subscription { status }", (read("""{"fields":[{"name":"status","args":[],"type":{"kind":"ENUM"}}]}""") as SubscriptionCatalog.Runnable).query)
        assertEquals(SubscriptionCatalog.NoSubscriptions, read("null"))
        assertEquals(SubscriptionCatalog.NoSubscriptions, read("""{"fields":[]}"""))
        assertEquals(SubscriptionCatalog.Unavailable, SubscriptionCatalog.read(null))
        assertEquals(SubscriptionCatalog.Unavailable, SubscriptionCatalog.read(buildJsonObject { put("__typename", "Query") }))
        assertEquals(SubscriptionCatalog.Unavailable, SubscriptionCatalog.read(Json.parseToJsonElement("""{"__schema":{}}""").jsonObject))
    }

    private companion object {
        val ACK: ProbeEvent = ProbeEvent.Text("""{"type":"connection_ack"}""")

        /** A subscription root with one field that needs no arguments and returns an object. */
        const val MESSAGE_ADDED = """{"fields":[{"name":"messageAdded","args":[],"type":{"kind":"OBJECT","ofType":null}}]}"""

        fun text(json: String): ProbeEvent = ProbeEvent.Text(json)

        /** An execution result in the protocol's own dialect. */
        fun SubscriptionProtocol.result(id: String, payload: String): ProbeEvent =
            text("""{"id":"$id","type":"${if (this == GRAPHQL_TRANSPORT_WS) "next" else "data"}","payload":$payload}""")

        fun SubscriptionProtocol.error(id: String, payload: String): ProbeEvent {
            // The legacy protocol carries one error object where the current one carries an array.
            val body = if (this == GRAPHQL_TRANSPORT_WS) payload else payload.removeSurrounding("[", "]")
            return text("""{"id":"$id","type":"error","payload":$body}""")
        }
    }
}
