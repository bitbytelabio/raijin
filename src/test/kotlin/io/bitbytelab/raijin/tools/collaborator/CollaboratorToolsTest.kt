package io.bitbytelab.raijin.tools.collaborator

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.bridge.CollaboratorBridge
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.testClientConnection
import io.bitbytelab.raijin.turbo.mcp.BurpCollaboratorProvider
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequestParams
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * The tool layer of the Collaborator tools: what is registered, what the schemas declare, and that a
 * bad argument or a bridge error comes back as an `isError` result with a parseable message. The
 * bridge runs on a Montoya stand-in that fails any call, so nothing here reaches Collaborator.
 */
class CollaboratorToolsTest {

    private val server = Server(
        Implementation("t", "0"),
        ServerOptions(ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false)))
    ).also { server ->
        val api = Proxy.newProxyInstance(MontoyaApi::class.java.classLoader, arrayOf(MontoyaApi::class.java)) { proxy, method, args ->
            when (method.name) {
                "hashCode" -> System.identityHashCode(proxy)
                "equals" -> proxy === args?.firstOrNull()
                "toString" -> "MontoyaApi"
                else -> error("unexpected Burp call MontoyaApi.${method.name}")
            }
        } as MontoyaApi
        val state = StateManager()
        val bridge = CollaboratorBridge(api, EventBus(), state, BurpCollaboratorProvider(BurpCollaboratorProvider.State()))
        CollaboratorTools.register(server, bridge, state)
    }

    private fun call(tool: String, args: JsonObjectBuilder.() -> Unit = {}): CallToolResult = runBlocking {
        server.tools.getValue(tool).handler(testClientConnection, CallToolRequest(CallToolRequestParams(tool, buildJsonObject(args))))
    }

    private fun json(result: CallToolResult): JsonObject =
        Json.parseToJsonElement((result.content.first() as TextContent).text).jsonObject

    /** The error message of a call that must have been rejected. */
    private fun rejection(tool: String, args: JsonObjectBuilder.() -> Unit = {}): String {
        val result = call(tool, args)
        val body = json(result)
        assertEquals(true, result.isError, "$tool: $body")
        return body.getValue("error").jsonPrimitive.content
    }

    private fun schema(tool: String): JsonObject = server.tools.getValue(tool).tool.inputSchema.properties ?: JsonObject(emptyMap())

    @Test
    fun `the collaborator tools are registered, list_clients among them`() {
        assertEquals(
            setOf(
                "collaborator_create_client", "collaborator_restore_client", "collaborator_list_clients",
                "collaborator_generate_payload", "collaborator_poll", "collaborator_server_info",
                "collaborator_get_secret", "collaborator_remove_client", "collaborator_default_payload",
            ),
            server.tools.keys.toSet()
        )
        assertEquals(emptySet<String>(), schema("collaborator_list_clients").keys)
        assertEquals(emptyList<String>(), server.tools.getValue("collaborator_list_clients").tool.inputSchema.required.orEmpty())
    }

    @Test
    fun `no parameter is named action, which the grouped tool keeps for dispatch`() {
        for ((name, tool) in server.tools) {
            assertFalse("action" in tool.tool.inputSchema.properties.orEmpty().keys, name)
        }
    }

    @Test
    fun `poll declares its closed and bounded parameters`() {
        val poll = schema("collaborator_poll")
        assertEquals(setOf("client_id", "type", "payload_id", "since", "limit", "max_body_length"), poll.keys)
        assertEquals(listOf("client_id"), server.tools.getValue("collaborator_poll").tool.inputSchema.required)

        val type = poll.getValue("type").jsonObject
        assertEquals(listOf("dns", "http", "smtp"), type.getValue("enum").jsonArray.map { it.jsonPrimitive.content })

        val since = poll.getValue("since").jsonObject
        assertEquals("integer", since.getValue("type").jsonPrimitive.content)
        assertEquals(0, since.getValue("minimum").jsonPrimitive.int)

        val limit = poll.getValue("limit").jsonObject
        assertEquals(1, limit.getValue("minimum").jsonPrimitive.int)
        assertEquals(1000, limit.getValue("maximum").jsonPrimitive.int)

        val maxBodyLength = poll.getValue("max_body_length").jsonObject
        assertEquals(1, maxBodyLength.getValue("minimum").jsonPrimitive.int)
        assertEquals(1_000_000, maxBodyLength.getValue("maximum").jsonPrimitive.int)
    }

    @Test
    fun `a missing or unusable client_id is reported by every tool that needs one`() {
        val tools = listOf(
            "collaborator_generate_payload", "collaborator_poll", "collaborator_server_info",
            "collaborator_get_secret", "collaborator_remove_client",
        )
        for (tool in tools) {
            assertEquals("Parameter 'client_id' is required", rejection(tool), tool)
            assertEquals("Parameter 'client_id' is required", rejection(tool) { put("client_id", "  ") }, tool)
            // an object where a string belongs must not surface as a cast failure
            assertEquals("Parameter 'client_id' is required", rejection(tool) { putJsonObject("client_id") { put("id", "x") } }, tool)
        }
        assertTrue("'secret_key' is required" in rejection("collaborator_restore_client"))
    }

    @Test
    fun `an unknown client is an isError result on every tool`() {
        for (tool in listOf("collaborator_generate_payload", "collaborator_poll", "collaborator_server_info", "collaborator_get_secret", "collaborator_remove_client")) {
            assertEquals("Client not found: collab-404", rejection(tool) { put("client_id", "collab-404") }, tool)
        }
    }

    @Test
    fun `poll rejects a type outside its enum`() {
        val message = rejection("collaborator_poll") { put("client_id", "collab-404"); put("type", "ftp") }
        assertEquals("Parameter 'type' has invalid value 'ftp'. Allowed: dns, http, smtp", message)
    }

    @Test
    fun `poll rejects numbers outside their bounds and values that are not integers`() {
        /** The rejection of a poll whose only fault is the argument [argument] adds. */
        fun poll(argument: JsonObjectBuilder.() -> Unit) = rejection("collaborator_poll") {
            put("client_id", "collab-404")
            argument()
        }

        assertEquals("Parameter 'since' must be a non-negative integer (got -1)", poll { put("since", -1) })
        assertTrue("'since' must be a non-negative integer" in poll { put("since", "yesterday") })
        assertTrue("'since' must be a non-negative integer" in poll { put("since", 1.5) })

        assertEquals("Parameter 'limit' must be between 1 and 1000 (got 0)", poll { put("limit", 0) })
        assertEquals("Parameter 'limit' must be between 1 and 1000 (got 1001)", poll { put("limit", 1001) })
        assertTrue("'limit' must be an integer" in poll { put("limit", "many") })

        assertEquals("Parameter 'max_body_length' must be between 1 and 1000000 (got 0)", poll { put("max_body_length", 0) })
        assertEquals(
            "Parameter 'max_body_length' must be between 1 and 1000000 (got 1000001)",
            poll { put("max_body_length", 1_000_001) }
        )
    }

    @Test
    fun `numbers sent as strings and JSON nulls get through to the bridge`() {
        // "Client not found" is the bridge speaking: the arguments were accepted
        val message = rejection("collaborator_poll") {
            put("client_id", "collab-404")
            put("since", "5")
            put("limit", "10")
            put("max_body_length", "2000")
            put("type", null as String?)
            put("payload_id", null as String?)
        }
        assertEquals("Client not found: collab-404", message)
    }

    @Test
    fun `a failure inside Burp is an isError result, not a thrown exception`() {
        assertTrue("Failed to create Collaborator client" in rejection("collaborator_create_client"))
        assertTrue("Failed to restore Collaborator client" in rejection("collaborator_restore_client") { put("secret_key", "c2VjcmV0") })
        assertNotEquals("", rejection("collaborator_default_payload") { put("without_server_location", "true") })
    }

    @Test
    fun `an error message with quotes and line breaks is still valid JSON`() {
        val clientId = "collab-\"1\"\n\\x"
        assertEquals("Client not found: $clientId", rejection("collaborator_get_secret") { put("client_id", clientId) })
    }

    @Test
    fun `listing with nothing registered is an empty list and not an error`() {
        val result = call("collaborator_list_clients")
        assertNotEquals(true, result.isError)
        val body = json(result)
        assertEquals(0, body.getValue("client_count").jsonPrimitive.int)
        assertTrue(body.getValue("clients").jsonArray.isEmpty())
    }
}
