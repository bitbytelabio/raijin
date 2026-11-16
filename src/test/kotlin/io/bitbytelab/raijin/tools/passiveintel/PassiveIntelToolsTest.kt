package io.bitbytelab.raijin.tools.passiveintel

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.bridge.PassiveIntelBridge
import io.bitbytelab.raijin.recon.SecretPatterns
import io.bitbytelab.raijin.testClientConnection
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
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The passive-intel tool layer: bad arguments are answered before proxy history is read. */
class PassiveIntelToolsTest {

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
        PassiveIntelTools.register(server, PassiveIntelBridge(api))
    }

    private val tool = server.tools.getValue("passive_intel")

    private fun call(args: JsonObject): CallToolResult = runBlocking {
        tool.handler(testClientConnection, CallToolRequest(CallToolRequestParams("passive_intel", args)))
    }

    private fun assertRejected(args: JsonObject, vararg fragments: String) {
        val result = call(args)
        val text = (result.content.first() as TextContent).text
        assertEquals(true, result.isError, text)
        val message = Json.parseToJsonElement(text).jsonObject.getValue("error").jsonPrimitive.content
        assertTrue("unexpected Burp call" !in message, "reached Burp: $message")
        fragments.forEach { assertTrue(it in message, "'$it' not in: $message") }
    }

    @Test
    fun `the schema lists the categories that exist and bounds max_items`() {
        val properties = tool.tool.inputSchema.properties!!
        val categories = properties.getValue("categories").jsonObject.getValue("items").jsonObject.getValue("enum").jsonArray.map { it.jsonPrimitive.content }
        assertEquals(SecretPatterns.ALL.keys.toList(), categories)
        assertTrue("debug_info" !in categories && "heroku_api_key" !in categories)
        assertEquals(1, properties.getValue("max_items").jsonObject.getValue("minimum").jsonPrimitive.int)
        assertTrue("action" !in properties)
    }

    @Test
    fun `the description names what is scanned for now, not what was dropped`() {
        val description = tool.tool.description.orEmpty()
        for (name in listOf("github_fine_grained_token", "gitlab_token", "openai_api_key", "anthropic_api_key", "source_map_url")) {
            assertTrue(name in description, name)
        }
        assertTrue("debug_info" !in description && "heroku_api_key" !in description)
    }

    @Test
    fun `out-of-range and non-numeric max_items are rejected`() {
        assertRejected(buildJsonObject { put("max_items", 0) }, "'max_items'", "between 1 and")
        assertRejected(buildJsonObject { put("max_items", -5) }, "'max_items'")
        assertRejected(buildJsonObject { put("max_items", "all") }, "'max_items'", "integer")
    }

    @Test
    fun `a category that does not exist is an error naming the ones that do`() {
        assertRejected(buildJsonObject { putJsonArray("categories") { add("jwt_token"); add("debug_info") } }, "Unknown categories: debug_info", "jwt_token", "source_map_url")
        assertRejected(buildJsonObject { putJsonArray("categories") { add("heroku_api_key") } }, "heroku_api_key")
    }

    @Test
    fun `an invalid host filter is rejected before history is read`() {
        assertRejected(buildJsonObject { put("host_filter", "(") }, "host_filter")
    }
}
