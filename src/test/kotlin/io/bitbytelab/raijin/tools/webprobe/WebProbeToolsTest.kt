package io.bitbytelab.raijin.tools.webprobe

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.bridge.WebProbeBridge
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

/** The web-probe tool layer: bad arguments are answered before Burp is asked for anything. */
class WebProbeToolsTest {

    private val api = Proxy.newProxyInstance(MontoyaApi::class.java.classLoader, arrayOf(MontoyaApi::class.java)) { proxy, method, args ->
        when (method.name) {
            "hashCode" -> System.identityHashCode(proxy)
            "equals" -> proxy === args?.firstOrNull()
            "toString" -> "MontoyaApi"
            else -> error("unexpected Burp call MontoyaApi.${method.name}")
        }
    } as MontoyaApi

    private val bridge = WebProbeBridge(api)

    private val server = Server(
        Implementation("t", "0"),
        ServerOptions(ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false)))
    ).also { WebProbeTools.register(it, bridge) }

    private fun call(tool: String, args: JsonObject): CallToolResult = runBlocking {
        server.tools.getValue(tool).handler(testClientConnection, CallToolRequest(CallToolRequestParams(tool, args)))
    }

    private fun assertRejected(tool: String, args: JsonObject, vararg fragments: String) {
        val result = call(tool, args)
        val text = (result.content.first() as TextContent).text
        assertEquals(true, result.isError, text)
        val message = Json.parseToJsonElement(text).jsonObject.getValue("error").jsonPrimitive.content
        assertTrue("unexpected Burp call" !in message, "$tool reached Burp: $message")
        fragments.forEach { assertTrue(it in message, "$tool: '$it' not in: $message") }
    }

    @Test
    fun `the three tools are registered and none has a parameter called action`() {
        assertEquals(setOf("cors_probe", "cache_probe", "recon_fingerprint"), server.tools.keys)
        for (tool in server.tools.values) {
            assertTrue("action" !in tool.tool.inputSchema.properties!!, tool.tool.name)
            assertEquals(listOf("url"), tool.tool.inputSchema.required)
        }
    }

    @Test
    fun `cache_probe names its checks and bounds its budget in the schema`() {
        val properties = server.tools.getValue("cache_probe").tool.inputSchema.properties!!
        assertEquals(setOf("url", "checks", "headers", "probe_headers", "probe_cookies", "max_requests"), properties.keys)
        val checks = properties.getValue("checks").jsonObject
        assertEquals("array", checks.getValue("type").jsonPrimitive.content)
        assertEquals(listOf("poisoning", "deception"), checks.getValue("items").jsonObject.getValue("enum").jsonArray.map { it.jsonPrimitive.content })
        val budget = properties.getValue("max_requests").jsonObject
        assertEquals(20, budget.getValue("minimum").jsonPrimitive.int)
        assertEquals(1000, budget.getValue("maximum").jsonPrimitive.int)
    }

    @Test
    fun `cache_probe rejects unknown checks, a budget out of range and malformed headers`() {
        fun args(extra: JsonObject) = JsonObject(buildJsonObject { put("url", "https://t.example/") } + extra)
        assertRejected("cache_probe", args(buildJsonObject { putJsonArray("checks") { add("poisoning"); add("xss") } }), "'checks'", "xss", "deception")
        assertRejected("cache_probe", args(buildJsonObject { put("max_requests", 5) }), "'max_requests'", "between 20 and 1000")
        assertRejected("cache_probe", args(buildJsonObject { put("max_requests", 100000) }), "'max_requests'")
        assertRejected("cache_probe", args(buildJsonObject { put("headers", 3) }), "'headers'", "object")
    }

    @Test
    fun `a missing url is named by every tool`() {
        for (tool in listOf("cors_probe", "cache_probe", "recon_fingerprint")) {
            assertRejected(tool, buildJsonObject {}, "'url'")
        }
    }

    @Test
    fun `the bridge rejects an unknown check itself`() {
        val result = bridge.cacheProbe("https://t.example/", checks = listOf("everything"))
        assertTrue("'checks'" in result.getValue("error").jsonPrimitive.content)
    }
}
