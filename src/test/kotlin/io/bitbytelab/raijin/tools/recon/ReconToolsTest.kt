package io.bitbytelab.raijin.tools.recon

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.bridge.ReconBridge
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
import kotlinx.serialization.json.JsonElement
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

/**
 * The recon tool layer: bad arguments come back as `isError` results naming the problem, before
 * anything is sent. The bridge runs on a Montoya stand-in that fails any call, so a test that
 * reached Burp would show that error instead of the expected one.
 */
class ReconToolsTest {

    private val api = Proxy.newProxyInstance(MontoyaApi::class.java.classLoader, arrayOf(MontoyaApi::class.java)) { proxy, method, args ->
        when (method.name) {
            "hashCode" -> System.identityHashCode(proxy)
            "equals" -> proxy === args?.firstOrNull()
            "toString" -> "MontoyaApi"
            else -> error("unexpected Burp call MontoyaApi.${method.name}")
        }
    } as MontoyaApi

    private val bridge = ReconBridge(api)

    private val server = Server(
        Implementation("t", "0"),
        ServerOptions(ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false)))
    ).also { ReconTools.register(it, bridge) }

    private fun call(tool: String, args: JsonObject): CallToolResult = runBlocking {
        server.tools.getValue(tool).handler(testClientConnection, CallToolRequest(CallToolRequestParams(tool, args)))
    }

    private fun errorOf(result: CallToolResult): String {
        val text = (result.content.first() as TextContent).text
        assertEquals(true, result.isError, text)
        return Json.parseToJsonElement(text).jsonObject.getValue("error").jsonPrimitive.content
    }

    private fun assertRejected(tool: String, args: JsonObject, vararg fragments: String) {
        val message = errorOf(call(tool, args))
        assertTrue("unexpected Burp call" !in message, "$tool reached Burp: $message")
        fragments.forEach { assertTrue(it in message, "$tool: '$it' not in: $message") }
    }

    private fun properties(tool: String): JsonObject = server.tools.getValue(tool).tool.inputSchema.properties!!

    private fun enumOf(tool: String, parameter: String): List<String> =
        properties(tool).getValue(parameter).jsonObject.getValue("enum").jsonArray.map { it.jsonPrimitive.content }

    private fun mine(name: String, value: JsonElement): JsonObject = buildJsonObject {
        put("url", "https://t.example/")
        put(name, value)
    }

    private fun json(text: String): JsonElement = Json.parseToJsonElement(text)

    @Test
    fun `closed-value parameters carry their values in the schema`() {
        assertEquals(listOf("reflection", "diff", "both"), enumOf("recon_param_mine", "mode"))
        assertEquals(listOf("query", "body", "json_body", "cookie", "header"), enumOf("recon_param_mine", "inject_in"))
        assertEquals(listOf("param-miner-headers", "param-miner-params"), enumOf("recon_param_mine", "wordlist"))
    }

    @Test
    fun `numeric parameters carry their bounds in the schema`() {
        val mine = properties("recon_param_mine")
        for ((name, minimum) in listOf("offset" to 0, "limit" to 1, "bucket_size" to 1, "max_requests" to 20)) {
            val property = mine.getValue(name).jsonObject
            assertEquals("integer", property.getValue("type").jsonPrimitive.content, name)
            assertEquals(minimum, property.getValue("minimum").jsonPrimitive.int, name)
            assertTrue(property.getValue("maximum").jsonPrimitive.int > minimum, name)
        }
        assertEquals(ReconBridge.MAX_HISTORY_ITEMS, properties("recon_js_endpoints").getValue("max_items").jsonObject.getValue("maximum").jsonPrimitive.int)
    }

    @Test
    fun `no parameter is called action, the name tool groups dispatch on`() {
        for (tool in listOf("recon_js_endpoints", "recon_content_discovery", "recon_param_mine")) {
            assertTrue("action" !in properties(tool), tool)
        }
        assertEquals(setOf("url"), server.tools.getValue("recon_param_mine").tool.inputSchema.required.orEmpty().toSet())
        assertEquals(setOf("base_url", "paths"), server.tools.getValue("recon_content_discovery").tool.inputSchema.required.orEmpty().toSet())
    }

    @Test
    fun `unknown enum values are rejected with the allowed ones`() {
        assertRejected("recon_param_mine", mine("mode", json("\"sideways\"")), "'mode'", "sideways", "reflection")
        assertRejected("recon_param_mine", mine("inject_in", json("\"path\"")), "'inject_in'", "json_body")
        assertRejected("recon_param_mine", mine("wordlist", json("\"rockyou\"")), "'wordlist'", "param-miner-headers")
    }

    @Test
    fun `out-of-range and non-numeric numbers are rejected`() {
        assertRejected("recon_param_mine", mine("offset", json("-1")), "'offset'", "between 0 and")
        assertRejected("recon_param_mine", mine("limit", json("0")), "'limit'", "between 1 and")
        assertRejected("recon_param_mine", mine("bucket_size", json("0")), "'bucket_size'", "between 1 and 256")
        assertRejected("recon_param_mine", mine("bucket_size", json("999")), "'bucket_size'", "got 999")
        assertRejected("recon_param_mine", mine("max_requests", json("5")), "'max_requests'", "between 20 and 5000")
        assertRejected("recon_param_mine", mine("max_requests", json("\"many\"")), "'max_requests'", "integer")
        assertRejected("recon_js_endpoints", buildJsonObject { put("max_items", 0) }, "'max_items'", "between 1 and")
        assertRejected("recon_js_endpoints", buildJsonObject { put("max_items", 100000) }, "'max_items'")
    }

    @Test
    fun `malformed structured parameters are rejected`() {
        assertRejected("recon_param_mine", mine("headers", json("7")), "'headers'", "object")
        assertRejected("recon_param_mine", mine("cookies", json("7")), "'cookies'")
        assertRejected("recon_param_mine", mine("cache_buster", json("\"sometimes\"")), "'cache_buster'", "true or false")
        assertRejected("recon_js_endpoints", buildJsonObject { put("fetch_source_maps", "maybe") }, "'fetch_source_maps'")
        assertRejected("recon_js_endpoints", buildJsonObject { put("host_filter", "(") }, "host_filter")
    }

    @Test
    fun `missing required parameters are named`() {
        assertRejected("recon_param_mine", buildJsonObject { put("mode", "diff") }, "'url'")
        assertRejected("recon_content_discovery", buildJsonObject { putJsonArray("paths") { add("admin") } }, "'base_url'")
        assertRejected("recon_content_discovery", buildJsonObject { put("base_url", "https://t.example") }, "'paths'")
        assertRejected("recon_content_discovery", buildJsonObject { put("base_url", "https://t.example"); putJsonArray("paths") {} }, "'paths'", "at least one")
    }

    @Test
    fun `the bridge validates mode, location and wordlist itself`() {
        fun error(result: JsonObject) = result.getValue("error").jsonPrimitive.content
        assertTrue("'mode'" in error(bridge.paramMine("https://t.example/", listOf("a"), mode = "nope")))
        assertTrue("'inject_in'" in error(bridge.paramMine("https://t.example/", listOf("a"), injectIn = "path")))
        assertTrue("'inject_in'" in error(bridge.paramMine("https://t.example/", listOf("a"), injectIn = " ")))
    }
}
