package io.bitbytelab.raijin.tools.http

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.bridge.HttpBridge
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.state.StateManager
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
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The HTTP tool layer: bad arguments come back as `isError` results naming the problem, before
 * anything is sent. The bridge runs on a Montoya stand-in that fails any call, so a test that
 * reached Burp would show that error instead of the expected one.
 */
class HttpToolsTest {

    private val state = StateManager()

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
        HttpTools.register(server, HttpBridge(api, EventBus(), state), state)
    }

    private fun call(tool: String, args: JsonObject): CallToolResult = runBlocking {
        server.tools.getValue(tool).handler(testClientConnection, CallToolRequest(CallToolRequestParams(tool, args)))
    }

    private fun json(result: CallToolResult): JsonObject =
        Json.parseToJsonElement((result.content.first() as TextContent).text).jsonObject

    private fun errorOf(result: CallToolResult): String {
        assertEquals(true, result.isError, (result.content.first() as TextContent).text)
        return json(result).getValue("error").jsonPrimitive.content
    }

    private fun assertRejected(tool: String, args: JsonObject, vararg fragments: String) {
        val message = errorOf(call(tool, args))
        fragments.forEach { assertTrue(it in message, "$tool: '$it' not in: $message") }
    }

    @Test
    fun `out-of-range numbers and unknown enum values are rejected`() {
        val fuzz = buildJsonObject { put("request", "GET /?q=FUZZ HTTP/1.1\r\n\r\n"); put("host", "h"); putJsonArray("payloads") { add("x") } }
        assertRejected("http_fuzz", JsonObject(fuzz + ("port" to Json.parseToJsonElement("70000"))), "'port'", "1 and 65535")
        assertRejected("http_race", buildJsonObject { put("request", "GET / HTTP/1.1\r\n\r\n"); put("host", "h"); put("count", 0) }, "'count'")
        assertRejected("http_send_request", buildJsonObject { put("url", "https://h/"); put("http_mode", "HTTP_3") }, "'http_mode'", "HTTP_2_IGNORE_ALPN")
        assertRejected("http_send_request", buildJsonObject { put("url", "https://h/"); put("timeout_ms", 0) }, "'timeout_ms'")
        val pipeline = buildJsonObject {
            put("host", "h")
            putJsonArray("requests") { add(buildJsonObject { put("raw_request", "GET / HTTP/1.1\r\n\r\n") }) }
        }
        assertRejected("http_send_pipeline", JsonObject(pipeline + ("write_mode" to Json.parseToJsonElement("\"burst\""))), "'write_mode'", "concat, single_write")
        assertRejected("http_send_pipeline", JsonObject(pipeline + ("max_responses" to Json.parseToJsonElement("0"))), "'max_responses'")
        assertRejected("http_send_pipeline", JsonObject(pipeline + ("http_mode" to Json.parseToJsonElement("\"HTTP_2\""))), "'http_mode'")
    }

    @Test
    fun `fuzz rejects malformed positions, stop conditions and payload libraries`() {
        fun fuzz(extra: JsonObject.() -> JsonObject) = buildJsonObject {
            put("request", "GET /?q=§a§ HTTP/1.1\r\n\r\n"); put("host", "h"); putJsonArray("payloads") { add("x") }
        }.extra()
        assertRejected("http_fuzz", fuzz { JsonObject(this + ("positions" to Json.parseToJsonElement("[[1]]"))) }, "positions[0]")
        assertRejected("http_fuzz", fuzz { JsonObject(this + ("stop_on_match" to Json.parseToJsonElement("""{"status_codes":["x"]}"""))) }, "status_codes")
        assertRejected("http_fuzz", fuzz { JsonObject(this + ("stop_on_match" to Json.parseToJsonElement("""{"body_regex":"("}"""))) }, "body_regex")
        assertRejected("http_fuzz", fuzz { JsonObject(this + ("payload_library" to Json.parseToJsonElement("\"nope\""))) }, "'payload_library'", "sqli")
    }

    @Test
    fun `traffic rules validate patterns and headers and keep a tool filter`() {
        fun rule(extra: JsonObject) = JsonObject(buildJsonObject { put("direction", "request") } + extra)
        assertRejected("http_set_traffic_rule", rule(buildJsonObject { put("match_url", "[") }), "'match_url'", "regex")
        assertRejected("http_set_traffic_rule", rule(buildJsonObject { put("modify_add_header", "no colon") }), "'modify_add_header'")
        assertRejected("http_set_traffic_rule", rule(buildJsonObject { putJsonObject("modify_replace_header") { put("X-A", "a\r\nInjected: 1") } }), "modify_replace_header")
        assertRejected("http_set_traffic_rule", rule(buildJsonObject { putJsonArray("tool_filter") { add("NOPE") } }), "unknown tool", "EXTENSIONS")
        assertRejected("http_set_traffic_rule", rule(buildJsonObject { put("action", "drop"); put("direction", "response") }), "direction=request")

        val set = call("http_set_traffic_rule", rule(buildJsonObject {
            put("rule_id", "probe-tag")
            put("modify_add_header", "X-Probe: 1")
            putJsonArray("tool_filter") { add("extensions") }
        }))
        assertFalse(set.isError == true, (set.content.first() as TextContent).text)
        assertEquals(setOf("EXTENSIONS"), state.trafficRules.single { it.ruleId == "probe-tag" }.toolFilter)

        val listed = json(call("http_list_traffic_rules", buildJsonObject {})).getValue("rules").jsonArray
            .single { it.jsonObject.getValue("rule_id").jsonPrimitive.content == "probe-tag" }.jsonObject
        assertEquals("modify", listed.getValue("action").jsonPrimitive.content)
        assertEquals(listOf("EXTENSIONS"), listed.getValue("tool_filter").jsonArray.map { it.jsonPrimitive.content })
    }

    @Test
    fun `chain rejects a bad extract regex before sending the step`() {
        val result = call("http_send_request_chain", buildJsonObject {
            putJsonArray("steps") {
                add(buildJsonObject {
                    put("url", "https://h/")
                    putJsonArray("extract") { add(buildJsonObject { put("name", "t"); put("pattern", "(") }) }
                })
            }
        })
        val step = json(result).getValue("steps").jsonArray.single().jsonObject
        assertEquals(false, step.getValue("success").jsonPrimitive.boolean)
        assertTrue("extract[0].pattern is not a valid regex" in step.getValue("error").jsonPrimitive.content, step.toString())
    }

    @Test
    fun `malformed raw bytes and a bad cookie expiration come back as errors`() {
        assertRejected("http_send_raw_bytes", buildJsonObject { put("host", "h"); put("raw_request_hex", "474") }, "odd number of digits")
        assertRejected(
            "http_cookie_jar_set",
            buildJsonObject { put("name", "n"); put("value", "v"); put("domain", "h"); put("expiration", "tomorrow") },
            "ISO-8601"
        )
        assertRejected("http_send_requests_parallel", buildJsonObject { putJsonArray("requests") { add("not an object") } }, "'requests'")
    }

    @Test
    fun `closed parameters publish their allowed values`() {
        fun enumOf(tool: String, param: String) = server.tools.getValue(tool).tool.inputSchema.properties!!
            .getValue(param).jsonObject.getValue("enum").jsonArray.map { it.jsonPrimitive.content }
        assertEquals(listOf("AUTO", "HTTP_1", "HTTP_2", "HTTP_2_IGNORE_ALPN"), enumOf("http_send_request", "http_mode"))
        assertEquals(listOf("concat", "single_write"), enumOf("http_send_pipeline", "write_mode"))
        assertEquals(listOf("modify", "drop", "spoof_response"), enumOf("http_set_traffic_rule", "action"))
        val toolFilterItems = server.tools.getValue("http_set_traffic_rule").tool.inputSchema.properties!!
            .getValue("tool_filter").jsonObject.getValue("items").jsonObject.getValue("enum").jsonArray.map { it.jsonPrimitive.content }
        assertTrue("EXTENSIONS" in toolFilterItems && "SCANNER" in toolFilterItems, toolFilterItems.toString())
    }
}
