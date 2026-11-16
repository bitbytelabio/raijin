package io.bitbytelab.raijin.tools.scanner

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.bridge.IntruderBridge
import io.bitbytelab.raijin.bridge.ScannerBridge
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.testClientConnection
import io.bitbytelab.raijin.tools.intruder.IntruderTools
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
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The scanner and Intruder tool layer: a bad argument comes back as an `isError` result that
 * names it, before Burp is asked for anything. The bridges run on a Montoya stand-in that fails
 * every call, so a test that reached Burp would show that failure instead.
 */
class ScannerToolsTest {

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
        ScannerTools.register(server, ScannerBridge(api, EventBus(), state), state)
        IntruderTools.register(server, IntruderBridge(api, state), state)
    }

    private fun call(tool: String, args: JsonObjectBuilder.() -> Unit = {}): CallToolResult = runBlocking {
        server.tools.getValue(tool).handler(testClientConnection, CallToolRequest(CallToolRequestParams(tool, buildJsonObject(args))))
    }

    private fun failure(tool: String, args: JsonObjectBuilder.() -> Unit = {}): String {
        val result = call(tool, args)
        val body = Json.parseToJsonElement((result.content.first() as TextContent).text).jsonObject
        assertEquals(true, result.isError, "$tool should have failed: $body")
        return body.getValue("error").jsonPrimitive.content
    }

    private fun enumOf(tool: String, parameter: String): List<String> {
        val schema = server.tools.getValue(tool).tool.inputSchema.properties?.get(parameter)?.jsonObject
        return assertNotNull(schema?.get("enum"), "$tool.$parameter has no enum").jsonArray.map { it.jsonPrimitive.content }
    }

    @Test
    fun `numbers outside their range are refused by name`() {
        // A limit past its range is clamped instead (ScannerToolLimitsTest); one that is not an integer is still refused.
        assertTrue(failure("scanner_start_crawl") {
            putJsonArray("urls") { add("https://t/") }; put("max_depth", "deep")
        }.startsWith("Parameter 'max_depth' must be an integer"))
        assertTrue(failure("scanner_get_all_issues") { put("max_results", 1.5) }.startsWith("Parameter 'max_results' must be an integer"))
        assertEquals("Parameter 'port' must be between 1 and 65535", failure("scanner_task_add_request") {
            put("task_id", "scan-001"); put("request", "R0VUIC8="); put("port", 70000)
        })
        assertEquals("Parameter 'port' must be an integer", failure("scanner_task_add_request") {
            put("task_id", "scan-001"); put("request", "R0VUIC8="); put("port", "https")
        })
        assertEquals("Parameter 'port' must be between 1 and 65535", failure("intruder_send") {
            put("request", "GET / HTTP/1.1\r\n\r\n"); put("host", "t"); put("port", 0)
        })
        assertEquals("position start (-3) must be >= 0", failure("intruder_send_with_positions") {
            put("request", "GET / HTTP/1.1\r\n\r\n"); put("host", "t"); put("port", 443)
            putJsonArray("positions") { add(buildJsonObject { put("start", -3); put("end", 2) }) }
        })
    }

    @Test
    fun `values outside a closed set are refused instead of silently meaning something else`() {
        assertTrue("severity" in failure("scanner_get_all_issues") { put("severity", "critical") })
        assertTrue("confidence" in failure("scanner_get_all_issues") { put("confidence", "sure") })
        // Used to produce an HTML report under a name ending in .pdf.
        assertTrue("format" in failure("scanner_generate_report") { put("output_path", "r.pdf"); put("format", "pdf") })
        assertTrue("audit_mode" in failure("scanner_start_audit") {
            putJsonArray("urls") { add("https://t/") }; put("audit_mode", "aggressive")
        })
        assertTrue("check_type" in failure("scanner_register_check") {
            put("check_name", "c"); put("issue_name", "i"); put("check_type", "hybrid"); put("passive_response_match", "x")
        })
        assertTrue("issue_severity" in failure("scanner_register_check") {
            put("check_name", "c"); put("issue_name", "i"); put("issue_severity", "urgent"); put("passive_response_match", "x")
        })
        assertTrue("transform_type" in failure("intruder_register_payload_processor") { put("name", "p"); put("transform_type", "rot13") })
    }

    @Test
    fun `an invalid regex is refused when the check or processor is registered`() {
        assertTrue(failure("scanner_register_check") {
            put("check_name", "c"); put("issue_name", "i"); put("passive_response_match", "([a-z")
        }.startsWith("Invalid passive_response_match regex:"))
        assertTrue(failure("scanner_register_check") {
            put("check_name", "c"); put("issue_name", "i"); put("check_type", "active")
            putJsonArray("active_payloads") { add("'") }; put("active_grep_match", "*")
        }.startsWith("Invalid active_response_match regex:"))
        assertTrue(failure("intruder_register_payload_processor") {
            put("name", "p"); put("transform_type", "regex_replace"); put("regex_pattern", "(?<x")
        }.startsWith("Invalid regex_pattern:"))
        assertEquals("regex_replace requires a non-empty regex_pattern", failure("intruder_register_payload_processor") {
            put("name", "p"); put("transform_type", "regex_replace")
        })
    }

    @Test
    fun `missing required arguments are named`() {
        assertEquals("At least one of 'urls' or 'requests' must be provided", failure("scanner_start_audit"))
        assertEquals("Parameter 'task_id' is required", failure("scanner_task_status"))
        assertEquals("Missing required parameter: port", failure("intruder_send") { put("request", "GET / HTTP/1.1\r\n\r\n"); put("host", "t") })
        assertEquals("Task not found: scan-404", failure("scanner_task_issues") { put("task_id", "scan-404") })
    }

    @Test
    fun `closed parameters list their values in the schema and none is called action`() {
        val severities = listOf("high", "medium", "low", "information")
        val confidences = listOf("certain", "firm", "tentative")
        assertEquals(listOf("light", "normal", "thorough"), enumOf("scanner_start_audit", "audit_mode"))
        assertEquals(listOf("passive", "active", "both"), enumOf("scanner_register_check", "check_type"))
        assertEquals(listOf("HTML", "XML"), enumOf("scanner_generate_report", "format"))
        assertEquals(severities, enumOf("scanner_register_check", "issue_severity"))
        assertEquals(confidences, enumOf("scanner_register_check", "issue_confidence"))
        // get_all_issues and create_issue are merged into one tool; their shared parameters must agree.
        for (tool in listOf("scanner_get_all_issues", "scanner_create_issue")) {
            assertEquals(severities, enumOf(tool, "severity"), tool)
            assertEquals(confidences, enumOf(tool, "confidence"), tool)
        }
        assertEquals(IntruderBridge.TRANSFORM_TYPES.toList(), enumOf("intruder_register_payload_processor", "transform_type"))
        for ((name, registered) in server.tools) {
            assertFalse(registered.tool.inputSchema.properties.orEmpty().containsKey("action"), name)
        }
    }
}
