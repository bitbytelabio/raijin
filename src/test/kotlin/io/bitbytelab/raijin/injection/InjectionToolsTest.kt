package io.bitbytelab.raijin.injection

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.bridge.InjectionBridge
import io.bitbytelab.raijin.testClientConnection
import io.bitbytelab.raijin.tools.injection.InjectionTools
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequestParams
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The `injection_probe` tool layer: class selection, the schema an agent sees, and argument
 * validation. Bad arguments must come back as an error naming the problem before Burp is touched;
 * the bridge here runs on a Montoya stand-in that fails any call.
 */
class InjectionToolsTest {

    private val request = "GET /item?id=FUZZ HTTP/1.1\r\nHost: t\r\n\r\n"

    private fun args(vararg extra: Pair<String, JsonElement>): Map<String, JsonElement> =
        mapOf<String, JsonElement>("request" to JsonPrimitive(request), "host" to JsonPrimitive("t")) + extra

    private fun rejected(vararg extra: Pair<String, JsonElement>): String =
        assertFailsWith<IllegalArgumentException> { InjectionTools.parseArguments(args(*extra)) }.message.orEmpty()

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
        InjectionTools.register(server, InjectionBridge(api))
    }

    // ---------------------------------------------------------------
    // Classes
    // ---------------------------------------------------------------

    @Test
    fun `no selection means every class, and a selection runs in a fixed order`() {
        assertEquals(InjectionClass.entries.toList(), InjectionClass.select(null).classes)
        assertEquals(InjectionClass.entries.toList(), InjectionClass.select(emptyList()).classes)
        val picked = InjectionClass.select(listOf(" XSS ", "sqli", "xss"))
        assertNull(picked.error)
        assertEquals(listOf(InjectionClass.SQLI, InjectionClass.XSS), picked.classes)
        assertEquals(listOf(InjectionClass.LFI), InjectionClass.select(listOf("traversal")).classes)
    }

    @Test
    fun `an unknown class is rejected with the list of valid ones`() {
        val selection = InjectionClass.select(listOf("sqli", "rce", "csrf"))
        assertTrue(selection.classes.isEmpty())
        val error = selection.error.orEmpty()
        assertTrue("'rce'" in error && "'csrf'" in error, error)
        InjectionClass.accepted.forEach { assertTrue(it in error, "$it missing from: $error") }
        assertEquals(InjectionClass.entries.map { it.id } + "traversal", InjectionClass.accepted)
    }

    // ---------------------------------------------------------------
    // Schema
    // ---------------------------------------------------------------

    @Test
    fun `the schema lists the allowed values of closed parameters and the numeric bounds`() {
        val tool = server.tools.getValue("injection_probe").tool
        val properties = tool.inputSchema.properties!!
        assertEquals(listOf("request", "host"), tool.inputSchema.required)
        assertEquals(
            InjectionClass.accepted,
            properties.getValue("classes").jsonObject.getValue("items").jsonObject.getValue("enum").jsonArray.map { it.jsonPrimitive.content },
        )
        assertEquals(
            listOf("auto", "raw", "url", "json", "xml"),
            properties.getValue("encoding").jsonObject.getValue("enum").jsonArray.map { it.jsonPrimitive.content },
        )
        val delay = properties.getValue("delay_seconds").jsonObject
        assertEquals(1, delay.getValue("minimum").jsonPrimitive.int)
        assertEquals(30, delay.getValue("maximum").jsonPrimitive.int)
        assertTrue("action" !in properties, "'action' is the dispatch parameter of the group tool")
        InjectionClass.entries.forEach { assertTrue(it.id in tool.description.orEmpty(), "${it.id} is not described") }
    }

    // ---------------------------------------------------------------
    // Arguments
    // ---------------------------------------------------------------

    @Test
    fun `defaults follow the port and the documented values`() {
        val parsed = InjectionTools.parseArguments(args())
        assertEquals(443, parsed.port)
        assertTrue(parsed.useTls)
        assertNull(parsed.classes)
        assertNull(parsed.encoding)
        assertEquals("1", parsed.baseValue)
        assertEquals(5, parsed.delaySeconds)
        assertTrue(parsed.oob)
        assertEquals(5, parsed.oobWaitSeconds)
        assertEquals(300, parsed.timeBudgetSeconds)

        val plain = InjectionTools.parseArguments(args("port" to JsonPrimitive(8080)))
        assertEquals(false, plain.useTls)
        assertTrue(InjectionTools.parseArguments(args("port" to JsonPrimitive(8443), "use_tls" to JsonPrimitive(true))).useTls)
    }

    @Test
    fun `given values are taken, in the forms clients send them`() {
        val parsed = InjectionTools.parseArguments(
            args(
                "classes" to buildJsonArray { add("sqli"); add("xss") },
                "encoding" to JsonPrimitive("RAW"),
                "base_value" to JsonPrimitive(""),
                "delay_seconds" to JsonPrimitive("12"),
                "oob" to JsonPrimitive(false),
                "oob_wait_seconds" to JsonPrimitive(0),
                "time_budget_seconds" to JsonPrimitive(60),
                "use_tls" to JsonNull,
            )
        )
        assertEquals(listOf("sqli", "xss"), parsed.classes)
        assertEquals("RAW", parsed.encoding)
        assertEquals("", parsed.baseValue)
        assertEquals(12, parsed.delaySeconds)
        assertEquals(false, parsed.oob)
        assertEquals(0, parsed.oobWaitSeconds)
        assertEquals(60, parsed.timeBudgetSeconds)
        assertTrue(parsed.useTls, "null is the same as absent")

        assertEquals(listOf("sqli", "lfi"), InjectionTools.parseArguments(args("classes" to JsonPrimitive("[\"sqli\",\"lfi\"]"))).classes)
    }

    @Test
    fun `missing, mistyped and out-of-range arguments are named`() {
        assertTrue("'request'" in assertFailsWith<IllegalArgumentException> { InjectionTools.parseArguments(mapOf("host" to JsonPrimitive("t"))) }.message.orEmpty())
        assertTrue("'host'" in rejected("host" to JsonPrimitive("  ")))
        assertTrue("between 1 and 65535" in rejected("port" to JsonPrimitive(70000)))
        assertTrue("'port' must be an integer" in rejected("port" to JsonPrimitive("https")))
        assertTrue("'delay_seconds' must be an integer" in rejected("delay_seconds" to JsonPrimitive("soon")))
        // Limits out of range are clamped (and reported on the result), not refused.
        val clamped = InjectionTools.parseArguments(
            args("delay_seconds" to JsonPrimitive(0), "oob_wait_seconds" to JsonPrimitive(600), "time_budget_seconds" to JsonPrimitive(1))
        )
        assertEquals(1, clamped.delaySeconds)
        assertEquals(60, clamped.oobWaitSeconds)
        assertEquals(10, clamped.timeBudgetSeconds)
        assertTrue(clamped.clamps.all { it.second?.clamped == true })
        assertTrue("'oob' must be true or false" in rejected("oob" to JsonPrimitive("maybe")))
        assertTrue("'base_value' must be a string" in rejected("base_value" to buildJsonObject { put("a", 1) }))

        val encoding = rejected("encoding" to JsonPrimitive("base64"))
        assertTrue("'encoding'" in encoding && "auto" in encoding && "raw" in encoding, encoding)
        val classes = rejected("classes" to buildJsonArray { add("sqli"); add("nope") })
        assertTrue("'nope'" in classes && "open_redirect" in classes, classes)
    }

    @Test
    fun `the tool returns bad arguments as an error result`() {
        val arguments = buildJsonObject {
            put("request", request)
            put("host", "t")
            put("classes", buildJsonArray { add("nope") })
        }
        val result = runBlocking {
            server.tools.getValue("injection_probe").handler(testClientConnection, CallToolRequest(CallToolRequestParams("injection_probe", arguments)))
        }
        assertEquals(true, result.isError)
        val body = Json.parseToJsonElement((result.content.first() as TextContent).text).jsonObject
        val error = body.getValue("error").jsonPrimitive.content
        assertTrue("'nope'" in error && "Allowed:" in error && "sqli" in error, error)
        assertEquals(setOf("error"), body.keys)
    }
}
