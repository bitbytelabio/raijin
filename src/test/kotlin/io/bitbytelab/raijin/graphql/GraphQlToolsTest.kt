package io.bitbytelab.raijin.graphql

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.bridge.GraphQlBridge
import io.bitbytelab.raijin.graphql.scanners.POIScanner
import io.bitbytelab.raijin.testClientConnection
import io.bitbytelab.raijin.tools.graphql.GraphQlTools
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
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.junit.jupiter.api.Timeout
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The `graphql_probe` tool against a Montoya API whose every call returns null: nothing can be
 * sent, so every request-sending mode sees a target that does not answer, which is exactly what
 * the argument handling and the unreachable-target paths need.
 */
class GraphQlToolsTest {

    private val server: Server = Server(
        Implementation("test", "0"),
        ServerOptions(ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false)))
    ).also { server ->
        val api = Proxy.newProxyInstance(MontoyaApi::class.java.classLoader, arrayOf(MontoyaApi::class.java)) { _, _, _ -> null } as MontoyaApi
        GraphQlTools.register(server, GraphQlBridge(api))
    }

    private fun call(args: JsonObject): CallToolResult = runBlocking {
        server.tools.getValue("graphql_probe").handler(testClientConnection, CallToolRequest(CallToolRequestParams("graphql_probe", args)))
    }

    private fun call(vararg args: Pair<String, Any>): CallToolResult = call(
        buildJsonObject {
            for ((name, value) in args) {
                when (value) {
                    is String -> put(name, value)
                    is Number -> put(name, value)
                    is Boolean -> put(name, value)
                    is List<*> -> putJsonArray(name) { value.forEach { add(it.toString()) } }
                    else -> error("unsupported argument type for $name")
                }
            }
        }
    )

    private fun json(result: CallToolResult): JsonObject =
        Json.parseToJsonElement((result.content.first() as TextContent).text).jsonObject

    private fun errorOf(result: CallToolResult): String {
        assertEquals(true, result.isError)
        return json(result).getValue("error").jsonPrimitive.content
    }

    private val url = "https://target.example/graphql"

    @Test
    fun `the schema declares the modes, categories and numeric bounds`() {
        val properties = server.tools.getValue("graphql_probe").tool.inputSchema.properties!!
        val modes = properties.getValue("mode").jsonObject.getValue("enum").jsonArray.map { it.jsonPrimitive.content }
        assertEquals(
            listOf(
                "probe", "query_templates", "poi_scan", "cycles_scan", "batch_attack", "fingerprint_engine",
                "bruteforce_schema", "subscription_probe",
            ),
            modes,
        )
        // Every mode is described where an agent reads about the parameter.
        val modeDescription = properties.getValue("mode").jsonObject.getValue("description").jsonPrimitive.content
        modes.forEach { assertTrue(it in modeDescription, "mode $it missing from: $modeDescription") }

        val categories = properties.getValue("categories").jsonObject.getValue("items").jsonObject.getValue("enum").jsonArray
        assertEquals(POIScanner.availableCategories(), categories.map { it.jsonPrimitive.content }.toSet())

        for ((name, min, max) in listOf(
            Triple("max_depth", 0, 20), Triple("bucket_size", 1, 500), Triple("depth_limit", 0, 10),
            Triple("max_requests", 1, 100_000), Triple("wait_ms", 250, 30_000),
        )) {
            val property = properties.getValue(name).jsonObject
            assertEquals(min, property.getValue("minimum").jsonPrimitive.int, name)
            assertEquals(max, property.getValue("maximum").jsonPrimitive.int, name)
        }
        assertFalse("action" in properties, "'action' is the dispatch parameter of the consolidated tool")
    }

    @Test
    fun `url is required and mode must be one of the declared values`() {
        assertEquals("Parameter 'url' is required", errorOf(call()))
        assertEquals("Parameter 'url' is required", errorOf(call("url" to "  ")))

        val message = errorOf(call("url" to url, "mode" to "subscriptions"))
        assertTrue("invalid value 'subscriptions'" in message, message)
        assertTrue("subscription_probe" in message && "bruteforce_schema" in message, message)
    }

    @Test
    @Timeout(60)
    fun `an unreachable target is one clear error in every request-sending mode`() {
        for (mode in listOf(null, "probe", "query_templates", "poi_scan", "cycles_scan", "fingerprint_engine", "bruteforce_schema")) {
            val result = if (mode == null) call("url" to url) else call("url" to url, "mode" to mode)
            val message = errorOf(result)
            assertTrue("Could not reach $url" in message, "$mode: $message")
        }
        val sent = errorOf(call("url" to url, "mode" to "batch_attack", "template" to "query { \$[INT:0:2] node(id: \$INT) { id } }", "send" to true))
        assertTrue("Could not reach $url" in sent, sent)

        val socket = errorOf(call("url" to url, "mode" to "subscription_probe"))
        assertTrue("Could not open a WebSocket to wss://target.example/graphql" in socket, socket)
    }

    @Test
    fun `batch_attack generates without sending, and reports its limits as errors`() {
        val template = "query { \$[INT:0:3] node(id: \"\$INT\") { id } }"
        val generated = call("url" to url, "mode" to "batch_attack", "template" to template)
        assertNull(generated.isError?.takeIf { it })
        assertEquals(3, json(generated).getValue("operations_generated").jsonPrimitive.int)
        assertTrue("op2:" in json(generated).getValue("query").jsonPrimitive.content)

        assertEquals("Parameter 'template' is required for mode=batch_attack", errorOf(call("url" to url, "mode" to "batch_attack")))

        val tooMany = errorOf(call("url" to url, "mode" to "batch_attack", "template" to "query { \$[INT:0:2000000000] node(id: \$INT) { id } }"))
        assertTrue("2000000000 sub-operations" in tooMany && "limit is ${BatchAttack.MAX_OPERATIONS}" in tooMany, tooMany)

        val noValues = errorOf(call("url" to url, "mode" to "batch_attack", "template" to "query { \$[LIST] node(id: \"\$LIST\") { id } }"))
        assertTrue("'values' is empty" in noValues, noValues)

        val noPlaceholder = errorOf(call("url" to url, "mode" to "batch_attack", "template" to "query { node { id } }"))
        assertTrue("placeholder" in noPlaceholder, noPlaceholder)

        val listed = call(
            "url" to url, "mode" to "batch_attack",
            "template" to "query { \$[LIST] node(id: \"\$LIST\") { id } }", "values" to listOf("a", "b"),
        )
        assertEquals(2, json(listed).getValue("operations_generated").jsonPrimitive.int)
    }

    @Test
    fun `numeric arguments outside their bounds are refused with the parameter named`() {
        val cases = listOf(
            Triple("query_templates", "max_depth", 21),
            Triple("query_templates", "max_depth", -1),
            Triple("bruteforce_schema", "bucket_size", 0),
            Triple("bruteforce_schema", "bucket_size", 501),
            Triple("bruteforce_schema", "depth_limit", 11),
            Triple("bruteforce_schema", "max_requests", 0),
            Triple("bruteforce_schema", "max_requests", 100_001),
            Triple("subscription_probe", "wait_ms", 100),
            Triple("subscription_probe", "wait_ms", 60_000),
        )
        for ((mode, parameter, value) in cases) {
            val message = errorOf(call("url" to url, "mode" to mode, parameter to value))
            assertTrue("'$parameter'" in message && "between" in message, "$mode $parameter=$value: $message")
        }
        val notANumber = errorOf(call("url" to url, "mode" to "bruteforce_schema", "bucket_size" to "many"))
        assertTrue("'bucket_size' must be an integer" in notANumber, notANumber)
    }

    @Test
    fun `poi_scan refuses a category that does not exist`() {
        val message = errorOf(call("url" to url, "mode" to "poi_scan", "categories" to listOf("auth", "secrets")))
        assertTrue("invalid value 'secrets'" in message, message)
        assertTrue("privileged" in message, message)

        // Valid categories, in any case, get as far as the (unreachable) target.
        val reached = errorOf(call("url" to url, "mode" to "poi_scan", "categories" to listOf("AUTH", "pii")))
        assertTrue("Could not reach" in reached, reached)
    }

    @Test
    fun `subscription_probe validates its url and connection payload`() {
        val scheme = errorOf(call("url" to "ftp://target.example/graphql", "mode" to "subscription_probe"))
        assertTrue("Unsupported scheme" in scheme, scheme)

        val payload = errorOf(call("url" to url, "mode" to "subscription_probe", "connection_payload" to "Bearer abc"))
        assertEquals("Parameter 'connection_payload' must be a JSON object", payload)

        // An object, also when it arrives as a JSON string, is accepted and the probe goes on to the target.
        val asObject = call(buildJsonObject {
            put("url", "ws://target.example/subscriptions")
            put("mode", "subscription_probe")
            putJsonObject("connection_payload") { put("Authorization", "Bearer abc") }
        })
        assertTrue("Could not open a WebSocket to ws://target.example/subscriptions" in errorOf(asObject))
        val asString = call("url" to url, "mode" to "subscription_probe", "connection_payload" to """{"Authorization":"Bearer abc"}""")
        assertTrue("Could not open a WebSocket" in errorOf(asString))
    }

    @Test
    fun `headers that cannot be parsed are reported next to the result`() {
        val result = call("url" to url, "mode" to "batch_attack", "template" to "query { \$[INT:0:2] node(id: \$INT) { id } }", "headers" to "not headers")
        val body = json(result)
        assertEquals(2, body.getValue("operations_generated").jsonPrimitive.int)
        assertTrue(body.getValue("headers_warning").jsonPrimitive.content.isNotBlank())
    }

    @Test
    fun `an error result is valid JSON flagged as an error`() {
        val result = call("url" to "https://target.example/gra\"ph\\ql", "mode" to "probe")
        assertEquals(true, result.isError)
        val body = json(result)
        assertTrue("https://target.example/gra\"ph\\ql" in body.getValue("error").jsonPrimitive.content)
        assertTrue(body.getValue("unreachable").jsonPrimitive.boolean)
    }
}
