package io.bitbytelab.raijin.tools.scancheck

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import io.bitbytelab.raijin.bridge.BCheckBridge
import io.bitbytelab.raijin.bridge.BambdaBridge
import io.bitbytelab.raijin.bridge.ScanCheckBridge
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.testClientConnection
import io.bitbytelab.raijin.tools.bambda.BambdaTools
import io.bitbytelab.raijin.tools.bcheck.BCheckTools
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
import kotlinx.serialization.json.addJsonObject
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
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** A [T] whose calls go to [handler] (method name, arguments); an unexpected call fails the test. */
private inline fun <reified T : Any> fake(noinline handler: (String, Array<out Any?>) -> Any?): T =
    Proxy.newProxyInstance(T::class.java.classLoader, arrayOf(T::class.java)) { proxy, method, args ->
        when (method.name) {
            "toString" -> "fake ${T::class.simpleName}"
            "hashCode" -> System.identityHashCode(proxy)
            "equals" -> proxy === args?.firstOrNull()
            else -> handler(method.name, args ?: emptyArray<Any?>())
        }
    } as T

private fun headers(vararg pairs: Pair<String, String>): List<HttpHeader> = pairs.map { (name, value) ->
    fake<HttpHeader> { m, _ ->
        when (m) {
            "name" -> name
            "value" -> value
            else -> error("unexpected HttpHeader.$m")
        }
    }
}

/** One proxy history entry as Burp hands it out. A null [responseBody] never got a response. */
private fun historyEntry(
    id: Int,
    url: String,
    responseBody: String?,
    status: Int = 200,
    inScope: Boolean = true,
): ProxyHttpRequestResponse {
    val host = url.substringAfter("://").substringBefore('/')
    val request = fake<HttpRequest> { m, _ ->
        when (m) {
            "url" -> url
            "method" -> "GET"
            "isInScope" -> inScope
            "httpService" -> fake<HttpService> { sm, _ -> if (sm == "host") host else error("unexpected HttpService.$sm") }
            "pathWithoutQuery" -> "/" + url.substringAfter("://").substringAfter('/', "").substringBefore('?')
            "headers" -> headers("Host" to host)
            "bodyToString" -> ""
            else -> error("unexpected HttpRequest.$m")
        }
    }
    val response = responseBody?.let { body ->
        fake<HttpResponse> { m, _ ->
            when (m) {
                "statusCode" -> status.toShort()
                "headers" -> headers("Content-Type" to "text/html")
                "bodyToString" -> body
                "body" -> fake<BurpByteArray> { bm, _ -> if (bm == "length") body.length else error("unexpected ByteArray.$bm") }
                else -> error("unexpected HttpResponse.$m")
            }
        }
    }
    return fake { m, _ ->
        when (m) {
            "id" -> id
            "finalRequest" -> request
            "hasResponse" -> response != null
            "originalResponse" -> response
            else -> error("unexpected ProxyHttpRequestResponse.$m")
        }
    }
}

/**
 * The custom-check tools an agent calls before a large scan: the two dry runs read a stand-in
 * proxy history and must not touch anything else in Burp, and `bambda_templates` needs no Burp
 * at all. Any other Burp call fails the test.
 */
class CustomCheckToolsTest {

    /** Oldest first, as Burp returns its history. */
    private val history = listOf(
        historyEntry(1, "https://shop.example/index.html", "welcome"),
        historyEntry(2, "https://shop.example/static/app.js?v=3", "const key = 'AKIAIOSFODNN7EXAMPLE';"),
        historyEntry(3, "https://cdn.example/lib.js", "AKIAIOSFODNN7EXAMPLE again", inScope = false),
        historyEntry(4, "https://shop.example/search?q=a", "No results for your query"),
        historyEntry(5, "https://shop.example/slow", null),
    )

    private val api: MontoyaApi = fake { m, _ ->
        check(m == "proxy") { "a dry run may only read the proxy history, not MontoyaApi.$m" }
        fake<burp.api.montoya.proxy.Proxy> { pm, pa ->
            check(pm == "history" && pa.isEmpty()) { "unexpected Proxy.$pm" }
            history
        }
    }

    private val server = Server(
        Implementation("t", "0"),
        ServerOptions(ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false)))
    ).also { server ->
        val state = StateManager()
        ScanCheckTools.register(server, ScanCheckBridge(api, state))
        BCheckTools.register(server, BCheckBridge(api, state))
        BambdaTools.register(server, BambdaBridge(api))
    }

    private fun call(tool: String, args: JsonObjectBuilder.() -> Unit = {}): CallToolResult = runBlocking {
        server.tools.getValue(tool).handler(testClientConnection, CallToolRequest(CallToolRequestParams(tool, buildJsonObject(args))))
    }

    private fun CallToolResult.json(): JsonObject = Json.parseToJsonElement((content.first() as TextContent).text).jsonObject

    private fun ok(tool: String, args: JsonObjectBuilder.() -> Unit = {}): JsonObject {
        val result = call(tool, args)
        assertFalse(result.isError == true, "$tool failed: ${result.json()}")
        return result.json()
    }

    private fun failure(tool: String, args: JsonObjectBuilder.() -> Unit = {}): String {
        val result = call(tool, args)
        assertEquals(true, result.isError, "$tool should have failed: ${result.json()}")
        return result.json().getValue("error").jsonPrimitive.content
    }

    private fun JsonObject.int(key: String): Int = getValue(key).jsonPrimitive.int

    private fun JsonObject.urls(key: String): List<String> =
        getValue(key).jsonArray.map { it.jsonObject.getValue("url").jsonPrimitive.content }

    private fun JsonObjectBuilder.keyCondition() = putJsonArray("conditions") {
        addJsonObject {
            put("location", "response_body")
            put("pattern", "AKIA[0-9A-Z]{16}")
        }
    }

    // ---- scancheck_dry_run ----------------------------------------------------

    @Test
    fun `a passive scan check is tried against the recorded history, newest first`() {
        val result = ok("scancheck_dry_run") { keyCondition() }

        assertEquals(0, result.int("requests_sent"))
        assertEquals(5, result.int("history_size"))
        assertEquals(5, result.int("items_evaluated"))
        assertEquals(1, result.int("items_without_response"))
        assertEquals(2, result.int("would_report"))
        assertEquals(listOf("https://cdn.example/lib.js", "https://shop.example/static/app.js?v=3"), result.urls("matches"))
    }

    @Test
    fun `the history a dry run reads can be narrowed`() {
        assertEquals(
            listOf("https://shop.example/static/app.js?v=3"),
            ok("scancheck_dry_run") { keyCondition(); put("in_scope_only", true) }.urls("matches"),
        )
        assertEquals(
            listOf("https://cdn.example/lib.js"),
            ok("scancheck_dry_run") { keyCondition(); put("url_pattern", "^https://cdn\\.") }.urls("matches"),
        )
        val newestTwo = ok("scancheck_dry_run") { keyCondition(); put("max_items", 2) }
        assertEquals(2, newestTwo.int("items_evaluated"))
        assertEquals(0, newestTwo.int("would_report"), "the two newest items do not leak the key")
    }

    @Test
    fun `an active scan check shows what the baseline already matches without sending`() {
        val result = ok("scancheck_dry_run") {
            putJsonArray("steps") {
                addJsonObject {
                    put("payload", "'")
                    putJsonArray("response_conditions") {
                        addJsonObject { put("location", "response_body"); put("pattern", "(?i)query|database") }
                    }
                }
            }
        }
        assertEquals("active", result.getValue("check").jsonPrimitive.content)
        assertEquals(0, result.int("requests_sent"))
        val step = result.getValue("steps").jsonArray.single().jsonObject
        assertEquals(1, step.int("baseline_matches"))
        assertEquals(listOf("https://shop.example/search?q=a"), step.urls("baseline_examples"))
    }

    @Test
    fun `a dry run with a definition that could not be deployed fails the same way deploying would`() {
        assertTrue("conditions" in failure("scancheck_dry_run"))
        assertTrue("Invalid regex in conditions[0].pattern" in failure("scancheck_dry_run") {
            putJsonArray("conditions") { addJsonObject { put("location", "response_body"); put("pattern", "([a-z") } }
        })
        assertTrue("location" in failure("scancheck_dry_run") {
            putJsonArray("conditions") { addJsonObject { put("location", "body"); put("pattern", "x") } }
        })
        assertTrue("match_mode" in failure("scancheck_dry_run") { keyCondition(); put("match_mode", "some") })
    }

    @Test
    fun `numeric arguments are checked against their bounds`() {
        assertEquals("max_items must be between 1 and 5000", failure("scancheck_dry_run") { keyCondition(); put("max_items", 0) })
        assertEquals("max_matches must be between 1 and 200", failure("scancheck_dry_run") { keyCondition(); put("max_matches", 201) })
        assertEquals("Parameter 'max_items' must be an integer", failure("bcheck_dry_run") {
            put("type", "passive_response"); put("match_pattern", "x"); put("max_items", "many")
        })
    }

    // ---- bcheck_dry_run -------------------------------------------------------

    @Test
    fun `a BCheck definition is tried against the history and its script shown, without importing it`() {
        val result = ok("bcheck_dry_run") {
            put("type", "passive_response")
            put("match_pattern", "AKIA[0-9A-Z]{16}")
        }
        assertEquals(2, result.int("would_report"))
        assertEquals(0, result.int("requests_sent"))
        val script = result.getValue("script").jsonPrimitive.content
        assertTrue("given response then" in script && "matches \"AKIA[0-9A-Z]{16}\"" in script, script)
    }

    @Test
    fun `a host level BCheck dry run counts the hosts it would probe`() {
        val result = ok("bcheck_dry_run") {
            put("type", "host_level")
            put("path", "/index.html")
            put("response_match_pattern", "welcome")
        }
        assertEquals(2, result.int("hosts"))
        assertEquals(2, result.int("probe_requests"))
        assertEquals(listOf("https://shop.example/index.html"), result.urls("matches"))
    }

    @Test
    fun `a BCheck definition that create would refuse is refused by the dry run too`() {
        assertTrue("match_pattern" in failure("bcheck_dry_run") { put("type", "passive_response") })
        assertTrue("type" in failure("bcheck_dry_run") { put("type", "sql_injection"); put("match_pattern", "x") })
        assertTrue("Missing required parameter: type" in failure("bcheck_dry_run") { put("match_pattern", "x") })
        // bcheck_create refuses the same definition before it reaches Burp (which this test's Burp would fail on).
        assertTrue("match_pattern" in failure("bcheck_create") {
            put("name", "n"); put("description", "d"); put("type", "passive_response")
            put("severity", "high"); put("confidence", "firm"); put("match_pattern", "")
        })
    }

    // ---- bambda_templates -----------------------------------------------------

    @Test
    fun `bambda_templates needs no Burp and lists starting points with the envelope format`() {
        val result = ok("bambda_templates")
        assertTrue(result.getValue("templates").jsonArray.isNotEmpty())
        assertTrue("source: |+" in result.getValue("envelope").jsonObject.getValue("example").jsonPrimitive.content)
    }

    // ---- schemas ----------------------------------------------------------------

    @Test
    fun `closed parameters carry their values in the schema and none is called action`() {
        fun property(tool: String, name: String): JsonObject? =
            server.tools.getValue(tool).tool.inputSchema.properties?.get(name)?.jsonObject

        fun enumOf(tool: String, name: String): List<String> =
            assertNotNull(property(tool, name)?.get("enum"), "$tool.$name has no enum").jsonArray.map { it.jsonPrimitive.content }

        for (tool in listOf("scancheck_create_passive", "scancheck_create_active", "bcheck_create")) {
            assertEquals(listOf("high", "medium", "low", "information"), enumOf(tool, "severity"), tool)
            assertEquals(listOf("certain", "firm", "tentative"), enumOf(tool, "confidence"), tool)
        }
        for (tool in listOf("scancheck_create_passive", "scancheck_create_active", "scancheck_dry_run")) {
            assertEquals(listOf("all", "any"), enumOf(tool, "match_mode"), tool)
        }
        for (tool in listOf("bcheck_create", "bcheck_dry_run")) {
            assertEquals(BCheckBridge.ALLOWED_TYPES.toList(), enumOf(tool, "type"), tool)
            assertEquals(listOf("matches", "is", "contains"), enumOf(tool, "match_condition"), tool)
            assertEquals(listOf("dns", "http"), enumOf(tool, "collaborator_payload_type"), tool)
            assertNotNull(property(tool, "path"), "$tool must take the host_level path separately")
        }
        // ToolConsolidation dispatches on a parameter named "action"; a member that had one would lose it.
        for ((name, registered) in server.tools) {
            assertFalse(registered.tool.inputSchema.properties.orEmpty().containsKey("action"), name)
        }
    }
}
