package io.bitbytelab.raijin.tools.accesscontrol

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.bridge.AccessControlBridge
import io.bitbytelab.raijin.bridge.AnalysisBridge
import io.bitbytelab.raijin.bridge.IdorHuntBridge
import io.bitbytelab.raijin.testClientConnection
import io.bitbytelab.raijin.tools.analysis.AnalysisTools
import io.bitbytelab.raijin.tools.authdiff.AuthDiffTools
import io.bitbytelab.raijin.tools.idor.IdorTools
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
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
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
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * The tool layer of auth_diff, access_control_sweep, idor_hunt and the analyze tools: a bad
 * argument comes back as an `isError` result naming the problem, before anything is sent. The
 * bridges run on a Montoya stand-in that fails any call, so a test that reached Burp would show
 * that failure instead of the expected message.
 */
class AccessToolsValidationTest {

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
        val analysis = AnalysisBridge(api)
        AuthDiffTools.register(server, analysis)
        AnalysisTools.register(server, analysis)
        AccessControlTools.register(server, AccessControlBridge(api))
        IdorTools.register(server, IdorHuntBridge(api))
    }

    private val request = "GET /api/users/1002 HTTP/1.1\r\nHost: h\r\nCookie: s=a\r\n\r\n"

    private fun call(tool: String, args: JsonObject): CallToolResult = runBlocking {
        server.tools.getValue(tool).handler(testClientConnection, CallToolRequest(CallToolRequestParams(tool, args)))
    }

    private fun text(result: CallToolResult): String = (result.content.first() as TextContent).text

    private fun json(result: CallToolResult): JsonObject = Json.parseToJsonElement(text(result)).jsonObject

    private fun assertRejected(tool: String, args: JsonObject, vararg fragments: String) {
        val result = call(tool, args)
        assertEquals(true, result.isError, text(result))
        val message = json(result).getValue("error").jsonPrimitive.content
        fragments.forEach { assertTrue(it in message, "$tool: '$it' not in: $message") }
    }

    /** These arguments with [key] set to the JSON value written in [json]. */
    private fun JsonObject.having(key: String, json: String) = JsonObject(this + (key to Json.parseToJsonElement(json)))

    private fun JsonObject.without(key: String) = JsonObject(this - key)

    /** Identities that each carry their own session cookie; `none` carries nothing. */
    private fun identities(vararg names: String): JsonArray = buildJsonArray {
        names.forEach { name ->
            add(buildJsonObject {
                put("name", name)
                if (name != "none") {
                    put("header_name", "Cookie")
                    put("header_value", "s=$name")
                }
            })
        }
    }

    // ---- auth_diff ----

    private val authDiff = buildJsonObject {
        put("request", request)
        put("host", "h")
        put("auth_levels", identities("admin", "none"))
    }

    @Test
    fun `auth_diff rejects bad ports, fields, patterns and level sets`() {
        assertRejected("auth_diff", authDiff.having("port", "70000"), "'port'", "1 and 65535")
        assertRejected("auth_diff", authDiff.having("port", "\"https\""), "'port'", "integer")
        assertRejected("auth_diff", authDiff.having("compare_fields", "[\"cookies\"]"), "'compare_fields'", "'cookies'", "status_code")
        assertRejected("auth_diff", authDiff.having("denied_regex", "\"(\""), "denied_regex")
        assertRejected("auth_diff", authDiff.having("auth_levels", "[{\"name\":\"none\"}]"), "at least 2")
        assertRejected("auth_diff", authDiff.having("request", "\"  \""), "Empty request")
        assertRejected("auth_diff", authDiff.without("auth_levels"), "'auth_levels'")
    }

    @Test
    fun `auth_diff refuses levels that would all send the request unchanged`() {
        val unchanged = authDiff.having("auth_levels", "[{\"name\":\"admin\"},{\"name\":\"user\"},{\"name\":\"none\"}]")
        assertRejected("auth_diff", unchanged, "'admin'", "'user'", "unchanged")
    }

    // ---- access_control_sweep ----

    @Test
    fun `access_control_sweep rejects missing lists and a bad pattern`() {
        val sweep = buildJsonObject {
            putJsonArray("requests") { add(buildJsonObject { put("raw_request", request); put("host", "h") }) }
            put("identities", identities("admin", "none"))
        }
        assertRejected("access_control_sweep", sweep.without("identities"), "'identities'")
        assertRejected("access_control_sweep", sweep.without("requests"), "'requests'")
        assertRejected("access_control_sweep", sweep.having("identities", "[{\"name\":\"none\"}]"), "identities", ">=2")
        assertRejected("access_control_sweep", sweep.having("denied_regex", "\"[\""), "denied_regex")
    }

    @Test
    fun `access_control_sweep reports a bad request entry on that entry only`() {
        val result = call("access_control_sweep", buildJsonObject {
            putJsonArray("requests") {
                add(buildJsonObject { put("raw_request", request); put("host", "h"); put("port", 0) })
                add(buildJsonObject { put("host", "h") })
            }
            put("identities", identities("admin", "none"))
        })
        assertNotEquals(true, result.isError, text(result))

        val entries = json(result).getValue("results").jsonArray.map { it.jsonObject }
        assertEquals(listOf(0, 1), entries.map { it.getValue("request_index").jsonPrimitive.int })
        assertTrue("'port'" in entries[0].getValue("error").jsonPrimitive.content, entries[0].toString())
        assertTrue("raw_request" in entries[1].getValue("error").jsonPrimitive.content, entries[1].toString())
        assertEquals(0, json(result).getValue("requests_with_broken_access_control").jsonPrimitive.int)
    }

    // ---- idor_hunt ----

    private val hunt = buildJsonObject {
        put("request", request)
        put("host", "h")
        put("identities", identities("alice", "bob"))
    }

    @Test
    fun `idor_hunt rejects bad numbers, unknown locations and missing parts`() {
        assertRejected("idor_hunt", hunt.having("enumerate", "\"many\""), "'enumerate'", "integer")
        assertRejected("idor_hunt", hunt.having("port", "0"), "'port'", "1 and 65535")
        assertRejected("idor_hunt", hunt.having("id_location", "\"body\""), "'id_location'", "body-json", "path")
        assertRejected("idor_hunt", hunt.having("identities", "[{\"name\":\"alice\"}]"), "identities", ">=2")
        assertRejected("idor_hunt", hunt.without("request"), "'request'")
    }

    @Test
    fun `idor_hunt clamps an enumerate count outside 0 to 25 and says so`() {
        // A pinned id the request does not hold ends the hunt before anything is sent.
        val pinned = hunt.having("id_value", "\"31337\"")
        for ((given, used) in listOf("26" to 25, "50" to 25, "-1" to 0)) {
            val result = json(call("idor_hunt", pinned.having("enumerate", given)))
            assertEquals(used, result["enumerate_clamped_to"]?.jsonPrimitive?.int, "$given: $result")
            assertTrue("Nothing was sent" in result.getValue("error").jsonPrimitive.content, result.toString())
        }
        assertFalse("enumerate_clamped_to" in json(call("idor_hunt", pinned.having("enumerate", "25"))))
    }

    @Test
    fun `idor_hunt sends nothing when the pinned id is not at a parameter boundary`() {
        // "100" is only a prefix of the path segment 1002.
        assertRejected("idor_hunt", hunt.having("id_value", "\"100\""), "id_value '100'", "Nothing was sent")
        assertRejected(
            "idor_hunt",
            hunt.having("id_value", "\"1002\"").having("id_location", "\"query\""),
            "id_value '1002'", "id_location 'query'"
        )
        assertRejected("idor_hunt", hunt.having("id_name", "\"account\""), "id_name 'account'")
    }

    // ---- analyze ----

    @Test
    fun `analyze tools reject bad enums, bounds and patterns`() {
        val diff = buildJsonObject {
            put("item1", "GET / HTTP/1.1\r\n\r\n")
            put("item2", "GET /a HTTP/1.1\r\n\r\n")
        }
        assertRejected("analyze_diff", diff.having("type", "\"header\""), "'type'", "request, response")
        assertRejected("analyze_diff", diff, "'type'", "required")

        val search = buildJsonObject { put("pattern", "token") }
        // A max_results past its range is clamped (AnalysisToolsTest); one that is not an integer is refused.
        assertRejected("analyze_response_body_search", search.having("max_results", "1.5"), "'max_results'", "integer")
        assertRejected("analyze_response_body_search", buildJsonObject { put("pattern", "[unclosed") }, "Invalid regex")
        assertRejected("analyze_response_body_search", buildJsonObject { put("pattern", "") }, "'pattern'")

        val points = buildJsonObject {
            put("request", request)
            put("host", "h")
        }
        assertRejected("analyze_insertion_points", points, "port")
        assertRejected("analyze_insertion_points", points.having("port", "65536"), "'port'", "1 and 65535")

        assertRejected("analyze_request", buildJsonObject { put("request", "") }, "Empty request")
        assertRejected("analyze_response", buildJsonObject { }, "response")
    }

    // ---- schemas ----

    @Test
    fun `closed-value parameters publish their values and no parameter is called action`() {
        fun properties(tool: String) = server.tools.getValue(tool).tool.inputSchema.properties!!
        fun enumOf(schema: JsonObject) = schema.getValue("enum").jsonArray.map { it.jsonPrimitive.content }

        assertEquals(
            listOf("path", "query", "header", "cookie", "body-json", "body-form"),
            enumOf(properties("idor_hunt").getValue("id_location").jsonObject)
        )
        assertEquals(
            listOf("status_code", "body_length", "body", "headers"),
            enumOf(properties("auth_diff").getValue("compare_fields").jsonObject.getValue("items").jsonObject)
        )
        assertEquals(listOf("request", "response"), enumOf(properties("analyze_diff").getValue("type").jsonObject))

        server.tools.values.forEach { registered ->
            assertFalse("action" in registered.tool.inputSchema.properties.orEmpty().keys, registered.tool.name)
        }
    }
}
