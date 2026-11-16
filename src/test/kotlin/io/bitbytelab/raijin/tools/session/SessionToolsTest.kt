package io.bitbytelab.raijin.tools.session

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
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The session tools: arguments are validated (or clamped, with a note) before anything is stored.
 * Burp is a stand-in that fails any call, so nothing here may reach it.
 */
class SessionToolsTest {

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
        SessionTools.register(server, HttpBridge(api, EventBus(), state), state)
    }

    private fun call(tool: String, args: JsonObject): CallToolResult = runBlocking {
        server.tools.getValue(tool).handler(testClientConnection, CallToolRequest(CallToolRequestParams(tool, args)))
    }

    private fun json(result: CallToolResult): JsonObject =
        Json.parseToJsonElement((result.content.first() as TextContent).text).jsonObject

    private fun ok(tool: String, args: JsonObject): JsonObject {
        val result = call(tool, args)
        assertFalse(result.isError == true, (result.content.first() as TextContent).text)
        return json(result)
    }

    private fun assertRejected(tool: String, args: JsonObject, vararg fragments: String) {
        val result = call(tool, args)
        assertEquals(true, result.isError, (result.content.first() as TextContent).text)
        val message = json(result).getValue("error").jsonPrimitive.content
        fragments.forEach { assertTrue(it in message, "$tool: '$it' not in: $message") }
    }

    private fun tokenRule(name: String, extra: JsonObject.() -> JsonObject = { this }) = buildJsonObject {
        put("rule_name", name)
        put("scope", "all")
        put("extract_from", "body")
        put("inject_into", "header")
        put("inject_name", "Authorization")
        put("inject_value_template", "Bearer {value}")
    }.extra()

    /** This object plus [pairs]; a string starting with '[' is a JSON array literal. */
    private fun JsonObject.with(vararg pairs: Pair<String, Any>): JsonObject = JsonObject(this + pairs.associate { (k, v) ->
        k to when (v) {
            is String -> if (v.startsWith("[")) Json.parseToJsonElement(v) else JsonPrimitive(v)
            is Boolean -> JsonPrimitive(v)
            is Number -> JsonPrimitive(v)
            else -> error("unsupported argument $v")
        }
    })

    @Test
    fun `token rules take a JSONPath or XPath instead of a regex and validate every selector`() {
        val created = ok("session_create_token_rule", tokenRule("jwt").with("extract_json_path" to "$.data.token", "inject_if_missing" to false))
        assertEquals("$.data.token", created.getValue("extract_json_path").jsonPrimitive.content)
        assertEquals(false, created.getValue("inject_if_missing").jsonPrimitive.boolean)
        assertEquals("$.data.token", state.sessionRules.single().extractJsonPath)

        assertRejected("session_create_token_rule", tokenRule("none"), "extract_regex", "extract_json_path", "extract_xpath")
        assertRejected("session_create_token_rule", tokenRule("bad-path").with("extract_json_path" to "$.a["), "extract_json_path")
        assertRejected("session_create_token_rule", tokenRule("both").with("extract_json_path" to "$.a", "extract_xpath" to "//a"), "not both")
        assertRejected("session_create_token_rule", tokenRule("bad-xpath").with("extract_xpath" to "//a["), "extract_xpath")
        assertRejected("session_create_token_rule", tokenRule("bad-regex").with("extract_regex" to "("), "extract_regex")
        assertRejected("session_create_token_rule", tokenRule("no-header").with("extract_from" to "header", "extract_regex" to "x=(\\w+)"), "extract_header_name")
        assertRejected("session_create_token_rule", tokenRule("wild").with("extract_regex" to "(.+)", "inject_into" to "json", "inject_name" to "$..token"), "exactly one value")
        assertRejected("session_create_token_rule", tokenRule("enc").with("extract_regex" to "(.+)", "inject_value_template" to "{value|rot13}"), "unknown encoder 'rot13'")
        assertRejected("session_create_token_rule", tokenRule("custom").with("extract_regex" to "(.+)", "scope" to "custom"), "scope_pattern")
        assertRejected("session_create_token_rule", tokenRule("target").with("extract_regex" to "(.+)", "inject_into" to "path"), "inject_into")

        ok("session_create_token_rule", tokenRule("query").with("extract_regex" to "(.+)", "inject_into" to "query", "inject_name" to "token", "inject_value_template" to "{value|url}"))
        val listed = ok("session_list_rules", buildJsonObject {}).getValue("rules").jsonArray.map { it.jsonObject }
        assertEquals(listOf("jwt", "query"), listed.map { it.getValue("rule_name").jsonPrimitive.content })
        assertEquals("query", listed[1].getValue("inject_into").jsonPrimitive.content)
        assertEquals(true, listed[1].getValue("inject_if_missing").jsonPrimitive.boolean)
    }

    private fun macro(name: String = "login", extra: JsonObject.() -> JsonObject = { this }) = buildJsonObject {
        put("name", name)
        put("scope", "all")
        putJsonArray("steps") { add(buildJsonObject { put("url", "https://target.example/login"); put("method", "POST") }) }
    }.extra()

    @Test
    fun `macro_set stores a validated macro with safe defaults and clamps numbers with a note`() {
        val created = ok("session_macro_set", macro())
        assertEquals("created", created.getValue("status").jsonPrimitive.content)
        val tools = created.getValue("tool_filter").jsonArray.map { it.jsonPrimitive.content }
        assertFalse("PROXY" in tools)
        assertTrue("EXTENSIONS" in tools && "REPEATER" in tools)
        assertEquals(listOf(401L), created.getValue("trigger_status").jsonArray.map { it.jsonPrimitive.long })
        assertEquals(true, created.getValue("require_credentials").jsonPrimitive.boolean)

        val clamped = ok("session_macro_set", macro().with(
            "min_interval_ms" to 99_999_999, "max_failures" to -1, "step_timeout_ms" to 0, "trigger_status" to "[401, 700]",
            "tool_filter" to "[\"scanner\", \"extensions\"]",
        ))
        assertEquals("replaced", clamped.getValue("status").jsonPrimitive.content)
        assertEquals(3_600_000L, clamped.getValue("min_interval_ms").jsonPrimitive.long)
        assertEquals(0L, clamped.getValue("max_failures").jsonPrimitive.long)
        assertEquals(100L, clamped.getValue("step_timeout_ms").jsonPrimitive.long)
        assertEquals(listOf(401L, 599L), clamped.getValue("trigger_status").jsonArray.map { it.jsonPrimitive.long })
        assertEquals(listOf("SCANNER", "EXTENSIONS"), clamped.getValue("tool_filter").jsonArray.map { it.jsonPrimitive.content })
        val notes = clamped.getValue("notes").jsonArray.map { it.jsonPrimitive.content }
        assertEquals(4, notes.size, notes.toString())
        assertTrue(notes.any { "'min_interval_ms'" in it } && notes.any { "'trigger_status'" in it })
    }

    @Test
    fun `macro_set rejects a macro that could never work`() {
        assertRejected("session_macro_set", buildJsonObject { put("name", "x"); put("scope", "all") }, "steps")
        assertRejected("session_macro_set", macro().with("scope" to "custom"), "scope_pattern")
        assertRejected("session_macro_set", macro().with("trigger_regex" to "("), "trigger_regex")
        assertRejected("session_macro_set", macro().with("tool_filter" to "[\"BROWSER\"]"), "unknown tool 'BROWSER'")
        assertRejected("session_macro_set", macro().with("trigger_status" to "[\"x\"]"), "trigger_status")
        assertRejected("session_macro_set", macro().with("http_mode" to "HTTP_3"), "http_mode")
        assertRejected("session_macro_set", macro("a\r\nX-Injected: 1"), "control characters")
        assertRejected("session_macro_set", buildJsonObject {
            put("name", "x"); put("scope", "all")
            putJsonArray("steps") { add(buildJsonObject { put("method", "GET") }) }
        }, "steps[0] needs a 'url' or a 'raw_request'")
        assertRejected("session_macro_set", buildJsonObject {
            put("name", "x"); put("scope", "all")
            putJsonArray("steps") {
                add(buildJsonObject {
                    put("url", "https://t/")
                    putJsonArray("extract") { add(buildJsonObject { put("name", "t"); put("pattern", "(") }) }
                })
            }
        }, "steps[0]: extract[0].pattern")
        assertTrue(state.sessionRules.isEmpty())
    }

    @Test
    fun `macros are listed with their state and removed by name`() {
        ok("session_macro_set", macro())
        val listed = ok("session_macro_list", buildJsonObject {}).getValue("macros").jsonArray.single().jsonObject
        assertEquals(listOf("POST https://target.example/login"), listed.getValue("steps").jsonArray.map { it.jsonPrimitive.content })
        val macroState = listed.getValue("state").jsonObject
        assertEquals(false, macroState.getValue("suspended").jsonPrimitive.boolean)
        assertEquals(0L, macroState.getValue("runs").jsonPrimitive.long)
        assertTrue(macroState.getValue("learned_cookies").jsonArray.isEmpty())

        assertRejected("session_macro_run", buildJsonObject { put("name", "nope") }, "No session macro named 'nope'")
        assertRejected("session_macro_remove", buildJsonObject { put("name", "nope") }, "No session macro named 'nope'")
        assertEquals("removed", ok("session_macro_remove", buildJsonObject { put("name", "login") }).getValue("status").jsonPrimitive.content)
        assertEquals(0L, ok("session_macro_list", buildJsonObject {}).getValue("count").jsonPrimitive.long)
    }
}
