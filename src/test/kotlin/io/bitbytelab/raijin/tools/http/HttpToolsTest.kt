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
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
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

/**
 * The HTTP tool layer: malformed arguments come back as `isError` results naming the problem,
 * before anything is sent, while out-of-range numbers are clamped with a note. The bridge runs on a
 * Montoya stand-in that fails any call, so a call that got past argument checking ends in a send
 * error.
 */
class HttpToolsTest {

    private val state = StateManager()

    private val server =
        Server(
                Implementation("t", "0"),
                ServerOptions(
                    ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false)),
                ),
            )
            .also { server ->
                val api =
                    Proxy.newProxyInstance(
                        MontoyaApi::class.java.classLoader,
                        arrayOf(MontoyaApi::class.java),
                    ) { proxy, method, args ->
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
        server.tools
            .getValue(tool)
            .handler(testClientConnection, CallToolRequest(CallToolRequestParams(tool, args)))
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

    private fun notes(result: CallToolResult): List<String> =
        json(result)["notes"]?.jsonArray?.map { it.jsonPrimitive.content }.orEmpty()

    private fun JsonObject.with(key: String, json: String) =
        JsonObject(this + (key to Json.parseToJsonElement(json)))

    private val pipeline = buildJsonObject {
        put("host", "127.0.0.1")
        put("port", 1)
        putJsonArray("requests") {
            add(buildJsonObject { put("raw_request", "GET / HTTP/1.1\r\n\r\n") })
        }
    }

    @Test
    fun `malformed values and unknown enum values are rejected`() {
        val fuzz = buildJsonObject {
            put("request", "GET /?q=FUZZ HTTP/1.1\r\n\r\n")
            put("host", "h")
            putJsonArray("payloads") { add("x") }
        }
        assertRejected("http_fuzz", fuzz.with("port", "70000"), "'port'", "1 and 65535")
        assertRejected(
            "http_fuzz",
            fuzz.with("attack_mode", "\"intruder\""),
            "'attack_mode'",
            "cluster_bomb",
        )
        assertRejected(
            "http_race",
            buildJsonObject {
                put("request", "GET / HTTP/1.1\r\n\r\n")
                put("host", "h")
                put("count", "many")
            },
            "'count'",
            "integer",
        )
        assertRejected(
            "http_send_request",
            buildJsonObject {
                put("url", "https://h/")
                put("http_mode", "HTTP_3")
            },
            "'http_mode'",
            "HTTP_2_IGNORE_ALPN",
        )
        assertRejected(
            "http_send_request",
            buildJsonObject {
                put("url", "https://h/")
                put("follow_redirects", "sometimes")
            },
            "'follow_redirects'",
            "same_host",
        )
        assertRejected(
            "http_send_pipeline",
            pipeline.with("write_mode", "\"burst\""),
            "'write_mode'",
            "concat, single_write",
        )
        assertRejected(
            "http_send_pipeline",
            pipeline.with("http_mode", "\"HTTP_2\""),
            "'http_mode'",
        )
    }

    @Test
    fun `out-of-range numbers are clamped with a note instead of rejected`() {
        val race =
            call(
                "http_race",
                buildJsonObject {
                    put("request", "GET / HTTP/1.1\r\n\r\n")
                    put("host", "h")
                    put("count", 0)
                },
            )
        assertTrue(
            notes(race).any { "'count' = 0" in it && "1 was used" in it },
            json(race).toString(),
        )
        assertFalse("'count'" in json(race)["error"]?.jsonPrimitive?.content.orEmpty())

        val pipelined = call("http_send_pipeline", pipeline.with("max_responses", "0"))
        assertTrue(notes(pipelined).any { "'max_responses' = 0" in it }, json(pipelined).toString())

        val fuzz = buildJsonObject {
            put("request", "GET /?q=FUZZ HTTP/1.1\r\n\r\n")
            put("host", "h")
            putJsonArray("payloads") { add("x") }
            put("concurrency", 500)
            put("max_requests", 0)
        }
        val fuzzed = notes(call("http_fuzz", fuzz))
        assertTrue(
            fuzzed.any { "'concurrency' = 500" in it } && fuzzed.any { "'max_requests' = 0" in it },
            fuzzed.toString(),
        )
    }

    @Test
    fun `timeout_ms 0 is the default and -1 means no hard timeout`() {
        val zero =
            call(
                "http_send_request",
                buildJsonObject {
                    put("url", "https://h/")
                    put("timeout_ms", 0)
                },
            )
        assertFalse("timeout_ms" in errorOf(zero), json(zero).toString())
        assertTrue(
            notes(zero).any { "0 'timeout_ms' read as the default" in it },
            notes(zero).toString(),
        )
        val none =
            call(
                "http_send_request",
                buildJsonObject {
                    put("url", "https://h/")
                    put("timeout_ms", -1)
                },
            )
        assertFalse("timeout_ms" in errorOf(none), json(none).toString())
        assertTrue(notes(none).isEmpty(), notes(none).toString())
    }

    @Test
    fun `http2 headers, fuzz payload sets and race options are checked before sending`() {
        assertRejected(
            "http_send_request",
            buildJsonObject { put("url", "https://h/") }
                .with("http2_headers", """[{"name":":path"}]"""),
            "http2_headers[0]",
            "'value'",
        )
        assertRejected(
            "http_send_request",
            buildJsonObject { put("url", "https://h/") }.with("http2_headers", """"x""""),
            "http2_headers",
        )

        val fuzz = buildJsonObject {
            put("request", "GET /?a=§1§&b=§2§ HTTP/1.1\r\n\r\n")
            put("host", "h")
        }
        assertRejected(
            "http_fuzz",
            fuzz.with("payload_sets", """[["a"]]""").with("payloads", """["b"]"""),
            "not both",
        )
        assertRejected(
            "http_fuzz",
            fuzz.with("payload_sets", """[["a"], []]"""),
            "payload_sets[1]",
            "empty",
        )
        assertRejected(
            "http_fuzz",
            fuzz.with("payload_sets", """["nope"]"""),
            "unknown payload library",
        )
        assertRejected(
            "http_fuzz",
            fuzz.with("payloads", """["a"]""").with("encoders", """["rot13"]"""),
            "rot13",
        )
        assertRejected(
            "http_fuzz",
            fuzz.with("payloads", """["a"]""").with("grep_regex", "\"(\""),
            "'grep_regex'",
        )
        assertRejected(
            "http_fuzz",
            fuzz.with("payloads", """["a"]""").with("filter_length", """["big"]"""),
            "filter_length",
        )
        assertRejected("http_fuzz", fuzz, "payload_sets")

        val race = buildJsonObject {
            put("request", "GET / HTTP/1.1\r\n\r\n")
            put("host", "h")
        }
        assertRejected(
            "http_race",
            race.with("sync", "\"single_packet\"").with("http_mode", "\"HTTP_1\""),
            "last_byte",
        )
        assertRejected(
            "http_race",
            race.with("sync", "\"last_byte\"").with("http_mode", "\"HTTP_2\""),
            "HTTP_1",
        )
        assertRejected("http_race", race.with("sni", "\"x\""), "last_byte")
    }

    @Test
    fun `fuzz rejects malformed positions and stop conditions`() {
        val fuzz = buildJsonObject {
            put("request", "GET /?q=§a§ HTTP/1.1\r\n\r\n")
            put("host", "h")
            putJsonArray("payloads") { add("x") }
        }
        assertRejected("http_fuzz", fuzz.with("positions", "[[1]]"), "positions[0]")
        assertRejected(
            "http_fuzz",
            fuzz.with("stop_on_match", """{"status_codes":["x"]}"""),
            "status_codes",
        )
        assertRejected(
            "http_fuzz",
            fuzz.with("stop_on_match", """{"body_regex":"("}"""),
            "body_regex",
        )
        assertRejected(
            "http_fuzz",
            fuzz.with("payload_library", "\"nope\""),
            "'payload_library'",
            "sqli",
        )
    }

    @Test
    fun `traffic rules keep header lines exactly as given and validate patterns`() {
        fun rule(extra: JsonObject) =
            JsonObject(buildJsonObject { put("direction", "request") } + extra)
        assertRejected(
            "http_set_traffic_rule",
            rule(buildJsonObject { put("match_url", "[") }),
            "'match_url'",
            "regex",
        )
        assertRejected(
            "http_set_traffic_rule",
            rule(buildJsonObject { putJsonArray("tool_filter") { add("NOPE") } }),
            "unknown tool",
            "EXTENSIONS",
        )
        assertRejected(
            "http_set_traffic_rule",
            rule(
                buildJsonObject {
                    put("action", "drop")
                    put("direction", "response")
                },
            ),
            "direction=request",
        )

        val raw =
            call(
                "http_set_traffic_rule",
                rule(
                    buildJsonObject {
                        put("rule_id", "raw")
                        put("modify_add_header", "Transfer-Encoding : chunked\r\nX-Smuggled: 1")
                        putJsonObject("modify_replace_header") { put("X-A", "a\r\nInjected: 1") }
                    },
                ),
            )
        assertEquals(null, raw.isError?.takeIf { it }, (raw.content.first() as TextContent).text)
        val stored = state.trafficRules.single { it.ruleId == "raw" }
        assertEquals("Transfer-Encoding : chunked\r\nX-Smuggled: 1", stored.modifyAddHeader)
        assertEquals(mapOf("X-A" to "a\r\nInjected: 1"), stored.modifyReplaceHeader)
        val noColon =
            call(
                "http_set_traffic_rule",
                rule(buildJsonObject { put("modify_add_header", "no colon") }),
            )
        assertEquals(
            null,
            noColon.isError?.takeIf { it },
            (noColon.content.first() as TextContent).text,
        )

        val set =
            call(
                "http_set_traffic_rule",
                rule(
                    buildJsonObject {
                        put("rule_id", "probe-tag")
                        put("modify_add_header", "X-Probe: 1")
                        putJsonArray("tool_filter") { add("extensions") }
                    },
                ),
            )
        assertEquals(null, set.isError?.takeIf { it }, (set.content.first() as TextContent).text)
        assertEquals(
            setOf("EXTENSIONS"),
            state.trafficRules.single { it.ruleId == "probe-tag" }.toolFilter,
        )

        val listed =
            json(call("http_list_traffic_rules", buildJsonObject {}))
                .getValue("rules")
                .jsonArray
                .single { it.jsonObject.getValue("rule_id").jsonPrimitive.content == "probe-tag" }
                .jsonObject
        assertEquals("modify", listed.getValue("action").jsonPrimitive.content)
        assertEquals(
            listOf("EXTENSIONS"),
            listed.getValue("tool_filter").jsonArray.map { it.jsonPrimitive.content },
        )
    }

    @Test
    fun `chain rejects a bad extract regex before sending the step`() {
        val result =
            call(
                "http_send_request_chain",
                buildJsonObject {
                    putJsonArray("steps") {
                        add(
                            buildJsonObject {
                                put("url", "https://h/")
                                putJsonArray("extract") {
                                    add(
                                        buildJsonObject {
                                            put("name", "t")
                                            put("pattern", "(")
                                        },
                                    )
                                }
                            },
                        )
                    }
                },
            )
        val step = json(result).getValue("steps").jsonArray.single().jsonObject
        assertEquals(false, step.getValue("success").jsonPrimitive.boolean)
        assertTrue(
            "extract[0].pattern is not a valid regex" in
                step.getValue("error").jsonPrimitive.content,
            step.toString(),
        )
    }

    @Test
    fun `malformed raw bytes and a bad cookie expiration come back as errors`() {
        assertRejected(
            "http_send_raw_bytes",
            buildJsonObject {
                put("host", "h")
                put("raw_request_hex", "474")
            },
            "odd number of digits",
        )
        assertRejected(
            "http_cookie_jar_set",
            buildJsonObject {
                put("name", "n")
                put("value", "v")
                put("domain", "h")
                put("expiration", "tomorrow")
            },
            "ISO-8601",
        )
        assertRejected(
            "http_send_requests_parallel",
            buildJsonObject { putJsonArray("requests") { add("not an object") } },
            "'requests'",
        )
    }

    @Test
    fun `closed parameters publish their allowed values`() {
        fun enumOf(tool: String, param: String) =
            server.tools
                .getValue(tool)
                .tool
                .inputSchema
                .properties!!
                .getValue(param)
                .jsonObject
                .getValue("enum")
                .jsonArray
                .map { it.jsonPrimitive.content }
        assertEquals(
            listOf("AUTO", "HTTP_1", "HTTP_2", "HTTP_2_IGNORE_ALPN"),
            enumOf("http_send_request", "http_mode"),
        )
        assertEquals(
            listOf("never", "always", "same_host", "in_scope"),
            enumOf("http_send_request", "follow_redirects"),
        )
        assertEquals(listOf("concat", "single_write"), enumOf("http_send_pipeline", "write_mode"))
        assertEquals(
            listOf("modify", "drop", "spoof_response"),
            enumOf("http_set_traffic_rule", "action"),
        )
        assertEquals(
            listOf("sniper", "battering_ram", "pitchfork", "cluster_bomb"),
            enumOf("http_fuzz", "attack_mode"),
        )
        assertEquals(listOf("all", "clusters", "summary"), enumOf("http_fuzz", "report"))
        assertEquals(listOf("single_packet", "last_byte"), enumOf("http_race", "sync"))
        val toolFilterItems =
            server.tools
                .getValue("http_set_traffic_rule")
                .tool
                .inputSchema
                .properties!!
                .getValue("tool_filter")
                .jsonObject
                .getValue("items")
                .jsonObject
                .getValue("enum")
                .jsonArray
                .map { it.jsonPrimitive.content }
        assertTrue(
            "EXTENSIONS" in toolFilterItems && "SCANNER" in toolFilterItems,
            toolFilterItems.toString(),
        )
        assertFalse(
            server.tools
                .getValue("http_race")
                .tool
                .inputSchema
                .properties!!
                .containsKey("gate_delay"),
        )
    }
}
