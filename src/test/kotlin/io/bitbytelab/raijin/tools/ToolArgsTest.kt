package io.bitbytelab.raijin.tools

import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

class ToolArgsTest {

    private val props = buildJsonObject {
        putJsonObject("url") { put("type", "string") }
        putJsonObject("algorithm") {
            put("type", "string")
            putJsonArray("enum") {
                add("MD5")
                add("SHA_256")
            }
        }
        putJsonObject("data") { put("type", "string") }
        putJsonObject("request") { put("type", "string") }
        putJsonObject("count") {
            put("type", "integer")
            put("minimum", 0)
        }
    }

    private fun json(r: CallToolResult): JsonObject =
        Json.parseToJsonElement((r.content.single() as TextContent).text).jsonObject

    @Test
    fun `a one-item array is read as the scalar it holds, except for payloads`() {
        val c =
            ToolArgs.coerce(
                props,
                buildJsonObject {
                    putJsonArray("url") { add("https://a.b/") }
                    putJsonArray("data") { add("x") }
                },
            )
        assertEquals(JsonPrimitive("https://a.b/"), c.args["url"])
        assertTrue("read 'url' from a one-item array" in c.notes, c.notes.toString())
        assertEquals(JsonPrimitive("[\"x\"]"), c.args["data"])
    }

    @Test
    fun `a quoted enum value is matched without its quotes`() {
        val c = ToolArgs.coerce(props, buildJsonObject { put("algorithm", "\"MD5\"") })
        assertEquals(JsonPrimitive("MD5"), c.args["algorithm"])
        assertEquals(listOf("matched 'algorithm' \"\"MD5\"\" to \"MD5\""), c.notes)
    }

    @Test
    fun `a request placeholder is refused`() {
        val (error, _) =
            ToolArgs.placeholderCheck(
                "http_race",
                "http_race",
                null,
                props,
                buildJsonObject { put("request", "<request>") },
                JsonObject(emptyMap()),
                destructive = false,
            )
        val body = json(assertNotNull(error))
        assertEquals(JsonPrimitive("placeholder_value"), body["code"])
        assertEquals(JsonPrimitive("request"), body["param"])
    }

    @Test
    fun `an empty free-form string is a value, an empty enum or list is unset`() {
        val ruleProps = buildJsonObject {
            put("modify_body_replacement", buildJsonObject { put("type", "string") })
            put(
                "mode",
                buildJsonObject {
                    put("type", "string")
                    putJsonArray("enum") { add("a") }
                },
            )
            put("tags", buildJsonObject { put("type", "array") })
        }
        val c =
            ToolArgs.dropEmptyUnknown(
                ruleProps,
                buildJsonObject {
                    put("modify_body_replacement", "")
                    put("mode", "")
                    putJsonArray("tags") {}
                },
                emptySet(),
                destructive = false,
            )
        assertEquals(buildJsonObject { put("modify_body_replacement", "") }, c.args)
        assertEquals(listOf("ignored empty or zero 'mode', 'tags'"), c.notes)
    }

    @Test
    fun `an empty host or method and a port of 0 below its minimum are unset, a body is not`() {
        val sendProps = buildJsonObject {
            put(
                "port",
                buildJsonObject {
                    put("type", "integer")
                    put("minimum", 1)
                },
            )
            put("method", buildJsonObject { put("type", "string") })
            put("host", buildJsonObject { put("type", "string") })
            put("body", buildJsonObject { put("type", "string") })
        }
        val c =
            ToolArgs.dropEmptyUnknown(
                sendProps,
                buildJsonObject {
                    put("port", 0)
                    put("method", "")
                    put("host", "")
                    put("body", "")
                },
                emptySet(),
                destructive = false,
            )
        assertEquals(buildJsonObject { put("body", "") }, c.args)
        assertEquals(
            listOf(
                "ignored empty or zero 'port', 'method', 'host'; " +
                    "an empty method is sent only inside raw_request",
            ),
            c.notes,
        )
        val text =
            ToolArgs.dropEmptyUnknown(
                sendProps,
                buildJsonObject { put("port", "0") },
                emptySet(),
                false,
            )
        assertEquals(JsonObject(emptyMap()), text.args)
        val required =
            ToolArgs.dropEmptyUnknown(
                sendProps,
                buildJsonObject {
                    put("port", 0)
                    put("host", "")
                },
                emptySet(),
                destructive = false,
                required = setOf("port", "host"),
            )
        assertEquals(emptyList<String>(), required.notes)
    }

    @Test
    fun `false and 0 of another action's parameters are filler, the action's own are values`() {
        val hashProps = buildJsonObject {
            put("data", buildJsonObject { put("type", "string") })
            put("algorithm", buildJsonObject { put("type", "string") })
            put("upper", buildJsonObject { put("type", "boolean") })
            put("rounds", buildJsonObject { put("type", "integer") })
        }
        val c =
            ToolArgs.dropEmptyUnknown(
                hashProps,
                buildJsonObject {
                    put("data", "x")
                    put("algorithm", "MD5")
                    put("upper", false)
                    put("rounds", 0)
                    put("encode_all", false)
                    put("length", 0)
                    put("other", true)
                },
                emptySet(),
                destructive = false,
            )
        assertEquals(
            listOf("data", "algorithm", "upper", "rounds", "other"),
            c.args.keys.toList(),
        )
        assertEquals(listOf("ignored 2 empty parameters of other actions"), c.notes)
    }

    @Test
    fun `a destructive call drops other actions' filler but keeps its own values`() {
        val removeProps = buildJsonObject {
            putJsonObject("list") { put("type", "string") }
            putJsonObject("index") { put("type", "integer") }
            putJsonObject("comment") { put("type", "string") }
        }
        val c =
            ToolArgs.dropEmptyUnknown(
                removeProps,
                buildJsonObject {
                    put("list", "include")
                    put("index", 0)
                    put("comment", "")
                    put("url", "")
                    put("enabled", false)
                },
                emptySet(),
                destructive = true,
            )
        assertEquals(listOf("list", "index", "comment"), c.args.keys.toList())
        assertEquals(listOf("ignored 2 empty parameters of other actions"), c.notes)
        val real =
            ToolArgs.dropEmptyUnknown(
                removeProps,
                buildJsonObject { put("url", "https://x") },
                emptySet(),
                destructive = true,
            )
        assertEquals(listOf("url"), ToolArgs.unknownParams(removeProps, real.args, emptySet()))
    }

    @Test
    fun `an empty optional id and a 0 timeout are unset`() {
        val p = buildJsonObject {
            putJsonObject("rule_id") { put("type", "string") }
            putJsonObject("timeout_ms") {
                put("type", "number")
                put("minimum", -1)
            }
            putJsonObject("count") { put("type", "integer") }
            putJsonObject("since_index") {
                put("type", "integer")
                put("minimum", -1)
            }
        }
        val c =
            ToolArgs.dropEmptyUnknown(
                p,
                buildJsonObject {
                    put("rule_id", "")
                    put("timeout_ms", 0)
                    put("count", 0)
                    put("since_index", 0)
                },
                emptySet(),
                destructive = false,
            )
        // since_index 0 is a real index, not the -1/0 convention of a timeout.
        assertEquals(
            buildJsonObject {
                put("count", 0)
                put("since_index", 0)
            },
            c.args,
        )
        assertEquals(
            null,
            ToolArgs.rangeCheck(
                "t",
                p,
                buildJsonObject { put("since_index", -5) },
                "t()",
                JsonObject(emptyMap()),
                destructive = false,
            ),
        )
        assertEquals(
            listOf(
                "ignored empty or zero 'rule_id', 'timeout_ms'; a 0 timeout is the default, -1 is none",
            ),
            c.notes,
        )
    }

    @Test
    fun `a value below a negative minimum or a port above its maximum is out of range`() {
        val p = buildJsonObject {
            putJsonObject("timeout_ms") {
                put("type", "number")
                put("minimum", -1)
            }
            putJsonObject("port") {
                put("type", "integer")
                put("minimum", 1)
                put("maximum", 65535)
            }
            putJsonObject("count") {
                put("type", "integer")
                put("minimum", 1)
                put("maximum", 10)
            }
        }
        fun check(args: JsonObject) =
            ToolArgs.rangeCheck("t", p, args, "t()", JsonObject(emptyMap()), destructive = false)
        val timeout = json(assertNotNull(check(buildJsonObject { put("timeout_ms", -5) })))
        assertEquals("out_of_range", timeout["code"]!!.jsonPrimitive.content)
        assertEquals(JsonObject(emptyMap()), timeout["retry"])
        assertEquals(null, check(buildJsonObject { put("timeout_ms", -1) }))
        val port = json(assertNotNull(check(buildJsonObject { put("port", 70000) })))
        assertEquals("port", port["param"]!!.jsonPrimitive.content)
        assertEquals(null, check(buildJsonObject { put("count", 50) }))
    }

    @Test
    fun `an unknown parameter whose value only one enum holds is renamed to it`() {
        val body =
            json(
                ToolArgs.unknownParameterError(
                    "util.hash",
                    props,
                    buildJsonObject {
                        put("type", "md5")
                        put("data", "x")
                    },
                    setOf("action"),
                    "util.hash(...)",
                    JsonObject(emptyMap()),
                    destructive = false,
                ),
            )
        assertEquals(
            listOf("algorithm"),
            body.getValue("did_you_mean").jsonArray.map { it.jsonPrimitive.content },
        )
        assertEquals(
            buildJsonObject {
                put("algorithm", "MD5")
                put("data", "x")
            },
            body["retry"],
        )
    }

    @Test
    fun `a value that exists as written is not a placeholder`() {
        val cookieProps = buildJsonObject {
            put("name", buildJsonObject { put("type", "string") })
            put("domain", buildJsonObject { put("type", "string") })
        }
        val args = buildJsonObject {
            put("name", "<name>")
            put("domain", "a.b")
        }
        val check = { literal: Set<String> ->
            ToolArgs.placeholderCheck(
                    "http_state.cookie_jar_delete",
                    "http_state",
                    "cookie_jar_delete",
                    cookieProps,
                    args,
                    JsonObject(emptyMap()),
                    destructive = true,
                    allowLiteral = literal,
                )
                .first
        }
        assertNotNull(check(emptySet()))
        assertEquals(null, check(setOf("<name>", "a.b")))
    }

    @Test
    fun `a negative count below a zero minimum is out of range and the retry drops it`() {
        val args = buildJsonObject {
            put("count", -1)
            put("url", "https://a.b/")
        }
        val body =
            json(
                assertNotNull(
                    ToolArgs.rangeCheck("t", props, args, "t()", JsonObject(emptyMap()), false),
                ),
            )
        assertEquals(JsonPrimitive("out_of_range"), body["code"])
        assertEquals(JsonPrimitive("count"), body["param"])
        assertEquals(buildJsonObject { put("url", "https://a.b/") }, body["retry"])
        assertEquals(
            null,
            ToolArgs.rangeCheck("t", props, args, "t()", JsonObject(emptyMap()), true)?.let {
                json(it)["retry"]
            },
        )
    }
}
