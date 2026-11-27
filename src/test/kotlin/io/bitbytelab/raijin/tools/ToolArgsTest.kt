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
import kotlinx.serialization.json.jsonObject
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
        assertEquals(listOf("ignored empty optional 'mode', 'tags'"), c.notes)
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
                "ignored 0 'port': below its minimum 1",
                "empty 'method' read as unset; send an empty method with raw_request",
                "ignored empty 'host'",
            ),
            c.notes,
        )
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
