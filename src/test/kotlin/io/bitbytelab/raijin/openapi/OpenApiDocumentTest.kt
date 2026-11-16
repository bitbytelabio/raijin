package io.bitbytelab.raijin.openapi

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class OpenApiDocumentTest {

    private fun json(text: String): JsonElement = Json.parseToJsonElement(text)

    private fun parseError(text: String): String =
        assertFailsWith<IllegalArgumentException> { OpenApiDocument.parse(text) }.message.orEmpty()

    // --- JSON ---

    @Test
    fun `a JSON document is parsed as written`() {
        val text = """{"openapi": "3.0.3", "info": {"version": 1.10}, "paths": {}}"""
        assertEquals(json(text), OpenApiDocument.parse(text).root)
    }

    @Test
    fun `a byte order mark and leading whitespace are ignored`() {
        assertEquals(json("""{"swagger": "2.0"}"""), OpenApiDocument.parse("\uFEFF \n{\"swagger\": \"2.0\"}").root)
    }

    // --- YAML ---

    @Test
    fun `YAML scalars follow the 1_2 core schema, not YAML 1_1`() {
        val root = OpenApiDocument.parse(
            """
            enabled: no
            mode: 0755
            opens: 12:30
            since: 2020-01-01
            hex: 0x1F
            grouped: 1_000
            flag: true
            count: 42
            ratio: 1.50
            tilde: ~
            empty:
            quoted: "123"
            200: ok
            """.trimIndent()
        ).root

        assertEquals(
            json(
                """
                {"enabled": "no", "mode": "0755", "opens": "12:30", "since": "2020-01-01", "hex": "0x1F",
                 "grouped": "1_000", "flag": true, "count": 42, "ratio": 1.50, "tilde": null, "empty": null,
                 "quoted": "123", "200": "ok"}
                """
            ),
            root
        )
    }

    @Test
    fun `YAML numbers keep 64-bit and fractional precision`() {
        val root = OpenApiDocument.parse("big: 9223372036854775807\nhuge: 123456789012345678901234567890\nfine: 0.1000").root
        assertEquals("9223372036854775807", root.getValue("big").jsonPrimitive.content)
        assertEquals("123456789012345678901234567890", root.getValue("huge").jsonPrimitive.content)
        assertEquals("0.1000", root.getValue("fine").jsonPrimitive.content)
        assertTrue(root.values.none { it.jsonPrimitive.isString })
    }

    @Test
    fun `anchors, aliases and merge keys are applied`() {
        val root = OpenApiDocument.parse(
            """
            base: &base
              type: object
              required: [id]
            derived:
              <<: *base
              type: string
            both: [*base, *base]
            """.trimIndent()
        ).root

        assertEquals(
            json(
                """
                {"base": {"type": "object", "required": ["id"]},
                 "derived": {"type": "string", "required": ["id"]},
                 "both": [{"type": "object", "required": ["id"]}, {"type": "object", "required": ["id"]}]}
                """
            ),
            root
        )
    }

    @Test
    fun `a merge key takes a list of mappings, the earlier one winning`() {
        val root = OpenApiDocument.parse(
            """
            a: &a {x: 1, y: 1}
            b: &b {y: 2, z: 2}
            merged:
              <<: [*a, *b]
              z: 3
            literal:
              "<<": kept
            """.trimIndent()
        ).root

        assertEquals(json("""{"x": 1, "y": 1, "z": 3}"""), root["merged"])
        assertEquals(json("""{"<<": "kept"}"""), root["literal"])
    }

    @Test
    fun `tags outside the JSON types are read as plain data`() {
        val root = OpenApiDocument.parse(
            """
            arn: !Sub arn:aws:lambda
            ids: !!set {a, b}
            text: !!str 123
            number: !!int "7"
            """.trimIndent()
        ).root

        assertEquals(json("""{"arn": "arn:aws:lambda", "ids": {"a": null, "b": null}, "text": "123", "number": 7}"""), root)
    }

    @Test
    fun `flow-style YAML that starts like JSON is still read`() {
        assertEquals(
            json("""{"openapi": "3.0.0", "paths": {}}"""),
            OpenApiDocument.parse("{openapi: 3.0.0, paths: {}}").root
        )
    }

    @Test
    fun `an alias to an enclosing collection becomes null instead of recursing`() {
        assertEquals(json("""{"loop": [1, null]}"""), OpenApiDocument.parse("loop: &loop [1, *loop]").root)
    }

    @Test
    fun `an alias bomb is refused`() {
        // Ten levels, each holding ten aliases to the one before: 10^10 values once expanded.
        val bomb = buildString {
            append("a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n")
            for (level in 1..9) {
                append("a$level: &a$level [").append((1..10).joinToString(", ") { "*a${level - 1}" }).append("]\n")
            }
        }
        assertTrue("expands to more than" in parseError(bomb))
    }

    @Test
    fun `aliases that chain into a deep structure are refused`() {
        // No line nests deeper than two levels, yet the expanded value is 300 lists deep.
        val chain = buildString {
            append("a0: &a0 []\n")
            for (level in 1..300) append("a$level: &a$level [*a${level - 1}]\n")
        }
        assertTrue("nested more than" in parseError(chain))
    }

    // --- unusable input ---

    @Test
    fun `a JSON document nested too deeply is refused`() {
        val deep = "{\"a\":" + "[".repeat(300) + "]".repeat(300) + "}"
        assertTrue("nested more than" in parseError(deep))
    }

    @Test
    fun `a JSON document nested beyond the parser's stack is refused rather than overflowing it`() {
        val abyss = "{\"a\":" + "[".repeat(200_000) + "]".repeat(200_000) + "}"
        assertFailsWith<IllegalArgumentException> { OpenApiDocument.parse(abyss) }
    }

    @Test
    fun `text that is neither JSON nor YAML is reported with both reasons`() {
        val message = parseError("""{"paths": [1, 2}""")
        assertTrue("neither valid JSON" in message, message)
        assertTrue("nor valid YAML" in message, message)
    }

    @Test
    fun `broken YAML is reported`() {
        assertTrue("not valid YAML" in parseError("paths: [1, 2"))
    }

    @Test
    fun `empty input, HTML and non-object documents are refused`() {
        assertTrue("empty" in parseError(" \n "))
        assertTrue("HTML" in parseError("<!DOCTYPE html><html><body>Swagger UI</body></html>"))
        assertTrue("top level" in parseError("- just\n- a list"))
        assertTrue("top level" in parseError("only a sentence"))
    }

    // --- $ref lookup ---

    private val doc = OpenApiDocument.parse(
        $$"""
        {"paths": {"/pets/{id}": {"get": {"parameters": [{"name": "id"}, {"name": "verbose"}]}}},
         "components": {"schemas": {"a/b": {"type": "string"}, "m~n": {"type": "integer"}, "100%": {"type": "boolean"}},
                        "parameters": {"First": {"$ref": "#/components/parameters/Second"},
                                       "Second": {"name": "limit", "in": "query"},
                                       "Ping": {"$ref": "#/components/parameters/Pong"},
                                       "Pong": {"$ref": "#/components/parameters/Ping"}}}}
        """
    )

    @Test
    fun `a pointer walks objects and arrays`() {
        assertEquals(json("""{"name": "verbose"}"""), doc.resolve("#/paths/~1pets~1{id}/get/parameters/1"))
        assertEquals(json("""{"name": "id"}"""), doc.resolve("#/paths/~1pets~1%7Bid%7D/get/parameters/0"))
        assertSame(doc.root, doc.resolve("#"))
    }

    @Test
    fun `pointer escapes and literal names resolve`() {
        assertEquals(json("""{"type": "string"}"""), doc.resolve("#/components/schemas/a~1b"))
        assertEquals(json("""{"type": "integer"}"""), doc.resolve("#/components/schemas/m~0n"))
        assertEquals(json("""{"type": "boolean"}"""), doc.resolve("#/components/schemas/100%25"))
        assertEquals(json("""{"type": "boolean"}"""), doc.resolve("#/components/schemas/100%"))
    }

    @Test
    fun `external, dangling and malformed references do not resolve`() {
        assertNull(doc.resolve("other.yaml#/components/schemas/a~1b"))
        assertNull(doc.resolve("#/components/schemas/Missing"))
        assertNull(doc.resolve("#/paths/~1pets~1{id}/get/parameters/7"))
        assertNull(doc.resolve("#components"))
    }

    @Test
    fun `deref follows a chain of references and stops on a loop`() {
        val first = doc.root.getValue("components").jsonObject.getValue("parameters").jsonObject.getValue("First")
        assertEquals<JsonElement?>(json("""{"name": "limit", "in": "query"}"""), doc.deref(first))
        assertNull(doc.deref(json($$"""{"$ref": "#/components/parameters/Ping"}""")))
        assertNull(doc.deref(json($$"""{"$ref": "#/components/parameters/Missing"}""")))
        assertNull(doc.deref(json("\"not an object\"")))
    }
}
