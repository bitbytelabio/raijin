package io.bitbytelab.raijin.openapi

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class OpenApiSchemaTest {

    private fun json(text: String): JsonElement = Json.parseToJsonElement(text)

    private fun example(schema: String, doc: OpenApiDocument = components): JsonElement =
        OpenApiSchema.example(json(schema), doc)

    private val components = OpenApiDocument.parse(
        $$"""
        {"openapi": "3.0.3", "components": {"schemas": {
          "User": {"type": "object", "properties": {
            "id": {"type": "integer"},
            "name": {"type": "string"},
            "address": {"$ref": "#/components/schemas/Address"}}},
          "Address": {"type": "object", "properties": {"city": {"type": "string"}}},
          "Node": {"type": "object", "properties": {
            "value": {"type": "integer"},
            "next": {"$ref": "#/components/schemas/Node"}}},
          "Tree": {"type": "object", "properties": {
            "name": {"type": "string"},
            "children": {"type": "array", "items": {"$ref": "#/components/schemas/Tree"}}}},
          "Animal": {"type": "object", "properties": {"kind": {"type": "string"}},
            "oneOf": [{"$ref": "#/components/schemas/Dog"}]},
          "Dog": {"allOf": [
            {"$ref": "#/components/schemas/Animal"},
            {"type": "object", "properties": {"bark": {"type": "boolean"}}}]},
          "Alias": {"$ref": "#/components/schemas/Alias"},
          "a/b": {"type": "string", "enum": ["slash"]},
          "m~n": {"type": "string", "enum": ["tilde"]},
          "Page\u00abUser\u00bb": {"type": "string", "enum": ["generic"]}
        }}}
        """
    )

    // --- $ref, enum, example, default ---

    @Test
    fun `resolves a ref into a nested object`() {
        assertEquals(
            json("""{"id": 1, "name": "test", "address": {"city": "test"}}"""),
            example($$"""{"$ref": "#/components/schemas/User"}""")
        )
    }

    @Test
    fun `enum yields the first value`() {
        assertEquals("active", example("""{"type": "string", "enum": ["active", "banned"]}""").jsonPrimitive.content)
    }

    @Test
    fun `explicit example is honoured`() {
        assertEquals("foo", example("""{"type": "string", "example": "foo"}""").jsonPrimitive.content)
    }

    @Test
    fun `example is preferred to default and default to enum`() {
        assertEquals("desc", example("""{"type": "string", "enum": ["asc", "desc"], "default": "desc"}""").jsonPrimitive.content)
        assertEquals(
            "newest",
            example("""{"type": "string", "enum": ["asc", "desc"], "default": "desc", "example": "newest"}""").jsonPrimitive.content
        )
    }

    @Test
    fun `an example the schema states for itself is taken whole`() {
        assertEquals(
            json("""{"id": 7}"""),
            example($$"""{"$ref": "#/components/schemas/User", "example": {"id": 7}}""")
        )
    }

    @Test
    fun `a null example or default counts as absent`() {
        assertEquals("test", example("""{"type": "string", "example": null, "default": null}""").jsonPrimitive.content)
        assertEquals("b", example("""{"type": "string", "enum": [null, "b"]}""").jsonPrimitive.content)
    }

    @Test
    fun `array of refs produces a one-element list`() {
        assertEquals(
            json("""[{"city": "test"}]"""),
            example($$"""{"type": "array", "items": {"$ref": "#/components/schemas/Address"}}""")
        )
    }

    @Test
    fun `string format hints produce realistic values`() {
        assertEquals("test@example.com", example("""{"type": "string", "format": "email"}""").jsonPrimitive.content)
        assertEquals("2020-01-01T00:00:00Z", example("""{"type": "string", "format": "date-time"}""").jsonPrimitive.content)
    }

    // --- allOf / oneOf / anyOf ---

    @Test
    fun `allOf merges object properties`() {
        assertEquals(
            json("""{"a": "test", "b": 1}"""),
            example(
                """{"allOf": [
                    {"type": "object", "properties": {"a": {"type": "string"}}},
                    {"type": "object", "properties": {"b": {"type": "integer"}}}]}"""
            )
        )
    }

    @Test
    fun `allOf members are merged with sibling properties`() {
        val merged = example(
            $$"""{"allOf": [
                {"$ref": "#/components/schemas/Address"},
                {"type": "object", "properties": {"zip": {"type": "integer"}}}],
              "properties": {"primary": {"type": "boolean"}, "city": {"type": "string", "example": "Hanoi"}}}"""
        )
        // The schema's own `city` wins over the one Address declares.
        assertEquals(json("""{"primary": true, "city": "Hanoi", "zip": 1}"""), merged)
    }

    @Test
    fun `allOf around a single non-object schema yields that schema's value`() {
        assertEquals(
            "slash",
            example($$"""{"description": "wrapped", "allOf": [{"$ref": "#/components/schemas/a~1b"}]}""").jsonPrimitive.content
        )
    }

    @Test
    fun `an object example of an allOf member is merged with the other members`() {
        assertEquals(
            json("""{"id": 5, "extra": "test"}"""),
            example(
                """{"allOf": [
                    {"type": "object", "properties": {"id": {"type": "integer"}}, "example": {"id": 5}},
                    {"type": "object", "properties": {"extra": {"type": "string"}}}]}"""
            )
        )
    }

    @Test
    fun `oneOf picks the first resolvable branch`() {
        assertEquals(
            json("""{"city": "test"}"""),
            example(
                $$"""{"oneOf": [
                    {"$ref": "#/components/schemas/Missing"},
                    {"$ref": "other.yaml#/components/schemas/Elsewhere"},
                    {"$ref": "#/components/schemas/Address"},
                    {"type": "integer"}]}"""
            )
        )
    }

    @Test
    fun `anyOf skips the null branch OpenAPI 3_1 uses for nullable`() {
        assertEquals(
            "00000000-0000-0000-0000-000000000000",
            example("""{"anyOf": [{"type": "null"}, {"type": "string", "format": "uuid"}]}""").jsonPrimitive.content
        )
        assertEquals(JsonNull, example("""{"anyOf": [{"type": "null"}]}"""))
    }

    @Test
    fun `the chosen oneOf branch is merged with sibling properties`() {
        assertEquals(
            json("""{"id": 1, "card": "test"}"""),
            example(
                """{"type": "object", "properties": {"id": {"type": "integer"}}, "oneOf": [
                    {"type": "object", "properties": {"card": {"type": "string"}}},
                    {"type": "object", "properties": {"iban": {"type": "string"}}}]}"""
            )
        )
    }

    // --- OpenAPI 3.1 ---

    @Test
    fun `type arrays use the first non-null type`() {
        assertEquals("test", example("""{"type": ["string", "null"]}""").jsonPrimitive.content)
        assertEquals(json("1"), example("""{"type": ["null", "integer"]}"""))
        assertEquals(JsonNull, example("""{"type": ["null"]}"""))
        assertEquals(json("""{"n": "test"}"""), example("""{"type": ["object", "null"], "properties": {"n": {"type": "string"}}}"""))
    }

    @Test
    fun `const and the examples array are example values`() {
        assertEquals("card", example("""{"const": "card"}""").jsonPrimitive.content)
        assertEquals("first", example("""{"type": "string", "examples": ["first", "second"]}""").jsonPrimitive.content)
    }

    // --- numbers ---

    @Test
    fun `float and double numbers get a fractional example`() {
        assertEquals(json("1.5"), example("""{"type": "number", "format": "double"}"""))
        assertEquals(json("1.5"), example("""{"type": "number", "format": "float"}"""))
        assertEquals(json("1"), example("""{"type": "number"}"""))
        assertEquals(json("1"), example("""{"type": "integer", "format": "int64"}"""))
    }

    @Test
    fun `64-bit and fractional defaults keep their exact value`() {
        assertEquals(
            "9007199254740993",
            example("""{"type": "integer", "format": "int64", "default": 9007199254740993}""").jsonPrimitive.content
        )
        assertEquals("0.25", example("""{"type": "number", "format": "float", "default": 0.25}""").jsonPrimitive.content)
        assertEquals(
            json("""{"big": 9223372036854775807}"""),
            example("""{"type": "object", "properties": {"big": {"type": "integer", "example": 9223372036854775807}}}""")
        )
    }

    // --- $ref pointers ---

    @Test
    fun `pointer escapes ~1 and ~0 are decoded`() {
        assertEquals("slash", example($$"""{"$ref": "#/components/schemas/a~1b"}""").jsonPrimitive.content)
        assertEquals("tilde", example($$"""{"$ref": "#/components/schemas/m~0n"}""").jsonPrimitive.content)
    }

    @Test
    fun `a pointer is decoded as a URI fragment, and an unescaped name still resolves`() {
        assertEquals("generic", example($$"""{"$ref": "#/components/schemas/Page%C2%ABUser%C2%BB"}""").jsonPrimitive.content)
        assertEquals("generic", example($$"""{"$ref": "#/components/schemas/Page\u00abUser\u00bb"}""").jsonPrimitive.content)
    }

    @Test
    fun `a dangling or external ref degrades to a placeholder`() {
        assertEquals("test", example($$"""{"$ref": "#/components/schemas/Missing"}""").jsonPrimitive.content)
        assertEquals("test", example($$"""{"$ref": "https://example.com/schemas.json#/Pet"}""").jsonPrimitive.content)
    }

    // --- cyclic schemas ---

    @Test
    fun `circular refs terminate without overflow`() {
        assertEquals(json("""{"value": 1}"""), example($$"""{"$ref": "#/components/schemas/Node"}"""))
    }

    @Test
    fun `a recursive array ends as an empty list`() {
        assertEquals(json("""{"name": "test", "children": []}"""), example($$"""{"$ref": "#/components/schemas/Tree"}"""))
    }

    @Test
    fun `a schema that only refers to itself terminates`() {
        assertEquals("test", example($$"""{"$ref": "#/components/schemas/Alias"}""").jsonPrimitive.content)
    }

    @Test
    fun `polymorphism through allOf and oneOf that point at each other terminates`() {
        val expected = json("""{"kind": "test", "bark": true}""")
        assertEquals(expected, example($$"""{"$ref": "#/components/schemas/Dog"}"""))
        assertEquals(expected, example($$"""{"$ref": "#/components/schemas/Animal"}"""))
    }

    @Test
    fun `a schema that fans out exponentially yields a bounded example`() {
        // Eight levels of twelve properties each would be 12^8 values if every one were expanded.
        val levels = (0 until 8).joinToString(",") { level ->
            val properties = (0 until 12).joinToString(",") { $$""""p$$it": {"$ref": "#/components/schemas/L$${level + 1}"}""" }
            $$""""L$$level": {"type": "object", "properties": {$$properties}}"""
        }
        val doc = OpenApiDocument.parse("""{"openapi": "3.0.3", "components": {"schemas": {$levels, "L8": {"type": "string"}}}}""")

        val result = OpenApiSchema.example(json($$"""{"$ref": "#/components/schemas/L0"}"""), doc)

        fun count(element: JsonElement): Int = when (element) {
            is JsonObject -> 1 + element.values.sumOf { count(it) }
            is JsonArray -> 1 + element.sumOf { count(it) }
            else -> 1
        }
        val values = count(result)
        assertTrue(values in 1_000..10_000, "example holds $values values")
    }

    // --- constructs the generator does not know ---

    @Test
    fun `unknown constructs degrade to a placeholder instead of failing`() {
        assertEquals(
            json("""{"negated": "test", "anything": "test", "mystery": "test", "elsewhere": "test", "untyped": ["test"]}"""),
            example(
                $$"""{"type": "object", "properties": {
                    "negated": {"not": {"type": "string"}},
                    "anything": true,
                    "mystery": {"type": "mystery"},
                    "elsewhere": {"$ref": "other.yaml#/Thing"},
                    "untyped": {"type": "array"}}}"""
            )
        )
        assertEquals("test", OpenApiSchema.example(null, components).jsonPrimitive.content)
    }

    // --- whole documents: YAML, every $ref target, forms, server URLs ---

    private val yamlShop = $$"""
        openapi: 3.0.3
        info:
          title: Shop
          version: 1.0
        servers:
          - url: https://api.example.com/v1
        paths:
          /users/{id}:
            parameters:
              - $ref: '#/components/parameters/UserId'
            put:
              operationId: updateUser
              requestBody:
                $ref: '#/components/requestBodies/UserBody'
              responses:
                200:
                  description: ok
        components:
          parameters:
            UserId:
              name: id
              in: path
              required: true
              schema:
                type: integer
                example: 42
          requestBodies:
            UserBody:
              content:
                application/json:
                  schema:
                    $ref: '#/components/schemas/User'
          schemas:
            User:
              type: object
              properties:
                name:
                  type: string
                  example: no
                joined:
                  type: string
                  example: 2020-01-01
                admin:
                  type: boolean
        """.trimIndent()

    @Test
    fun `a YAML document imports like its JSON counterpart`() {
        val plan = OpenApiImport.plan(OpenApiDocument.parse(yamlShop))

        assertEquals("OpenAPI 3.0.3", plan.version)
        assertEquals("https://api.example.com/v1", plan.server.url)
        val request = plan.requests.single()
        assertEquals("PUT", request.method)
        assertEquals("updateUser", request.operationId)
        assertEquals("https://api.example.com/v1/users/42", request.url)
        val body = assertNotNull(request.body)
        assertEquals("application/json", body.contentType)
        // YAML 1.2 scalars: `no` and a date stay the strings the author wrote.
        assertEquals("""{"name":"no","joined":"2020-01-01","admin":true}""", body.text)
    }

    @Test
    fun `refs to components parameters and requestBodies are followed`() {
        val request = OpenApiImport.plan(OpenApiDocument.parse(yamlShop)).requests.single()
        assertEquals("/v1/users/42", request.target) // the `id` path parameter came through #/components/parameters
        assertEquals(json("""{"name": "no", "joined": "2020-01-01", "admin": true}"""), json(assertNotNull(request.body).text))
    }

    @Test
    fun `refs to components examples and pathItems are followed`() {
        val plan = OpenApiImport.plan(
            OpenApiDocument.parse(
                $$"""
                {"openapi": "3.1.0", "servers": [{"url": "https://api.example.com"}],
                 "paths": {"/search": {"$ref": "#/components/pathItems/Search"}},
                 "components": {
                   "pathItems": {"Search": {"get": {"parameters": [
                     {"name": "token", "in": "query", "schema": {"type": "string"},
                      "examples": {"one": {"$ref": "#/components/examples/Token"}}}]}}},
                   "examples": {"Token": {"value": "abc"}}}}
                """
            )
        )
        assertEquals("/search?token=abc", plan.requests.single().target)
    }

    @Test
    fun `Swagger 2 refs to parameters and definitions are followed`() {
        val plan = OpenApiImport.plan(
            OpenApiDocument.parse(
                $$"""
                {"swagger": "2.0", "host": "api.example.com", "schemes": ["https"],
                 "paths": {"/pets": {"post": {"parameters": [
                   {"$ref": "#/parameters/Limit"},
                   {"name": "pet", "in": "body", "schema": {"$ref": "#/definitions/Pet"}}]}}},
                 "parameters": {"Limit": {"name": "limit", "in": "query", "type": "integer", "default": 20}},
                 "definitions": {"Pet": {"type": "object", "properties": {"name": {"type": "string", "example": "Rex"}}}}}
                """
            )
        )
        val request = plan.requests.single()
        assertEquals("/pets?limit=20", request.target)
        assertEquals("""{"name":"Rex"}""", assertNotNull(request.body).text)
    }

    @Test
    fun `Swagger 2 formData parameters become a URL-encoded body`() {
        val plan = OpenApiImport.plan(
            OpenApiDocument.parse(
                """
                {"swagger": "2.0", "host": "api.example.com", "basePath": "/v2", "schemes": ["https"],
                 "paths": {"/pets/{petId}": {"post": {
                   "consumes": ["application/x-www-form-urlencoded"],
                   "parameters": [
                     {"name": "petId", "in": "path", "required": true, "type": "integer", "format": "int64"},
                     {"name": "name", "in": "formData", "type": "string", "default": "Rex & Co"},
                     {"name": "tags", "in": "formData", "type": "array", "items": {"type": "string"},
                      "collectionFormat": "pipes", "default": ["x y", "z"]}]}}}}
                """
            )
        )
        val request = plan.requests.single()
        assertEquals("POST", request.method)
        assertEquals("/v2/pets/1", request.target)
        val body = assertNotNull(request.body)
        assertEquals("application/x-www-form-urlencoded", body.contentType)
        assertEquals("name=Rex+%26+Co&tags=x+y%7Cz", body.text)
    }

    @Test
    fun `a multipart body has one part per field, files and objects typed`() {
        val plan = OpenApiImport.plan(
            OpenApiDocument.parse(
                """
                {"openapi": "3.0.3", "servers": [{"url": "https://api.example.com"}],
                 "paths": {"/upload": {"post": {"requestBody": {"content": {"multipart/form-data": {"schema": {
                   "type": "object", "properties": {
                     "note": {"type": "string", "example": "hi"},
                     "avatar": {"type": "string", "format": "binary"},
                     "meta": {"type": "object", "properties": {"k": {"type": "integer"}}}}}}}}}}}}
                """
            )
        )
        val body = assertNotNull(plan.requests.single().body)
        val boundary = OpenApiBodies.BOUNDARY
        assertEquals("multipart/form-data; boundary=$boundary", body.contentType)
        assertEquals(
            "--$boundary\r\n" +
                "Content-Disposition: form-data; name=\"note\"\r\n\r\nhi\r\n" +
                "--$boundary\r\n" +
                "Content-Disposition: form-data; name=\"avatar\"; filename=\"test.txt\"\r\n" +
                "Content-Type: application/octet-stream\r\n\r\ntest\r\n" +
                "--$boundary\r\n" +
                "Content-Disposition: form-data; name=\"meta\"\r\n" +
                "Content-Type: application/json\r\n\r\n{\"k\":1}\r\n" +
                "--$boundary--\r\n",
            body.text
        )
    }

    @Test
    fun `a relative server URL resolves against the document URL`() {
        val doc = OpenApiDocument.parse(
            """{"openapi": "3.0.3", "servers": [{"url": "/api/v3"}], "paths": {"/ping": {"get": {}}}}"""
        )

        val plan = OpenApiImport.plan(doc, documentUrl = "https://shop.example.com/docs/openapi.json")
        assertEquals("https://shop.example.com/api/v3", plan.server.url)
        assertEquals("https://shop.example.com/api/v3/ping", plan.requests.single().url)

        // Without the document URL there is nothing to resolve it against, and base_url is asked for.
        val failure = assertFailsWith<IllegalArgumentException> { OpenApiImport.plan(doc) }
        assertTrue("base_url" in failure.message.orEmpty(), failure.message)
    }

    @Test
    fun `anyOf nullable branch referenced via ref is deprioritized behind non-null branches`() {
        val doc = OpenApiDocument.parse(
            $$"""
            {"openapi": "3.1.0", "components": {"schemas": {
              "NullValue": {"type": "null"},
              "NullCycle": {"$ref": "#/components/schemas/NullCycle"},
              "NullableName": {"anyOf": [
                {"$ref": "#/components/schemas/NullValue"},
                {"$ref": "#/components/schemas/NullCycle"},
                {"type": "string", "example": "alice"}]}
            }}}
            """
        )
        assertEquals("alice", OpenApiSchema.example(json($$"""{"$ref": "#/components/schemas/NullableName"}"""), doc).jsonPrimitive.content)
    }
}
