package io.bitbytelab.raijin.openapi

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class OpenApiImportTest {

    private fun json(text: String): JsonElement = Json.parseToJsonElement(text)

    private fun plan(text: String, baseUrl: String? = null, documentUrl: String? = null): ImportPlan =
        OpenApiImport.plan(OpenApiDocument.parse(text), baseUrl, documentUrl)

    /** Requests keyed the way a request line reads: `GET /path?query`. */
    private fun ImportPlan.byLine(): Map<String, PlannedRequest> = requests.associateBy { "${it.method} ${it.target}" }

    // --- a Swagger 2.0 JSON document ---

    private val petstore = $$"""
        {
          "swagger": "2.0",
          "info": {"title": "Petstore", "version": "1.0.0"},
          "host": "petstore.example.com",
          "basePath": "/v2",
          "schemes": ["http", "https"],
          "consumes": ["application/json"],
          "security": [{"api_key": []}],
          "paths": {
            "/pet": {
              "post": {
                "operationId": "addPet",
                "summary": "Add a pet",
                "tags": ["pet"],
                "consumes": ["application/xml", "application/json"],
                "security": [{"petstore_auth": ["write:pets"]}],
                "parameters": [{"in": "body", "name": "body", "required": true, "schema": {"$ref": "#/definitions/Pet"}}]
              }
            },
            "/pet/findByStatus": {
              "get": {
                "parameters": [{
                  "name": "status", "in": "query", "required": true, "type": "array", "collectionFormat": "multi",
                  "items": {"type": "string", "enum": ["available", "pending", "sold"], "default": "available"}
                }]
              }
            },
            "/pet/{petId}": {
              "get": {
                "parameters": [{"name": "petId", "in": "path", "required": true, "type": "integer", "format": "int64"}]
              },
              "post": {
                "consumes": ["application/x-www-form-urlencoded"],
                "parameters": [
                  {"name": "petId", "in": "path", "required": true, "type": "integer", "format": "int64"},
                  {"name": "name", "in": "formData", "type": "string"},
                  {"name": "status", "in": "formData", "type": "string"}
                ]
              },
              "delete": {
                "parameters": [
                  {"name": "api_key", "in": "header", "type": "string"},
                  {"name": "petId", "in": "path", "required": true, "type": "integer", "format": "int64"}
                ]
              }
            },
            "/pet/{petId}/uploadImage": {
              "post": {
                "consumes": ["multipart/form-data"],
                "parameters": [
                  {"name": "petId", "in": "path", "required": true, "type": "integer", "format": "int64"},
                  {"name": "additionalMetadata", "in": "formData", "type": "string"},
                  {"name": "file", "in": "formData", "type": "file"}
                ]
              }
            }
          },
          "securityDefinitions": {
            "petstore_auth": {
              "type": "oauth2", "flow": "implicit",
              "authorizationUrl": "https://petstore.example.com/oauth/authorize",
              "scopes": {"write:pets": "modify pets"}
            },
            "api_key": {"type": "apiKey", "name": "api_key", "in": "header", "x-internal": true},
            "login": {"type": "basic"}
          },
          "definitions": {
            "Pet": {
              "type": "object",
              "required": ["name", "photoUrls"],
              "properties": {
                "id": {"type": "integer", "format": "int64"},
                "name": {"type": "string", "example": "doggie"},
                "photoUrls": {"type": "array", "items": {"type": "string"}},
                "status": {"type": "string", "enum": ["available", "pending", "sold"]}
              }
            }
          }
        }
        """

    @Test
    fun `a Swagger 2 JSON document becomes one request per operation`() {
        val plan = plan(petstore)

        assertEquals("Swagger 2.0", plan.version)
        assertEquals("https://petstore.example.com/v2", plan.server.url) // https is preferred when both are offered
        assertEquals(
            listOf(
                "POST /v2/pet",
                "GET /v2/pet/findByStatus?status=available",
                "GET /v2/pet/1",
                "POST /v2/pet/1",
                "DELETE /v2/pet/1",
                "POST /v2/pet/1/uploadImage"
            ),
            plan.requests.map { "${it.method} ${it.target}" }
        )
        assertTrue(plan.warnings.isEmpty(), plan.warnings.toString())
    }

    @Test
    fun `a Swagger 2 body parameter becomes a JSON body built from the referenced definition`() {
        val request = plan(petstore).byLine().getValue("POST /v2/pet")

        assertEquals("addPet", request.operationId)
        assertEquals("Add a pet", request.summary)
        assertEquals(listOf("pet"), request.tags)
        val body = assertNotNull(request.body)
        assertEquals("application/json", body.contentType) // JSON is preferred to the XML listed first
        assertEquals("""{"id":1,"name":"doggie","photoUrls":["test"],"status":"available"}""", body.text)
    }

    @Test
    fun `Swagger 2 form and file parameters become form bodies`() {
        val requests = plan(petstore).byLine()

        val form = assertNotNull(requests.getValue("POST /v2/pet/1").body)
        assertEquals("application/x-www-form-urlencoded", form.contentType)
        assertEquals("name=test&status=test", form.text)

        val upload = assertNotNull(requests.getValue("POST /v2/pet/1/uploadImage").body)
        val boundary = OpenApiBodies.BOUNDARY
        assertEquals("multipart/form-data; boundary=$boundary", upload.contentType)
        assertEquals(
            "--$boundary\r\n" +
                "Content-Disposition: form-data; name=\"additionalMetadata\"\r\n\r\ntest\r\n" +
                "--$boundary\r\n" +
                "Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n" +
                "Content-Type: application/octet-stream\r\n\r\ntest\r\n" +
                "--$boundary--\r\n",
            upload.text
        )
    }

    @Test
    fun `header parameters travel as headers, and a request without a body has none`() {
        val delete = plan(petstore).byLine().getValue("DELETE /v2/pet/1")
        assertEquals(listOf("api_key" to "test"), delete.headers)
        assertNull(delete.body)
        assertEquals(0, delete.queryParameters)
    }

    @Test
    fun `security schemes say how each credential is carried, and operations which ones they need`() {
        val plan = plan(petstore)

        val schemes = plan.securitySchemes
        assertEquals(setOf("petstore_auth", "api_key", "login"), schemes.keys)
        assertEquals(
            json("""{"type": "apiKey", "name": "api_key", "in": "header", "credential": "header api_key: <api key>"}"""),
            schemes["api_key"] // the vendor extension is left out
        )
        assertEquals(
            "header Authorization: Bearer <access token>",
            schemes.getValue("petstore_auth").jsonObject.getValue("credential").jsonPrimitive.content
        )
        assertEquals(
            "header Authorization: Basic <base64(user:password)>",
            schemes.getValue("login").jsonObject.getValue("credential").jsonPrimitive.content
        )

        val requests = plan.byLine()
        assertEquals<JsonElement?>(json("""[{"petstore_auth": ["write:pets"]}]"""), requests.getValue("POST /v2/pet").security)
        // An operation without its own requirement falls under the document's.
        assertEquals<JsonElement?>(json("""[{"api_key": []}]"""), requests.getValue("GET /v2/pet/1").security)
    }

    // --- an OpenAPI 3.0 YAML document ---

    private val shop = """
        openapi: 3.0.3
        info:
          title: Shop
          version: 1.0
        servers:
          - url: https://{tenant}.example.com/api/{version}
            variables:
              tenant:
                default: acme
              version:
                enum: [v1, v2]
                default: v2
        security:
          - bearer: []
        paths:
          /orders/{orderId}/items:
            parameters:
              - name: orderId
                in: path
                required: true
                schema:
                  type: string
                  example: a/b c
              - name: limit
                in: query
                schema:
                  type: integer
                  default: 10
            get:
              operationId: listItems
              tags: [orders]
              parameters:
                - name: limit
                  in: query
                  schema:
                    type: integer
                    example: 50
                - name: status
                  in: query
                  schema:
                    type: array
                    items:
                      type: string
                      enum: [open, closed]
                - name: q
                  in: query
                  schema:
                    type: string
                    example: a&b=c d
                - name: session
                  in: cookie
                  schema:
                    type: string
                    example: abc 123
                - name: theme
                  in: cookie
                  schema:
                    type: string
                    enum: [dark]
                - name: X-Trace
                  in: header
                  schema:
                    type: string
                    format: uuid
            delete:
              operationId: deleteItems
              security: []
              requestBody:
                content:
                  application/vnd.api+json:
                    schema:
                      type: object
                      properties:
                        ids:
                          type: array
                          items:
                            type: integer
                            format: int64
        components:
          securitySchemes:
            bearer:
              type: http
              scheme: bearer
              bearerFormat: JWT
            session:
              type: apiKey
              in: cookie
              name: session
        """.trimIndent()

    @Test
    fun `an OpenAPI 3_0 YAML document imports with its server variables filled in`() {
        val plan = plan(shop)

        assertEquals("OpenAPI 3.0.3", plan.version)
        assertEquals("https://acme.example.com/api/v2", plan.server.url)
        assertEquals(listOf("GET", "DELETE"), plan.requests.map { it.method })
    }

    @Test
    fun `path and query values are percent-encoded, and an operation parameter overrides the path-level one`() {
        val get = plan(shop).requests.first()

        // `a/b c` stays one path segment; `limit` is sent once, with the operation's value.
        assertEquals("/api/v2/orders/a%2Fb%20c/items?limit=50&status=open&q=a%26b%3Dc%20d", get.target)
        assertEquals(3, get.queryParameters)
        assertEquals(listOf("orders"), get.tags)
        assertEquals("https://acme.example.com/api/v2/orders/a%2Fb%20c/items?limit=50&status=open&q=a%26b%3Dc%20d", get.url)
    }

    @Test
    fun `cookie parameters are joined into one Cookie header`() {
        val get = plan(shop).requests.first()
        assertEquals(
            listOf(
                "X-Trace" to "00000000-0000-0000-0000-000000000000",
                "Cookie" to "session=abc%20123; theme=dark"
            ),
            get.headers
        )
    }

    @Test
    fun `DELETE carries the body its operation declares, under a +json media type`() {
        val delete = plan(shop).requests.last()

        assertEquals("DELETE", delete.method)
        assertEquals("/api/v2/orders/a%2Fb%20c/items?limit=10", delete.target) // only the path-level parameters apply
        val body = assertNotNull(delete.body)
        assertEquals("application/vnd.api+json", body.contentType)
        assertEquals("""{"ids":[1]}""", body.text)
    }

    @Test
    fun `an empty security requirement overrides the document default`() {
        val plan = plan(shop)

        assertEquals<JsonElement?>(json("""[{"bearer": []}]"""), plan.requests.first().security)
        assertEquals<JsonElement?>(JsonArray(emptyList()), plan.requests.last().security)
        assertEquals(
            json(
                """
                {"bearer": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT",
                            "credential": "header Authorization: Bearer <token>"},
                 "session": {"type": "apiKey", "in": "cookie", "name": "session",
                             "credential": "cookie session=<api key>"}}
                """
            ),
            plan.securitySchemes
        )
    }

    // --- an OpenAPI 3.1 document ---

    private val pay = $$"""
        {
          "openapi": "3.1.0",
          "info": {"title": "Pay", "version": "1"},
          "servers": [{"url": "/pay"}],
          "paths": {
            "/charges": {"$ref": "#/components/pathItems/Charges"}
          },
          "webhooks": {
            "paid": {"post": {"requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}}}}
          },
          "components": {
            "pathItems": {
              "Charges": {
                "post": {
                  "operationId": "createCharge",
                  "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Charge"}}}}
                }
              }
            },
            "schemas": {
              "Charge": {
                "type": "object",
                "properties": {
                  "amount": {"type": ["integer", "null"], "format": "int64", "examples": [9007199254740993]},
                  "currency": {"type": "string", "const": "EUR"},
                  "note": {"type": ["null", "string"]},
                  "rate": {"type": "number", "format": "double"},
                  "source": {"oneOf": [{"$ref": "#/components/schemas/Card"}, {"$ref": "#/components/schemas/Iban"}]},
                  "parent": {"$ref": "#/components/schemas/Charge"}
                }
              },
              "Card": {
                "type": "object",
                "properties": {"kind": {"const": "card"}, "number": {"type": "string", "default": "4242424242424242"}}
              },
              "Iban": {"type": "object", "properties": {"kind": {"const": "iban"}}}
            },
            "securitySchemes": {"mtls": {"type": "mutualTLS"}}
          }
        }
        """

    @Test
    fun `an OpenAPI 3_1 document imports, its relative server resolved against the document URL`() {
        val plan = plan(pay, documentUrl = "https://pay.example.com/spec/openapi.json")

        assertEquals("OpenAPI 3.1.0", plan.version)
        assertEquals("https://pay.example.com/pay", plan.server.url)
        val request = plan.requests.single() // the webhook is not a request to the API
        assertEquals("POST", request.method)
        assertEquals("createCharge", request.operationId)
        assertEquals("https://pay.example.com/pay/charges", request.url)
        val body = assertNotNull(request.body)
        assertEquals("application/json", body.contentType)
        assertEquals(
            """{"amount":9007199254740993,"currency":"EUR","note":"test","rate":1.5,""" +
                """"source":{"kind":"card","number":"4242424242424242"}}""",
            body.text
        )
        assertEquals(
            "TLS client certificate",
            plan.securitySchemes.getValue("mtls").jsonObject.getValue("credential").jsonPrimitive.content
        )
    }

    // --- bodies ---

    private fun bodyOf(content: String, schemas: String = "{}"): PlannedBody = assertNotNull(
        plan(
            """
            {"openapi": "3.0.3", "servers": [{"url": "https://api.example.com"}],
             "paths": {"/things": {"post": {"requestBody": {"content": $content}}}},
             "components": {"schemas": $schemas}}
            """
        ).requests.single().body
    )

    @Test
    fun `an XML body follows the xml hints of the schema`() {
        val body = bodyOf(
            $$"""{"application/xml": {"schema": {"$ref": "#/components/schemas/Pet"}}}""",
            """
            {"Pet": {"type": "object", "xml": {"name": "pet"}, "properties": {
               "id": {"type": "integer", "xml": {"attribute": true}},
               "name": {"type": "string", "example": "Tom & Jerry"},
               "tags": {"type": "array", "xml": {"wrapped": true}, "items": {"type": "string", "xml": {"name": "tag"}}},
               "photos": {"type": "array", "items": {"type": "string"}},
               "owner": {"type": "object", "xml": {"prefix": "o", "namespace": "urn:owner"},
                         "properties": {"first name": {"type": "string"}}}}}}
            """
        )

        assertEquals("application/xml", body.contentType)
        assertEquals(
            """<?xml version="1.0" encoding="UTF-8"?>""" +
                """<pet id="1"><name>Tom &amp; Jerry</name><tags><tag>test</tag></tags><photos>test</photos>""" +
                """<o:owner xmlns:o="urn:owner"><first_name>test</first_name></o:owner></pet>""",
            body.text
        )
    }

    @Test
    fun `an XML body without hints is named after the schema, a top-level array wrapped`() {
        val schemas = """{"Pet": {"type": "object", "properties": {"id": {"type": "integer"}}}}"""
        assertEquals(
            """<?xml version="1.0" encoding="UTF-8"?><Pet><id>1</id></Pet>""",
            bodyOf($$"""{"text/xml": {"schema": {"$ref": "#/components/schemas/Pet"}}}""", schemas).text
        )
        assertEquals(
            """<?xml version="1.0" encoding="UTF-8"?><root><Pet><id>1</id></Pet></root>""",
            bodyOf(
                $$"""{"application/xml": {"schema": {"type": "array", "items": {"$ref": "#/components/schemas/Pet"}}}}""",
                schemas
            ).text
        )
    }

    @Test
    fun `JSON is preferred among several media types, then a form`() {
        val schema = """{"schema": {"type": "object", "properties": {"a": {"type": "integer"}}}}"""
        val preferred = bodyOf(
            """{"application/xml": $schema, "application/x-www-form-urlencoded": $schema, "application/problem+json": $schema}"""
        )
        assertEquals("application/problem+json", preferred.contentType)
        assertEquals("""{"a":1}""", preferred.text)

        val form = bodyOf("""{"text/plain": $schema, "application/x-www-form-urlencoded": $schema}""")
        assertEquals("application/x-www-form-urlencoded", form.contentType)
        assertEquals("a=1", form.text)
    }

    @Test
    fun `a media type example is used in place of one generated from the schema`() {
        val direct = bodyOf("""{"application/json": {"schema": {"type": "object"}, "example": {"id": 7}}}""")
        assertEquals("""{"id":7}""", direct.text)

        val named = bodyOf("""{"application/json": {"examples": {"first": {"value": {"id": 8}}, "second": {"value": {"id": 9}}}}}""")
        assertEquals("""{"id":8}""", named.text)

        // A JSON document given as a string (common in YAML) is sent as that document.
        val quoted = bodyOf("""{"application/json": {"example": "{\"id\": 10}"}}""")
        assertEquals("""{"id": 10}""", quoted.text)

        // A form body written out as one string is sent as it stands.
        val form = bodyOf("""{"application/x-www-form-urlencoded": {"example": "grant_type=client_credentials&scope=a+b"}}""")
        assertEquals("grant_type=client_credentials&scope=a+b", form.text)
    }

    @Test
    fun `a URL-encoded body follows the encoding object`() {
        val body = bodyOf(
            """
            {"application/x-www-form-urlencoded": {
               "schema": {"type": "object", "properties": {
                 "name": {"type": "string", "example": "a b&c"},
                 "ids": {"type": "array", "items": {"type": "integer"}, "example": [1, 2]},
                 "csv": {"type": "array", "items": {"type": "integer"}, "example": [3, 4]},
                 "filter": {"type": "object", "properties": {"k": {"type": "string", "example": "v"}}}}},
               "encoding": {"csv": {"style": "form", "explode": false}, "filter": {"style": "deepObject"}}}}
            """
        )
        assertEquals("name=a+b%26c&ids=1&ids=2&csv=3,4&filter%5Bk%5D=v", body.text)
    }

    @Test
    fun `media types the importer cannot model still get a body`() {
        val wildcard = bodyOf("""{"*/*": {"schema": {"type": "object", "properties": {"a": {"type": "boolean"}}}}}""")
        assertEquals("application/json", wildcard.contentType)
        assertEquals("""{"a":true}""", wildcard.text)

        val binary = bodyOf("""{"application/x-protobuf": {}}""")
        assertEquals("application/x-protobuf", binary.contentType)
        assertEquals("test", binary.text)

        val text = bodyOf("""{"text/plain": {"schema": {"type": "string", "example": "hello"}}}""")
        assertEquals("text/plain", text.contentType)
        assertEquals("hello", text.text)

        val empty = bodyOf("""{"application/json": {}}""")
        assertEquals("{}", empty.text)
    }

    // --- parameters ---

    private fun targetOf(path: String, parameters: String): String = plan(
        """
        {"openapi": "3.0.3", "servers": [{"url": "https://api.example.com/base/"}],
         "paths": {"$path": {"get": {"parameters": $parameters}}}}
        """
    ).requests.single().target

    @Test
    fun `an undeclared placeholder is filled and the literal part of a path is escaped`() {
        assertEquals(
            "/base/files/my%20docs/x/1",
            targetOf("/files/my docs/{fileId}/{undeclared}", """[{"name": "fileId", "in": "path", "schema": {"type": "string", "example": "x"}}]""")
        )
    }

    @Test
    fun `a fragment in the path template is dropped and a literal query kept`() {
        assertEquals(
            "/base/rpc?Action=List&page=1",
            targetOf("/rpc?Action=List#list", """[{"name": "page", "in": "query", "schema": {"type": "integer"}}]""")
        )
    }

    @Test
    fun `parameter examples come from example, examples, then the schema`() {
        assertEquals(
            "/base/p?a=direct&b=named&c=5&d=test",
            targetOf(
                "/p",
                """
                [{"name": "a", "in": "query", "example": "direct", "schema": {"type": "string", "example": "ignored"}},
                 {"name": "b", "in": "query", "examples": {"one": {"value": "named"}}, "schema": {"type": "string"}},
                 {"name": "c", "in": "query", "schema": {"type": "integer", "minimum": 5, "default": 5}},
                 {"name": "d", "in": "query"}]
                """
            )
        )
    }

    @Test
    fun `a parameter described by content is sent as one serialised value`() {
        assertEquals(
            "/base/p?filter=%7B%22a%22%3A1%7D",
            targetOf(
                "/p",
                """[{"name": "filter", "in": "query", "content": {"application/json": {"schema": {
                     "type": "object", "properties": {"a": {"type": "integer"}}}}}}]"""
            )
        )
    }

    @Test
    fun `style and explode decide how arrays and objects are spread`() {
        assertEquals(
            "/base/p/1,2?ids=1&ids=2&csv=1,2&pipes=1%7C2&deep%5Bk%5D=v&obj=v&keep=a/b?c",
            targetOf(
                "/p/{list}",
                """
                [{"name": "list", "in": "path", "schema": {"type": "array", "items": {"type": "integer"}}, "example": [1, 2]},
                 {"name": "ids", "in": "query", "example": [1, 2]},
                 {"name": "csv", "in": "query", "explode": false, "example": [1, 2]},
                 {"name": "pipes", "in": "query", "style": "pipeDelimited", "example": [1, 2]},
                 {"name": "deep", "in": "query", "style": "deepObject", "example": {"k": "v"}},
                 {"name": "ignored", "in": "query", "example": {"obj": "v"}},
                 {"name": "keep", "in": "query", "allowReserved": true, "example": "a/b?c"}]
                """
            )
        )
    }

    @Test
    fun `a line break in a header example cannot split the header`() {
        val request = plan(
            """
            {"openapi": "3.0.3", "servers": [{"url": "https://api.example.com"}],
             "paths": {"/p": {"get": {"parameters": [
               {"name": "X-Note", "in": "header", "example": "one\r\nX-Injected: two"},
               {"name": "X-List", "in": "header", "example": ["a", "b"]}]}}}}
            """
        ).requests.single()
        assertEquals(listOf("X-Note" to "oneX-Injected: two", "X-List" to "a,b"), request.headers)
    }

    @Test
    fun `a declared Content-Type header gives way to the body's`() {
        val request = plan(
            """
            {"openapi": "3.0.3", "servers": [{"url": "https://api.example.com"}],
             "paths": {"/p": {"post": {
               "parameters": [{"name": "content-type", "in": "header", "example": "text/plain"}],
               "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}}}}}}
            """
        ).requests.single()
        assertTrue(request.headers.isEmpty(), request.headers.toString())
        assertEquals("application/json", assertNotNull(request.body).contentType)
    }

    @Test
    fun `headers the connection sets itself are not given placeholder values`() {
        // Documents generated from captured traffic list every header that was seen.
        val request = plan(
            """
            {"openapi": "3.0.3", "servers": [{"url": "https://api.example.com"}],
             "paths": {"/p": {"get": {"parameters": [
               {"name": "Host", "in": "header", "schema": {"type": "string"}},
               {"name": "Content-Length", "in": "header", "schema": {"type": "integer"}},
               {"name": "Transfer-Encoding", "in": "header", "schema": {"type": "string"}},
               {"name": "connection", "in": "header", "schema": {"type": "string"}},
               {"name": "User-Agent", "in": "header", "schema": {"type": "string", "example": "probe/1.0"}}]}}}}
            """
        ).requests.single()
        assertEquals(listOf("User-Agent" to "probe/1.0"), request.headers)
    }

    // --- servers ---

    @Test
    fun `base_url replaces every server of the document`() {
        val document = """
            {"openapi": "3.0.3", "servers": [{"url": "https://prod.example.com/v1"}],
             "paths": {"/files": {"servers": [{"url": "https://files.example.com"}], "get": {}},
                       "/admin": {"get": {"servers": [{"url": "https://admin.example.com/internal"}]}},
                       "/ping": {"get": {}}}}
            """

        val declared = plan(document)
        assertEquals("https://prod.example.com/v1", declared.server.url)
        assertEquals(
            listOf("https://files.example.com/files", "https://admin.example.com/internal/admin", "https://prod.example.com/v1/ping"),
            declared.requests.map { it.url }
        )

        val pinned = plan(document, baseUrl = " http://127.0.0.1:8080/stage ")
        assertEquals("http://127.0.0.1:8080/stage", pinned.server.url)
        assertEquals(
            listOf("http://127.0.0.1:8080/stage/files", "http://127.0.0.1:8080/stage/admin", "http://127.0.0.1:8080/stage/ping"),
            pinned.requests.map { it.url }
        )
    }

    @Test
    fun `an unusable server or base URL is an error before anything is planned`() {
        val document = """{"openapi": "3.0.3", "servers": [{"url": "https://{tenant}.example.com"}], "paths": {}}"""
        assertTrue("No usable server URL" in assertFailsWith<IllegalArgumentException> { plan(document) }.message.orEmpty())
        assertEquals(
            "Invalid base URL: ftp://files.example.com",
            assertFailsWith<IllegalArgumentException> { plan(document, baseUrl = "ftp://files.example.com") }.message
        )
    }

    @Test
    fun `a Swagger 2 document without host is served from where it was downloaded`() {
        val plan = plan(
            """{"swagger": "2.0", "basePath": "api", "paths": {"/ping": {"get": {}}}}""",
            documentUrl = "http://localhost:8080/v2/api-docs"
        )
        assertEquals("http://localhost:8080/api", plan.server.url)
        assertEquals("http://localhost:8080/api/ping", plan.requests.single().url)
    }

    // --- documents that are not quite right ---

    @Test
    fun `a document that is not OpenAPI or Swagger is refused`() {
        val failure = assertFailsWith<IllegalArgumentException> { plan("""{"paths": {}}""") }
        assertTrue("missing 'openapi' or 'swagger'" in failure.message.orEmpty())
    }

    @Test
    fun `malformed parts of a document are skipped, the rest is imported`() {
        val plan = plan(
            $$"""
            {"openapi": "3.0.3", "servers": [{"url": "https://api.example.com"}],
             "paths": {
               "x-internal": {"get": {}},
               "/broken": "not a path item",
               "/dangling": {"$ref": "#/components/pathItems/Missing"},
               "/odd": {
                 "parameters": "none",
                 "get": {
                   "parameters": [
                     {"$ref": "#/components/parameters/Missing"},
                     {"in": "query"},
                     "junk",
                     {"name": "ok", "in": "query", "schema": {"$ref": "elsewhere.yaml#/Thing"}},
                     {"name": "where", "in": "matrix-of-nowhere"}],
                   "requestBody": {"$ref": "#/components/requestBodies/Missing"},
                   "callbacks": {"onEvent": {"{$request.body#/url}": {"post": {}}}},
                   "security": "none"
                 },
                 "post": "not an operation",
                 "put": {"requestBody": {"content": "none"}}
               }
             }}
            """
        )

        assertEquals(listOf("GET /odd?ok=test", "PUT /odd"), plan.requests.map { "${it.method} ${it.target}" })
        assertTrue(plan.requests.all { it.body == null && it.security == null })
        assertTrue(plan.securitySchemes.isEmpty())
    }
}
