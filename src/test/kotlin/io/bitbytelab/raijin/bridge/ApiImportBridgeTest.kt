package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.openapi.PlannedBody
import io.bitbytelab.raijin.openapi.PlannedRequest
import io.bitbytelab.raijin.openapi.ServerUrl
import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** What `api_import_openapi` returns, and what it does before Burp is involved. */
class ApiImportBridgeTest {

    private fun json(text: String): JsonElement = Json.parseToJsonElement(text)

    private val base = ServerUrl("https", "api.example.com", 443, "/v1")

    private fun request(
        body: PlannedBody? = null,
        server: ServerUrl = base,
        security: JsonArray? = null
    ) = PlannedRequest(
        method = "POST",
        server = server,
        target = "/v1/pets?limit=1",
        headers = listOf("X-Trace" to "1"),
        body = body,
        operationId = "addPet",
        summary = "Add a pet",
        tags = listOf("pet", "store"),
        queryParameters = 1,
        security = security
    )

    @Test
    fun `an entry carries the request line and what the operation says of itself`() {
        assertEquals(
            json(
                """
                {"method": "POST", "path": "/v1/pets?limit=1", "operation_id": "addPet", "summary": "Add a pet",
                 "tags": ["pet", "store"], "query_params": 1, "has_body": false}
                """
            ),
            ApiImportBridge.describe(request(), base)
        )
    }

    @Test
    fun `a body is shown with its content type`() {
        val entry = ApiImportBridge.describe(request(PlannedBody("application/json", """{"name":"Rex"}""")), base)

        assertEquals("true", entry.getValue("has_body").jsonPrimitive.content)
        assertEquals("application/json", entry.getValue("content_type").jsonPrimitive.content)
        assertEquals("""{"name":"Rex"}""", entry.getValue("body_preview").jsonPrimitive.content)
    }

    @Test
    fun `a long body is cut to a preview that says how long it was`() {
        val entry = ApiImportBridge.describe(request(PlannedBody("text/plain", "x".repeat(500))), base)

        assertEquals("x".repeat(200) + "... [truncated, full length: 500]", entry.getValue("body_preview").jsonPrimitive.content)
    }

    @Test
    fun `a preview is never cut inside a surrogate pair`() {
        // The 200th and 201st chars are the two halves of one emoji.
        val text = "a".repeat(199) + "\uD83D\uDE00" + "b".repeat(50)
        val preview = ApiImportBridge.describe(request(PlannedBody("text/plain", text)), base)
            .getValue("body_preview").jsonPrimitive.content

        assertEquals("a".repeat(199) + "... [truncated, full length: 251]", preview)
    }

    @Test
    fun `the server is named only for a request that goes elsewhere`() {
        assertFalse("server" in ApiImportBridge.describe(request(), base))

        val elsewhere = ServerUrl("https", "files.example.com", 8443, "")
        assertEquals(
            "https://files.example.com:8443",
            ApiImportBridge.describe(request(server = elsewhere), base).getValue("server").jsonPrimitive.content
        )
    }

    @Test
    fun `the security requirement of the operation is passed on, an empty one included`() {
        val required = json("""[{"petstore_auth": ["write:pets"]}, {"api_key": []}]""").jsonArray
        assertEquals<JsonElement?>(required, ApiImportBridge.describe(request(security = required), base)["security"])

        val open = ApiImportBridge.describe(request(security = JsonArray(emptyList())), base)
        assertEquals<JsonElement?>(JsonArray(emptyList()), open["security"])

        assertFalse("security" in ApiImportBridge.describe(request(), base))
    }

    @Test
    fun `a request that could not be built, sent or stored says why`() {
        assertFalse("error" in ApiImportBridge.describe(request(), base))
        assertEquals(
            "Illegal character in path",
            ApiImportBridge.describe(request(), base, "Illegal character in path").getValue("error").jsonPrimitive.content
        )
    }

    // --- the import itself, up to the point where Burp is needed ---

    /** A Burp that fails the test when called: parsing, planning and describing must not need it. */
    private val untouchedBurp = Proxy.newProxyInstance(
        MontoyaApi::class.java.classLoader,
        arrayOf(MontoyaApi::class.java)
    ) { _, method, _ -> throw AssertionError("unexpected Burp call: ${method.name}") } as MontoyaApi

    private fun importSpec(
        spec: String,
        baseUrl: String? = null,
        specUrl: String? = null,
        store: Boolean = false
    ): JsonObject = ApiImportBridge(untouchedBurp, StateManager()).importOpenApi(
        spec, baseUrl, null, null,
        addToScope = store, addToSitemap = store, sendRequests = store, specUrl = specUrl
    )

    private val petApi = """
        {"openapi": "3.0.3",
         "servers": [{"url": "https://api.example.com/v1"}],
         "security": [{"key": []}],
         "paths": {"/pets": {
           "get": {"operationId": "listPets", "summary": "List pets", "tags": ["pets"],
                   "parameters": [{"name": "limit", "in": "query", "schema": {"type": "integer"}}]},
           "post": {"operationId": "addPet", "security": [],
                    "requestBody": {"content": {"application/json": {"schema": {
                      "type": "object", "properties": {"name": {"type": "string"}}}}}}}}},
         "components": {"securitySchemes": {"key": {"type": "apiKey", "in": "header", "name": "X-Key"}}}}
        """

    @Test
    fun `an import that neither sends nor stores reports the requests without touching Burp`() {
        assertEquals(
            json(
                """
                {"spec_version": "OpenAPI 3.0.3",
                 "base_url": "https://api.example.com/v1",
                 "total_endpoints": 2,
                 "requests_sent": 0,
                 "skipped_out_of_scope": 0,
                 "added_to_sitemap": 0,
                 "added_to_scope": false,
                 "security_schemes": {"key": {"type": "apiKey", "in": "header", "name": "X-Key",
                                              "credential": "header X-Key: <api key>"}},
                 "endpoints": [
                   {"method": "GET", "path": "/v1/pets?limit=1", "operation_id": "listPets", "summary": "List pets",
                    "tags": ["pets"], "query_params": 1, "has_body": false, "security": [{"key": []}]},
                   {"method": "POST", "path": "/v1/pets", "operation_id": "addPet", "summary": "", "tags": [],
                    "query_params": 0, "has_body": true, "content_type": "application/json",
                    "body_preview": "{\"name\":\"test\"}", "security": []}]}
                """
            ),
            importSpec(petApi)
        )
    }

    @Test
    fun `base_url and spec_url decide where the requests go`() {
        assertEquals("http://127.0.0.1:8080/stage", importSpec(petApi, baseUrl = "http://127.0.0.1:8080/stage").getValue("base_url").jsonPrimitive.content)

        val relative = """{"openapi": "3.0.3", "servers": [{"url": "/api"}], "paths": {"/ping": {"get": {}}}}"""
        val resolved = importSpec(relative, specUrl = "https://shop.example.com/docs/openapi.yaml")
        assertEquals("https://shop.example.com/api", resolved.getValue("base_url").jsonPrimitive.content)
        assertTrue("base_url" in importSpec(relative).getValue("error").jsonPrimitive.content)
    }

    @Test
    fun `a document that cannot be imported is an error before scope or site map are touched`() {
        // `store` asks for scope, site map and sending: none of them may happen for these.
        assertTrue("HTML" in importSpec("<html><body>Swagger UI</body></html>", store = true).getValue("error").jsonPrimitive.content)
        assertTrue("not valid YAML" in importSpec("paths: [1, 2", store = true).getValue("error").jsonPrimitive.content)
        assertTrue("missing 'openapi' or 'swagger'" in importSpec("""{"paths": {}}""", store = true).getValue("error").jsonPrimitive.content)
        assertEquals(
            "Invalid base URL: https://bad host.com",
            importSpec(petApi, baseUrl = "https://bad host.com", store = true).getValue("error").jsonPrimitive.content
        )
    }

    @Test
    fun `a YAML document is imported like a JSON one`() {
        val result = importSpec(
            """
            swagger: "2.0"
            host: api.example.com
            basePath: /v2
            paths:
              /pets/{petId}:
                delete:
                  parameters:
                    - name: petId
                      in: path
                      required: true
                      type: integer
            """.trimIndent()
        )
        assertEquals("Swagger 2.0", result.getValue("spec_version").jsonPrimitive.content)
        assertEquals("https://api.example.com/v2", result.getValue("base_url").jsonPrimitive.content)
        assertEquals(
            json(
                """
                [{"method": "DELETE", "path": "/v2/pets/1", "operation_id": "delete /pets/{petId}", "summary": "",
                  "tags": [], "query_params": 0, "has_body": false}]
                """
            ),
            result["endpoints"]
        )
    }
}
