package io.bitbytelab.raijin.transport

import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The JSON tool API the `raijin` CLI calls instead of opening an MCP session. */
class ToolApiTest {

    private val port = 9876

    private fun server(): Server {
        val server = Server(
            Implementation("burpsuite", "test"),
            ServerOptions(ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false)))
        )
        server.addTool("ok_tool", "returns", ToolSchema()) { request ->
            CallToolResult(content = listOf(TextContent("args=${request.params.arguments}")))
        }
        server.addTool("boom_tool", "throws", ToolSchema()) { _ -> throw IllegalStateException("boom") }
        return server
    }

    private fun ApplicationTestBuilder.mount() = application {
        installLocalhostSecurity(listOf(port))
        installToolApi(server())
    }

    private suspend fun ApplicationTestBuilder.call(
        name: String,
        body: String,
        host: String = "127.0.0.1:$port",
        contentType: ContentType = ContentType.Application.Json,
    ): HttpResponse =
        client.post("${ToolApi.BASE}/tools/$name") {
            header(HttpHeaders.Host, host)
            header(HttpHeaders.ContentType, contentType.toString())
            setBody(body)
        }

    private fun json(response: HttpResponse, text: String): JsonObject =
        Json.parseToJsonElement(text).jsonObject.also {
            assertEquals("application/json", response.headers[HttpHeaders.ContentType]?.substringBefore(';'))
        }

    @Test
    fun `tools list returns every registered tool`() = testApplication {
        mount()
        val response = client.get("${ToolApi.BASE}/tools") { header(HttpHeaders.Host, "127.0.0.1:$port") }
        assertEquals(HttpStatusCode.OK, response.status)
        val names = json(response, response.bodyAsText()).getValue("tools").jsonArray
            .map { it.jsonObject.getValue("name").jsonPrimitive.content }
        assertEquals(listOf("ok_tool", "boom_tool"), names)
    }

    @Test
    fun `calling a tool passes the body as its arguments`() = testApplication {
        mount()
        val response = call("ok_tool", """{"a":1}""")
        assertEquals(HttpStatusCode.OK, response.status)
        val result = json(response, response.bodyAsText())
        val text = result.getValue("content").jsonArray[0].jsonObject.getValue("text").jsonPrimitive.content
        assertEquals("""args={"a":1}""", text)
    }

    @Test
    fun `an empty body means no arguments`() = testApplication {
        mount()
        val response = call("ok_tool", "")
        assertEquals(HttpStatusCode.OK, response.status)
        assertTrue(response.bodyAsText().contains("args={}"), response.bodyAsText())
    }

    @Test
    fun `a throwing tool gives an error result like the MCP server`() = testApplication {
        mount()
        val response = call("boom_tool", "{}")
        assertEquals(HttpStatusCode.OK, response.status)
        val result = json(response, response.bodyAsText())
        assertTrue(result.getValue("isError").jsonPrimitive.boolean)
        val text = result.getValue("content").jsonArray[0].jsonObject.getValue("text").jsonPrimitive.content
        assertTrue(text.startsWith("Error executing tool boom_tool"), text)
    }

    @Test
    fun `an unknown tool is 404`() = testApplication {
        mount()
        val response = call("nope", "{}")
        assertEquals(HttpStatusCode.NotFound, response.status)
        assertEquals("unknown tool nope", json(response, response.bodyAsText()).getValue("error").jsonPrimitive.content)
    }

    @Test
    fun `a body that is not a JSON object is 400`() = testApplication {
        mount()
        val response = call("ok_tool", "[1]")
        assertEquals(HttpStatusCode.BadRequest, response.status)
        assertTrue(response.bodyAsText().contains("JSON object"))
    }

    @Test
    fun `a body that is not sent as JSON is 415`() = testApplication {
        mount()
        val response = call("ok_tool", """{"a":1}""", contentType = ContentType.Text.Plain)
        assertEquals(HttpStatusCode.UnsupportedMediaType, response.status)
    }

    @Test
    fun `a foreign Host header is refused`() = testApplication {
        mount()
        val response = call("ok_tool", "{}", host = "evil.example:$port")
        assertEquals(HttpStatusCode.Forbidden, response.status)
    }
}
