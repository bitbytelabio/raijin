package io.bitbytelab.raijin.transport

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
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Tools reach clients over the Streamable HTTP endpoint the way Claude Code and omp connect to it. */
class StreamableHttpTest {

    private val port = 9876
    private val path = McpServerManager.STREAMABLE_HTTP_PATH

    private fun toolServer(): Server {
        val server = Server(Implementation("burpsuite", "test"), ServerOptions(McpServerManager.serverCapabilities()))
        server.addTool("ok_tool", "returns", ToolSchema()) { _ -> CallToolResult(content = listOf(TextContent("ok"))) }
        return server
    }

    private fun ApplicationTestBuilder.mount() = application {
        installLocalhostSecurity(listOf(port))
        installStreamableHttp(toolServer())
    }

    private suspend fun ApplicationTestBuilder.rpc(body: String, sessionId: String? = null): HttpResponse =
        client.post(path) {
            header(HttpHeaders.Host, "127.0.0.1:$port")
            header(HttpHeaders.Accept, "application/json, text/event-stream")
            header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            sessionId?.let { header("Mcp-Session-Id", it) }
            setBody(body)
        }

    private suspend fun ApplicationTestBuilder.initialize(): String {
        val init = rpc(
            """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18",""" +
                """"capabilities":{},"clientInfo":{"name":"test","version":"0"}}}"""
        )
        assertEquals(HttpStatusCode.OK, init.status, init.bodyAsText())
        val result = Json.parseToJsonElement(init.bodyAsText()).jsonObject.getValue("result").jsonObject
        assertNotNull(result.getValue("capabilities").jsonObject["tools"], "server must advertise tools")
        val sessionId = assertNotNull(init.headers["Mcp-Session-Id"], "initialize must open a session")
        rpc("""{"jsonrpc":"2.0","method":"notifications/initialized"}""", sessionId)
        return sessionId
    }

    private suspend fun ApplicationTestBuilder.result(body: String, sessionId: String): JsonObject {
        val response = rpc(body, sessionId)
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        return Json.parseToJsonElement(response.bodyAsText()).jsonObject.getValue("result").jsonObject
    }

    @Test
    fun `tools list over streamable http returns the registered tools`() = testApplication {
        mount()
        val sessionId = initialize()
        val tools = result("""{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}""", sessionId)
        val names = tools.getValue("tools").jsonArray.map { it.jsonObject.getValue("name").jsonPrimitive.content }
        assertEquals(listOf("ok_tool"), names)
    }

    @Test
    fun `a foreign Host header is refused`() = testApplication {
        mount()
        val response = client.post(path) {
            header(HttpHeaders.Host, "evil.example:$port")
            header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody("""{"jsonrpc":"2.0","id":1,"method":"ping"}""")
        }
        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertTrue(response.bodyAsText().contains("invalid Host header"))
    }
}
