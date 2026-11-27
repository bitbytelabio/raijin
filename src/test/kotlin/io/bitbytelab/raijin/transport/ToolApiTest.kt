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
import io.bitbytelab.raijin.tools.ToolArgs
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ReadResourceResult
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.TextResourceContents
import io.modelcontextprotocol.kotlin.sdk.types.ToolAnnotations
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The JSON tool API the `raijin` CLI calls instead of opening an MCP session. */
class ToolApiTest {

    private val port = 9876

    /** Calls that reached `wipe_tool`'s handler. */
    private var wiped = 0

    private fun server(): Server {
        val server = Server(
            Implementation("burpsuite", "test"),
            ServerOptions(
                ServerCapabilities(
                    tools = ServerCapabilities.Tools(listChanged = false),
                    resources = ServerCapabilities.Resources(subscribe = false, listChanged = false),
                )
            )
        )
        server.addTool("ok_tool", "returns", ToolSchema()) { request ->
            CallToolResult(content = listOf(TextContent("args=${request.params.arguments}")))
        }
        server.addTool("boom_tool", "throws", ToolSchema()) { _ -> throw IllegalStateException("boom") }
        server.addTool("json_tool", "json", ToolSchema()) { _ -> toolJsonResult(buildJsonObject { put("ok", true) }) }
        server.addTool("wipe_tool", "wipes", ToolSchema(), toolAnnotations = ToolAnnotations(destructiveHint = true)) { _ ->
            wiped++
            toolJsonResult(buildJsonObject { put("wiped", true) })
        }
        server.addTool("err_tool", "fails", ToolSchema()) { _ ->
            ToolArgs.error("missing_parameter", "x") {
                putJsonObject("example") { put("action", "check"); put("url", "<url>") }
            }
        }
        server.addResource("burp://test", "test", "a test resource", "text/plain") {
            ReadResourceResult(listOf(TextResourceContents("hello", "burp://test", "text/plain")))
        }
        return server
    }

    private fun text(result: JsonObject) =
        result.getValue("content").jsonArray[0].jsonObject.getValue("text").jsonPrimitive.content

    private fun error(response: HttpResponse, body: String): JsonObject {
        assertEquals(HttpStatusCode.OK, response.status)
        val result = json(response, body)
        assertTrue(result.getValue("isError").jsonPrimitive.boolean, body)
        return Json.parseToJsonElement(text(result)).jsonObject
    }

    private suspend fun ApplicationTestBuilder.get(path: String): HttpResponse =
        client.get("${ToolApi.BASE}/$path") { header(HttpHeaders.Host, "127.0.0.1:$port") }

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
        assertEquals(listOf("ok_tool", "boom_tool", "json_tool", "wipe_tool", "err_tool"), names)
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
        val err = error(response, response.bodyAsText())
        assertEquals("internal", err.getValue("code").jsonPrimitive.content)
        assertEquals("boom_tool failed: boom.", err.getValue("error").jsonPrimitive.content)
        assertEquals(false, err.getValue("retryable").jsonPrimitive.boolean)
    }

    @Test
    fun `an unknown tool is an unknown_tool error with suggestions`() = testApplication {
        mount()
        val nope = call("nope", "{}").let { error(it, it.bodyAsText()) }
        assertEquals("unknown_tool", nope.getValue("code").jsonPrimitive.content)
        assertTrue("did_you_mean" !in nope, nope.toString())
        assertTrue("retry" !in nope, nope.toString())

        val typo = call("ok_tol", "{}").let { error(it, it.bodyAsText()) }
        assertEquals(listOf("ok_tool"), typo.getValue("did_you_mean").jsonArray.map { it.jsonPrimitive.content })
        assertEquals(buildJsonObject { put("do", "ok_tool") }, typo.getValue("retry"))
    }

    @Test
    fun `a name differing in case and separators runs the tool and says so`() = testApplication {
        mount()
        val response = call("JSON.Tool", "{}")
        val result = json(response, response.bodyAsText())
        assertEquals(
            buildJsonObject { put("ok", true); putJsonArray("notes") { add("ran 'JSON.Tool' as json_tool") } },
            Json.parseToJsonElement(text(result)),
        )
    }

    @Test
    fun `a destructive tool is never run from an inexact name`() = testApplication {
        mount()
        val wipe = call("Wipe.Tool", "{}").let { error(it, it.bodyAsText()) }
        assertEquals("unknown_tool", wipe.getValue("code").jsonPrimitive.content)
        assertEquals(buildJsonObject { put("do", "wipe_tool") }, wipe.getValue("retry"))
        assertEquals(0, wiped)
    }

    @Test
    fun `error envelopes come back in run form`() = testApplication {
        mount()
        val err = call("err_tool", "{}").let { error(it, it.bodyAsText()) }
        assertEquals(buildJsonObject { put("do", "err_tool.check"); put("url", "<url>") }, err.getValue("example"))
        assertEquals("guide {\"topic\":\"err_tool\"}", err.getValue("see").jsonPrimitive.content)
    }

    @Test
    fun `info carries the server instructions`() = testApplication {
        mount()
        val response = get("info")
        val info = json(response, response.bodyAsText())
        assertEquals(McpServerManager.SERVER_INSTRUCTIONS, info.getValue("instructions").jsonPrimitive.content)
    }

    @Test
    fun `resources are listed and read`() = testApplication {
        mount()
        val list = get("resources").let { json(it, it.bodyAsText()) }
        assertEquals(listOf("burp://test"), list.getValue("resources").jsonArray.map { it.jsonObject.getValue("uri").jsonPrimitive.content })

        val read = get("resources/read?uri=burp://test")
        assertEquals(HttpStatusCode.OK, read.status)
        val contents = json(read, read.bodyAsText()).getValue("contents").jsonArray
        assertEquals("hello", contents[0].jsonObject.getValue("text").jsonPrimitive.content)

        val unknown = get("resources/read?uri=burp://nope")
        assertEquals(HttpStatusCode.NotFound, unknown.status)
        assertEquals(HttpStatusCode.BadRequest, get("resources/read").status)
    }

    @Test
    fun `a body that is not a JSON object is 400`() = testApplication {
        mount()
        val response = call("ok_tool", "[1]")
        assertEquals(HttpStatusCode.BadRequest, response.status)
        val body = Json.parseToJsonElement(response.bodyAsText()).jsonObject
        assertTrue(body.getValue("error").jsonPrimitive.content.contains("JSON object"))
        assertEquals("invalid_type", body.getValue("code").jsonPrimitive.content)
    }

    @Test
    fun `a body that is not sent as JSON is 415`() = testApplication {
        mount()
        val response = call("ok_tool", """{"a":1}""", contentType = ContentType.Text.Plain)
        assertEquals(HttpStatusCode.UnsupportedMediaType, response.status)
        assertEquals("invalid_arguments", Json.parseToJsonElement(response.bodyAsText()).jsonObject.getValue("code").jsonPrimitive.content)
    }

    @Test
    fun `a foreign Host header is refused`() = testApplication {
        mount()
        val response = call("ok_tool", "{}", host = "evil.example:$port")
        assertEquals(HttpStatusCode.Forbidden, response.status)
    }
}
