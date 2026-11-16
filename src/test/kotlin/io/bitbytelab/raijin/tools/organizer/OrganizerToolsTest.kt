package io.bitbytelab.raijin.tools.organizer

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.organizer.Organizer
import burp.api.montoya.organizer.OrganizerItem
import io.bitbytelab.raijin.bridge.OrganizerBridge
import io.bitbytelab.raijin.testClientConnection
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequestParams
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** organizer_get_items clamps its limits and says so, instead of refusing values it used to run with. */
class OrganizerToolsTest {

    private inline fun <reified T> stub(crossinline answer: (String) -> Any?): T =
        Proxy.newProxyInstance(T::class.java.classLoader, arrayOf(T::class.java)) { _, m, _ -> answer(m.name) } as T

    private val server = Server(
        Implementation("t", "0"),
        ServerOptions(ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false)))
    ).also { server ->
        val request = stub<HttpRequest> { m -> if (m == "toString") "GET /x HTTP/1.1\r\nHost: a.test\r\n\r\n" else null }
        val items = (1..3).map { id ->
            stub<OrganizerItem> { m ->
                when (m) {
                    "id" -> id
                    "url" -> "https://a.test/$id"
                    "request" -> request
                    "hasResponse" -> false
                    else -> null
                }
            }
        }
        val organizer = stub<Organizer> { m -> if (m == "items") items else null }
        OrganizerTools.register(server, OrganizerBridge(stub<MontoyaApi> { m -> if (m == "organizer") organizer else null }))
    }

    private fun call(args: JsonObjectBuilder.() -> Unit): CallToolResult = runBlocking {
        server.tools.getValue("organizer_get_items")
            .handler(testClientConnection, CallToolRequest(CallToolRequestParams("organizer_get_items", buildJsonObject(args))))
    }

    private fun body(result: CallToolResult): JsonObject =
        Json.parseToJsonElement((result.content.first() as TextContent).text).jsonObject

    @Test
    fun `limits past their range are clamped and reported, not refused`() {
        val many = call { put("max_results", 50_000); put("include_request", true); put("max_response_length", -1) }
        assertNotEquals(true, many.isError, body(many).toString())
        val result = body(many)
        assertEquals(3, result["returned_items"]?.jsonPrimitive?.int)
        assertEquals(10_000, result["max_results_clamped_to"]?.jsonPrimitive?.int)
        assertEquals(0, result["max_response_length_clamped_to"]?.jsonPrimitive?.int)
        val first = result.getValue("items").jsonArray[0].jsonObject
        assertTrue(first["request"]?.jsonPrimitive?.content.orEmpty().contains("Host: a.test"), first.toString())
        assertNull(first["request_truncated"], "0 keeps the default cap")

        val none = body(call { put("max_results", -5) })
        assertEquals(0, none["returned_items"]?.jsonPrimitive?.int)
        assertEquals(0, none["max_results_clamped_to"]?.jsonPrimitive?.int)

        val integral = body(call { put("max_results", 2.0) })
        assertEquals(2, integral["returned_items"]?.jsonPrimitive?.int)
        assertNull(integral["max_results_clamped_to"])
    }
}
