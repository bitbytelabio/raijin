package io.bitbytelab.raijin.tools.analysis

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.Proxy as BurpProxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import io.bitbytelab.raijin.bridge.AnalysisBridge
import io.bitbytelab.raijin.testClientConnection
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequestParams
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull

/** analyze_response_body_search clamps max_results into its range and reports it, instead of refusing it. */
class AnalysisToolsTest {

    private inline fun <reified T> stub(crossinline answer: (String) -> Any?): T =
        Proxy.newProxyInstance(T::class.java.classLoader, arrayOf(T::class.java)) { _, m, _ -> answer(m.name) } as T

    private val server = Server(
        Implementation("t", "0"),
        ServerOptions(ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false)))
    ).also { server ->
        // Three history entries whose responses all hold a token.
        val history = List(3) { i ->
            val request = stub<HttpRequest> { m ->
                when (m) {
                    "url" -> "https://t.test/$i"
                    "method" -> "GET"
                    else -> null
                }
            }
            val response = stub<HttpResponse> { m ->
                when (m) {
                    "bodyToString" -> "token=$i"
                    "statusCode" -> 200.toShort()
                    else -> null
                }
            }
            stub<ProxyHttpRequestResponse> { m ->
                when (m) {
                    "finalRequest" -> request
                    "originalResponse" -> response
                    else -> null
                }
            }
        }
        val proxy = stub<BurpProxy> { m -> if (m == "history") history else null }
        AnalysisTools.register(server, AnalysisBridge(stub<MontoyaApi> { m -> if (m == "proxy") proxy else null }))
    }

    private fun search(args: JsonObjectBuilder.() -> Unit): JsonObject = runBlocking {
        val tool = "analyze_response_body_search"
        val arguments = buildJsonObject { put("pattern", "token"); args() }
        val result = server.tools.getValue(tool).handler(testClientConnection, CallToolRequest(CallToolRequestParams(tool, arguments)))
        val body = Json.parseToJsonElement((result.content.first() as TextContent).text).jsonObject
        assertNotEquals(true, result.isError, body.toString())
        body
    }

    @Test
    fun `max_results past either end is clamped and reported`() {
        val many = search { put("max_results", 1000) }
        assertEquals(AnalysisBridge.SEARCH_MAX_RESULTS, many["max_results_clamped_to"]?.jsonPrimitive?.int)
        assertEquals(AnalysisBridge.SEARCH_MAX_RESULTS, many["max_results"]?.jsonPrimitive?.int)
        assertEquals(3, many["match_count"]?.jsonPrimitive?.int)

        val none = search { put("max_results", 0) }
        assertEquals(1, none["max_results_clamped_to"]?.jsonPrimitive?.int)
        assertEquals(1, none["match_count"]?.jsonPrimitive?.int)

        val inRange = search { put("max_results", 2) }
        assertEquals(2, inRange["match_count"]?.jsonPrimitive?.int)
        assertNull(inRange["max_results_clamped_to"])
    }
}
