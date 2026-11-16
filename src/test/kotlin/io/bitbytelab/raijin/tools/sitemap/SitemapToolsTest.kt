package io.bitbytelab.raijin.tools.sitemap

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import burp.api.montoya.sitemap.SiteMap
import io.bitbytelab.raijin.bridge.SitemapBridge
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
import kotlinx.serialization.json.JsonElement
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

/** The site map tools still accept the arguments they accepted before the argument checks came in. */
class SitemapToolsTest {

    private inline fun <reified T> stub(crossinline answer: (String) -> Any?): T =
        Proxy.newProxyInstance(T::class.java.classLoader, arrayOf(T::class.java)) { _, m, _ -> answer(m.name) } as T

    private fun issue(name: String, severity: AuditIssueSeverity) = stub<AuditIssue> { m ->
        when (m) {
            "name" -> name
            "severity" -> severity
            "confidence" -> AuditIssueConfidence.FIRM
            "baseUrl" -> "https://t.test/"
            else -> null
        }
    }

    private val server = Server(
        Implementation("t", "0"),
        ServerOptions(ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false)))
    ).also { server ->
        val request = stub<HttpRequest> { m -> if (m == "url") "https://t.test/a" else null }
        val entry = stub<HttpRequestResponse> { m ->
            when (m) {
                "request" -> request
                "hasResponse" -> false
                else -> null
            }
        }
        val issues = listOf(issue("Reflected XSS", AuditIssueSeverity.HIGH), issue("Dismissed", AuditIssueSeverity.FALSE_POSITIVE))
        val siteMap = stub<SiteMap> { m ->
            when (m) {
                "requestResponses" -> List(3) { entry }
                "issues" -> issues
                else -> null
            }
        }
        SitemapTools.register(server, SitemapBridge(stub<MontoyaApi> { m -> if (m == "siteMap") siteMap else null }))
    }

    private fun call(tool: String, args: JsonObjectBuilder.() -> Unit): CallToolResult = runBlocking {
        server.tools.getValue(tool).handler(testClientConnection, CallToolRequest(CallToolRequestParams(tool, buildJsonObject(args))))
    }

    private fun body(result: CallToolResult): JsonElement = Json.parseToJsonElement((result.content.first() as TextContent).text)

    @Test
    fun `max_results past either end is clamped and reported, not refused`() {
        val many = call("sitemap_query") { put("max_results", 50_000) }
        assertNotEquals(true, many.isError, body(many).toString())
        assertEquals(3, body(many).jsonObject["returned"]?.jsonPrimitive?.int)
        assertEquals(10_000, body(many).jsonObject["max_results_clamped_to"]?.jsonPrimitive?.int)

        val countsOnly = body(call("sitemap_query") { put("max_results", -1) }).jsonObject
        assertEquals(3, countsOnly["matched"]?.jsonPrimitive?.int)
        assertEquals(0, countsOnly["returned"]?.jsonPrimitive?.int)
        assertEquals(0, countsOnly["max_results_clamped_to"]?.jsonPrimitive?.int)

        val integral = body(call("sitemap_query") { put("max_results", 2.0) }).jsonObject
        assertEquals(2, integral["returned"]?.jsonPrimitive?.int)
        assertNull(integral["max_results_clamped_to"])
    }

    @Test
    fun `get_issues filters on FALSE_POSITIVE`() {
        val result = call("sitemap_get_issues") { put("severity", "false_positive") }
        assertNotEquals(true, result.isError, body(result).toString())
        assertEquals(listOf("Dismissed"), body(result).jsonArray.map { it.jsonObject.getValue("name").jsonPrimitive.content })
    }
}
