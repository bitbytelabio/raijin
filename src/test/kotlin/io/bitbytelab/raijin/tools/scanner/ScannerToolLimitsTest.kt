package io.bitbytelab.raijin.tools.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import burp.api.montoya.scanner.Crawl
import burp.api.montoya.scanner.CrawlConfiguration
import burp.api.montoya.scanner.Scanner
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import burp.api.montoya.sitemap.SiteMap
import io.bitbytelab.raijin.bridge.ScannerBridge
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.state.StateManager
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
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import java.lang.reflect.Proxy
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull

/** Limits the scanner tools used to accept past their range are clamped and reported, not refused. */
class ScannerToolLimitsTest {

    private inline fun <reified T> stub(crossinline answer: (String) -> Any?): T =
        Proxy.newProxyInstance(T::class.java.classLoader, arrayOf(T::class.java)) { _, m, _ -> answer(m.name) } as T

    private fun issue(name: String) = stub<AuditIssue> { m ->
        when (m) {
            "name" -> name
            "baseUrl" -> "https://t.test/"
            "severity" -> AuditIssueSeverity.HIGH
            "confidence" -> AuditIssueConfidence.FIRM
            else -> null
        }
    }

    private val server = Server(
        Implementation("t", "0"),
        ServerOptions(ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false)))
    ).also { server ->
        val issues = List(3) { issue("Issue $it") }
        val crawl = stub<Crawl> { m -> if (m == "statusMessage") "Crawling" else null }
        val api = stub<MontoyaApi> { m ->
            when (m) {
                "siteMap" -> stub<SiteMap> { sm -> if (sm == "issues") issues else null }
                "scanner" -> stub<Scanner> { sm -> if (sm == "startCrawl") crawl else null }
                else -> null
            }
        }
        val state = StateManager()
        ScannerTools.register(server, ScannerBridge(api, EventBus(), state), state)
    }

    /** Builds a crawl configuration; nothing else Burp's factory makes is available, as outside Burp. */
    private val factory = Proxy.newProxyInstance(
        MontoyaObjectFactory::class.java.classLoader, arrayOf(MontoyaObjectFactory::class.java)
    ) { _, m, _ ->
        if (m.name == "crawlConfiguration") stub<CrawlConfiguration> { null }
        else throw IllegalStateException("MontoyaObjectFactory.${m.name} is not available in this test")
    } as MontoyaObjectFactory

    private var previousFactory: MontoyaObjectFactory? = null

    @BeforeTest
    fun installFactory() {
        previousFactory = ObjectFactoryLocator.FACTORY
        ObjectFactoryLocator.FACTORY = factory
    }

    @AfterTest
    fun restoreFactory() {
        ObjectFactoryLocator.FACTORY = previousFactory
    }

    private fun call(tool: String, args: JsonObjectBuilder.() -> Unit): JsonObject = runBlocking {
        val result = server.tools.getValue(tool).handler(testClientConnection, CallToolRequest(CallToolRequestParams(tool, buildJsonObject(args))))
        val body = Json.parseToJsonElement((result.content.first() as TextContent).text).jsonObject
        assertNotEquals(true, result.isError, body.toString())
        body
    }

    @Test
    fun `a negative crawl depth is clamped to 0 and reported`() {
        val clamped = call("scanner_start_crawl") {
            putJsonArray("urls") { add("https://t.test/") }
            put("max_depth", -1)
        }
        assertEquals(0, clamped["max_depth_clamped_to"]?.jsonPrimitive?.int)
        assertEquals(listOf("max_depth"), clamped.getValue("ignored").jsonArray.map { it.jsonPrimitive.content })

        val inRange = call("scanner_start_crawl") {
            putJsonArray("urls") { add("https://t.test/") }
            put("max_depth", 3)
        }
        assertNull(inRange["max_depth_clamped_to"])
    }

    @Test
    fun `an issue limit below 1 is clamped to 1 and reported`() {
        val one = call("scanner_get_all_issues") { put("max_results", 0) }
        assertEquals(1, one["returned"]?.jsonPrimitive?.int)
        assertEquals(3, one["total_filtered"]?.jsonPrimitive?.int)
        assertEquals(1, one["max_results_clamped_to"]?.jsonPrimitive?.int)

        val two = call("scanner_get_all_issues") { put("max_results", 2) }
        assertEquals(2, two["returned"]?.jsonPrimitive?.int)
        assertNull(two["max_results_clamped_to"])
    }
}
