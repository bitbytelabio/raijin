package io.bitbytelab.raijin.transport

import burp.api.montoya.http.message.HttpRequestResponse
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.testClientConnection
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequestParams
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.yield
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import java.io.File
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

class ToolCallTrackerTest {

    private fun fakeExchange(): HttpRequestResponse = Proxy.newProxyInstance(
        HttpRequestResponse::class.java.classLoader,
        arrayOf(HttpRequestResponse::class.java)
    ) { proxy, method, args ->
        when (method.name) {
            "hashCode" -> System.identityHashCode(proxy)
            "equals" -> proxy === args?.firstOrNull()
            "toString" -> "fakeExchange"
            else -> null
        }
    } as HttpRequestResponse

    private fun text(s: String) = CallToolResult(content = listOf(TextContent(s)))

    // ---- audit coverage -------------------------------------------------------

    @Test fun `mutating tools are audited, read-only members of the same families are not`() {
        val audited = listOf(
            "turbo_run", "turbo_start_run", "turbo_start_run_async", "turbo_stop_run", "turbo_delete_run",
            "http_send_requests_parallel", "http_race", "config_set", "config_match_replace_add",
            "config_upstream_proxy_set", "websocket_send_text", "websocket_create", "websocket_set_intercept_rule",
            "persistence_store", "persistence_delete", "preference_store", "proxy_intercept_enable",
            "scanner_start_audit", "session_remove_rule"
        )
        val notAudited = listOf(
            "util_base64_decode", "turbo_run_status", "turbo_run_results", "turbo_list_runs", "turbo_get_docs",
            "config_match_replace_list", "config_proxy_listeners_list", "websocket_list", "websocket_get_messages",
            "persistence_get", "persistence_list", "preference_get", "proxy_intercept_status", "scanner_task_status",
            "session_list_rules"
        )
        audited.forEach { assertTrue(ToolCallTracker.shouldAudit(it, "", "", false), it) }
        notAudited.forEach { assertFalse(ToolCallTracker.shouldAudit(it, "", "", false), it) }
        assertTrue(ToolCallTracker.shouldAudit("turbo_run_status", "", "", isError = true), "errors are always audited")
        assertTrue(ToolCallTracker.shouldAudit("util_base64_decode", "https://x", "", false), "outbound requests are always audited")
    }

    // ---- summaries never assume primitives --------------------------------------

    @Test fun `array and object arguments are summarized instead of crashing the record`() {
        val args = buildJsonObject {
            putJsonArray("url") { add("https://a.example/"); add("https://b.example/") }
            putJsonObject("method") { put("nested", true) }
            putJsonArray("host") { }
            put("action", buildJsonObject {})
        }
        val s = ToolCallTracker.summarize("http_send_requests_parallel", args, text("""{"results":[]}"""))
        assertEquals("", s.url)
        assertEquals("", s.method)
        assertEquals("", s.host)
        assertEquals(args.keys, s.arguments.keys)
        AuditLog.buildEntry(s.toolName, "ts", 1, s.isError, args, s.url, s.host, s.method, s.statusCode)
    }

    @Test fun `http details come from the result first, then nested objects, then arguments`() {
        val fromResult = ToolCallTracker.summarize(
            "http_send_request",
            buildJsonObject { put("url", "https://arg.example/") },
            text("""{"request":{"url":"https://res.example/a","method":"POST"},"response":{"status_code":201}}""")
        )
        assertEquals("https://res.example/a", fromResult.url)
        assertEquals("POST", fromResult.method)
        assertEquals("res.example", fromResult.host)
        assertEquals(201, fromResult.statusCode)

        val fromArgs = ToolCallTracker.summarize("http_send_request", buildJsonObject { put("url", "https://arg.example/x") }, text("not json"))
        assertEquals("https://arg.example/x", fromArgs.url)
        assertEquals("arg.example", fromArgs.host)
        assertEquals("not json", fromArgs.resultSummary)
    }

    @Test fun `a failed call is recorded as an error result`() {
        val thrown = ToolCallTracker.failureResult(IllegalStateException("boom"))
        assertEquals(true, thrown.isError)
        assertTrue((thrown.content.first() as TextContent).text.contains("boom"))
        val cancelled = ToolCallTracker.failureResult(CancellationException("gone"))
        assertTrue((cancelled.content.first() as TextContent).text.contains("cancelled"))
    }

    // ---- the per-call capture element -------------------------------------------

    @Test fun `the capture element follows the call across dispatcher hops and nowhere else`() = runBlocking {
        val holder = ToolCallTracker.HttpCaptureHolder()
        val first = fakeExchange()
        val second = fakeExchange()
        withContext(ToolCallTracker.ToolCallCaptureContext(holder)) {
            withContext(Dispatchers.IO) { ToolCallTracker.recordSentResult(first) }
            assertSame(first, holder.value)
            yield()
            ToolCallTracker.recordSentResult(second)
        }
        assertSame(second, holder.value)
        ToolCallTracker.recordSentResult(first)
        assertSame(second, holder.value, "outside the call nothing may write to its holder")
        withContext(Dispatchers.IO) { ToolCallTracker.recordSentResult(first) }
        assertSame(second, holder.value)
    }

    // ---- wrapAll: try/finally recording -------------------------------------------

    @Test fun `a tool that throws is still recorded in activity, events and the audit log`() {
        val tempAudit = File.createTempFile("raijin-audit-tracker", ".jsonl").apply { delete() }
        val previous = AuditLog.store
        AuditLog.store = AuditFileStore(tempAudit)
        try {
            val server = Server(Implementation("test", "0"), ServerOptions(ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false))))
            val exchange = fakeExchange()
            server.addTool("boom_tool", "throws", ToolSchema()) { _ ->
                withContext(Dispatchers.IO) { ToolCallTracker.recordSentResult(exchange) }
                throw IllegalStateException("boom")
            }
            server.addTool("ok_tool", "returns", ToolSchema()) { _ -> CallToolResult(content = listOf(TextContent("""{"ok":true}"""))) }
            val bus = EventBus()
            val state = StateManager()
            ToolCallTracker.wrapAll(server, bus, state)

            assertFailsWith<IllegalStateException> {
                runBlocking {
                    server.tools.getValue("boom_tool").handler(
                        testClientConnection,
                        CallToolRequest(CallToolRequestParams("boom_tool", buildJsonObject { putJsonArray("ids") { add(1) } }))
                    )
                }
            }
            val entry = state.mcpActivity.first()
            assertEquals("boom_tool", entry.toolName)
            assertTrue(entry.isError)
            assertTrue(entry.resultSummary.contains("boom"))
            assertSame(exchange, entry.requestResponse, "the exchange sent on an IO thread is attached to the record")
            val event = bus.getEvents().single()
            assertEquals("tool.called", event.type)
            val line = tempAudit.readLines().single()
            assertEquals("boom_tool", Json.parseToJsonElement(line).jsonObject.getValue("tool").jsonPrimitive.content)

            runBlocking {
                server.tools.getValue("ok_tool").handler(testClientConnection, CallToolRequest(CallToolRequestParams("ok_tool", JsonObject(emptyMap()))))
            }
            assertEquals("ok_tool", state.mcpActivity.first().toolName)
            assertFalse(state.mcpActivity.first().isError)
            assertEquals(1, tempAudit.readLines().size, "a read-only success is not audited")
        } finally {
            AuditLog.store = previous
            tempAudit.delete()
        }
    }
}
