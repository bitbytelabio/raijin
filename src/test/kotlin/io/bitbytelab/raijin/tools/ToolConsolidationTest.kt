package io.bitbytelab.raijin.tools

import io.bitbytelab.raijin.bridge.DecoderBridge
import io.bitbytelab.raijin.testClientConnection
import io.bitbytelab.raijin.tools.decoder.DecoderTools
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequestParams
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.*
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ToolConsolidationTest {

    private fun server() = Server(
        Implementation("t", "0"),
        ServerOptions(ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false)))
    )

    private fun fake(s: Server, name: String, required: List<String> = emptyList(), vararg props: String) {
        s.addTool(
            name = name,
            description = "Does $name. More detail follows.",
            inputSchema = ToolSchema(
                properties = buildJsonObject { props.forEach { p -> putJsonObject(p) { put("type", "string"); put("description", "the $p") } } },
                required = required
            )
        ) { req -> CallToolResult(content = listOf(TextContent("$name:" + req.params.arguments.toString()))) }
    }

    private fun call(s: Server, tool: String, args: JsonObject) = runBlocking {
        s.tools.getValue(tool).handler(testClientConnection, CallToolRequest(CallToolRequestParams(tool, args)))
    }

    private fun text(r: CallToolResult) = (r.content.first() as TextContent).text

    /** All tool names registered in the source tree, found the same way a reader would. */
    private fun sourceToolNames(): Set<String> {
        val re = Regex("""name\s*=\s*"([a-z0-9_]+)"\s*,\s*\n\s*description""")
        return File("src/main/kotlin/io/bitbytelab/raijin/tools").walkTopDown()
            .filter { it.extension == "kt" && it.name.endsWith("Tools.kt") }
            .flatMap { re.findAll(it.readText()).map { m -> m.groupValues[1] } }
            .toSet()
    }

    @Test
    fun `groups are disjoint and do not overlap KEEP`() {
        val members = ToolConsolidation.GROUPS.flatMap { it.actions.values }
        assertEquals(members.size, members.toSet().size, "a tool is in two groups")
        assertTrue(members.none { it in ToolConsolidation.KEEP })
        assertEquals(ToolConsolidation.GROUPS.size, ToolConsolidation.GROUPS.map { it.tool }.toSet().size)
    }

    @Test
    fun `every tool in the sources is grouped or kept, and nothing refers to a missing tool`() {
        val sources = sourceToolNames()
        assertTrue(sources.size > 100, "tool scan found only ${sources.size}")
        val assigned = ToolConsolidation.GROUPS.flatMap { it.actions.values }.toSet() + ToolConsolidation.KEEP
        assertEquals(emptySet(), sources - assigned, "tools neither grouped nor kept")
        assertEquals(emptySet(), assigned - sources, "groups name tools that do not exist")
    }

    @Test
    fun `apply merges groups, copies the rest and dispatches`() {
        val legacy = server()
        fake(legacy, "scope_check", listOf("url"), "url")
        fake(legacy, "scope_include", listOf("url"), "url")
        fake(legacy, "proxy_history", emptyList(), "count")
        val target = server()
        val groups = ToolConsolidation.GROUPS // real table; only register what it needs for this assertion
        // apply() requires every member, so use a trimmed copy of the logic via the public contract:
        val partial = legacy
        listOf("scope_exclude", "scope_get_config", "scope_list", "scope_remove").forEach { fake(partial, it, emptyList(), "url") }
        // register the other groups' members as empty stubs
        groups.filter { it.tool != "scope" }.flatMap { it.actions.values }.forEach { fake(partial, it) }
        ToolConsolidation.apply(partial, target)

        assertTrue("scope" in target.tools && "scope_check" !in target.tools)
        assertTrue("proxy_history" in target.tools, "kept tool is copied")

        val scope = target.tools.getValue("scope").tool
        val desc = scope.description!!
        assertTrue("check(url*)" in desc, desc)
        assertTrue("get_config(" in desc, desc)
        val action = scope.inputSchema.properties!!.getValue("action").jsonObject
        assertEquals(setOf("check", "include", "exclude", "get_config", "list", "remove"),
            action.getValue("enum").jsonArray.map { it.jsonPrimitive.content }.toSet())

        val ok = call(target, "scope", buildJsonObject { put("action", "check"); put("url", "https://a") })
        assertEquals("""scope_check:{"url":"https://a"}""", text(ok))
    }

    @Test
    fun `unknown action and missing parameter are reported`() {
        val legacy = server()
        ToolConsolidation.GROUPS.flatMap { it.actions.values }.forEach {
            fake(legacy, it, if (it == "scope_check") listOf("url") else emptyList(), "url")
        }
        ToolConsolidation.KEEP.forEach { fake(legacy, it) }
        val target = server()
        ToolConsolidation.apply(legacy, target)

        val bad = call(target, "scope", buildJsonObject { put("action", "nope") })
        assertEquals(true, bad.isError)
        assertTrue("unknown_action" in text(bad) && "include" in text(bad))

        val none = call(target, "scope", buildJsonObject {})
        assertEquals(true, none.isError)

        val missing = call(target, "scope", buildJsonObject { put("action", "check") })
        assertEquals(true, missing.isError)
        assertTrue("action 'check' requires 'url'" in text(missing), text(missing))
        assertFalse(target.tools.keys.any { it == "scope_check" })
    }

    @Test
    fun `rule action parameter is renamed so it does not clash with dispatch action`() {
        val legacy = server()
        val ruleActionMembers = setOf(
            "proxy_set_request_rule",
            "proxy_set_response_rule",
            "http_set_traffic_rule",
            "websocket_set_intercept_rule"
        )
        ToolConsolidation.GROUPS.flatMap { it.actions.values }.forEach { name ->
            if (name in ruleActionMembers) fake(legacy, name, emptyList(), "action", "pattern")
            else fake(legacy, name, emptyList(), "pattern")
        }
        ToolConsolidation.KEEP.forEach { fake(legacy, it) }
        val target = server()
        ToolConsolidation.apply(legacy, target)

        val proxyProps = target.tools.getValue("proxy_rule").tool.inputSchema.properties!!
        assertTrue("rule_action" in proxyProps)
        val pr = call(target, "proxy_rule", buildJsonObject { put("action", "set_request_rule"); put("rule_action", "drop") })
        assertEquals("""proxy_set_request_rule:{"action":"drop"}""", text(pr))

        val httpProps = target.tools.getValue("http_rule").tool.inputSchema.properties!!
        assertTrue("rule_action" in httpProps)
        val hr = call(target, "http_rule", buildJsonObject { put("action", "traffic_rule_set"); put("rule_action", "spoof_response") })
        assertEquals("""http_set_traffic_rule:{"action":"spoof_response"}""", text(hr))

        val wsProps = target.tools.getValue("websocket").tool.inputSchema.properties!!
        assertTrue("rule_action" in wsProps)
        val wr = call(target, "websocket", buildJsonObject { put("action", "set_intercept_rule"); put("rule_action", "drop") })
        assertEquals("""websocket_set_intercept_rule:{"action":"drop"}""", text(wr))
    }

    @Test
    fun `apply rejects group member declaring unrenamed action parameter`() {
        val legacy = server()
        ToolConsolidation.GROUPS.flatMap { it.actions.values }.forEach { name ->
            if (name == "scope_check") fake(legacy, name, emptyList(), "action") else fake(legacy, name)
        }
        ToolConsolidation.KEEP.forEach { fake(legacy, it) }
        val target = server()
        val ex = kotlin.test.assertFailsWith<IllegalStateException> {
            ToolConsolidation.apply(legacy, target)
        }
        assertTrue("action" in (ex.message ?: ""), ex.message)
    }

    @Test
    fun `decoder action accepts the data array send_to_tool publishes`() {
        val sent = mutableListOf<String>()
        val legacy = server()
        DecoderTools.register(legacy, DecoderBridge { sent += it })
        ToolConsolidation.GROUPS.flatMap { it.actions.values }
            .filter { it !in legacy.tools }
            .forEach { fake(legacy, it) }
        ToolConsolidation.KEEP.forEach { fake(legacy, it) }
        val target = server()
        ToolConsolidation.apply(legacy, target)

        val dataType = target.tools.getValue("send_to_tool").tool.inputSchema.properties!!
            .getValue("data").jsonObject.getValue("type").jsonPrimitive.content
        assertEquals("array", dataType)

        val ok = call(target, "send_to_tool", buildJsonObject {
            put("action", "decoder")
            put("data", buildJsonArray { add("raijin-smoke"); add("second") })
        })
        assertFalse(ok.isError == true, text(ok))
        assertEquals(listOf("raijin-smoke", "second"), sent)
        assertTrue("items_sent" in text(ok), text(ok))

        val one = call(target, "send_to_tool", buildJsonObject {
            put("action", "decoder")
            put("data", "plain")
        })
        assertFalse(one.isError == true, text(one))
        assertEquals(listOf("raijin-smoke", "second", "plain"), sent)

        val empty = call(target, "send_to_tool", buildJsonObject {
            put("action", "decoder")
            put("data", buildJsonArray { })
        })
        assertEquals(true, empty.isError)
        assertTrue("at least one item" in text(empty), text(empty))
        assertEquals(3, sent.size)
    }

    @Test
    fun `legacyName maps tool and action back to the member`() {
        assertEquals("burp_shutdown", ToolConsolidation.legacyName("burp", "shutdown"))
        assertEquals(null, ToolConsolidation.legacyName("http_fuzz", null))
    }
}
