package io.bitbytelab.raijin.tools

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
                buildJsonObject { props.forEach { p -> putJsonObject(p) { put("type", "string"); put("description", "the $p") } } },
                required
            )
        ) { req -> CallToolResult(content = listOf(TextContent("$name:" + req.params.arguments.toString()))) }
    }

    private fun call(s: Server, tool: String, args: JsonObject) = runBlocking {
        s.tools.getValue(tool).handler(CallToolRequest(CallToolRequestParams(tool, args)))
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
        listOf("scope_exclude", "scope_get_config").forEach { fake(partial, it, emptyList(), "url") }
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
        assertEquals(setOf("check", "include", "exclude", "get_config"),
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
        ToolConsolidation.GROUPS.flatMap { it.actions.values }.forEach { fake(legacy, it, emptyList(), "action", "pattern") }
        ToolConsolidation.KEEP.forEach { fake(legacy, it) }
        val target = server()
        ToolConsolidation.apply(legacy, target)

        val props = target.tools.getValue("proxy_rule").tool.inputSchema.properties!!
        assertTrue("rule_action" in props)
        val r = call(target, "proxy_rule", buildJsonObject { put("action", "set_request_rule"); put("rule_action", "drop") })
        assertEquals("""proxy_set_request_rule:{"action":"drop"}""", text(r))
    }

    @Test
    fun `legacyName maps tool and action back to the member`() {
        assertEquals("burp_shutdown", ToolConsolidation.legacyName("burp", "shutdown"))
        assertEquals(null, ToolConsolidation.legacyName("http_fuzz", null))
    }
}
