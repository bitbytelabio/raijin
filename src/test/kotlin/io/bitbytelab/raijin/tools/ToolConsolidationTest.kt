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
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
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

    /** The real tools, registered on first use; see [RegisteredTools]. */
    private val real = lazy { RegisteredTools() }

    @AfterTest
    fun closeRealTools() {
        if (real.isInitialized()) real.value.close()
    }

    @Test
    fun `groups are disjoint and do not overlap KEEP`() {
        val members = ToolConsolidation.GROUPS.flatMap { it.actions.values }
        assertEquals(members.size, members.toSet().size, "a tool is in two groups")
        assertTrue(members.none { it in ToolConsolidation.KEEP })
        assertEquals(ToolConsolidation.GROUPS.size, ToolConsolidation.GROUPS.map { it.tool }.toSet().size)
    }

    @Test
    fun `every registered tool is grouped or kept, and nothing refers to a missing tool`() {
        val registered = real.value.members.tools.keys
        val assigned = ToolConsolidation.GROUPS.flatMap { it.actions.values }.toSet() + ToolConsolidation.KEEP
        assertEquals(emptySet(), registered - assigned, "tools neither grouped nor kept")
        assertEquals(emptySet(), assigned - registered, "groups name tools that do not exist")
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

    /** Every real member tool, and the tools [ToolConsolidation] publishes from them. */
    private fun consolidatedWithRealTools(): Pair<Server, Server> = real.value.members to real.value.published

    private fun JsonObject.str(key: String) = (this[key] as? JsonPrimitive)?.contentOrNull

    @Test
    fun `merged group schemas keep every action's parameter description and enum values`() {
        val (legacy, target) = consolidatedWithRealTools()
        for (g in ToolConsolidation.GROUPS) {
            val props = target.tools.getValue(g.tool).tool.inputSchema.properties!!
            assertEquals(g.actions.keys.toList(),
                props.getValue("action").jsonObject.getValue("enum").jsonArray.map { it.jsonPrimitive.content })
            for ((action, member) in g.actions) {
                val memberProps = legacy.tools.getValue(member).tool.inputSchema.properties ?: continue
                val sameName = memberProps.keys.associateWith { g.renames[action]?.get(it) ?: it }
                for ((name, rawDef) in memberProps) {
                    val pub = sameName.getValue(name)
                    assertTrue(pub != "action", "${g.tool}.$action publishes '$name' as 'action'")
                    val def = rawDef.jsonObject
                    val merged = props.getValue(pub).jsonObject
                    val desc = merged.str("description").orEmpty()
                    val own = def.str("description").orEmpty().trim()
                    assertTrue(own in desc, "${g.tool}.$pub lost $action's description '$own': $desc")
                    val mergedEnum = merged["enum"]?.jsonArray
                    def["enum"]?.jsonArray?.forEach { v ->
                        assertTrue(mergedEnum?.contains(v) == true || v.jsonPrimitive.content in desc,
                            "${g.tool}.$pub lost $action's enum value $v")
                    }
                    if (mergedEnum != null) {
                        assertNotNull(def["enum"], "${g.tool}.$pub enum would reject values $action accepts")
                    }
                    def["type"]?.let { t -> merged["type"]?.let { assertEquals(t, it, "${g.tool}.$pub type") } }
                }
            }
        }
    }

    @Test
    fun `shared closed parameters unite their enums and keep per-action allowed values`() {
        val (_, target) = consolidatedWithRealTools()
        fun param(tool: String, name: String) =
            target.tools.getValue(tool).tool.inputSchema.properties!!.getValue(name).jsonObject
        fun enumOf(p: JsonObject) = p.getValue("enum").jsonArray.map { it.jsonPrimitive.content }.toSet()

        val algorithm = param("util", "algorithm")
        assertEquals(setOf("MD5", "SHA_1", "SHA_256", "SHA_384", "SHA_512", "GZIP", "DEFLATE", "BROTLI"), enumOf(algorithm))
        val algDesc = algorithm.str("description")!!
        assertTrue("[hash]" in algDesc && "[compress]" in algDesc && "[decompress]" in algDesc, algDesc)

        val level = param("log", "level")
        assertEquals(setOf("output", "error", "debug", "info", "critical"), enumOf(level))
        assertTrue("[message]" in level.str("description")!! && "[event]" in level.str("description")!!)

        val type = param("config", "type")
        assertTrue(setOf("request_header", "response_body", "HTTP", "SOCKS5").all { it in enumOf(type) })
        assertTrue("[match_replace_add]" in type.str("description")!! && "[upstream_proxy_set]" in type.str("description")!!)

        val data = param("util", "data")
        assertEquals("string", data.str("type"))
        assertTrue("Base64-encoded compressed data" in data.str("description")!!)
        assertTrue("The URL-encoded string to decode" in data.str("description")!!)
    }

    @Test
    fun `mergeParam keeps a free-form action's values and every mode of an enum action`() {
        val jwtModes = listOf(
            "analyze", "forge_none", "alg_confusion", "crack", "sign", "sign_key", "verify",
            "encrypt", "decrypt", "embed_jwk", "empty_hmac", "psychic", "header_url",
        )
        val graphql = buildJsonObject { put("type", "string"); put("description", "probe (default) | query_templates | poi_scan") }
        val jwt = buildJsonObject {
            put("type", "string")
            putJsonArray("enum") { jwtModes.forEach { add(it) } }
            put("description", "JWT operation (default analyze)")
        }
        val merged = ToolConsolidation.mergeParam(listOf("graphql" to graphql, "jwt" to jwt), groupSize = 6)

        assertNull(merged["enum"], "graphql accepts values outside jwt's enum")
        assertEquals("string", merged.str("type"))
        val desc = merged.str("description")!!
        assertTrue("[graphql] probe (default) | query_templates | poi_scan" in desc, desc)
        assertTrue("[jwt] JWT operation (default analyze)" in desc, desc)
        jwtModes.forEach { assertTrue(it in desc, "mode $it missing: $desc") }
    }

    @Test
    fun `mergeParam unites enums, keeps agreed keys and drops conflicting types`() {
        val a = buildJsonObject { put("type", "string"); putJsonArray("enum") { add("x"); add("y") }; put("description", "first") }
        val b = buildJsonObject { put("type", "string"); putJsonArray("enum") { add("y"); add("z") }; put("description", "second") }
        val united = ToolConsolidation.mergeParam(listOf("a" to a, "b" to b), groupSize = 3)
        assertEquals(listOf("x", "y", "z"), united.getValue("enum").jsonArray.map { it.jsonPrimitive.content })
        assertTrue("[a] first (one of: x, y)" in united.str("description")!!, united.toString())
        assertTrue("[b] second (one of: y, z)" in united.str("description")!!, united.toString())

        val same = buildJsonObject { put("type", "integer"); put("minimum", 1); put("description", "count") }
        val shared = ToolConsolidation.mergeParam(listOf("a" to same, "b" to same), groupSize = 3)
        assertEquals(1, shared.getValue("minimum").jsonPrimitive.int)
        assertEquals("count [actions: a, b]", shared.str("description"))
        assertEquals("count", ToolConsolidation.mergeParam(listOf("a" to same, "b" to same), groupSize = 2).str("description"))

        val scalar = buildJsonObject { put("type", "string"); put("description", "one item") }
        val list = buildJsonObject { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "many items") }
        val conflict = ToolConsolidation.mergeParam(listOf("a" to scalar, "b" to list), groupSize = 2)
        assertNull(conflict["type"])
        assertNull(conflict["items"])
        val desc = conflict.str("description")!!
        assertTrue("any JSON value" in desc && "one item (type: string)" in desc && "many items (type: array)" in desc, desc)

        val d1 = buildJsonObject { put("type", "integer"); put("default", 10); put("description", "depth") }
        val d2 = buildJsonObject { put("type", "integer"); put("default", 5); put("description", "depth") }
        val defaults = ToolConsolidation.mergeParam(listOf("a" to d1, "b" to d2), groupSize = 2)
        assertNull(defaults["default"])
        assertTrue("[a] depth (default: 10)" in defaults.str("description")!! && "[b] depth (default: 5)" in defaults.str("description")!!)
    }

    @Test
    fun `summary does not cut at abbreviations`() {
        assertEquals("Send it to a tool (e.g. Repeater) for replay.",
            ToolConsolidation.summary("Send it to a tool (e.g. Repeater) for replay. More text."))
        assertEquals("Pick an encoding, i.e. base64 or hex, and decode.",
            ToolConsolidation.summary("Pick an encoding, i.e. base64 or hex, and decode. Then stop."))
        assertEquals("Does it.", ToolConsolidation.summary("Does it. Next sentence."))
        assertEquals("Version 1.2 is fine!", ToolConsolidation.summary("Version 1.2 is fine! Really."))
        assertEquals("No terminator", ToolConsolidation.summary("No terminator"))
        val long = "word ".repeat(60)
        assertTrue(ToolConsolidation.summary(long).endsWith("...") && ToolConsolidation.summary(long).length == 160)
    }
}
