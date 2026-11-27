package io.bitbytelab.raijin.tools

import io.modelcontextprotocol.kotlin.sdk.types.Tool
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

class ToolNamesTest {

    private val empty = JsonObject(emptyMap())

    /** The published names: every group tool and every KEEP tool, with their real annotations. */
    private val published: Map<String, Tool> =
        (ToolConsolidation.GROUPS.map { it.tool } + ToolConsolidation.KEEP).associateWith {
            Tool(name = it, inputSchema = ToolSchema(), annotations = ToolHints.of(it))
        }

    private fun resolve(raw: String) = ToolNames.resolve(raw, published)

    @Test
    fun `exact, legacy member and dotted names`() {
        assertEquals(ToolNames.Found("proxy_history", null, empty, null), resolve("proxy_history"))
        assertEquals(
            ToolNames.Found("scope", "list", empty, "'scope_list' is now scope.list"),
            resolve("scope_list"),
        )
        assertEquals(ToolNames.Found("scope", "chek", empty, null), resolve("scope.chek"))
    }

    @Test
    fun `case and separators are forgiven, but never for a destructive call`() {
        assertEquals(
            ToolNames.Found("burp", "version", empty, "ran 'Burp.Version' as burp.version"),
            resolve("Burp.Version"),
        )
        assertEquals(
            ToolNames.NotFound(listOf("burp.shutdown"), "burp.shutdown"),
            resolve("Burp.Shutdown"),
        )
        assertEquals(
            ToolNames.NotFound(listOf("burp.shutdown"), "burp.shutdown"),
            resolve("burp.Shutdown"),
        )
        assertEquals(ToolNames.Found("burp", "shutdown", empty, null), resolve("burp.shutdown"))
    }

    @Test
    fun `a hash name runs util hash with that algorithm`() {
        assertEquals(
            ToolNames.Found(
                "util",
                "hash",
                buildJsonObject { put("algorithm", "SHA_256") },
                "ran 'sha256' as util.hash with algorithm SHA_256",
            ),
            resolve("sha256"),
        )
    }

    @Test
    fun `unknown names get suggestions and a retry only when one is certain`() {
        assertEquals(
            ToolNames.NotFound(listOf("proxy_history"), "proxy_history"),
            resolve("proxy_histroy"),
        )
        assertEquals(ToolNames.NotFound(emptyList(), null), resolve("nope_tool"))
    }

    @Test
    fun `short names are not near longer unrelated words`() {
        val names = published.keys + listOf("ai", "log")
        for (wanted in listOf("email", "catalog")) {
            val hits = ToolArgs.closest(wanted, names)
            assertTrue("ai" !in hits && "log" !in hits, "$wanted: $hits")
        }
    }

    @Test
    fun `a server prefix is read off the name, with a note`() {
        for (raw in
            listOf(
                "raijin.proxy_history",
                "mcp__raijin__proxy_history",
                "functions.proxy_history",
            )) {
            val r = resolve(raw)
            assertTrue(
                r is ToolNames.Found &&
                    r.tool == "proxy_history" &&
                    r.note == "read '$raw' as proxy_history",
                "$raw: $r",
            )
        }
        assertEquals(
            ToolNames.Found(
                "scope",
                "list",
                empty,
                "read 'raijin/scope/list' as scope.list; ran 'scope/list' as scope.list",
            ),
            resolve("raijin/scope/list"),
        )
    }

    @Test
    fun `a typo's retry always names one call that takes the arguments as sent`() {
        val real = RegisteredTools()
        try {
            val tools = real.published.tools.mapValues { it.value.tool }
            val calls =
                tools.keys.filter { it !in ToolConsolidation.GROUPS.map { g -> g.tool } } +
                    ToolConsolidation.GROUPS.filter { it.tool in tools }
                        .flatMap { g -> g.actions.keys.map { "${g.tool}.$it" } }
            val bad = calls.flatMap { call ->
                call.indices
                    .map { i -> call.removeRange(i, i + 1) }
                    .filter { it.isNotBlank() }
                    .mapNotNull { typo ->
                        val r =
                            ToolNames.resolve(typo, tools) as? ToolNames.NotFound
                                ?: return@mapNotNull null
                        val result =
                            io.bitbytelab.raijin.transport.unknownTool(typo, r, empty, tools)
                        val text =
                            (result.content.single()
                                    as io.modelcontextprotocol.kotlin.sdk.types.TextContent)
                                .text
                        val retry =
                            (kotlinx.serialization.json.Json.parseToJsonElement(text)
                                as JsonObject)["retry"]
                                as? JsonObject ?: return@mapNotNull null
                        val name = (retry["do"] as kotlinx.serialization.json.JsonPrimitive).content
                        val found = ToolNames.resolve(name, tools) as? ToolNames.Found
                        val tool = name.substringBefore('.')
                        val action = name.substringAfter('.', "").ifEmpty { null }
                        if (
                            found != null &&
                                found.note == null &&
                                ToolConsolidation.callFits(
                                    tool,
                                    action,
                                    JsonObject(retry - "do"),
                                    tools[tool],
                                )
                        )
                            null
                        else "$typo -> $retry"
                    }
            }
            assertEquals(emptyList(), bad)
        } finally {
            real.close()
        }
    }
}
