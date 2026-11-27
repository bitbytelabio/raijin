package io.bitbytelab.raijin.tools

import io.bitbytelab.raijin.testClientConnection
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequestParams
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Every hand-picked example runs: it names a published tool or action and fits its schema. */
class ToolExamplesTest {

    private val real = lazy { RegisteredTools() }

    @AfterTest
    fun close() {
        if (real.isInitialized()) real.value.close()
    }

    @Test
    fun `every hand-picked example fits the schema of its tool or action`() {
        val members = real.value.members.tools
        val published = real.value.published.tools
        val groups = ToolConsolidation.GROUPS.associateBy { it.tool }
        val misfits =
            ToolExamples.EXAMPLES.mapNotNull { (key, args) ->
                val tool = key.substringBefore('.')
                val action = key.substringAfter('.', "").ifEmpty { null }
                val group = groups[tool]
                val schema =
                    when {
                        group != null && action != null -> {
                            val member =
                                group.actions[action]
                                    ?: return@mapNotNull "$key: ${group.tool} has no action $action"
                            val renames = group.renames[action].orEmpty()
                            val s = members.getValue(member).tool.inputSchema
                            JsonObject(
                                s.properties.orEmpty().mapKeys { (k, _) -> renames[k] ?: k },
                            ) to s.required.orEmpty().map { renames[it] ?: it }.toSet()
                        }
                        group == null && action == null -> {
                            val s =
                                published[tool]?.tool?.inputSchema
                                    ?: return@mapNotNull "$key: no published tool $tool"
                            (s.properties ?: JsonObject(emptyMap())) to s.required.orEmpty().toSet()
                        }
                        else ->
                            return@mapNotNull "$key: grouped tools need tool.action, others the tool name"
                    }
                val needed = schema.second - ToolExamples.ID_SOURCES[tool].orEmpty().keys
                if (ToolArgs.fits(args, schema.first, needed)) null
                else "$key: $args does not fit ${schema.first.keys}"
            }
        assertEquals(emptyList(), misfits)
    }

    @Test
    fun `every id source is a call that resolves exactly`() {
        val published = real.value.published.tools.mapValues { it.value.tool }
        val bad =
            ToolExamples.ID_SOURCES.flatMap { (tool, params) ->
                    params.map { (param, call) ->
                        when (val r = ToolNames.resolve(call, published)) {
                            is ToolNames.Found ->
                                if (
                                    r.note == null &&
                                        (r.tool !in ToolConsolidation.GROUPS.map { it.tool } ||
                                            ToolConsolidation.resolveAction(r.tool, r.action) ==
                                                r.action)
                                )
                                    null
                                else "$tool.$param: $call -> $r"
                            is ToolNames.NotFound -> "$tool.$param: $call -> $r"
                        }
                    }
                }
                .filterNotNull()
        assertEquals(emptyList(), bad)
    }

    /** Every `example` of the shipped catalog: each ungrouped tool's and each action's. */
    private fun catalogExamples(): Map<String, JsonObject> {
        val text =
            javaClass.getResourceAsStream("/catalog/tools.json")!!.readBytes().decodeToString()
        val tools =
            Json.parseToJsonElement(text).jsonObject.getValue("tools").jsonArray.map {
                it.jsonObject
            }
        return tools
            .flatMap { t ->
                val name = t.getValue("name").jsonPrimitive.content
                val own = listOfNotNull((t["example"] as? JsonObject)?.let { name to it })
                own +
                    (t["actions"] as? JsonObject).orEmpty().map { (a, spec) ->
                        "$name.$a" to spec.jsonObject.getValue("example").jsonObject
                    }
            }
            .toMap()
    }

    @Test
    fun `catalog examples hold no empty object and few placeholders`() {
        val examples = catalogExamples()
        val empty =
            examples
                .filter { (_, call) ->
                    call.values.any { v ->
                        v == JsonObject(emptyMap()) ||
                            (v is JsonArray && v.any { it == JsonObject(emptyMap()) })
                    }
                }
                .keys
        assertEquals(emptySet(), empty)
        val placeholders =
            examples
                .filter { (_, call) ->
                    call.values.any { v ->
                        (v as? JsonPrimitive)
                            ?.takeIf { it.isString }
                            ?.content
                            ?.let { it.startsWith("<") && it.endsWith(">") } == true
                    }
                }
                .keys
        assertTrue(
            placeholders.size <= MAX_PLACEHOLDER_EXAMPLES,
            "${placeholders.size} examples hold a placeholder: $placeholders",
        )
    }

    private companion object {
        /**
         * Catalog examples that still show a `"<param>"` placeholder; lower it as real values are
         * added.
         */
        const val MAX_PLACEHOLDER_EXAMPLES = 37
    }

    @Test
    fun `examples remove or stop nothing`() {
        val destructive =
            ToolExamples.EXAMPLES.keys.filter { key ->
                val tool = key.substringBefore('.')
                val action = key.substringAfter('.', "").ifEmpty { null }
                ToolNames.destructive(tool, action, real.value.published.tools[tool]?.tool)
            }
        assertEquals(emptyList(), destructive)
    }

    @Test
    fun `a grouped tool called without an action shows a read-only example`() {
        val burp = real.value.published.tools.getValue("burp")
        val result = runBlocking {
            burp.handler(
                testClientConnection,
                CallToolRequest(CallToolRequestParams("burp", JsonObject(emptyMap()))),
            )
        }
        val text = (result.content.single() as TextContent).text
        val example = Json.parseToJsonElement(text).jsonObject.getValue("example").jsonObject
        assertEquals(JsonPrimitive("version"), example["action"], text)
        assertTrue("config_json" !in example, text)
    }
}
