package io.bitbytelab.raijin.tools

import io.bitbytelab.raijin.testClientConnection
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequestParams
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

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
        val misfits = ToolExamples.EXAMPLES.mapNotNull { (key, args) ->
            val tool = key.substringBefore('.')
            val action = key.substringAfter('.', "").ifEmpty { null }
            val group = groups[tool]
            val schema = when {
                group != null && action != null -> {
                    val member = group.actions[action] ?: return@mapNotNull "$key: ${group.tool} has no action $action"
                    val renames = group.renames[action].orEmpty()
                    val s = members.getValue(member).tool.inputSchema
                    JsonObject(s.properties.orEmpty().mapKeys { (k, _) -> renames[k] ?: k }) to
                        s.required.orEmpty().map { renames[it] ?: it }.toSet()
                }
                group == null && action == null -> {
                    val s = published[tool]?.tool?.inputSchema ?: return@mapNotNull "$key: no published tool $tool"
                    (s.properties ?: JsonObject(emptyMap())) to s.required.orEmpty().toSet()
                }
                else -> return@mapNotNull "$key: grouped tools need tool.action, others the tool name"
            }
            if (ToolArgs.fits(args, schema.first, schema.second)) null else "$key: $args does not fit ${schema.first.keys}"
        }
        assertEquals(emptyList(), misfits)
    }

    @Test
    fun `examples remove or stop nothing`() {
        val destructive = ToolExamples.EXAMPLES.keys.filter { key ->
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
            burp.handler(testClientConnection, CallToolRequest(CallToolRequestParams("burp", JsonObject(emptyMap()))))
        }
        val text = (result.content.single() as TextContent).text
        val example = Json.parseToJsonElement(text).jsonObject.getValue("example").jsonObject
        assertEquals(JsonPrimitive("version"), example["action"], text)
        assertTrue("config_json" !in example, text)
    }
}
