package io.bitbytelab.raijin.skills

import io.bitbytelab.raijin.tools.RegisteredTools
import io.bitbytelab.raijin.tools.ToolConsolidation
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.doubleOrNull

/**
 * The tool calls the playbooks bundled with the raijin CLI (`crates/cli/src/skills`) show an agent,
 * written as inline code `run {"do":"<tool>", ...}` (`run
 * {"do":"http_rule.macro_run","name":"<name>"}`), checked against the schemas Raijin publishes,
 * with the real tools registered on a Montoya stand-in ([RegisteredTools]).
 *
 * A call is checked as a client would send it: the text after `run ` is one strict JSON object with
 * a string `do`; the tool is published; a grouped tool names one of its actions
 * (`<tool>.<action>`); every parameter is one that action takes (under its published name), and
 * every required one is given; and a value written out fits the parameter's type, allowed values
 * and bounds. A string `"<...>"` or `"..."` stands for any value. Tools the CLI runs itself
 * ([CLI_TOOLS]) are checked by the CLI's own tests. Inline code that does not start with `run {` is
 * not a tool call.
 */
class SkillToolContractTest {

    private val tools = RegisteredTools()
    private val checker = CallChecker(tools)
    private val skillsDir = File("crates/cli/src/skills")

    @AfterTest fun close() = tools.close()

    /** Every playbook file, keyed by its path under [skillsDir]. */
    private fun skillFiles(): List<Pair<String, String>> {
        val files =
            skillsDir
                .walkTopDown()
                .filter { it.isFile && it.extension == "md" }
                .sortedBy { it.path }
                .toList()
        assertTrue(files.isNotEmpty(), "no playbook under ${skillsDir.absolutePath}")
        return files.map { it.relativeTo(skillsDir).invariantSeparatorsPath to it.readText() }
    }

    @Test
    fun `every tool call in the shipped skills fits the published tools`() {
        val calls = skillFiles().flatMap { (path, text) -> ToolCalls.find(text).map { path to it } }
        assertTrue(calls.isNotEmpty(), "no tool call found in the skills")
        val problems = calls.flatMap { (path, call) ->
            checker.problems(call).map { "$path: `${call.text}`: $it" }
        }
        assertEquals(emptyList(), problems, problems.joinToString("\n"))
    }

    @Test
    fun `every skill file uses run calls only`() {
        val oldCall = Regex("`[a-z_]+\\((action|[a-z_]+)=")
        val problems =
            skillFiles().flatMap { (path, text) ->
                buildList {
                    oldCall.find(text)?.let {
                        add("$path: old tool(param=value) notation: ${it.value}")
                    }
                    listOf("execute(", "discover(", "load_skill")
                        .filter { it in text }
                        .forEach { add("$path: mentions $it") }
                }
            }
        assertEquals(emptyList(), problems, problems.joinToString("\n"))
    }

    @Test
    fun `a call that does not fit is reported, and other inline code is not a call`() {
        val fitting =
            listOf(
                """run {"do":"http_state.pipeline_connections","close_all":true}""",
                """run {"do":"proxy_rule.set_request_rule","rule_action":"drop"}""",
                """run {"do":"http_race","request":"<raw>","host":"<host>","count":20,"sync":"last_byte"}""",
                """run {"do":"http_fuzz","request":"<raw>","host":"<host>","attack_mode":"cluster_bomb","payload_sets":["<...>"],"encoders":["base64","url"]}""",
                """run {"do":"websocket.wait_message","connection_id":"<id>","since_index":"<message_index>"}""",
                """run {"do":"sitemap.query","note_contains":"[MCP]"}""",
            )
        val misfits =
            listOf(
                """run {"do":"no_such_tool","url":"<url>"}""", // not a tool
                """run {"do":"session_macro_run","name":"<name>"}""", // a member tool, published as
                // http_rule.macro_run
                """run {"do":"http_rule","name":"<name>"}""", // a grouped tool without an action
                """run {"do":"http_rule.macro_start"}""", // not an action of the tool
                """run {"do":"http_rule.token_rule_list","name":"<name>"}""", // a parameter of
                // another action
                """run {"do":"http_race","sync":"first_byte"}""", // not an allowed value
                """run {"do":"http_send_pipeline","keep_open":"yes"}""", // not a boolean
                """run {"do":"http_fuzz","encoders":["rot13"]}""", // an array item that is not
                // allowed
                """run {"do":"http_state.pipeline_connections","close":"all"}""", // text for an
                // array
                """run {"do":"analyze.diff","item1":"<a>","item2":"<b>"}""", // a required parameter
                // left out
                """run {do:"x"}""", // not strict JSON
            )
        val cli = """run {"do":"burp_up"}"""
        val notCalls =
            listOf(
                "engine.queue(delay=...)",
                "{value|url}",
                "http_send_request",
                """guide {"topic":"http"}""",
            )
        val markdown = (fitting + misfits + cli + notCalls).joinToString("\n") { "- `$it`" }

        val calls = ToolCalls.find(markdown)
        assertEquals(fitting + misfits + cli, calls.map { it.text })
        assertEquals(misfits, calls.filter { checker.problems(it).isNotEmpty() }.map { it.text })
    }
}

/**
 * Tools the raijin CLI runs itself (Burp lifecycle, offline history); its own tests check their
 * calls.
 */
private val CLI_TOOLS =
    setOf(
        "burp_up",
        "burp_down",
        "burp_status",
        "history_list",
        "history_show",
        "history_search",
        "history_endpoints",
        "history_diff",
        "history_export",
        "data_list",
        "data_search",
        "data_get",
        "data_payloads",
        "data_add",
        "data_import",
        "data_update",
    )

/**
 * A `run` call written in a skill: its inline code [text], the [tool] and its arguments (a grouped
 * tool's action included as `action`), or the [parseProblem] that kept it from being one.
 */
private class ToolCall(
    val text: String,
    val tool: String,
    val args: List<Pair<String, JsonElement>>,
    val parseProblem: String? = null,
)

private object ToolCalls {

    private val CODE = Regex("`([^`\\n]+)`")
    private const val PREFIX = "run {"

    /** The `run` calls written as inline code in [markdown], in order. */
    fun find(markdown: String): List<ToolCall> =
        CODE.findAll(markdown)
            .map { it.groupValues[1].trim() }
            .filter { it.startsWith(PREFIX) }
            .map(::parse)
            .toList()

    private fun parse(code: String): ToolCall {
        val json = strictJson(code.removePrefix("run").trim()) as? JsonObject
        val target =
            (json?.get("do") as? JsonPrimitive)?.takeIf { it.isString }?.content
                ?: return ToolCall(code, "", emptyList(), """not a strict run {"do":...} call""")
        val tool = target.substringBefore('.')
        val action = target.substringAfter('.', "").takeIf { '.' in target }
        val args = buildList {
            action?.let { add("action" to JsonPrimitive(it)) }
            // `project` picks the Burp that runs the call; the gateway takes it off before
            // forwarding.
            json
                .filterKeys { it != "do" && it != "project" }
                .forEach { (name, value) -> add(name to value) }
        }
        return ToolCall(code, tool, args)
    }

    private val NUMBER = Regex("-?\\d+(\\.\\d+)?([eE][+-]?\\d+)?")

    /**
     * [text] as JSON, or null when it is not strict JSON (kotlinx reads a bare word as an unquoted
     * literal).
     */
    private fun strictJson(text: String): JsonElement? =
        try {
            Json.parseToJsonElement(text).takeIf(::isStrict)
        } catch (_: Exception) {
            null
        }

    private fun isStrict(element: JsonElement): Boolean =
        when (element) {
            is JsonObject -> element.values.all(::isStrict)
            is JsonArray -> element.all(::isStrict)
            is JsonPrimitive ->
                element.isString ||
                    element is JsonNull ||
                    element.content == "true" ||
                    element.content == "false" ||
                    NUMBER.matches(element.content)
        }
}

/** An argument value as a skill writes it. */
private sealed interface DocValue {

    /** `"<...>"` or `"..."`: any value. */
    object Placeholder : DocValue

    /** Any other JSON value, checked as written. */
    class Literal(val json: JsonElement) : DocValue

    companion object {
        private val ANY = Regex("^<.*>$")

        fun of(value: JsonElement): DocValue {
            val text = (value as? JsonPrimitive)?.takeIf { it.isString }?.content
            return if (text != null && (text == "..." || ANY.matches(text))) Placeholder
            else Literal(value)
        }
    }
}

/** Checks [ToolCall]s against the tools [RegisteredTools] publishes, action by action. */
private class CallChecker(tools: RegisteredTools) {

    private val published = tools.published.tools
    private val members = tools.members.tools
    private val groups = ToolConsolidation.GROUPS.associateBy { it.tool }

    /** The call that replaces a member tool's own name, for a skill that still uses it. */
    private val folded: Map<String, String> =
        ToolConsolidation.GROUPS.flatMap { g ->
                g.actions.map { (action, member) -> member to "${g.tool}.$action" }
            }
            .toMap()

    /** What is wrong with [call]; empty when it fits the published tools. */
    fun problems(call: ToolCall): List<String> {
        call.parseProblem?.let {
            return listOf(it)
        }
        if (call.tool in CLI_TOOLS) return emptyList()
        val tool =
            published[call.tool]?.tool
                ?: return listOf(
                    folded[call.tool]?.let { "not a published tool; use $it" }
                        ?: "not a published tool",
                )
        val properties = tool.inputSchema.properties ?: JsonObject(emptyMap())
        val given = call.args.map { it.first }.toSet()
        val group =
            groups[call.tool]
                ?: return call.args.mapNotNull { (name, value) ->
                    valueProblem(name, properties[name] as? JsonObject, value, call.tool)
                } + missing(tool.inputSchema.required.orEmpty(), given, call.tool)

        val actionArg =
            call.args.firstOrNull { it.first == "action" }?.second
                ?: return listOf("names no action")
        val action =
            (DocValue.of(actionArg) as? DocValue.Literal)
                ?.json
                ?.let { it as? JsonPrimitive }
                ?.takeIf { it.isString }
                ?.content ?: return listOf("names no action")
        val publishedActions =
            ((properties["action"] as? JsonObject)?.get("enum") as? JsonArray)
                ?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
                .orEmpty()
        val member = group.actions[action]?.let { members[it]?.tool }
        if (action !in publishedActions || member == null)
            return listOf("$action is not an action of ${call.tool}")
        val memberName =
            group.renames[action].orEmpty().entries.associate { (memberParam, publicParam) ->
                publicParam to memberParam
            }
        val memberProperties = member.inputSchema.properties ?: JsonObject(emptyMap())
        val publicName = group.renames[action].orEmpty()
        val required = member.inputSchema.required.orEmpty().map { publicName[it] ?: it }
        return call.args
            .filter { it.first != "action" }
            .mapNotNull { (name, value) ->
                if (name !in properties) "${call.tool} publishes no parameter $name"
                else
                    valueProblem(
                        name,
                        memberProperties[memberName[name] ?: name] as? JsonObject,
                        value,
                        "action $action",
                    )
            } + missing(required, given, "action $action")
    }

    /** The parameters of [required] a call that gives [given] leaves out, one problem each. */
    private fun missing(required: List<String>, given: Set<String>, owner: String): List<String> =
        required.filter { it !in given }.map { "$owner needs parameter $it" }

    /**
     * What is wrong with [value] as parameter [name] of [owner], whose definition is [def]; null
     * when it fits.
     */
    private fun valueProblem(
        name: String,
        def: JsonObject?,
        value: JsonElement,
        owner: String,
    ): String? {
        def ?: return "$owner takes no parameter $name"
        return fit(def, value)?.let { "$name: $it" }
    }

    /**
     * What is wrong with [value] for the schema [def]: its type, allowed values, bounds or an array
     * item.
     */
    private fun fit(def: JsonObject, value: JsonElement): String? {
        if (DocValue.of(value) == DocValue.Placeholder) return null
        type(def)?.let { if (!hasType(value, it)) return "takes $it, not $value" }
        (def["enum"] as? JsonArray)?.let { allowed ->
            val text = (value as? JsonPrimitive)?.contentOrNull
            if (allowed.none { (it as? JsonPrimitive)?.contentOrNull == text })
                return "$value is not one of $allowed"
        }
        (value as? JsonPrimitive)
            ?.takeUnless { it.isString }
            ?.doubleOrNull
            ?.let { number ->
                (def["minimum"] as? JsonPrimitive)?.doubleOrNull?.let {
                    if (number < it) return "$value is below the minimum $it"
                }
                (def["maximum"] as? JsonPrimitive)?.doubleOrNull?.let {
                    if (number > it) return "$value is above the maximum $it"
                }
            }
        val items = def["items"] as? JsonObject
        if (items != null && value is JsonArray)
            value
                .firstNotNullOfOrNull { fit(items, it) }
                ?.let {
                    return "an item $it"
                }
        return null
    }

    private fun type(def: JsonObject): String? = (def["type"] as? JsonPrimitive)?.contentOrNull

    private fun hasType(value: JsonElement, type: String): Boolean {
        val primitive = value as? JsonPrimitive
        val literal = primitive?.takeUnless { it.isString || it is JsonNull }
        return when (type) {
            "string" -> primitive?.isString == true
            "boolean" -> literal?.booleanOrNull != null
            "integer" -> literal?.doubleOrNull?.let { it % 1.0 == 0.0 } == true
            "number" -> literal?.doubleOrNull != null
            "array" -> value is JsonArray
            "object" -> value is JsonObject
            else -> true
        }
    }
}
