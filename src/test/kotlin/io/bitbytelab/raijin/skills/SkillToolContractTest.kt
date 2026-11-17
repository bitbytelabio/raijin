package io.bitbytelab.raijin.skills

import io.bitbytelab.raijin.tools.RegisteredTools
import io.bitbytelab.raijin.tools.ToolConsolidation
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The tool calls the shipped skills show an agent, written as inline code `tool(name=value, ...)`
 * (`http_rule(action=macro_run, name=...)`), checked against the schemas Raijin publishes, with the
 * real tools registered on a Montoya stand-in ([RegisteredTools]).
 *
 * A call is checked as a client would send it: the tool is published, a grouped tool names one of
 * its actions, every parameter is one that action takes (under its published name), and a value
 * written out fits the parameter's type, allowed values and bounds. `...` and `<...>` stand for any
 * value, `[...]` and `{...}` for any array and object, and `a|b` lists alternatives, each checked.
 * Inline code that is not such a call (a bare name, `engine.queue(delay=...)`, `string(//token)`)
 * is not a tool call.
 */
class SkillToolContractTest {

    private val tools = RegisteredTools()
    private val checker = CallChecker(tools)

    @AfterTest
    fun close() = tools.close()

    @Test
    fun `every tool call in the shipped skills fits the published tools`() {
        val calls = SkillCatalog.list().flatMap { skill ->
            ToolCalls.find(skill.description + "\n" + skill.body).map { skill.name to it }
        }
        assertTrue(calls.isNotEmpty(), "no tool call found in the skills")
        val problems = calls.flatMap { (skill, call) -> checker.problems(call).map { "$skill: `${call.text}`: $it" } }
        assertEquals(emptyList(), problems, problems.joinToString("\n"))
    }

    @Test
    fun `a call that does not fit is reported, and other inline code is not a call`() {
        val fitting = listOf(
            "http_state(action=pipeline_connections, close_all=true)",
            "proxy_rule(action=set_request_rule|set_response_rule, rule_action=modify|drop|tag)",
            "http_race(request=..., host=..., count=20, sync=last_byte)",
            "http_fuzz(request=..., host=..., attack_mode=cluster_bomb, payload_sets=[...], encoders=[\"base64\", \"url\"])",
            "websocket(action=wait_message, connection_id=..., since_index=<message_index>)",
            "sitemap(action=query, note_contains=\"[MCP]\")",
        )
        val misfits = listOf(
            "no_such_tool(url=...)", // not a tool
            "session_macro_run(name=...)", // a member tool, published as http_rule(action=macro_run)
            "http_rule(name=...)", // a grouped tool without an action
            "http_rule(action=macro_start)", // not an action of the tool
            "http_rule(action=token_rule_list, name=...)", // a parameter of another action
            "http_race(sync=first_byte)", // not an allowed value
            "http_send_pipeline(keep_open=yes)", // not a boolean
            "http_fuzz(encoders=[\"rot13\"])", // an array item that is not allowed
            "http_state(action=pipeline_connections, close=all)", // text for an array
        )
        val notCalls = listOf("engine.queue(delay=...)", "string(//token)", "{value|url}", "http_send_request")
        val markdown = (fitting + misfits + notCalls).joinToString("\n") { "- `$it`" }

        val calls = ToolCalls.find(markdown)
        assertEquals(fitting + misfits, calls.map { it.text })
        assertEquals(misfits, calls.filter { checker.problems(it).isNotEmpty() }.map { it.text })
    }
}

/** A tool call written in a skill: its inline code [text], the [tool] and its `name=value` arguments, `...` left out. */
private class ToolCall(val text: String, val tool: String, val args: List<Pair<String, String>>)

private object ToolCalls {

    private val CODE = Regex("`([^`\\n]+)`")
    private val CALL = Regex("([a-z][a-z0-9_]*)\\((.*)\\)")
    private val ARG = Regex("([a-z_][a-z0-9_]*)\\s*=\\s*(\\S.*)")

    /** The tool calls written as inline code in [markdown], in order. */
    fun find(markdown: String): List<ToolCall> =
        CODE.findAll(markdown).mapNotNull { parse(it.groupValues[1].trim()) }.toList()

    private fun parse(code: String): ToolCall? {
        val call = CALL.matchEntire(code) ?: return null
        val args = split(call.groupValues[2]).filter { it != "..." }.map { item ->
            val arg = ARG.matchEntire(item) ?: return null
            arg.groupValues[1] to arg.groupValues[2].trim()
        }
        return ToolCall(code, call.groupValues[1], args)
    }

    /** [text] cut at the commas outside quotes and brackets; parts trimmed, empty ones dropped. */
    private fun split(text: String): List<String> {
        val parts = mutableListOf<String>()
        val part = StringBuilder()
        var depth = 0
        var quote: Char? = null
        for (c in text) {
            when {
                quote != null -> if (c == quote) quote = null
                c == '"' || c == '\'' -> quote = c
                c in "([{" -> depth++
                c in ")]}" -> depth--
                c == ',' && depth == 0 -> {
                    parts += part.toString()
                    part.clear()
                    continue
                }
            }
            part.append(c)
        }
        parts += part.toString()
        return parts.map { it.trim() }.filter { it.isNotEmpty() }
    }
}

/** An argument value as a skill writes it. */
private sealed interface DocValue {

    /** `...` or `<...>`: any value. */
    object Placeholder : DocValue

    /** `[...]` or `{...}`: any value of JSON type [type]. */
    class Shape(val type: String) : DocValue

    /** A JSON value: a bare word or quoted text (a string), `true`, `20`, `["url"]`. */
    class Literal(val json: JsonElement) : DocValue

    companion object {
        private val NUMBER = Regex("-?\\d+(\\.\\d+)?([eE][+-]?\\d+)?")

        /** The values [raw] stands for: its alternatives (`a|b`), or itself. */
        fun parse(raw: String): List<DocValue> {
            val value = raw.trim()
            return when {
                value == "..." || (value.startsWith("<") && value.endsWith(">")) -> listOf(Placeholder)
                value.length >= 2 && value.first() == '\'' && value.last() == '\'' ->
                    listOf(Literal(JsonPrimitive(value.substring(1, value.length - 1))))
                value.isNotEmpty() && value.first() in "\"[{" -> listOf(
                    strictJson(value)?.let(::Literal) ?: when (value.first()) {
                        '"' -> Literal(JsonPrimitive(value.trim('"')))
                        '[' -> Shape("array")
                        else -> Shape("object")
                    }
                )
                '|' in value -> value.split('|').flatMap { parse(it) }
                value == "true" || value == "false" -> listOf(Literal(JsonPrimitive(value.toBoolean())))
                NUMBER.matches(value) -> listOf(Literal(JsonPrimitive(value.toBigDecimal())))
                else -> listOf(Literal(JsonPrimitive(value)))
            }
        }

        /** [text] as JSON, or null when it is not strict JSON (kotlinx reads a bare word as an unquoted literal). */
        private fun strictJson(text: String): JsonElement? = try {
            Json.parseToJsonElement(text).takeIf(::isStrict)
        } catch (_: Exception) {
            null
        }

        private fun isStrict(element: JsonElement): Boolean = when (element) {
            is JsonObject -> element.values.all(::isStrict)
            is JsonArray -> element.all(::isStrict)
            is JsonPrimitive -> element.isString || element is JsonNull ||
                element.content == "true" || element.content == "false" || NUMBER.matches(element.content)
        }
    }
}

/** Checks [ToolCall]s against the tools [RegisteredTools] publishes, action by action. */
private class CallChecker(tools: RegisteredTools) {

    private val published = tools.published.tools
    private val members = tools.members.tools
    private val groups = ToolConsolidation.GROUPS.associateBy { it.tool }

    /** The call that replaces a member tool's own name, for a skill that still uses it. */
    private val folded: Map<String, String> = ToolConsolidation.GROUPS
        .flatMap { g -> g.actions.map { (action, member) -> member to "${g.tool}(action=$action)" } }
        .toMap()

    /** What is wrong with [call]; empty when it fits the published tools. */
    fun problems(call: ToolCall): List<String> {
        val tool = published[call.tool]?.tool
            ?: return listOf(folded[call.tool]?.let { "not a published tool; use $it" } ?: "not a published tool")
        val properties = tool.inputSchema.properties ?: JsonObject(emptyMap())
        val group = groups[call.tool]
            ?: return call.args.mapNotNull { (name, value) -> valueProblem(name, properties[name] as? JsonObject, value, call.tool) }

        val actionArg = call.args.firstOrNull { it.first == "action" }?.second ?: return listOf("names no action")
        val publishedActions = ((properties["action"] as? JsonObject)?.get("enum") as? JsonArray)
            ?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }.orEmpty()
        return DocValue.parse(actionArg).flatMap { value ->
            val action = ((value as? DocValue.Literal)?.json as? JsonPrimitive)?.takeIf { it.isString }?.content
                ?: return@flatMap listOf("names no action")
            val member = group.actions[action]?.let { members[it]?.tool }
            if (action !in publishedActions || member == null) return@flatMap listOf("$action is not an action of ${call.tool}")
            val memberName = group.renames[action].orEmpty().entries.associate { (memberParam, publicParam) -> publicParam to memberParam }
            val memberProperties = member.inputSchema.properties ?: JsonObject(emptyMap())
            call.args.filter { it.first != "action" }.mapNotNull { (name, raw) ->
                if (name !in properties) "${call.tool} publishes no parameter $name"
                else valueProblem(name, memberProperties[memberName[name] ?: name] as? JsonObject, raw, "action $action")
            }
        }
    }

    /** What is wrong with [raw] as parameter [name] of [owner], whose definition is [def]; null when it fits. */
    private fun valueProblem(name: String, def: JsonObject?, raw: String, owner: String): String? {
        def ?: return "$owner takes no parameter $name"
        return DocValue.parse(raw).firstNotNullOfOrNull { fit(def, it) }?.let { "$name: $it" }
    }

    private fun fit(def: JsonObject, value: DocValue): String? = when (value) {
        DocValue.Placeholder -> null
        is DocValue.Shape -> type(def)?.takeIf { it != value.type }?.let { "takes $it, not an ${value.type}" }
        is DocValue.Literal -> fit(def, value.json)
    }

    /** What is wrong with [value] for the schema [def]: its type, allowed values, bounds or an array item. */
    private fun fit(def: JsonObject, value: JsonElement): String? {
        type(def)?.let { if (!hasType(value, it)) return "takes $it, not $value" }
        (def["enum"] as? JsonArray)?.let { allowed ->
            val text = (value as? JsonPrimitive)?.contentOrNull
            if (allowed.none { (it as? JsonPrimitive)?.contentOrNull == text }) return "$value is not one of $allowed"
        }
        (value as? JsonPrimitive)?.takeUnless { it.isString }?.doubleOrNull?.let { number ->
            (def["minimum"] as? JsonPrimitive)?.doubleOrNull?.let { if (number < it) return "$value is below the minimum $it" }
            (def["maximum"] as? JsonPrimitive)?.doubleOrNull?.let { if (number > it) return "$value is above the maximum $it" }
        }
        val items = def["items"] as? JsonObject
        if (items != null && value is JsonArray) value.firstNotNullOfOrNull { fit(items, it) }?.let { return "an item $it" }
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
