package io.bitbytelab.raijin.tools

import io.bitbytelab.raijin.core.isStrictJson
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.serialization.json.*

/**
 * Argument checks shared by every published tool: the `usage` line and copy-ready `example` an
 * argument error carries, "did you mean" suggestions, and the type coercions that undo the usual
 * agent mistakes (an object sent as a JSON string, a single value where an array is declared).
 *
 * Coercion only moves a value toward the declared `type` of a parameter the schema knows; any other
 * value reaches the handler untouched, so wire content is never altered.
 */
internal object ToolArgs {

    /** Up to [max] of [names] close to [wanted] (edit distance or containment), closest first. */
    fun closest(wanted: String, names: Collection<String>, max: Int = 3): List<String> {
        val w = wanted.lowercase()
        if (w.isEmpty()) return emptyList()
        val limit = maxOf(2, w.length / 3)
        return names.asSequence()
            .map { it to levenshtein(w, it.lowercase()) }
            .filter { (name, d) -> val n = name.lowercase(); d <= limit || n.contains(w) || w.contains(n) }
            .sortedWith(compareBy<Pair<String, Int>> { it.second }.thenBy { it.first })
            .take(max)
            .map { it.first }
            .toList()
    }

    private fun levenshtein(a: String, b: String): Int {
        var prev = IntArray(b.length + 1) { it }
        var cur = IntArray(b.length + 1)
        for (i in 1..a.length) {
            cur[0] = i
            for (j in 1..b.length) {
                val cost = if (a[i - 1] == b[j - 1]) 0 else 1
                cur[j] = minOf(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            }
            val t = prev; prev = cur; cur = t
        }
        return prev[b.length]
    }

    /**
     * One-line call signature, required parameters first (marked `*`), e.g.
     * `scope(action="remove", list*: "include"|"exclude", index*: integer)`.
     */
    fun signature(tool: String, action: String?, props: JsonObject, required: Set<String>): String {
        val parts = mutableListOf<String>()
        if (action != null) parts += "action=\"$action\""
        ordered(props, required).forEach { (name, def) ->
            parts += name + (if (name in required) "*" else "") + ": " + typeText(def)
        }
        return "$tool(${parts.joinToString(", ")})"
    }

    /** A minimal correct call: `action` (when given), then a placeholder for every required parameter. */
    fun example(action: String?, props: JsonObject, required: Set<String>): JsonObject = buildJsonObject {
        if (action != null) put("action", action)
        ordered(props, required).filter { it.first in required }.forEach { (name, def) -> put(name, placeholder(name, def)) }
    }

    private fun ordered(props: JsonObject, required: Set<String>): List<Pair<String, JsonObject>> {
        val all = props.entries.map { (k, v) -> k to (v as? JsonObject ?: JsonObject(emptyMap())) }
        return all.filter { it.first in required } + all.filter { it.first !in required }
    }

    private fun JsonObject.typeName(): String? = (this["type"] as? JsonPrimitive)?.contentOrNull

    private fun typeText(def: JsonObject): String {
        (def["enum"] as? JsonArray)?.let { values ->
            val shown = values.take(8).joinToString("|") { it.toString() }
            return if (values.size > 8) "$shown|..." else shown
        }
        return when (val type = def.typeName()) {
            "array" -> (def["items"] as? JsonObject)?.typeName()?.let { "array of $it" } ?: "array"
            null -> "any"
            else -> type
        }
    }

    private fun placeholder(name: String, def: JsonObject): JsonElement {
        (def["enum"] as? JsonArray)?.firstOrNull()?.let { return it }
        return when (def.typeName()) {
            "string" -> JsonPrimitive("<$name>")
            "integer" -> (def["minimum"] as? JsonPrimitive)?.takeIf { it.longOrNull != null } ?: JsonPrimitive(1)
            "number" -> JsonPrimitive(1)
            "boolean" -> JsonPrimitive(true)
            "array" -> JsonArray(listOf(placeholder(name, def["items"] as? JsonObject ?: JsonObject(emptyMap()))))
            "object" -> JsonObject(emptyMap())
            else -> JsonPrimitive("<$name>")
        }
    }

    /** [args] with values of known parameters moved toward their declared `type` where that is lossless. */
    fun coerce(props: JsonObject?, args: JsonObject): JsonObject {
        if (props == null || args.isEmpty()) return args
        var changed = false
        val out = LinkedHashMap<String, JsonElement>(args.size)
        args.forEach { (k, v) ->
            val type = (props[k] as? JsonObject)?.typeName()
            val c = if (type == null) v else coerceValue(type, v)
            if (c !== v) changed = true
            out[k] = c
        }
        return if (changed) JsonObject(out) else args
    }

    private fun coerceValue(type: String, v: JsonElement): JsonElement = when (type) {
        "string" -> if (v is JsonObject || v is JsonArray) JsonPrimitive(v.toString()) else v
        "object" -> (v as? JsonPrimitive)?.takeIf { it.isString }?.let { parseStrict(it.content) as? JsonObject } ?: v
        "array" -> when {
            v is JsonArray || v is JsonNull -> v
            v is JsonPrimitive && v.isString -> parseStrict(v.content) as? JsonArray ?: JsonArray(listOf(v))
            else -> JsonArray(listOf(v))
        }
        else -> v
    }

    /** [text] parsed as JSON, or null when it is not JSON or holds unquoted words (`[admin]` stays a string). */
    private fun parseStrict(text: String): JsonElement? =
        runCatching { Json.parseToJsonElement(text) }.getOrNull()?.takeIf { it.isStrictJson() }

    /** Keys of [args] that are neither declared in [props] nor in [ignore], in argument order. */
    fun unknownParams(props: JsonObject?, args: JsonObject, ignore: Set<String>): List<String> =
        args.keys.filter { it !in ignore && (props == null || it !in props) }

    /** `Parameter(s) ...: 'x' (did you mean 'y'?), 'z'` fragment for [unknown] against [known]. */
    fun unknownList(unknown: List<String>, known: Collection<String>): String = unknown.joinToString(", ") { key ->
        val hint = closest(key, known, 1).firstOrNull()
        if (hint != null) "'$key' (did you mean '$hint'?)" else "'$key'"
    }

    /** An argument error: `{"error": message, "code": code, ...extra}` with `isError`. */
    fun error(code: String, message: String, extra: JsonObjectBuilder.() -> Unit = {}): CallToolResult =
        toolJsonResult(buildJsonObject { put("error", message); put("code", code); extra() })

    private val ARGUMENT_ERROR = Regex(
        "(?i)\\b(required|missing|invalid|must|unknown|expected|allowed|not a valid|cannot be empty|parameter|JsonPrimitive|JsonObject|JsonArray)\\b"
    )
    private const val MAX_ENRICHED_CHARS = 8192

    /**
     * Adds `usage` and `example` to a handler's argument error (a single small JSON text whose
     * `error` reads like a bad-argument message). Any other result is returned as is.
     */
    fun enrich(result: CallToolResult, usage: String, example: JsonObject): CallToolResult {
        if (result.isError != true) return result
        val content = result.content.singleOrNull() as? TextContent ?: return result
        if (content.text.length > MAX_ENRICHED_CHARS) return result
        val json = parseStrict(content.text) as? JsonObject ?: return result
        val error = (json["error"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return result
        if ("usage" in json || !ARGUMENT_ERROR.containsMatchIn(error)) return result
        val enriched = JsonObject(json + mapOf("usage" to JsonPrimitive(usage), "example" to example))
        return result.copy(content = listOf(content.copy(text = enriched.toString())))
    }
}
