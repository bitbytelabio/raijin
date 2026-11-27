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
     * `scope.remove(list*: "include"|"exclude", index*: integer)`: the call name `run` takes.
     */
    fun signature(tool: String, action: String?, props: JsonObject, required: Set<String>): String {
        val parts = ordered(props, required).map { (name, def) ->
            name + (if (name in required) "*" else "") + ": " + typeText(def)
        }
        return "${callName(tool, action)}(${parts.joinToString(", ")})"
    }

    /** `tool.action` for a grouped call, else `tool`. */
    fun callName(tool: String, action: String?): String = if (action == null) tool else "$tool.$action"

    /**
     * A correct call: `action` (when given), then the hand-picked arguments of [ToolExamples] when they
     * fit [props], else a placeholder for every required parameter.
     */
    fun example(tool: String, action: String?, props: JsonObject, required: Set<String>): JsonObject = buildJsonObject {
        if (action != null) put("action", action)
        val picked = ToolExamples.of(tool, action)?.takeIf { fits(it, props, required) }
        if (picked != null) {
            picked.forEach { (k, v) -> put(k, v) }
        } else {
            ordered(props, required).filter { it.first in required }.forEach { (name, def) -> put(name, placeholder(name, def)) }
        }
    }

    /** Whether [args] sets every [required] parameter, only declared ones, with values of the declared type and enum. */
    fun fits(args: JsonObject, props: JsonObject, required: Set<String>): Boolean =
        required.all { it in args } && args.all { (k, v) ->
            val def = props[k] as? JsonObject ?: return@all false
            typeFits(def, v) && stringEnum(def)?.let { allowed -> (v as? JsonPrimitive)?.content in allowed } != false
        }

    private fun typeFits(def: JsonObject, v: JsonElement): Boolean = when (def.typeName()) {
        "string" -> v is JsonPrimitive && v.isString
        "integer" -> v is JsonPrimitive && !v.isString && v.longOrNull != null
        "number" -> v is JsonPrimitive && !v.isString && v.doubleOrNull != null
        "boolean" -> v is JsonPrimitive && !v.isString && v.booleanOrNull != null
        "array" -> v is JsonArray
        "object" -> v is JsonObject
        else -> true
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

    /** Coerced arguments plus one note per change a caller should learn from (empty when silent). */
    data class Coerced(val args: JsonObject, val notes: List<String>)

    /**
     * [args] with values of known parameters moved toward their declared `type` where that is lossless,
     * and string enum values matched to their canonical spelling. [Coerced.args] is [args] itself when
     * nothing changed. Wrapping a scalar in an array is silent; JSON text read as an object or array,
     * and number, boolean and enum fixes are noted, so the caller sends the right form next time.
     */
    fun coerce(props: JsonObject?, args: JsonObject): Coerced {
        if (props == null || args.isEmpty()) return Coerced(args, emptyList())
        val notes = mutableListOf<String>()
        var changed = false
        val out = LinkedHashMap<String, JsonElement>(args.size)
        args.forEach { (k, v) ->
            val def = props[k] as? JsonObject
            val c = if (def == null) v else coerceValue(k, def, v, notes)
            if (c !== v) changed = true
            out[k] = c
        }
        return Coerced(if (changed) JsonObject(out) else args, notes)
    }

    private val INTEGER_TEXT = Regex("^-?\\d+$")
    private val NUMBER_TEXT = Regex("^-?(\\d+\\.?\\d*|\\.\\d+)([eE][-+]?\\d+)?$")

    private fun coerceValue(name: String, def: JsonObject, v: JsonElement, notes: MutableList<String>): JsonElement {
        val typed = when (def.typeName()) {
            "string" -> if (v is JsonObject || v is JsonArray) JsonPrimitive(v.toString()) else v
            "object" -> (v as? JsonPrimitive)?.takeIf { it.isString }?.let { parseStrict(it.content) as? JsonObject }
                ?.also { notes += "parsed '$name' from a JSON string" } ?: v
            "array" -> {
                val array = when {
                    v is JsonArray || v is JsonNull -> v
                    v is JsonPrimitive && v.isString -> (parseStrict(v.content) as? JsonArray)
                        ?.also { notes += "parsed '$name' from a JSON string" } ?: JsonArray(listOf(v))
                    else -> JsonArray(listOf(v))
                }
                val items = def["items"] as? JsonObject
                if (array is JsonArray && items != null && stringEnum(items) != null) {
                    val matched = array.map { matchEnum(name, items, it, notes) }
                    if (matched.indices.any { matched[it] !== array[it] }) JsonArray(matched) else array
                } else array
            }
            "integer" -> toInteger(name, v, notes)
            "number" -> {
                val p = v as? JsonPrimitive
                val text = p?.takeIf { it.isString }?.content?.trim()
                if (text != null && NUMBER_TEXT.matches(text) && text.toDouble().isFinite()) {
                    notes += "coerced '$name' from string \"${p.content}\" to number"
                    text.toLongOrNull()?.let { JsonPrimitive(it) } ?: JsonPrimitive(text.toDouble())
                } else v
            }
            "boolean" -> {
                val p = v as? JsonPrimitive
                when (p?.takeIf { it.isString }?.content?.trim()?.lowercase()) {
                    "true" -> JsonPrimitive(true).also { notes += "coerced '$name' from string \"${p.content}\" to boolean" }
                    "false" -> JsonPrimitive(false).also { notes += "coerced '$name' from string \"${p.content}\" to boolean" }
                    else -> v
                }
            }
            else -> v
        }
        return matchEnum(name, def, typed, notes)
    }

    private fun toInteger(name: String, v: JsonElement, notes: MutableList<String>): JsonElement {
        val p = v as? JsonPrimitive ?: return v
        if (p.isString) {
            val text = p.content.trim()
            val n = text.takeIf { INTEGER_TEXT.matches(it) }?.toLongOrNull() ?: return v
            notes += "coerced '$name' from string \"${p.content}\" to integer"
            return JsonPrimitive(n)
        }
        if (p is JsonNull || p.longOrNull != null) return v
        val d = p.doubleOrNull ?: return v
        if (!d.isFinite() || d % 1.0 != 0.0 || d < Long.MIN_VALUE.toDouble() || d >= Long.MAX_VALUE.toDouble()) return v
        notes += "coerced '$name' from ${p.content} to integer"
        return JsonPrimitive(d.toLong())
    }

    /** The string `enum` of [def], or null when it has none. */
    private fun stringEnum(def: JsonObject): List<String>? =
        (def["enum"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }
            ?.takeIf { it.isNotEmpty() }

    /** Enum comparison key: lowercase, without `-`, `_`, `.` and spaces (`sha-256` matches `SHA_256`). */
    internal fun enumKey(s: String): String = s.lowercase().filter { it != '-' && it != '_' && it != '.' && it != ' ' }

    private fun matchEnum(name: String, def: JsonObject, v: JsonElement, notes: MutableList<String>): JsonElement {
        val allowed = stringEnum(def) ?: return v
        val p = v as? JsonPrimitive ?: return v
        if (!p.isString || p.content in allowed) return v
        val key = enumKey(p.content)
        val hit = allowed.filter { enumKey(it) == key }.singleOrNull() ?: return v
        notes += "matched '$name' \"${p.content}\" to \"$hit\""
        return JsonPrimitive(hit)
    }

    /** [text] parsed as JSON, or null when it is not JSON or holds unquoted words (`[admin]` stays a string). */
    private fun parseStrict(text: String): JsonElement? =
        runCatching { Json.parseToJsonElement(text) }.getOrNull()?.takeIf { it.isStrictJson() }

    /** Keys of [args] that are neither declared in [props] nor in [ignore], in argument order. */
    fun unknownParams(props: JsonObject?, args: JsonObject, ignore: Set<String>): List<String> =
        args.keys.filter { it !in ignore && (props == null || it !in props) }

    /** Error codes a caller can fix by changing the call; any other code gets `retryable: false`. */
    val RETRYABLE: Set<String> = setOf(
        "unknown_tool", "unknown_action", "missing_action", "unknown_topic", "unknown_parameter",
        "missing_parameter", "invalid_type", "invalid_enum", "out_of_range", "invalid_arguments",
        "not_found", "burp_not_running", "project_not_running", "project_required",
    )

    /** Field order of the error envelope; other fields go between [ENVELOPE_HEAD] and [ENVELOPE_TAIL]. */
    private val ENVELOPE_HEAD = listOf(
        "error", "code", "param", "got", "expected", "allowed", "did_you_mean", "retry", "example", "usage",
    )
    private val ENVELOPE_TAIL = listOf("retryable", "see")

    /** Envelope fields left out when empty. */
    private val OMITTED_WHEN_EMPTY = setOf("allowed", "did_you_mean")

    /**
     * [fields] in envelope order, without empty `allowed`/`did_you_mean`, and with an `error` that ends
     * in punctuation, so text appended to it (`Do not resend ...`) starts a new sentence.
     */
    private fun envelope(fields: Map<String, JsonElement>): JsonObject {
        fun rank(key: String): Int = ENVELOPE_HEAD.indexOf(key).takeIf { it >= 0 }
            ?: ENVELOPE_TAIL.indexOf(key).takeIf { it >= 0 }?.let { ENVELOPE_HEAD.size + 1 + it }
            ?: ENVELOPE_HEAD.size
        return JsonObject(
            fields.entries
                .filterNot { (k, v) -> k in OMITTED_WHEN_EMPTY && v is JsonArray && v.isEmpty() }
                .sortedBy { rank(it.key) }
                .associate { (k, v) -> k to if (k == "error") sentence(v) else v }
        )
    }

    private fun sentence(v: JsonElement): JsonElement {
        val text = (v as? JsonPrimitive)?.takeIf { it.isString }?.content?.trimEnd() ?: return v
        return if (text.isEmpty() || text.last() in ".!?)") JsonPrimitive(text) else JsonPrimitive("$text.")
    }

    /** An error: `{"error": message, "code": code, ...extra, "retryable": ...}` with `isError`. */
    fun error(code: String, message: String, extra: JsonObjectBuilder.() -> Unit = {}): CallToolResult {
        val built = buildJsonObject { put("error", message); put("code", code); extra() }
        val fields = if ("retryable" in built) built else built + ("retryable" to JsonPrimitive(code in RETRYABLE))
        return toolJsonResult(envelope(fields))
    }

    /**
     * Parameter names that mean the same thing across tools and the APIs agents know (`limit` for
     * `count`, `query` for `pattern`, `input` for `data`). An undeclared name maps to the one member of
     * its group the tool declares. Shipped in `catalog/tools.json` as `param_synonyms` for the CLI.
     */
    val PARAM_SYNONYMS: List<List<String>> = listOf(
        listOf("count", "limit", "max", "max_results", "max_items", "size"),
        listOf("start_index", "offset", "skip"),
        listOf("pattern", "query", "q", "regex", "search", "search_pattern"),
        listOf("data", "input", "text", "value", "string"),
        listOf("url", "uri"),
        listOf("request", "raw_request"),
        listOf("response", "raw_response"),
    )

    /** The parameter of [props] that [key] means by [PARAM_SYNONYMS], when exactly one fits. */
    fun synonym(key: String, props: JsonObject): String? =
        PARAM_SYNONYMS.firstOrNull { key in it }?.filter { it != key && it in props }?.singleOrNull()

    /** Group tool -> the action that lists what a `not_found` error refers to. */
    private val LIST_ACTIONS: Map<String, String> = mapOf(
        "turbo_run" to "list", "collaborator" to "list_clients", "findings" to "list",
        "scanner_task" to "list", "autorize" to "list_rules", "websocket" to "list",
        "proxy_intercept" to "list_held", "proxy_rule" to "list", "persistence" to "list",
        "organizer" to "get_items", "turbo_docs" to "list_examples", "scope" to "list",
        "events" to "get",
    )

    /** `run {"do":"<tool>.<list action>"}` for a `not_found` error of [tool], or null. */
    private fun listCall(tool: String): String? =
        LIST_ACTIONS[tool]?.let { "run {\"do\":\"$tool.$it\"}" }

    /**
     * `unknown_parameter` error for the keys of [args] that [props] does not declare (outside [ignore]).
     * `retry` is [args] with each unknown key renamed to its suggestion, given only when every unknown
     * key has one, none is already set, they are distinct, and the call is not [destructive].
     */
    fun unknownParameterError(
        call: String,
        props: JsonObject,
        args: JsonObject,
        ignore: Set<String>,
        usage: String,
        example: JsonObject,
        destructive: Boolean,
    ): CallToolResult {
        val unknown = unknownParams(props, args, ignore)
        val targets = unknown.associateWith { key -> synonym(key, props) ?: closest(key, props.keys, 1).firstOrNull() }
        val list = unknown.joinToString(", ") { key -> targets[key]?.let { "'$key' (did you mean '$it'?)" } ?: "'$key'" }
        val chosen = targets.values.filterNotNull()
        val certain = !destructive && chosen.size == unknown.size && chosen.toSet().size == chosen.size &&
            chosen.none { it in args }
        return error(
            "unknown_parameter",
            "Parameter(s) not accepted by $call: $list. Remove or rename them; 'usage' lists every accepted parameter.",
        ) {
            put("param", unknown.first())
            putJsonArray("did_you_mean") { chosen.distinct().forEach { add(it) } }
            if (certain) put("retry", JsonObject(args.entries.associate { (k, v) -> (targets[k] ?: k) to v }))
            put("example", example)
            put("usage", usage)
        }
    }

    private val ARGUMENT_ERROR = Regex(
        "(?i)\\b(required|missing|invalid|must|unknown|expected|allowed|not a valid|cannot be empty|parameter|JsonPrimitive|JsonObject|JsonArray)\\b"
    )
    private val NOT_FOUND = Regex("(?i)\\b(not found|no such|does not exist|unknown (run|client|id|finding|task|rule))\\b")
    private val TYPE_ERROR = Regex("(?i)\\bmust be (an? )?(integer|number|boolean|string|array|object)\\b")
    private val BARE_CODE = Regex("^[a-z]+(_[a-z]+)*$")

    /** Codes some handlers answer with alone, as envelope codes. */
    private val BARE_CODES = mapOf(
        "not_found" to "not_found", "evicted" to "not_found", "doc_not_found" to "not_found",
        "request_not_found" to "not_found",
    )

    /** Codes an argument error can have; these gain `usage` and `example`. */
    private val ARGUMENT_CODES = setOf("invalid_enum", "invalid_type", "invalid_arguments", "out_of_range", "missing_parameter")

    /**
     * Makes every error result of [tool] (with [action]) one envelope with `error`, `code` and
     * `retryable`. A result that already has a `code` only gains `retryable` when it lacks it. Otherwise
     * the code is read from the handler's message:
     * - an argument outside its declared enum: `invalid_enum` with `param`, `got`, `allowed`;
     * - "not found": `not_found` (retryable) with `see` pointing at the action that lists the ids;
     * - "must be an integer": `invalid_type` with `expected`;
     * - another bad-argument message: `invalid_arguments`;
     * - anything else (including plain text): `tool_failed`.
     * Argument errors gain [usage] and [example]; `param` (and `got`) is set when the message names
     * exactly one parameter of [props], or quotes the value of one argument.
     */
    fun enrich(
        result: CallToolResult,
        tool: String,
        action: String?,
        usage: String,
        example: JsonObject,
        props: JsonObject,
        args: JsonObject,
    ): CallToolResult {
        if (result.isError != true) return result
        val content = result.content.singleOrNull() as? TextContent ?: return result
        val call = callName(tool, action)
        val json = parseStrict(content.text) as? JsonObject
            ?: JsonObject(mapOf("error" to JsonPrimitive("$call: ${content.text.trim()}")))
        val fields = LinkedHashMap<String, JsonElement>(json)
        if ((json["code"] as? JsonPrimitive)?.isString == true) {
            val code = json.getValue("code").jsonPrimitive.content
            fields.putIfAbsent("retryable", JsonPrimitive(code in RETRYABLE))
            return result.copy(content = listOf(content.copy(text = envelope(fields).toString())))
        }
        var error = (json["error"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: "$call failed"
        // `available_topics`, `available_examples`: the envelope calls the accepted values `allowed`.
        json.keys.filter { it.startsWith("available_") && json[it] is JsonArray }.forEach { key ->
            fields.remove(key)?.let { fields.putIfAbsent("allowed", it) }
        }
        val bad = enumViolation(props, args)
        val code = when {
            bad != null -> {
                if (BARE_CODE.matches(error)) {
                    val shown = bad.third.take(10).joinToString(", ") { "\"$it\"" } + if (bad.third.size > 10) ", ..." else ""
                    error = "$call: '${bad.first}' must be one of $shown; got \"${bad.second}\""
                }
                "invalid_enum"
            }
            error in BARE_CODES || ('_' in error && BARE_CODE.matches(error)) -> {
                // A handler that answers with a code alone (`not_found`, `evicted`): say what was not
                // found when the call has one argument, a string id.
                val given = args.filterKeys { it != "action" }
                val id = given.entries.singleOrNull()?.takeIf { (_, v) -> v is JsonPrimitive && v.isString }
                val raw = error
                error = "$call: ${raw.replace('_', ' ')}" + id?.let { (k, v) -> " ($k \"${v.jsonPrimitive.content}\")" }.orEmpty()
                id?.let { (k, v) ->
                    fields.putIfAbsent("param", JsonPrimitive(k))
                    fields.putIfAbsent("got", v)
                }
                BARE_CODES[raw] ?: raw
            }
            NOT_FOUND.containsMatchIn(error) -> "not_found"
            TYPE_ERROR.containsMatchIn(error) -> "invalid_type"
            ARGUMENT_ERROR.containsMatchIn(error) -> "invalid_arguments"
            else -> "tool_failed"
        }
        fields["error"] = JsonPrimitive(error)
        fields["code"] = JsonPrimitive(code)
        if (bad != null) {
            fields["param"] = JsonPrimitive(bad.first)
            fields["got"] = JsonPrimitive(bad.second)
            fields["allowed"] = JsonArray(bad.third.map { JsonPrimitive(it) })
        } else if (code != "tool_failed" && "param" !in fields) {
            namedParam(error, props, args, soleArgument = code == "invalid_type" || code == "not_found")?.let { name ->
                fields["param"] = JsonPrimitive(name)
                args[name]?.let { fields["got"] = it }
            }
        }
        if (code == "invalid_type") {
            TYPE_ERROR.find(error)?.let { fields.putIfAbsent("expected", JsonPrimitive(it.groupValues[2].lowercase())) }
        }
        if (code == "not_found") listCall(tool)?.let { fields.putIfAbsent("see", JsonPrimitive(it)) }
        if (code in ARGUMENT_CODES) {
            fields["usage"] = JsonPrimitive(usage)
            fields["example"] = example
        }
        fields.putIfAbsent("retryable", JsonPrimitive(code in RETRYABLE))
        return result.copy(content = listOf(content.copy(text = envelope(fields).toString())))
    }

    /**
     * The one parameter of [props] that [message] names (`'url'`, `url`), else the one argument whose
     * value it quotes, else (with [soleArgument]) the only argument of the call.
     */
    private fun namedParam(message: String, props: JsonObject, args: JsonObject, soleArgument: Boolean): String? {
        val named = props.keys.filter { it != "action" && Regex("(?<![A-Za-z0-9_])${Regex.escape(it)}(?![A-Za-z0-9_])").containsMatchIn(message) }
        named.singleOrNull()?.let { return it }
        val given = args.filterKeys { it != "action" }
        given.entries.filter { (_, v) ->
            (v as? JsonPrimitive)?.takeIf { it.isString }?.content?.takeIf { it.length >= 2 }?.let { it in message } == true
        }.map { it.key }.singleOrNull()?.let { return it }
        return if (soleArgument) given.keys.singleOrNull() else null
    }

    /** (parameter, value, enum) of the first string argument, or array item, outside its declared enum. */
    private fun enumViolation(props: JsonObject, args: JsonObject): Triple<String, String, List<String>>? {
        for ((name, value) in args) {
            val def = props[name] as? JsonObject ?: continue
            val own = stringEnum(def)
            val allowed = own ?: (def["items"] as? JsonObject)?.let { stringEnum(it) } ?: continue
            val values = if (own != null) listOf(value) else (value as? JsonArray ?: continue)
            for (v in values) {
                val s = (v as? JsonPrimitive)?.takeIf { it.isString }?.content ?: continue
                if (allowed.none { enumKey(it) == enumKey(s) }) return Triple(name, s, allowed)
            }
        }
        return null
    }

    /**
     * [result] with [notes] (what the server changed in the call) in its `notes` array. Only a result
     * that is one text block holding a JSON object takes them: `notes` is added, or appended to when
     * it is already an array; any other result is returned as is.
     */
    fun withNotes(result: CallToolResult, notes: List<String>): CallToolResult {
        if (notes.isEmpty()) return result
        val content = result.content.singleOrNull() as? TextContent ?: return result
        val json = runCatching { Json.parseToJsonElement(content.text) }.getOrNull() as? JsonObject ?: return result
        val merged = when (val existing = json["notes"]) {
            null -> JsonArray(notes.map { JsonPrimitive(it) })
            is JsonArray -> JsonArray(existing + notes.map { JsonPrimitive(it) })
            else -> return result
        }
        return result.copy(content = listOf(content.copy(text = JsonObject(json + ("notes" to merged)).toString())))
    }
}
