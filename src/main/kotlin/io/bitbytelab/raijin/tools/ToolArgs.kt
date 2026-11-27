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

    /**
     * Up to [max] of [names] close to [wanted], closest first: within edit distance `max(2,
     * len/3)`, or one containing the other per [containsNear], compared in [ToolNames.norm] form
     * (case and `-`/`.`/`/`/space separators ignored). Same rule as the CLI's `util::suggest`.
     */
    fun closest(wanted: String, names: Collection<String>, max: Int = 3): List<String> {
        val w = ToolNames.norm(wanted)
        if (w.isEmpty()) return emptyList()
        val limit = maxOf(2, w.length / 3)
        return names
            .asSequence()
            .map { name ->
                val n = ToolNames.norm(name)
                Triple(name, n, levenshtein(w, n))
            }
            .filter { (_, n, d) -> d <= limit || containsNear(w, n) }
            .sortedWith(compareBy<Triple<String, String, Int>> { it.third }.thenBy { it.first })
            .take(max)
            .map { it.first }
            .toList()
    }

    /** A suggested call name; [sameWords] when it says the same words as the name asked for. */
    data class CallHint(val name: String, val sameWords: Boolean)

    private val STOP_WORDS = setOf("to", "the", "a", "an", "of", "for", "in", "on", "by")
    private val CANONICAL_WORDS: Map<String, String> =
        listOf("get", "list", "show", "fetch", "read", "view", "query").associateWith { "get" } +
            listOf("add", "create", "new", "include", "insert").associateWith { "add" } +
            listOf("find", "search", "grep", "lookup").associateWith { "search" } +
            mapOf("scanner" to "scan")

    /**
     * The words of a call name: [ToolNames.norm] split on `_`, without stop words, singular, and
     * with synonyms in one form (`list`/`show` -> `get`, `create`/`include` -> `add`, `find` ->
     * `search`, `scanner` -> `scan`). Same rule as the CLI's `intent_tokens`.
     */
    internal fun intentTokens(name: String): Set<String> =
        ToolNames.norm(name)
            .split('_')
            .filter { it.isNotEmpty() && it !in STOP_WORDS }
            .map {
                if (it.length > 3 && it.endsWith('s') && !it.endsWith("ss")) it.dropLast(1) else it
            }
            .map { CANONICAL_WORDS[it] ?: it }
            .toSet()

    /**
     * Up to [max] call names of [names] for [wanted], by intent: first the ones with the same words
     * ([intentTokens]), then the near ones of [closest]'s rule (by edit distance), then the ones
     * holding every word of [wanted] (fewest extra words first). `ai` calls rank after the others
     * of their class. Same rule as the CLI's `suggest_call`.
     */
    fun closestCalls(wanted: String, names: Collection<String>, max: Int = 3): List<CallHint> {
        val w = ToolNames.norm(wanted)
        if (w.isEmpty()) return emptyList()
        val limit = maxOf(2, w.length / 3)
        val want = intentTokens(wanted)
        data class Ranked(val name: String, val cls: Int, val ai: Int, val sub: Int)
        return names
            .asSequence()
            .distinct()
            .mapNotNull { name ->
                val n = ToolNames.norm(name)
                val have = intentTokens(name)
                val d = levenshtein(w, n)
                val cls =
                    when {
                        want.isNotEmpty() && have == want -> 0 to 0
                        d <= limit || containsNear(w, n) -> 1 to d
                        want.isNotEmpty() && have.containsAll(want) -> 2 to (have.size - want.size)
                        else -> return@mapNotNull null
                    }
                val ai = if (n == "ai" || n.startsWith("ai_")) 1 else 0
                Ranked(name, cls.first, ai, cls.second)
            }
            .sortedWith(compareBy<Ranked>({ it.cls }, { it.ai }, { it.sub }, { it.name }))
            .take(max)
            .map { CallHint(it.name, it.cls == 0) }
            .toList()
    }

    /**
     * Whether one of [wanted] and [name] (both normalized) contains the other and the shorter is
     * long enough to mean it: at least 4 chars and 60% of [wanted], so `ai` is not near `email`.
     */
    internal fun containsNear(wanted: String, name: String): Boolean {
        if (name.isEmpty() || !(name.contains(wanted) || wanted.contains(name))) return false
        val shorter = minOf(name.length, wanted.length)
        return shorter >= 4 && shorter * 10 >= wanted.length * 6
    }

    internal fun levenshtein(a: String, b: String): Int {
        var prev = IntArray(b.length + 1) { it }
        var cur = IntArray(b.length + 1)
        for (i in 1..a.length) {
            cur[0] = i
            for (j in 1..b.length) {
                val cost = if (a[i - 1] == b[j - 1]) 0 else 1
                cur[j] = minOf(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            }
            val t = prev
            prev = cur
            cur = t
        }
        return prev[b.length]
    }

    /**
     * One-line call signature, required parameters first (marked `*`), e.g. `scope.remove(list*:
     * "include"|"exclude", index*: integer)`: the call name `run` takes.
     */
    fun signature(tool: String, action: String?, props: JsonObject, required: Set<String>): String {
        val parts =
            ordered(props, required).map { (name, def) ->
                name + (if (name in required) "*" else "") + ": " + typeText(def)
            }
        return "${callName(tool, action)}(${parts.joinToString(", ")})"
    }

    /** `tool.action` for a grouped call, else `tool`. */
    fun callName(tool: String, action: String?): String =
        if (action == null) tool else "$tool.$action"

    /**
     * A correct call: `action` (when given), then the hand-picked arguments of [ToolExamples] when
     * they fit [props], else a placeholder for every required parameter. Ids that come from another
     * call ([ToolExamples.ID_SOURCES]) are left out, as are object and object-array parameters,
     * which have no placeholder worth copying.
     */
    fun example(
        tool: String,
        action: String?,
        props: JsonObject,
        required: Set<String>,
    ): JsonObject = buildJsonObject {
        if (action != null) put("action", action)
        val needed = required - ToolExamples.ids(tool, action).keys
        val picked = ToolExamples.of(tool, action)?.takeIf { fits(it, props, needed) }
        if (picked != null) {
            picked.forEach { (k, v) -> put(k, v) }
        } else {
            ordered(props, needed)
                .filter { it.first in needed && !objectShaped(it.second) }
                .forEach { (name, def) -> put(name, placeholder(name, def)) }
        }
    }

    private fun objectShaped(def: JsonObject): Boolean =
        def.typeName() == "object" ||
            (def.typeName() == "array" && (def["items"] as? JsonObject)?.typeName() == "object")

    /**
     * Whether [args] sets every [required] parameter, only declared ones, with values of the
     * declared type and enum.
     */
    fun fits(args: JsonObject, props: JsonObject, required: Set<String>): Boolean =
        required.all { it in args } &&
            args.all { (k, v) ->
                val def = props[k] as? JsonObject ?: return@all false
                typeFits(def, v) &&
                    stringEnum(def)?.let { allowed -> (v as? JsonPrimitive)?.content in allowed } !=
                        false
            }

    internal fun typeFits(def: JsonObject, v: JsonElement): Boolean =
        when (def.typeName()) {
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
        (def["enum"] as? JsonArray)?.firstOrNull()?.let {
            return it
        }
        return when (def.typeName()) {
            "string" -> JsonPrimitive("<$name>")
            "integer" ->
                (def["minimum"] as? JsonPrimitive)?.takeIf { it.longOrNull != null }
                    ?: JsonPrimitive(1)
            "number" -> JsonPrimitive(1)
            "boolean" -> JsonPrimitive(true)
            "array" ->
                JsonArray(
                    listOf(
                        placeholder(name, def["items"] as? JsonObject ?: JsonObject(emptyMap())),
                    ),
                )
            "object" -> JsonObject(emptyMap())
            else -> JsonPrimitive("<$name>")
        }
    }

    /**
     * Coerced arguments plus one note per change a caller should learn from (empty when silent).
     */
    data class Coerced(val args: JsonObject, val notes: List<String>)

    /**
     * [args] with values of known parameters moved toward their declared `type` where that is
     * lossless, and string enum values matched to their canonical spelling. [Coerced.args] is
     * [args] itself when nothing changed. Wrapping a scalar in an array is silent; JSON text read
     * as an object or array, and number, boolean and enum fixes are noted, so the caller sends the
     * right form next time.
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

    /** Parameters whose content is sent or stored as written: a one-item array stays JSON text. */
    private val PAYLOAD_PARAMS =
        setOf(
            "body",
            "data",
            "raw_request",
            "raw_request_hex",
            "headers",
            "script",
            "payload",
            "message",
            "request",
            "response",
            "value",
            "content",
        )

    private val SCALAR_TYPES = setOf("string", "integer", "number", "boolean")

    private fun coerceValue(
        name: String,
        def: JsonObject,
        given: JsonElement,
        notes: MutableList<String>,
    ): JsonElement {
        val single = (given as? JsonArray)?.singleOrNull() as? JsonPrimitive
        val v =
            if (
                single != null &&
                    single !is JsonNull &&
                    def.typeName() in SCALAR_TYPES &&
                    name !in PAYLOAD_PARAMS
            ) {
                notes += "read '$name' from a one-item array"
                single
            } else given
        val typed =
            when (def.typeName()) {
                "string" ->
                    if (v is JsonObject || v is JsonArray) {
                        notes += "serialized '$name' from JSON to text"
                        JsonPrimitive(v.toString())
                    } else v
                "object" ->
                    (v as? JsonPrimitive)
                        ?.takeIf { it.isString }
                        ?.let { parseStrict(it.content) as? JsonObject }
                        ?.also { notes += "parsed '$name' from a JSON string" } ?: v
                "array" -> {
                    val array =
                        when {
                            v is JsonArray || v is JsonNull -> v
                            v is JsonPrimitive && v.isString ->
                                (parseStrict(v.content) as? JsonArray)?.also {
                                    notes += "parsed '$name' from a JSON string"
                                } ?: JsonArray(listOf(v))
                            else -> JsonArray(listOf(v))
                        }
                    val items = def["items"] as? JsonObject
                    if (array is JsonArray && items != null && stringEnum(items) != null) {
                        val matched = array.map { matchEnum(name, items, it, notes) }
                        if (matched.indices.any { matched[it] !== array[it] }) JsonArray(matched)
                        else array
                    } else array
                }
                "integer" -> toInteger(name, v, notes)
                "number" -> {
                    val p = v as? JsonPrimitive
                    val text = p?.takeIf { it.isString }?.content?.trim()
                    if (text != null && NUMBER_TEXT.matches(text) && text.toDouble().isFinite()) {
                        notes += "coerced '$name' from string \"${p.content}\" to number"
                        text.toLongOrNull()?.let { JsonPrimitive(it) }
                            ?: JsonPrimitive(text.toDouble())
                    } else v
                }
                "boolean" -> {
                    val p = v as? JsonPrimitive
                    when {
                        p == null || p is JsonNull -> v
                        p.isString ->
                            booleanWord(p.content)?.let {
                                JsonPrimitive(it).also {
                                    notes +=
                                        "coerced '$name' from string \"${p.content}\" to boolean"
                                }
                            } ?: v
                        p.longOrNull == 0L || p.longOrNull == 1L ->
                            JsonPrimitive(p.longOrNull == 1L).also {
                                notes += "coerced '$name' from ${p.content} to boolean"
                            }
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
        if (
            !d.isFinite() ||
                d % 1.0 != 0.0 ||
                d < Long.MIN_VALUE.toDouble() ||
                d >= Long.MAX_VALUE.toDouble()
        )
            return v
        notes += "coerced '$name' from ${p.content} to integer"
        return JsonPrimitive(d.toLong())
    }

    /** The string `enum` of [def], or null when it has none. */
    private fun stringEnum(def: JsonObject): List<String>? =
        (def["enum"] as? JsonArray)
            ?.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }
            ?.takeIf { it.isNotEmpty() }

    /**
     * Enum comparison key: lowercase, without `-`, `_`, `.` and spaces (`sha-256` matches
     * `SHA_256`).
     */
    internal fun enumKey(s: String): String =
        s.lowercase().filter { it != '-' && it != '_' && it != '.' && it != ' ' }

    private fun matchEnum(
        name: String,
        def: JsonObject,
        v: JsonElement,
        notes: MutableList<String>,
    ): JsonElement {
        val allowed = stringEnum(def) ?: return v
        val p = v as? JsonPrimitive ?: return v
        if (!p.isString || p.content in allowed) return v
        fun hitOf(s: String): String? =
            if (s in allowed) s else allowed.filter { enumKey(it) == enumKey(s) }.singleOrNull()
        val hit = hitOf(p.content) ?: unquote(p.content)?.let(::hitOf) ?: return v
        notes += "matched '$name' \"${p.content}\" to \"$hit\""
        return JsonPrimitive(hit)
    }

    private const val QUOTES = "\"'`"

    /**
     * [s] trimmed and without one pair of matching surrounding quotes (`"`, `'` or a backtick), or
     * null when it is not quoted. Same rule as the CLI's `error::unquote`.
     */
    internal fun unquote(s: String): String? {
        val t = s.trim()
        return if (t.length >= 2 && t.first() == t.last() && t.first() in QUOTES)
            t.substring(1, t.length - 1)
        else null
    }

    /**
     * [text] parsed as JSON, or null when it is not JSON or holds unquoted words (`[admin]` stays a
     * string).
     */
    private fun parseStrict(text: String): JsonElement? = runCatching {
        Json.parseToJsonElement(text)
    }
        .getOrNull()
        ?.takeIf { it.isStrictJson() }

    /**
     * Parameters whose empty value (`""`, `[]`, `{}`) is sent as written. Same list as the CLI's
     * `PAYLOAD_KEYS`.
     */
    private val EMPTY_KEPT = setOf("body", "data", "raw_request", "payload", "script", "headers")

    private fun isEmptyValue(v: JsonElement): Boolean =
        when (v) {
            is JsonNull -> true
            is JsonArray -> v.isEmpty()
            is JsonObject -> v.isEmpty()
            is JsonPrimitive -> v.isString && v.content.isEmpty()
        }

    /**
     * Whether `""` for the parameter [def] declares can only mean "not set": an enum, where `""` is
     * no value. A free-form string keeps its `""` (`modify_body_replacement: ""` deletes matches,
     * `comment: ""` clears a note).
     */
    private fun emptyStringIsUnset(def: JsonElement?): Boolean =
        (def as? JsonObject)?.containsKey("enum") == true

    /**
     * [args] without the empty values (`""`, `[]`, `{}`, `null`) a strict client fills in for every
     * property of the schema: those of keys outside [props] and [ignore] (another action's
     * parameters in a grouped tool), and those of optional keys of [props] that are not payloads
     * ([EMPTY_KEPT]): `[]`, `{}`, `null`, and `""` for an enum ([emptyStringIsUnset]). Each kind
     * gets one note. A [destructive] call keeps everything, so its checks see what was sent.
     */
    fun dropEmptyUnknown(
        props: JsonObject?,
        args: JsonObject,
        ignore: Set<String>,
        destructive: Boolean,
        required: Set<String> = emptySet(),
    ): Coerced {
        if (destructive || args.isEmpty()) return Coerced(args, emptyList())
        val foreign = mutableListOf<String>()
        val optional = mutableListOf<String>()
        for ((k, v) in args) {
            if (k in ignore || !isEmptyValue(v)) continue
            val freeString = v is JsonPrimitive && v.isString && !emptyStringIsUnset(props?.get(k))
            when {
                props == null || k !in props -> foreign += k
                k !in required && k !in EMPTY_KEPT && !freeString -> optional += k
            }
        }
        if (foreign.isEmpty() && optional.isEmpty()) return Coerced(args, emptyList())
        val notes = mutableListOf<String>()
        if (foreign.isNotEmpty())
            notes +=
                "ignored ${foreign.size} empty parameter${if (foreign.size == 1) "" else "s"} " +
                    "of other actions"
        if (optional.isNotEmpty())
            notes += "ignored empty optional ${optional.joinToString(", ") { "'$it'" }}"
        val dropped = (foreign + optional).toSet()
        return Coerced(JsonObject(args.filterKeys { it !in dropped }), notes)
    }

    /** Keys of [args] that are neither declared in [props] nor in [ignore], in argument order. */
    fun unknownParams(props: JsonObject?, args: JsonObject, ignore: Set<String>): List<String> =
        args.keys.filter { it !in ignore && (props == null || it !in props) }

    /**
     * Text a boolean parameter takes for each value. Shipped in `catalog/tools.json` as
     * `boolean_words` for the CLI.
     */
    val BOOLEAN_WORDS: Map<Boolean, List<String>> =
        mapOf(
            true to listOf("true", "1", "yes", "on"),
            false to listOf("false", "0", "no", "off"),
        )

    /** The boolean [text] means by [BOOLEAN_WORDS], trimmed and in any case, or null. */
    fun booleanWord(text: String): Boolean? {
        val t = text.trim().lowercase()
        return BOOLEAN_WORDS.entries.firstOrNull { t in it.value }?.key
    }

    private val CAMEL_BOUNDARY = Regex("(?<=[a-z0-9])(?=[A-Z])")

    /**
     * A parameter name in the form tools declare: trimmed, without surrounding `*`, camelCase split
     * with `_`, lowercase, `-` and spaces as `_` (`maxResults` -> `max_results`). Same rule as the
     * CLI's `canonical_param`.
     */
    fun canonicalParam(key: String): String =
        key.trim()
            .trim('*')
            .trim()
            .replace(CAMEL_BOUNDARY, "_")
            .lowercase()
            .replace('-', '_')
            .replace(' ', '_')

    /**
     * [args] with undeclared names that clearly mean a declared one renamed, each change noted: the
     * canonical form of a name ([canonicalParam]), a boolean `regex` flag dropped where `pattern`
     * is always a regex, and a [PARAM_SYNONYMS] member whose value fits the target's type. A target
     * already set, or claimed by an earlier rename, is left alone, as is every name of a
     * [destructive] call: those go to [unknownParameterError]. Keys in [ignore] are never touched.
     * Same rule as the CLI's `rename_params`.
     */
    fun renameParams(
        props: JsonObject,
        args: JsonObject,
        ignore: Set<String>,
        destructive: Boolean,
    ): Coerced {
        if (destructive || args.keys.all { it in props || it in ignore })
            return Coerced(args, emptyList())
        val notes = mutableListOf<String>()
        val claimed = mutableSetOf<String>()
        val out = LinkedHashMap<String, JsonElement>(args.size)
        for ((k, v) in args) {
            if (k in props || k in ignore) {
                out[k] = v
                continue
            }
            val c = canonicalParam(k)
            if (c in props && c !in args && c !in claimed) {
                notes += "read '$k' as '$c'"
                claimed += c
                out[c] = v
                continue
            }
            if (
                c == "regex" &&
                    v is JsonPrimitive &&
                    !v.isString &&
                    v.booleanOrNull != null &&
                    "pattern" in props
            ) {
                notes += "dropped 'regex': 'pattern' is always a regex here"
                continue
            }
            val t = synonym(c, props)
            if (t != null && t !in args && t !in claimed) {
                val def = props[t] as? JsonObject
                if (def == null || typeFits(def, coerceValue(t, def, v, mutableListOf()))) {
                    notes += "read '$k' as '$t'"
                    claimed += t
                    out[t] = v
                    continue
                }
            }
            out[k] = v
        }
        return Coerced(JsonObject(out), notes)
    }

    /**
     * `out_of_range` for the first integer/number argument below 0 whose schema `minimum` is >= 0;
     * `retry` drops it (default applies) unless [destructive]. Values below a minimum >= 1 but not
     * negative are left to the handlers, which clamp them.
     */
    fun rangeCheck(
        call: String,
        props: JsonObject,
        args: JsonObject,
        usage: String,
        example: JsonObject,
        destructive: Boolean,
    ): CallToolResult? {
        for ((param, value) in args) {
            if (param == "action") continue
            val def = props[param] as? JsonObject ?: continue
            val type = def.typeName()
            if (type != "integer" && type != "number") continue
            val min = (def["minimum"] as? JsonPrimitive)?.takeIf { !it.isString } ?: continue
            val minValue = min.doubleOrNull ?: continue
            val v = (value as? JsonPrimitive)?.takeIf { !it.isString }?.doubleOrNull ?: continue
            if (minValue < 0 || v >= 0) continue
            val kind = if (type == "integer") "an integer" else "a number"
            return error(
                "out_of_range",
                "$call: '$param' must be $kind ≥ ${min.content}, got ${value.jsonPrimitive.content}.",
            ) {
                put("param", param)
                put("got", value)
                if (!destructive) put("retry", JsonObject(args - param))
                put("usage", usage)
                put("example", example)
            }
        }
        return null
    }

    /**
     * Per member tool (`http_cookie_jar_delete`), the values of a call's arguments that exist as
     * written in Burp, for [placeholderCheck]'s `allowLiteral`; set where the tool is registered.
     */
    val literalValues: MutableMap<String, (JsonObject) -> Set<String>> =
        java.util.concurrent.ConcurrentHashMap()

    /** [literalValues] of [tool] for [args]; empty when it has none or Burp cannot be asked. */
    fun literalValuesOf(tool: String, args: JsonObject): Set<String> =
        literalValues[tool]?.let { runCatching { it(args) }.getOrNull() } ?: emptySet()

    private val PLACEHOLDER_FROM = Regex("^<[^<>]* from [^<>]*>$")
    private val ID_LIKE = setOf("id", "url", "uri", "token", "base_url")

    /** Parameters a placeholder in makes the call pointless: the target and what is sent. */
    private val STRICT_PLACEHOLDER_PARAMS = setOf("host", "urls", "request", "name", "domain")

    private fun isPlaceholder(param: String, s: String): Boolean =
        s == "<$param>" || PLACEHOLDER_FROM.matches(s)

    /**
     * A placeholder copied from an example (`"<token>"`, `"<run_id from turbo_run.list>"`) in
     * [args]: a `placeholder_value` error, since such a call cannot do what was meant, for any
     * parameter of a [destructive] call and for an id, URL, token, target or request parameter
     * (also any listed in [ToolExamples.ids]); for any other parameter a note, and the value is
     * sent as written. A value in [allowLiteral] exists as written (a cookie really named `<name>`)
     * and is never a placeholder. Returns (error or null, notes).
     */
    fun placeholderCheck(
        call: String,
        tool: String,
        action: String?,
        props: JsonObject,
        args: JsonObject,
        example: JsonObject,
        destructive: Boolean,
        allowLiteral: Set<String> = emptySet(),
    ): Pair<CallToolResult?, List<String>> {
        val notes = mutableListOf<String>()
        val ids = ToolExamples.ids(tool, action)
        for ((param, value) in args) {
            if (param == "action" || param !in props) continue
            val items = (value as? JsonArray)?.toList() ?: listOf(value)
            val v =
                items.firstNotNullOfOrNull { item ->
                    (item as? JsonPrimitive)
                        ?.takeIf { it.isString }
                        ?.content
                        ?.takeIf { isPlaceholder(param, it) && it !in allowLiteral }
                } ?: continue
            val strict =
                destructive ||
                    param in ID_LIKE ||
                    param.endsWith("_id") ||
                    param.endsWith("_url") ||
                    param.endsWith("_token") ||
                    param in ids ||
                    param in STRICT_PLACEHOLDER_PARAMS
            if (!strict) {
                notes += "'$param' is the placeholder \"$v\" from an example; sent as written"
                continue
            }
            val source = ToolExamples.idSource(tool, action, param)
            val from = (source?.get("do") as? JsonPrimitive)?.content
            val exampleValue = (example[param] as? JsonPrimitive)?.takeIf { it.isString }?.content
            return error(
                "placeholder_value",
                "$call: '$param' holds the placeholder \"$v\"; pass a real value." +
                    (from?.let { " Get it from $it." } ?: ""),
            ) {
                put("param", param)
                put("got", v)
                source?.let { put("see", it) }
                if (exampleValue == null || !isPlaceholder(param, exampleValue))
                    put("example", example)
            } to notes
        }
        return null to notes
    }

    /**
     * Error codes a caller can fix by changing the call; any other code gets `retryable: false`.
     */
    val RETRYABLE: Set<String> =
        setOf(
            "unknown_tool",
            "unknown_action",
            "missing_action",
            "unknown_topic",
            "unknown_parameter",
            "missing_parameter",
            "invalid_type",
            "invalid_enum",
            "out_of_range",
            "invalid_arguments",
            "not_found",
            "burp_not_running",
            "project_not_running",
            "project_required",
            "placeholder_value",
            "no_response",
        )

    /**
     * Field order of the error envelope; other fields go between [ENVELOPE_HEAD] and
     * [ENVELOPE_TAIL].
     */
    private val ENVELOPE_HEAD =
        listOf(
            "error",
            "code",
            "param",
            "got",
            "expected",
            "allowed",
            "did_you_mean",
            "retry",
            "example",
            "usage",
        )
    private val ENVELOPE_TAIL = listOf("retryable", "see")

    /** Envelope fields left out when empty. */
    private val OMITTED_WHEN_EMPTY = setOf("allowed", "did_you_mean")

    /**
     * [fields] in envelope order, without empty `allowed`/`did_you_mean`, and with an `error` that
     * ends in punctuation, so text appended to it (`Do not resend ...`) starts a new sentence.
     */
    private fun envelope(fields: Map<String, JsonElement>): JsonObject {
        fun rank(key: String): Int =
            ENVELOPE_HEAD.indexOf(key).takeIf { it >= 0 }
                ?: ENVELOPE_TAIL.indexOf(key)
                    .takeIf { it >= 0 }
                    ?.let { ENVELOPE_HEAD.size + 1 + it }
                ?: ENVELOPE_HEAD.size
        return JsonObject(
            fields.entries
                .filterNot { (k, v) -> k in OMITTED_WHEN_EMPTY && v is JsonArray && v.isEmpty() }
                .sortedBy { rank(it.key) }
                .associate { (k, v) -> k to if (k == "error") sentence(v) else v },
        )
    }

    private fun sentence(v: JsonElement): JsonElement {
        val text = (v as? JsonPrimitive)?.takeIf { it.isString }?.content?.trimEnd() ?: return v
        return if (text.isEmpty() || text.last() in ".!?") JsonPrimitive(text)
        else JsonPrimitive("$text.")
    }

    /** An error: `{"error": message, "code": code, ...extra, "retryable": ...}` with `isError`. */
    fun error(
        code: String,
        message: String,
        extra: JsonObjectBuilder.() -> Unit = {},
    ): CallToolResult {
        val built = buildJsonObject {
            put("error", message)
            put("code", code)
            extra()
        }
        val fields =
            if ("retryable" in built) built
            else built + ("retryable" to JsonPrimitive(code in RETRYABLE))
        return toolJsonResult(envelope(fields))
    }

    /**
     * Parameter names that mean the same thing across tools and the APIs agents know (`limit` for
     * `count`, `query` for `pattern`, `input` for `data`). An undeclared name maps to the one
     * member of its group the tool declares. Shipped in `catalog/tools.json` as `param_synonyms`
     * for the CLI.
     */
    val PARAM_SYNONYMS: List<List<String>> =
        listOf(
            listOf(
                "count",
                "limit",
                "max",
                "max_results",
                "max_items",
                "size",
                "max_events",
                "max_matches",
            ),
            listOf("start_index", "offset", "skip"),
            listOf(
                "pattern",
                "query",
                "q",
                "regex",
                "search",
                "search_pattern",
                "keyword",
                "keywords",
                "term",
                "terms",
                "search_query",
                "text",
            ),
            listOf("data", "input", "text", "value", "string"),
            listOf("url", "uri"),
            listOf("request", "raw_request"),
            listOf("response", "raw_response"),
        )

    /**
     * The parameter of [props] that [key] means by [PARAM_SYNONYMS]: of the groups holding [key],
     * in table order, the first where exactly one other member is declared (`text` is `query` for a
     * search tool, `data` for a tool without a search parameter). Same rule as the CLI.
     */
    fun synonym(key: String, props: JsonObject): String? =
        PARAM_SYNONYMS.asSequence()
            .filter { key in it }
            .firstNotNullOfOrNull { group ->
                group.filter { it != key && it in props }.singleOrNull()
            }

    /** Tool -> the call that lists what a `not_found` error of that tool refers to. */
    private val LIST_CALLS: Map<String, String> =
        mapOf(
            "turbo_run" to "turbo_run.list",
            "collaborator" to "collaborator.list_clients",
            "findings" to "findings.list",
            "scanner_task" to "scanner_task.list",
            "autorize" to "autorize.list_rules",
            "websocket" to "websocket.list",
            "proxy_intercept" to "proxy_intercept.list_held",
            "proxy_rule" to "proxy_rule.list",
            "persistence" to "persistence.list",
            "organizer" to "organizer.get_items",
            "turbo_docs" to "turbo_docs.list_examples",
            "scope" to "scope.list",
            "events" to "events.get",
            "proxy_annotate" to "proxy_history",
        )

    /** `{"do": "<list call>"}` for a `not_found` error of [tool], or null. */
    fun listCall(tool: String): JsonObject? =
        LIST_CALLS[tool]?.let { buildJsonObject { put("do", it) } }

    /** `{"guide":{}}`, or `{"guide":{"topic":topic}}`: a `see` that points at `guide`. */
    fun guideCall(topic: String?): JsonObject = buildJsonObject {
        putJsonObject("guide") { if (topic != null) put("topic", topic) }
    }

    /** Most `allowed` values an error lists; [MAX_DID_YOU_MEAN] for `did_you_mean`. */
    private const val MAX_ALLOWED = 20
    private const val MAX_DID_YOU_MEAN = 5

    /**
     * [values] capped at [MAX_ALLOWED]: the 5 closest to [got] first, then the rest in order; true
     * when cut.
     */
    internal fun cappedAllowed(got: String, values: List<String>): Pair<List<String>, Boolean> {
        if (values.size <= MAX_ALLOWED) return values to false
        val near = closest(got, values, MAX_DID_YOU_MEAN)
        return (near + values.filter { it !in near }).take(MAX_ALLOWED) to true
    }

    /**
     * `unknown_parameter` error for the keys of [args] that [props] does not declare (outside
     * [ignore]). `retry` is [args] with each unknown key renamed to its suggestion, given only when
     * every unknown key has one, none is already set, they are distinct, and the call is not
     * [destructive].
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
        val targets = unknown.associateWith { key ->
            val c = canonicalParam(key)
            synonym(c, props) ?: closest(c, props.keys, 1).firstOrNull()
        }
        val list =
            unknown.joinToString(", ") { key ->
                targets[key]?.let { "'$key' (did you mean '$it'?)" } ?: "'$key'"
            }
        val chosen = targets.values.filterNotNull()
        val certain =
            !destructive &&
                chosen.size == unknown.size &&
                chosen.toSet().size == chosen.size &&
                chosen.none { it in args }
        return error(
            "unknown_parameter",
            "Parameter(s) not accepted by $call: $list. Remove or rename them; 'usage' lists every accepted parameter.",
        ) {
            put("param", unknown.first())
            putJsonArray("did_you_mean") {
                chosen.distinct().take(MAX_DID_YOU_MEAN).forEach { add(it) }
            }
            if (certain)
                put(
                    "retry",
                    JsonObject(args.entries.associate { (k, v) -> (targets[k] ?: k) to v }),
                )
            put("example", example)
            put("usage", usage)
        }
    }

    private val ARGUMENT_ERROR =
        Regex(
            "(?i)\\b(required|missing|invalid|must|unknown|expected|allowed|not a valid|cannot be empty|parameter|JsonPrimitive|JsonObject|JsonArray)\\b",
        )
    private val NOT_FOUND =
        Regex(
            "(?i)\\b(not found|no such|does not exist|unknown (run|client|id|finding|task|rule))\\b",
        )
    private val TYPE_ERROR =
        Regex("(?i)\\bmust be (an? )?(integer|number|boolean|string|array|object)\\b")
    private val BARE_CODE = Regex("^[a-z]+(_[a-z]+)*$")

    /** Codes some handlers answer with alone, as envelope codes. */
    private val BARE_CODES =
        mapOf(
            "not_found" to "not_found",
            "evicted" to "not_found",
            "doc_not_found" to "not_found",
            "request_not_found" to "not_found",
        )

    /** Codes an argument error can have; these gain `usage` and `example`. */
    private val ARGUMENT_CODES =
        setOf(
            "invalid_enum",
            "invalid_type",
            "invalid_arguments",
            "out_of_range",
            "missing_parameter",
        )

    /**
     * Makes every error result of [tool] (with [action]) one envelope with `error`, `code` and
     * `retryable`. A result that already has a `code` only gains `retryable` when it lacks it.
     * Otherwise the code is read from the handler's message:
     * - an argument outside its declared enum: `invalid_enum` with `param`, `got`, `allowed`;
     * - "not found": `not_found` (retryable) with `see` pointing at the action that lists the ids;
     * - "must be an integer": `invalid_type` with `expected`;
     * - another bad-argument message: `invalid_arguments`;
     * - anything else (including plain text): `tool_failed`. Argument errors gain [usage] and
     *   [example]; `param` (and `got`) is set when the message names exactly one parameter of
     *   [props], or quotes the value of one argument.
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
        val json =
            parseStrict(content.text) as? JsonObject
                ?: JsonObject(mapOf("error" to JsonPrimitive("$call: ${content.text.trim()}")))
        val fields = LinkedHashMap<String, JsonElement>(json)
        if ((json["code"] as? JsonPrimitive)?.isString == true) {
            val code = json.getValue("code").jsonPrimitive.content
            if (code in ARGUMENT_CODES) {
                fields.putIfAbsent("usage", JsonPrimitive(usage))
                fields.putIfAbsent("example", example)
            }
            idSee(tool, action, fields)
            fields.putIfAbsent("retryable", JsonPrimitive(code in RETRYABLE))
            return result.copy(content = listOf(content.copy(text = envelope(fields).toString())))
        }
        var error =
            (json["error"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: "$call failed"
        // `available_topics`, `available_examples`: the envelope calls the accepted values
        // `allowed`.
        json.keys
            .filter { it.startsWith("available_") && json[it] is JsonArray }
            .forEach { key ->
                fields.remove(key)?.let { fields.putIfAbsent("allowed", it) }
            }
        val bad = enumViolation(props, args)
        val (allowedShown, allowedCut) =
            bad?.let { cappedAllowed(it.second, it.third) } ?: (emptyList<String>() to false)
        val code =
            when {
                bad != null -> {
                    if (BARE_CODE.matches(error)) {
                        error =
                            "$call: '${bad.first}' is not one of the ${bad.third.size} allowed values (see 'allowed'); got \"${bad.second}\"."
                    }
                    "invalid_enum"
                }
                error in BARE_CODES || ('_' in error && BARE_CODE.matches(error)) -> {
                    // A handler that answers with a code alone (`not_found`, `evicted`): say what
                    // was not
                    // found when the call has one argument, a string id.
                    val given = args.filterKeys { it != "action" }
                    val id =
                        given.entries.singleOrNull()?.takeIf { (_, v) ->
                            v is JsonPrimitive && v.isString
                        }
                    val raw = error
                    val mapped = BARE_CODES[raw] ?: raw
                    error =
                        if (id == null) "$call: ${raw.replace('_', ' ')}."
                        else {
                            val (k, v) = id
                            val noun = k.removeSuffix("_id").replace('_', ' ')
                            val value = v.jsonPrimitive.content
                            when {
                                raw == "evicted" ->
                                    "$call: $noun \"$value\" was evicted (runs are kept for a limited time)."
                                mapped == "not_found" ->
                                    "$call: no $noun \"$value\"." +
                                        (listCall(tool)?.let {
                                            " List them with ${it.getValue("do").jsonPrimitive.content}."
                                        } ?: "")
                                else -> "$call: ${raw.replace('_', ' ')} ($k \"$value\")."
                            }
                        }
                    id?.let { (k, v) ->
                        fields.putIfAbsent("param", JsonPrimitive(k))
                        fields.putIfAbsent("got", v)
                    }
                    mapped
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
            fields["allowed"] = JsonArray(allowedShown.map { JsonPrimitive(it) })
            if (allowedCut) fields.putIfAbsent("see", listCall(tool) ?: guideCall(call))
        } else if (code != "tool_failed" && "param" !in fields) {
            namedParam(
                    error,
                    props,
                    args,
                    soleArgument = code == "invalid_type" || code == "not_found",
                )
                ?.let { name ->
                    fields["param"] = JsonPrimitive(name)
                    args[name]?.let { fields["got"] = it }
                }
        }
        if (code == "invalid_type") {
            TYPE_ERROR.find(error)?.let {
                fields.putIfAbsent("expected", JsonPrimitive(it.groupValues[2].lowercase()))
            }
        }
        idSee(tool, action, fields)
        if (code == "not_found") listCall(tool)?.let { fields.putIfAbsent("see", it) }
        if (code in ARGUMENT_CODES) {
            fields["usage"] = JsonPrimitive(usage)
            fields["example"] = example
        }
        fields.putIfAbsent("retryable", JsonPrimitive(code in RETRYABLE))
        return result.copy(content = listOf(content.copy(text = envelope(fields).toString())))
    }

    /**
     * `see` = the call that lists ids of the envelope's `param` ([ToolExamples.idSource]), when it
     * has one.
     */
    private fun idSee(tool: String, action: String?, fields: MutableMap<String, JsonElement>) {
        val param = (fields["param"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return
        ToolExamples.idSource(tool, action, param)?.let { fields.putIfAbsent("see", it) }
    }

    /**
     * The one parameter of [props] that [message] names (`'url'`, `url`), else the one argument
     * whose value it quotes, else (with [soleArgument]) the only argument of the call.
     */
    private fun namedParam(
        message: String,
        props: JsonObject,
        args: JsonObject,
        soleArgument: Boolean,
    ): String? {
        val named =
            props.keys.filter {
                it != "action" &&
                    Regex("(?<![A-Za-z0-9_])${Regex.escape(it)}(?![A-Za-z0-9_])")
                        .containsMatchIn(message)
            }
        named.singleOrNull()?.let {
            return it
        }
        val given = args.filterKeys { it != "action" }
        given.entries
            .filter { (_, v) ->
                (v as? JsonPrimitive)
                    ?.takeIf { it.isString }
                    ?.content
                    ?.takeIf { it.length >= 2 }
                    ?.let { it in message } == true
            }
            .map { it.key }
            .singleOrNull()
            ?.let {
                return it
            }
        return if (soleArgument) given.keys.singleOrNull() else null
    }

    /**
     * (parameter, value, enum) of the first string argument, or array item, outside its declared
     * enum.
     */
    private fun enumViolation(
        props: JsonObject,
        args: JsonObject,
    ): Triple<String, String, List<String>>? {
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
     * [result] with [notes] (what the server changed in the call) in its `notes` array, then its
     * warnings mirrored there too ([mirrorWarnings]). Only a result that is one text block holding
     * a JSON object takes them: `notes` is added, or appended to when it is already an array. A
     * text block that is not JSON at all gets the notes as a leading `note: ...` line; any other
     * result is returned as is.
     */
    fun withNotes(result: CallToolResult, notes: List<String>): CallToolResult {
        val content = result.content.singleOrNull() as? TextContent ?: return result
        // Parsing every result only to find no warning would cost the large ones (history, bodies)
        // dearly.
        if (notes.isEmpty() && WARNING_HINTS.none { it in content.text }) return result
        val parsed = runCatching { Json.parseToJsonElement(content.text) }.getOrNull()
        if (parsed == null && notes.isNotEmpty()) {
            // Plain text (a doc, a script): the notes go in front of it.
            val text = "note: ${notes.joinToString("; ")}\n\n${content.text}"
            return result.copy(content = listOf(content.copy(text = text)))
        }
        val json = parsed as? JsonObject ?: return result
        val existing = json["notes"]
        if (existing != null && existing !is JsonArray) return result
        val have =
            (existing as? JsonArray)
                .orEmpty()
                .mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
                .toMutableSet()
        val added = notes.toMutableList()
        have += notes
        mirrorWarnings(json).forEach { if (have.add(it)) added += it }
        if (added.isEmpty()) return result
        val merged = JsonArray((existing as? JsonArray).orEmpty() + added.map { JsonPrimitive(it) })
        return result.copy(
            content =
                listOf(content.copy(text = JsonObject(json + ("notes" to merged)).toString())),
        )
    }

    private val WARNING_HINTS = listOf("_warning", "\"warnings\"", "_clamped_to")
    private val WARNING_KEYS = listOf("scope_warning", "headers_warning")

    /**
     * The non-fatal news of a result as note lines (the fields themselves stay): `scope_warning`
     * and `headers_warning`, each `warnings` entry (an object as compact JSON), every
     * `<x>_clamped_to` as `"<x> clamped to <value>"`, and the warnings of `steps`/`results` items
     * as `"step n: ..."` / `"request n: ..."`.
     */
    internal fun mirrorWarnings(json: JsonObject): List<String> {
        val out = mutableListOf<String>()
        WARNING_KEYS.forEach { k ->
            (json[k] as? JsonPrimitive)?.takeIf { it.isString }?.let { out += it.content }
        }
        (json["warnings"] as? JsonArray)?.forEach { w ->
            out += (w as? JsonPrimitive)?.takeIf { it.isString }?.content ?: w.toString()
        }
        json.forEach { (k, v) ->
            if (k.endsWith("_clamped_to")) out += "${k.removeSuffix("_clamped_to")} clamped to $v"
        }
        for ((key, label) in listOf("steps" to "step", "results" to "request")) {
            (json[key] as? JsonArray)?.forEachIndexed { i, item ->
                val o = item as? JsonObject ?: return@forEachIndexed
                WARNING_KEYS.forEach { k ->
                    (o[k] as? JsonPrimitive)
                        ?.takeIf { it.isString }
                        ?.let { out += "$label ${i + 1}: ${it.content}" }
                }
            }
        }
        return out
    }
}
