package io.bitbytelab.raijin.core

import kotlinx.serialization.json.*
import java.math.BigDecimal
import java.math.RoundingMode

/**
 * Robust JSON argument extraction helpers for MCP tool parameters.
 *
 * MCP clients may send arguments in various forms:
 * - Proper JSON types (ideal): `{"urls": ["a", "b"]}`
 * - Double-serialized strings: `{"urls": "[\"a\", \"b\"]"}`
 * - Single values where arrays expected: `{"urls": "a"}`
 * - Stringified objects: `{"headers": "{\"Content-Type\": \"application/json\"}"}`
 *
 * These helpers handle all cases gracefully.
 */

private val json = Json { ignoreUnknownKeys = true; isLenient = true }

/**
 * True when kotlinx parsed this as a real JSON literal (string, number, boolean, null). kotlinx reads
 * an unquoted word such as `admin` in `[admin]` as a literal without checking it.
 */
fun JsonPrimitive.isStrictLiteral(): Boolean =
    isString || this is JsonNull || booleanOrNull != null || content.toDoubleOrNull() != null

/** True when every primitive in this element is a real JSON literal ([isStrictLiteral]). */
fun JsonElement.isStrictJson(): Boolean = when (this) {
    is JsonPrimitive -> isStrictLiteral()
    is JsonArray -> all { it.isStrictJson() }
    is JsonObject -> values.all { it.isStrictJson() }
}

/**
 * Extract a string list from a JsonElement that might be:
 * - A JsonArray of strings
 * - A JsonPrimitive containing a JSON array string
 * - A JsonPrimitive containing a single string (returned as single-element list)
 */
fun JsonElement?.asStringList(): List<String>? {
    if (this == null) return null
    return when (this) {
        is JsonArray -> this.mapNotNull {
            when (it) {
                is JsonNull -> null
                is JsonPrimitive -> it.contentOrNull
                else -> it.toString()
            }
        }
        is JsonPrimitive -> {
            val str = this.contentOrNull ?: return null
            if (str.trimStart().startsWith("[")) {
                // Strict parse: "[admin]" is a value, not a lenient one-element array.
                val parsed = try { Json.parseToJsonElement(str) } catch (_: Exception) { null }
                val strict = parsed is JsonArray && parsed.all { it is JsonPrimitive && it.isStrictLiteral() }
                if (strict) {
                    parsed.mapNotNull { if (it is JsonNull) null else it.jsonPrimitive.contentOrNull }
                } else {
                    listOf(str)
                }
            } else {
                listOf(str)
            }
        }
        is JsonObject -> listOf(this.toString())
        else -> null
    }
}

/**
 * Extract a list of JsonObject from a JsonElement that might be:
 * - A JsonArray of objects
 * - A JsonPrimitive containing a JSON array string
 */
fun JsonElement?.asJsonObjectList(): List<JsonObject>? {
    if (this == null) return null
    return when (this) {
        is JsonArray -> this.mapNotNull {
            when (it) {
                is JsonObject -> it
                is JsonPrimitive -> {
                    try { json.parseToJsonElement(it.content).jsonObject } catch (_: Exception) { null }
                }
                else -> null
            }
        }
        is JsonPrimitive -> {
            val str = this.contentOrNull ?: return null
            try {
                json.parseToJsonElement(str).jsonArray.mapNotNull {
                    when (it) {
                        is JsonObject -> it
                        else -> null
                    }
                }
            } catch (_: Exception) { null }
        }
        else -> null
    }
}

/**
 * Extract a JsonObject from a JsonElement that might be:
 * - A JsonObject directly
 * - A JsonPrimitive containing a JSON object string
 */
fun JsonElement?.asJsonObjectSafe(): JsonObject? {
    if (this == null) return null
    return when (this) {
        is JsonObject -> this
        is JsonPrimitive -> {
            val str = this.contentOrNull ?: return null
            if (str.trimStart().startsWith("{")) {
                try { json.parseToJsonElement(str).jsonObject } catch (_: Exception) { null }
            } else null
        }
        else -> null
    }
}

/**
 * Extract a Map<String, String> from a JsonElement that might be:
 * - A JsonObject with string values:                    {"X-Foo": "bar"}
 * - A JsonObject with structured values:                {"X-Foo": {"nested": "obj"}} → value JSON-serialized
 * - A JsonArray of [name, value] tuples:                [["X-Foo", "bar"], ["X-Bar", "baz"]]
 * - A JsonArray of {name, value} objects (Burp-native): [{"name":"X-Foo","value":"bar"}]
 * - A JsonArray of {key, value} objects:                [{"key":"X-Foo","value":"bar"}]
 * - A JsonArray of "Name: value" strings:               ["X-Foo: bar"]
 * - A JsonPrimitive containing JSON of any of the above
 *
 * On unparseable input, [asStringMap] returns null (existing contract).
 * Use [asStringMapResult] to obtain parse details/warnings without losing the map.
 */
fun JsonElement?.asStringMap(): Map<String, String>? = this.asStringMapResult().first

/**
 * Like [asStringMap] but returns both the parsed map and an optional warning describing
 * how the input was interpreted (or why it could not be). The warning is null on success.
 *
 * Callers should surface the warning in MCP tool responses so that agents learn the
 * correct format instead of having their headers silently dropped.
 */
fun JsonElement?.asStringMapResult(): Pair<Map<String, String>?, String?> = asHeaders().let { it.map to it.warning }

/**
 * Headers read from a tool argument: [map] (null when nothing could be read), a [warning] on how the
 * input was read or what was skipped, and [unparsed], the entries (or lines) that could not be read
 * (at least 1 when something was given and nothing could be read; 0 for no input, null or blank).
 * A caller that must send what it was given refuses when [unparsed] > 0.
 */
data class HeaderParse(val map: Map<String, String>?, val warning: String?, val unparsed: Int)

/** [asStringMapResult] with the count of entries that could not be read. */
fun JsonElement?.asHeaders(): HeaderParse {
    if (this == null) return HeaderParse(null, null, 0)
    return when (this) {
        is JsonNull -> HeaderParse(null, null, 0)
        is JsonObject -> HeaderParse(objectToStringMap(this), null, 0)
        is JsonArray -> arrayToStringMap(this)
        is JsonPrimitive -> {
            val str = this.contentOrNull ?: return HeaderParse(null, "headers primitive had no content", 1)
            if (str.isBlank()) return HeaderParse(null, null, 0)
            val trimmed = str.trimStart()
            try {
                val parsed = json.parseToJsonElement(str)
                when (parsed) {
                    is JsonObject -> HeaderParse(objectToStringMap(parsed), null, 0)
                    is JsonArray -> arrayToStringMap(parsed)
                    else -> HeaderParse(null, "headers primitive parsed to ${parsed::class.simpleName}, expected object or array", 1)
                }
            } catch (_: Exception) {
                if (trimmed.contains(":")) {
                    // Best-effort raw HTTP header parsing: "X-Foo: bar\nX-Bar: baz"
                    val (map, warnings, noColon) = parseRawHeaderBlock(str)
                    if (map.isNotEmpty()) {
                        HeaderParse(
                            map,
                            (listOf("parsed as raw HTTP header block (one 'Name: value' per line)") + warnings).joinToString("; "),
                            noColon,
                        )
                    } else {
                        HeaderParse(null, "headers string is not JSON and not parseable as 'Name: value' lines", 1)
                    }
                } else {
                    HeaderParse(null, "headers string is not valid JSON and contains no ':' for raw header parsing", 1)
                }
            }
        }
    }
}

/** `Name: value` split at the first `:`, the value losing at most one leading space; null without a `:`. */
private fun headerLine(line: String): Pair<String, String>? {
    val colon = line.indexOf(':')
    if (colon < 0) return null
    return line.substring(0, colon) to line.substring(colon + 1).removePrefix(" ")
}

private fun objectToStringMap(obj: JsonObject): Map<String, String> =
    obj.entries.associate { (k, v) ->
        k to when (v) {
            is JsonPrimitive -> v.contentOrNull ?: v.toString()
            else -> v.toString()
        }
    }

/**
 * Converts an array of header-like elements to a string map. Supports:
 * - [["name","value"], ...]
 * - [{"name":"...","value":"..."}, ...]
 * - [{"key":"...","value":"..."}, ...]
 * - ["Name: value", ...] (split at the first `:`, the value byte-exact but for one leading space)
 *
 * Multiple entries with the same name are coalesced (last value wins) — same as a real
 * HTTP server's lookup by header name in this MCP layer.
 */
private fun arrayToStringMap(arr: JsonArray): HeaderParse {
    if (arr.isEmpty()) return HeaderParse(emptyMap(), null, 0)
    val result = object : LinkedHashMap<String, String>() {
        val duplicates = LinkedHashSet<String>()
        override fun put(key: String, value: String): String? {
            if (containsKey(key)) duplicates += key
            return super.put(key, value)
        }
    }
    var unrecognized = 0
    for (element in arr) {
        when (element) {
            is JsonArray -> {
                if (element.size >= 2) {
                    val name = (element[0] as? JsonPrimitive)?.contentOrNull
                    val value = (element[1] as? JsonPrimitive)?.contentOrNull
                        ?: element[1].toString()
                    if (name != null) result[name] = value else unrecognized++
                } else {
                    unrecognized++
                }
            }
            is JsonObject -> {
                // Try {name,value} or {key,value}
                val name = (element["name"] as? JsonPrimitive)?.contentOrNull
                    ?: (element["key"] as? JsonPrimitive)?.contentOrNull
                val value = (element["value"] as? JsonPrimitive)?.contentOrNull
                    ?: element["value"]?.toString()
                if (name != null && value != null) {
                    result[name] = value
                } else if (element.size == 1) {
                    // Treat as single-entry map: {"X-Foo": "bar"}
                    val (k, v) = element.entries.first()
                    val vStr = (v as? JsonPrimitive)?.contentOrNull ?: v.toString()
                    result[k] = vStr
                } else {
                    unrecognized++
                }
            }
            is JsonPrimitive -> {
                val pair = element.takeIf { it.isString }?.let { headerLine(it.content) }
                if (pair != null) result[pair.first] = pair.second else unrecognized++
            }
        }
    }
    val warnings = buildList {
        if (unrecognized > 0) {
            add("$unrecognized of ${arr.size} header entries could not be parsed; expected \"Name: value\", [name,value] pair, {name,value}, {key,value}, or single-entry object")
        }
        result.duplicates.forEach { add(duplicateHeaderWarning(it)) }
    }
    return HeaderParse(LinkedHashMap(result), warnings.takeIf { it.isNotEmpty() }?.joinToString("; "), unrecognized)
}

private fun duplicateHeaderWarning(name: String) =
    "duplicate header '$name': last value kept; use raw_request to send duplicates"

/**
 * `Name: value` lines split at the first `:`. The name is kept exactly as written (no token check,
 * so `Transfer-Encoding : chunked` keeps its space) and the value loses at most one leading space.
 * Returns the map, warnings for lines without a `:` and for repeated names, and the count of lines without a `:`.
 */
private fun parseRawHeaderBlock(block: String): Triple<Map<String, String>, List<String>, Int> {
    val result = linkedMapOf<String, String>()
    val warnings = mutableListOf<String>()
    val noColon = mutableListOf<String>()
    block.lineSequence().forEach { raw ->
        val line = raw.removeSuffix("\r")
        if (line.isBlank()) return@forEach
        val (name, value) = headerLine(line) ?: run {
            noColon += line
            return@forEach
        }
        if (name in result) warnings += duplicateHeaderWarning(name)
        result[name] = value
    }
    if (noColon.isNotEmpty()) warnings.add(0, "lines without ':' skipped: ${noColon.take(5).joinToString(" | ")}")
    return Triple(result, warnings, noColon.size)
}

/**
 * Extract a request/response body from a JsonElement that might be:
 * - A JsonPrimitive string (returned as-is)
 * - A JsonObject or JsonArray (serialized to compact JSON string — natural for JSON bodies)
 * - A JsonPrimitive number/boolean (stringified)
 * - null (returned as null)
 *
 * This avoids the common MCP error "Element class JsonObject is not a JsonPrimitive"
 * when callers pass `body: { "key": "value" }` directly instead of stringifying first.
 */
fun JsonElement?.asBodyString(): String? {
    if (this == null) return null
    return when (this) {
        is JsonNull -> null
        is JsonPrimitive -> this.contentOrNull ?: this.toString()
        is JsonObject -> this.toString()
        is JsonArray -> this.toString()
    }
}

/**
 * Extract a Long from a JsonElement that might be:
 * - A JsonPrimitive integral number, however it is written (`50`, `50.0`, `5e1`)
 * - A JsonPrimitive numeric string of the same
 * Returns null when absent, JSON null, fractional, non-numeric or outside the Long range. Nothing is
 * rounded: `50.0000000000000001` is fractional, and `9007199254740993e0` keeps its last digit.
 */
fun JsonElement?.asLongSafe(): Long? {
    val text = numberText() ?: return null
    text.toLongOrNull()?.let { return it }
    val n = integralOrNull(text) ?: return null
    return if (n in LONG_RANGE) n.longValueExact() else null
}

/**
 * Extract an Int from a JsonElement the way [asLongSafe] reads a Long.
 * Returns null when absent, JSON null, fractional, non-numeric or outside the Int range.
 */
fun JsonElement?.asIntSafe(): Int? =
    asLongSafe()?.takeIf { it in Int.MIN_VALUE..Int.MAX_VALUE }?.toInt()

/**
 * Reads an integer tool argument [name] bounded to [min]..[max]. Success holds null when the
 * argument is absent or JSON null (the caller applies its default or reports it missing); failure
 * carries a caller-facing [IllegalArgumentException] for a non-integer or out-of-range value.
 */
fun JsonElement?.asBoundedInt(name: String, min: Int, max: Int): Result<Int?> {
    if (this == null || this is JsonNull) return Result.success(null)
    val n = integralArg(name).getOrElse { return Result.failure(it) }
    if (n < BigDecimal.valueOf(min.toLong()) || n > BigDecimal.valueOf(max.toLong())) {
        return Result.failure(IllegalArgumentException("Parameter '$name' must be between $min and $max (got ${numberText()})"))
    }
    return Result.success(n.intValueExact())
}

/**
 * An integer argument read by [asClampedInt]: the [value] the tool uses, and whether the caller's
 * value lay outside the accepted range and was moved to its nearest end.
 */
data class ClampedInt(val value: Int, val clamped: Boolean)

/**
 * Reads an integer tool argument [name] clamped into [min]..[max], for limits where an oversized or
 * negative value should still run rather than fail. Success holds null when the argument is absent
 * or JSON null (the caller applies its default); failure carries a caller-facing
 * [IllegalArgumentException] for a value that is not an integer. Report a clamp with
 * [withClampReport], so the caller learns the value that was used.
 */
fun JsonElement?.asClampedInt(name: String, min: Int, max: Int): Result<ClampedInt?> {
    if (this == null || this is JsonNull) return Result.success(null)
    val n = integralArg(name).getOrElse { return Result.failure(it) }
    val bound = when {
        n < BigDecimal.valueOf(min.toLong()) -> min
        n > BigDecimal.valueOf(max.toLong()) -> max
        else -> return Result.success(ClampedInt(n.intValueExact(), clamped = false))
    }
    return Result.success(ClampedInt(bound, clamped = true))
}

/** This result plus `<name>_clamped_to` when [arg] was clamped, naming the value the tool used instead. */
fun JsonObject.withClampReport(name: String, arg: ClampedInt?): JsonObject =
    if (arg?.clamped == true) JsonObject(this + ("${name}_clamped_to" to JsonPrimitive(arg.value))) else this

private val LONG_RANGE = BigDecimal.valueOf(Long.MIN_VALUE)..BigDecimal.valueOf(Long.MAX_VALUE)

/** The text of a number or string argument, trimmed and unquoted once; null for JSON null and non-primitives. */
private fun JsonElement?.numberText(): String? {
    val p = this as? JsonPrimitive ?: return null
    if (p is JsonNull) return null
    return p.content.trim().removeSurrounding("\"")
}

/** This argument's exact integral value, or the caller-facing error naming [name]. */
private fun JsonElement.integralArg(name: String): Result<BigDecimal> =
    numberText()?.let(::integralOrNull)?.let { Result.success(it) }
        ?: Result.failure(IllegalArgumentException("Parameter '$name' must be an integer (got $this)"))

/**
 * The exact value of [text] when it is an integral decimal number (`50`, `-7`, `50.0`, `5e1`), else
 * null. Nothing is rounded. A fraction is only looked for in a value of at least 1, so the check
 * divides by a power of ten no longer than [text], and a huge exponent costs nothing.
 */
private fun integralOrNull(text: String): BigDecimal? {
    text.toLongOrNull()?.let { return BigDecimal.valueOf(it) }
    val n = text.toBigDecimalOrNull() ?: return null
    val whole = n.signum() == 0 || n.scale() <= 0 ||
        (n.precision() > n.scale() && n.setScale(0, RoundingMode.DOWN).compareTo(n) == 0)
    return if (whole) n else null
}

/**
 * Extract a Boolean from a JsonElement that might be:
 * - A JsonPrimitive boolean
 * - A JsonPrimitive string "true"/"false" (case-insensitive)
 * Returns null when absent, JSON null or anything else.
 */
fun JsonElement?.asBooleanSafe(): Boolean? {
    val p = this as? JsonPrimitive ?: return null
    if (p is JsonNull) return null
    return when (p.content.trim().lowercase()) {
        "true" -> true
        "false" -> false
        else -> null
    }
}
