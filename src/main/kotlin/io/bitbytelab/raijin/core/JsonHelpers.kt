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
                is JsonPrimitive -> it.contentOrNull
                else -> it.toString()
            }
        }
        is JsonPrimitive -> {
            val str = this.contentOrNull ?: return null
            if (str.trimStart().startsWith("[")) {
                try {
                    json.parseToJsonElement(str).jsonArray.map { it.jsonPrimitive.content }
                } catch (_: Exception) {
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
fun JsonElement?.asStringMapResult(): Pair<Map<String, String>?, String?> {
    if (this == null) return null to null
    return when (this) {
        is JsonNull -> null to null
        is JsonObject -> objectToStringMap(this) to null
        is JsonArray -> arrayToStringMap(this)
        is JsonPrimitive -> {
            val str = this.contentOrNull ?: return null to "headers primitive had no content"
            val trimmed = str.trimStart()
            try {
                val parsed = json.parseToJsonElement(str)
                when (parsed) {
                    is JsonObject -> objectToStringMap(parsed) to null
                    is JsonArray -> arrayToStringMap(parsed)
                    else -> null to "headers primitive parsed to ${parsed::class.simpleName}, expected object or array"
                }
            } catch (_: Exception) {
                if (trimmed.contains(":")) {
                    // Best-effort raw HTTP header parsing: "X-Foo: bar\nX-Bar: baz"
                    val map = parseRawHeaderBlock(str)
                    if (map.isNotEmpty()) map to "parsed as raw HTTP header block (one 'Name: value' per line)"
                    else null to "headers string is not JSON and not parseable as 'Name: value' lines"
                } else {
                    null to "headers string is not valid JSON and contains no ':' for raw header parsing"
                }
            }
        }
    }
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
 *
 * Multiple entries with the same name are coalesced (last value wins) — same as a real
 * HTTP server's lookup by header name in this MCP layer.
 */
private fun arrayToStringMap(arr: JsonArray): Pair<Map<String, String>?, String?> {
    if (arr.isEmpty()) return emptyMap<String, String>() to null
    val result = linkedMapOf<String, String>()
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
            else -> unrecognized++
        }
    }
    val warning = if (unrecognized > 0)
        "$unrecognized of ${arr.size} header entries could not be parsed; expected [name,value] pair, {name,value}, {key,value}, or single-entry object"
    else null
    return result to warning
}

private val rawHeaderLineRegex = Regex("^([A-Za-z0-9!#$%&'*+\\-.^_`|~]+)\\s*:\\s*(.*)$")

private fun parseRawHeaderBlock(block: String): Map<String, String> {
    val result = linkedMapOf<String, String>()
    block.lineSequence().forEach { line ->
        val trimmed = line.trim().trimEnd('\r')
        if (trimmed.isEmpty()) return@forEach
        rawHeaderLineRegex.matchEntire(trimmed)?.let { m ->
            result[m.groupValues[1]] = m.groupValues[2]
        }
    }
    return result
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
