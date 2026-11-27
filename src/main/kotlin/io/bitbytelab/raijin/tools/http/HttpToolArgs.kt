package io.bitbytelab.raijin.tools.http

import io.bitbytelab.raijin.core.EnumValidation
import io.bitbytelab.raijin.core.asBooleanSafe
import io.bitbytelab.raijin.core.asJsonObjectList
import io.bitbytelab.raijin.core.asLongSafe
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

/**
 * The arguments of one HTTP or session tool call.
 *
 * A malformed value (text where a number belongs, an unknown enum value) throws
 * [IllegalArgumentException] with the message the handler returns through `toolError`. A number
 * outside its range is not an error: it is clamped into the range and the adjustment is recorded in
 * [notes], which [withNotes] attaches to the result, so a caller asking for 5000 requests gets the
 * maximum and is told so.
 */
internal class ToolArgs(private val args: Map<String, JsonElement>) {

    /** Adjustments made while reading the arguments, for the result's `notes`. */
    val notes: MutableList<String> = ArrayList()

    /** The argument, or null when it is absent or JSON null. */
    operator fun get(name: String): JsonElement? = args[name]?.takeUnless { it is JsonNull }

    fun has(name: String): Boolean = get(name) != null

    /** Text argument; a number or boolean is read as its text. */
    fun string(name: String): String? {
        val element = get(name) ?: return null
        return (element as? JsonPrimitive)?.contentOrNull
            ?: throw IllegalArgumentException("Parameter '$name' must be a string")
    }

    /** Boolean argument (`true`/`false`, also as text); null when absent. */
    fun bool(name: String): Boolean? {
        val element = get(name) ?: return null
        return element.asBooleanSafe()
            ?: throw IllegalArgumentException("Parameter '$name' must be true or false")
    }

    /** Integer argument that must lie within [range] (a port, an index); null when absent. */
    fun long(name: String, range: LongRange): Long? {
        val value = integer(name) ?: return null
        require(value in range) {
            "Parameter '$name' must be between ${range.first} and ${range.last} (got $value)"
        }
        return value
    }

    fun int(name: String, range: IntRange): Int? =
        long(name, range.first.toLong()..range.last.toLong())?.toInt()

    /** Integer argument clamped into [range]; null when absent. */
    fun clampedLong(name: String, range: LongRange): Long? {
        val value = integer(name) ?: return null
        return clamp(name, value, range.first, range.last)
    }

    fun clampedInt(name: String, range: IntRange): Int? =
        clampedLong(name, range.first.toLong()..range.last.toLong())?.toInt()

    /** Number argument (fractions allowed) clamped into [range]; null when absent. */
    fun clampedDouble(name: String, range: ClosedFloatingPointRange<Double>): Double? {
        val element = get(name) ?: return null
        val value =
            (element as? JsonPrimitive)?.contentOrNull?.trim()?.toDoubleOrNull()?.takeIf {
                it.isFinite()
            } ?: throw IllegalArgumentException("Parameter '$name' must be a number")
        if (value in range) return value
        val clamped = value.coerceIn(range)
        notes +=
            "Parameter '$name' = ${number(value)} is outside ${number(range.start)}-${number(range.endInclusive)}; " +
                "${number(clamped)} was used."
        return clamped
    }

    /**
     * A hard timeout in milliseconds: [default] when absent, and `0` for no hard timeout (the send
     * waits for Burp, as `timeout_ms: 0` always meant). A negative value is read as 0 and a value
     * above [max] as [max], each with a note.
     */
    fun timeoutMs(name: String, default: Long, max: Long = MAX_TIMEOUT_MS): Long {
        val value = integer(name) ?: return default
        if (value < 0) {
            notes += "Parameter '$name' = $value is negative; 0 (no hard timeout) was used."
            return 0
        }
        return clamp(name, value, 0, max)
    }

    /**
     * String argument from the closed set [allowed] (case-insensitive); null when absent or blank.
     * With [booleans], a JSON boolean reads as `first` (true) or `second` (false), noted.
     */
    fun enum(name: String, allowed: List<String>, booleans: Pair<String, String>? = null): String? {
        val element = get(name)
        if (booleans != null && element is JsonPrimitive && !element.isString) {
            element.content.toBooleanStrictOrNull()?.let { b ->
                val value = if (b) booleans.first else booleans.second
                notes += "read $name $b as \"$value\""
                return value
            }
        }
        val value = string(name) ?: return null
        EnumValidation.error(value, allowed.toSet(), name)?.let {
            throw IllegalArgumentException(
                it["error"]?.jsonPrimitive?.contentOrNull
                    ?: "Parameter '$name' has an invalid value",
            )
        }
        val trimmed = value.trim()
        return allowed.firstOrNull { it.equals(trimmed, ignoreCase = true) }
            ?: trimmed.ifEmpty { null }
    }

    /** TLS flag from `use_tls` or its aliases `tls` / `https`; TLS by default on port 443. */
    fun tls(port: Int): Boolean = explicitTls() ?: (port == 443)

    /** use_tls (or its aliases tls / https) when the caller gave one. */
    fun explicitTls(): Boolean? = bool("use_tls") ?: bool("tls") ?: bool("https")

    /** The `port` argument, else 80 when TLS is explicitly off and 443 otherwise. */
    fun portOrDefault(ports: IntRange): Int =
        int("port", ports) ?: if (explicitTls() == false) 80 else 443

    /** Non-empty list of objects under [name]; null when absent. Every item must be an object. */
    fun objectList(name: String, what: String): List<JsonObject>? {
        val element = get(name) ?: return null
        val items =
            element.asJsonObjectList()
                ?: throw IllegalArgumentException("'$name' must be an array of $what objects")
        val given = (element as? JsonArray)?.size ?: items.size
        require(items.size == given) {
            "Every item in '$name' must be a $what object (${given - items.size} of $given are not)"
        }
        require(items.isNotEmpty()) { "'$name' must contain at least one $what object" }
        return items
    }

    /** [result] with [notes] added to its `notes` array (after any notes it already has). */
    fun withNotes(result: JsonObject): JsonObject {
        if (notes.isEmpty()) return result
        val merged = buildJsonArray {
            (result["notes"] as? JsonArray)?.forEach { add(it) }
            notes.forEach { add(it) }
        }
        return JsonObject(result + ("notes" to merged))
    }

    private fun integer(name: String): Long? {
        val element = get(name) ?: return null
        return element.asLongSafe()
            ?: throw IllegalArgumentException("Parameter '$name' must be an integer (got $element)")
    }

    private fun clamp(name: String, value: Long, min: Long, max: Long): Long {
        if (value in min..max) return value
        val clamped = value.coerceIn(min, max)
        notes += "Parameter '$name' = $value is outside $min-$max; $clamped was used."
        return clamped
    }

    private fun number(value: Double): String =
        if (value % 1.0 == 0.0 && kotlin.math.abs(value) < 1e15) value.toLong().toString()
        else value.toString()

    companion object {
        /** Ceiling of every hard timeout (ten minutes). */
        const val MAX_TIMEOUT_MS = 600_000L
    }
}

/** Adds a string property whose value must be one of [values]. */
internal fun JsonObjectBuilder.enumProperty(
    name: String,
    values: List<String>,
    description: String,
) {
    putJsonObject(name) {
        put("type", "string")
        putJsonArray("enum") { values.forEach { add(it) } }
        put("description", description)
    }
}

/** Adds a property of JSON type [type] with [description]. */
internal fun JsonObjectBuilder.property(name: String, type: String, description: String) {
    putJsonObject(name) {
        put("type", type)
        put("description", description)
    }
}
