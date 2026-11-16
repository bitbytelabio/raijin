package io.bitbytelab.raijin.openapi

import kotlinx.serialization.json.*
import java.net.URLEncoder

private const val HEX = "0123456789ABCDEF"

/** Percent-encodes [text] as UTF-8, leaving the RFC 3986 unreserved characters and those in [keep]. */
internal fun percentEncode(text: String, keep: String = ""): String {
    val out = StringBuilder(text.length + 8)
    for (byte in text.toByteArray(Charsets.UTF_8)) {
        val code = byte.toInt() and 0xFF
        val char = code.toChar()
        if (char in 'A'..'Z' || char in 'a'..'z' || char in '0'..'9' || char in "-._~" || char in keep) {
            out.append(char)
        } else {
            out.append('%').append(HEX[code shr 4]).append(HEX[code and 0xF])
        }
    }
    return out.toString()
}

/** `application/x-www-form-urlencoded` escaping: a space becomes `+`. */
internal fun formEncode(text: String): String = URLEncoder.encode(text, Charsets.UTF_8)

/** A value as it is written into a URL, a header or a form field: a scalar as its text, a container as JSON. */
internal fun JsonElement.asFieldText(): String = when (this) {
    is JsonNull -> ""
    is JsonPrimitive -> content
    else -> toString()
}

/** How a parameter or form field spreads its value: OpenAPI 3 `style` / `explode`, or Swagger 2 `collectionFormat`. */
internal class ParameterStyle(val style: String, val explode: Boolean) {
    companion object {
        val FORM = ParameterStyle("form", true)

        fun of(parameter: JsonObject, location: String?, swagger2: Boolean): ParameterStyle {
            val positional = location == "path" || location == "header"
            if (swagger2) {
                return when (val format = parameter["collectionFormat"].asText() ?: "csv") {
                    "multi" -> FORM
                    "ssv", "tsv", "pipes" -> ParameterStyle(format, false)
                    else -> ParameterStyle(if (positional) "simple" else "form", false)
                }
            }
            val style = parameter["style"].asText() ?: if (positional) "simple" else "form"
            return ParameterStyle(style, (parameter["explode"] as? JsonPrimitive)?.booleanOrNull ?: (style == "form"))
        }
    }
}

/**
 * The `name=value` pairs a query, cookie or form parameter becomes. Names and values go through
 * [encode]; the delimiter joining a non-exploded array is not part of any value, so a comma stays one.
 */
internal fun formPairs(
    name: String,
    value: JsonElement,
    style: ParameterStyle,
    encode: (String) -> String
): List<Pair<String, String>> = when (value) {
    is JsonArray -> if (style.style == "form" && style.explode) {
        value.map { encode(name) to encode(it.asFieldText()) }
    } else {
        listOf(encode(name) to value.joinToString(delimiter(style.style, encode)) { encode(it.asFieldText()) })
    }
    is JsonObject -> when {
        // The brackets are escaped along with the name: servers decode a name before reading it, while a
        // strict URL parser may not take them raw.
        style.style == "deepObject" -> value.map { (key, item) -> encode("$name[$key]") to encode(item.asFieldText()) }
        style.explode -> value.map { (key, item) -> encode(key) to encode(item.asFieldText()) }
        else -> listOf(
            encode(name) to value.entries.joinToString(",") { (key, item) -> encode(key) + "," + encode(item.asFieldText()) }
        )
    }
    else -> listOf(encode(name) to encode(value.asFieldText()))
}

/** The single string a path or header parameter becomes: `simple` style unless it asks for `label` or `matrix`. */
internal fun pathText(name: String, value: JsonElement, style: ParameterStyle, encode: (String) -> String): String {
    val items = when (value) {
        is JsonArray -> value.map { encode(it.asFieldText()) }
        is JsonObject -> value.map { (key, item) -> encode(key) + (if (style.explode) "=" else ",") + encode(item.asFieldText()) }
        else -> listOf(encode(value.asFieldText()))
    }
    return when (style.style) {
        "label" -> items.joinToString(if (style.explode) "." else ",", prefix = ".")
        "matrix" -> {
            // An exploded object supplies its own keys; everything else repeats the parameter name.
            val named = if (value is JsonObject && style.explode) "" else encode(name) + "="
            if (style.explode) items.joinToString("") { ";$named$it" } else ";" + named + items.joinToString(",")
        }
        else -> items.joinToString(delimiter(style.style, encode))
    }
}

private fun delimiter(style: String, encode: (String) -> String): String = when (style) {
    "spaceDelimited", "ssv" -> encode(" ")
    "pipeDelimited", "pipes" -> encode("|")
    "tsv" -> encode("\t")
    else -> ","
}
