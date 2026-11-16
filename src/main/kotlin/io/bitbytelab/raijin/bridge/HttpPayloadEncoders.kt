package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.core.UrlEncoding
import kotlinx.serialization.json.JsonPrimitive
import java.util.Base64

/**
 * Named text encoders: applied to `http_fuzz` payloads before they are placed in the request, and
 * to an extracted session value through a `{value|url}` style placeholder
 * ([SessionRuleEngine.render]). Encoders work on the UTF-8 bytes of the text and can be chained.
 */
internal object PayloadEncoders {

    private const val HEX_UPPER = "0123456789ABCDEF"
    private const val URL_UNRESERVED = "-._~"

    private val encoders: Map<String, (String) -> String> = linkedMapOf(
        "url" to { value: String -> urlEncode(value) },
        "url_all" to { value: String -> UrlEncoding.percentEncodeAll(value) },
        "double_url" to { value: String -> urlEncode(urlEncode(value)) },
        "json" to { value: String -> jsonEscape(value) },
        "base64" to { value: String -> Base64.getEncoder().encodeToString(value.toByteArray(Charsets.UTF_8)) },
        "base64url" to { value: String -> Base64.getUrlEncoder().withoutPadding().encodeToString(value.toByteArray(Charsets.UTF_8)) },
        "html" to { value: String -> htmlEscape(value) },
        "hex" to { value: String -> value.toByteArray(Charsets.UTF_8).joinToString("") { "%02x".format(it.toInt() and 0xFF) } },
        "raw" to { value: String -> value },
    )

    /** Encoder names, in documentation order. */
    val names: List<String> = encoders.keys.toList()

    /** The first of [names] that is not an encoder, or null when all are known. */
    fun unknown(names: List<String>): String? = names.firstOrNull { key(it) !in encoders }

    /**
     * One function applying [names] left to right.
     * @throws IllegalArgumentException naming an unknown encoder.
     */
    fun chain(names: List<String>): (String) -> String {
        val steps = names.map { name ->
            encoders[key(name)] ?: throw IllegalArgumentException(
                "Unknown encoder '$name'. Allowed: ${this.names.joinToString(", ")}"
            )
        }
        if (steps.isEmpty()) return { it }
        return { value -> steps.fold(value) { text, step -> step(text) } }
    }

    private fun key(name: String): String = name.trim().lowercase()

    /** Percent-encodes every byte except RFC 3986 unreserved characters (letters, digits, `-._~`). */
    fun urlEncode(value: String): String {
        val out = StringBuilder(value.length + 16)
        for (byte in value.toByteArray(Charsets.UTF_8)) {
            val code = byte.toInt() and 0xFF
            val char = code.toChar()
            if (code < 0x80 && (char in 'a'..'z' || char in 'A'..'Z' || char in '0'..'9' || char in URL_UNRESERVED)) {
                out.append(char)
            } else {
                out.append('%').append(HEX_UPPER[code shr 4]).append(HEX_UPPER[code and 0x0F])
            }
        }
        return out.toString()
    }

    /** [value] as the inside of a JSON string: quotes, backslashes and control characters escaped, no surrounding quotes. */
    fun jsonEscape(value: String): String {
        val quoted = JsonPrimitive(value).toString()
        return quoted.substring(1, quoted.length - 1)
    }

    fun htmlEscape(value: String): String = buildString(value.length + 16) {
        for (char in value) {
            when (char) {
                '&' -> append("&amp;")
                '<' -> append("&lt;")
                '>' -> append("&gt;")
                '"' -> append("&quot;")
                '\'' -> append("&#x27;")
                else -> append(char)
            }
        }
    }
}
