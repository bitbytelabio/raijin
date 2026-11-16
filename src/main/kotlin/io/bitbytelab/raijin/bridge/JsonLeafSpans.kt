package io.bitbytelab.raijin.bridge

import kotlinx.serialization.json.JsonPrimitive

/**
 * Scalar leaves of a JSON document together with the exact span each one occupies in the source
 * text. Replacing a value by its span changes that value and nothing else: whitespace, key order,
 * escapes and duplicate keys of the rest of the body stay byte for byte as they were sent, which a
 * parse-and-reserialize round trip would not guarantee.
 */
internal object JsonLeafSpans {

    /**
     * @param path dotted path from the root: `user.id`, `items[2].id`, `[0]`
     *   (same notation as [io.bitbytelab.raijin.core.JsonInsertionPoints]).
     * @param key the object key the leaf hangs under; for an array element, the key of the array.
     * @param start index of the first character of the value token (the opening quote of a string).
     * @param end index just past the token.
     * @param quoted the leaf is a JSON string.
     * @param value the decoded string, or the literal text of a number / `true` / `false` / `null`.
     */
    data class Leaf(
        val path: String,
        val key: String,
        val start: Int,
        val end: Int,
        val quoted: Boolean,
        val value: String,
    )

    private const val MAX_DEPTH = 256
    private const val LITERAL_END = ",}] \t\r\n"
    private val NUMBER = Regex("-?(?:0|[1-9]\\d*)(?:\\.\\d+)?(?:[eE][+-]?\\d+)?")

    /** Leaves of [text] in document order, or null when it is not one well-formed JSON value. */
    fun scan(text: String): List<Leaf>? = try {
        Scanner(text).document()
    } catch (_: Malformed) {
        null
    }

    fun isNumber(text: String): Boolean = NUMBER.matches(text)

    /** [value] as a JSON string token, quotes included. */
    fun quote(value: String): String = JsonPrimitive(value).toString()

    /**
     * The token to write in place of [leaf] for [newValue]. A number stays a bare number when the
     * new value is one too, anything else becomes a string. A new value that is itself a JSON
     * array is written as that array: the type-juggling probe that sends `["5"]` where `"5"` stood.
     */
    fun render(leaf: Leaf, newValue: String): String = when {
        newValue.startsWith("[") && scan(newValue) != null -> newValue
        !leaf.quoted && isNumber(newValue) -> newValue
        else -> quote(newValue)
    }

    private class Malformed : RuntimeException(null, null, false, false)

    private class Scanner(private val s: String) {
        private var i = 0
        private val leaves = ArrayList<Leaf>()

        fun document(): List<Leaf> {
            value("", "", 0)
            skipWhitespace()
            if (i != s.length) throw Malformed()
            return leaves
        }

        private fun skipWhitespace() {
            while (i < s.length && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++
        }

        private fun value(path: String, key: String, depth: Int) {
            if (depth > MAX_DEPTH) throw Malformed()
            skipWhitespace()
            if (i >= s.length) throw Malformed()
            when (s[i]) {
                '{' -> obj(path, depth)
                '[' -> array(path, key, depth)
                '"' -> {
                    val start = i
                    val text = string()
                    leaves += Leaf(path, key, start, i, quoted = true, value = text)
                }
                else -> {
                    val start = i
                    while (i < s.length && s[i] !in LITERAL_END) i++
                    val literal = s.substring(start, i)
                    if (literal != "true" && literal != "false" && literal != "null" && !NUMBER.matches(literal)) {
                        throw Malformed()
                    }
                    leaves += Leaf(path, key, start, i, quoted = false, value = literal)
                }
            }
        }

        private fun obj(path: String, depth: Int) {
            i++ // {
            skipWhitespace()
            if (i < s.length && s[i] == '}') {
                i++
                return
            }
            while (true) {
                skipWhitespace()
                if (i >= s.length || s[i] != '"') throw Malformed()
                val key = string()
                skipWhitespace()
                if (i >= s.length || s[i] != ':') throw Malformed()
                i++
                value(if (path.isEmpty()) key else "$path.$key", key, depth + 1)
                skipWhitespace()
                if (i >= s.length) throw Malformed()
                val c = s[i++]
                if (c == '}') return
                if (c != ',') throw Malformed()
            }
        }

        private fun array(path: String, key: String, depth: Int) {
            i++ // [
            skipWhitespace()
            if (i < s.length && s[i] == ']') {
                i++
                return
            }
            var n = 0
            while (true) {
                value("$path[$n]", key, depth + 1)
                n++
                skipWhitespace()
                if (i >= s.length) throw Malformed()
                val c = s[i++]
                if (c == ']') return
                if (c != ',') throw Malformed()
            }
        }

        /** Reads the string that starts at the opening quote under [i]; leaves [i] past the closing quote. */
        private fun string(): String {
            val out = StringBuilder()
            i++ // opening quote
            while (true) {
                if (i >= s.length) throw Malformed()
                when (val c = s[i++]) {
                    '"' -> return out.toString()
                    '\\' -> out.append(escape())
                    else -> out.append(c)
                }
            }
        }

        /** Decodes the escape whose backslash was just consumed. */
        private fun escape(): Char {
            if (i >= s.length) throw Malformed()
            return when (val e = s[i++]) {
                '"', '\\', '/' -> e
                'b' -> '\b'
                'f' -> '\u000C'
                'n' -> '\n'
                'r' -> '\r'
                't' -> '\t'
                'u' -> {
                    if (i + 4 > s.length) throw Malformed()
                    val hex = s.substring(i, i + 4)
                    if (!hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) throw Malformed()
                    i += 4
                    hex.toInt(16).toChar()
                }
                else -> throw Malformed()
            }
        }
    }
}
