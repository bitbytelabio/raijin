package io.bitbytelab.raijin.jwt

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive

/**
 * Edits the top-level members of a JSON object in its original text, without parsing the object
 * into a tree and printing it again. A JWS signs bytes, and real tokens carry things a JSON tree
 * loses: a member that appears twice, `1.0` next to `1`, `\/` escapes, whitespace, member order.
 * Whatever a change does not name comes out byte for byte.
 *
 * The scan is deliberately loose about values (`NaN`, a bare word, a number of any shape all pass):
 * it only has to know where each top-level member starts and ends.
 */
internal object RawJson {

    /** One top-level member. [name] is unescaped; the offsets point into the scanned text. */
    class Member(val name: String, val start: Int, val valueStart: Int, val valueEnd: Int)

    /** The top-level members of [text] in order, or null when [text] is not one JSON object. */
    fun members(text: String): List<Member>? {
        var i = skipSpace(text, 0)
        if (i >= text.length || text[i] != '{') return null
        i = skipSpace(text, i + 1)
        val found = ArrayList<Member>()
        if (i < text.length && text[i] == '}') return if (skipSpace(text, i + 1) == text.length) found else null
        while (true) {
            if (i >= text.length || text[i] != '"') return null
            val nameEnd = stringEnd(text, i) ?: return null
            val colon = skipSpace(text, nameEnd)
            if (colon >= text.length || text[colon] != ':') return null
            val valueStart = skipSpace(text, colon + 1)
            val valueEnd = valueEnd(text, valueStart) ?: return null
            found.add(Member(unescape(text, i + 1, nameEnd - 1), i, valueStart, valueEnd))
            i = skipSpace(text, valueEnd)
            if (i >= text.length) return null
            if (text[i] == '}') return if (skipSpace(text, i + 1) == text.length) found else null
            if (text[i] != ',') return null
            i = skipSpace(text, i + 1)
        }
    }

    /** Names carried by more than one top-level member of [text], in the order they first appear. */
    fun repeated(text: String): List<String> {
        val names = members(text)?.map { it.name } ?: return emptyList()
        return names.groupingBy { it }.eachCount().filterValues { it > 1 }.keys.toList()
    }

    /**
     * [text] with every top-level member named in [changes] given its new value (each copy of a
     * repeated member), and the names [text] does not have yet appended in the order of [changes].
     * Null when [text] is not one JSON object.
     */
    fun set(text: String, changes: Map<String, JsonElement>): String? {
        val members = members(text) ?: return null
        if (changes.isEmpty()) return text
        val out = StringBuilder(text.length + 64)
        val replaced = HashSet<String>()
        var copied = 0
        for (member in members) {
            val value = changes[member.name] ?: continue
            replaced.add(member.name)
            out.append(text, copied, member.valueStart).append(value.toString())
            copied = member.valueEnd
        }
        val insertAt = members.lastOrNull()?.valueEnd ?: (text.indexOf('{') + 1)
        out.append(text, copied, insertAt)
        var first = members.isEmpty()
        for ((name, value) in changes) {
            if (name in replaced) continue
            if (!first) out.append(',')
            first = false
            out.append(JsonPrimitive(name).toString()).append(':').append(value.toString())
        }
        out.append(text, insertAt, text.length)
        return out.toString()
    }

    /**
     * [text] without the top-level members named in [names]. The members that stay keep their own
     * bytes and the separators between them. Null when [text] is not one JSON object.
     */
    fun remove(text: String, names: Set<String>): String? {
        val members = members(text) ?: return null
        if (members.none { it.name in names }) return text
        val out = StringBuilder(text.length)
        out.append(text, 0, members.first().start)
        var previous = -1
        for ((index, member) in members.withIndex()) {
            if (member.name in names) continue
            // The separator that followed the last member kept: its comma and the space around it.
            if (previous >= 0) out.append(text, members[previous].valueEnd, members[previous + 1].start)
            out.append(text, member.start, member.valueEnd)
            previous = index
        }
        out.append(text, members.last().valueEnd, text.length)
        return out.toString()
    }

    private fun isSpace(c: Char): Boolean = c == ' ' || c == '\t' || c == '\n' || c == '\r'

    private fun skipSpace(text: String, from: Int): Int {
        var i = from
        while (i < text.length && isSpace(text[i])) i += 1
        return i
    }

    /** Index just past the string that opens at [open], or null when it never closes. */
    private fun stringEnd(text: String, open: Int): Int? {
        var i = open + 1
        while (i < text.length) {
            val c = text[i]
            if (c == '"') return i + 1
            i += if (c == '\\') 2 else 1
        }
        return null
    }

    /** Index just past the value that starts at [start], or null when it is missing or never closes. */
    private fun valueEnd(text: String, start: Int): Int? {
        if (start >= text.length) return null
        val c = text[start]
        if (c == '"') return stringEnd(text, start)
        if (c == '{' || c == '[') return nestedEnd(text, start)
        var i = start
        while (i < text.length && text[i] != ',' && text[i] != '}' && text[i] != ']' && !isSpace(text[i])) i += 1
        return if (i > start) i else null
    }

    private fun nestedEnd(text: String, start: Int): Int? {
        var depth = 0
        var i = start
        while (i < text.length) {
            val c = text[i]
            if (c == '"') {
                i = stringEnd(text, i) ?: return null
                continue
            }
            if (c == '{' || c == '[') depth += 1
            if (c == '}' || c == ']') {
                depth -= 1
                if (depth == 0) return i + 1
            }
            i += 1
        }
        return null
    }

    /** The JSON string body in `text[from, to)` with its escapes resolved, so `"\u0065xp"` names `exp`. */
    private fun unescape(text: String, from: Int, to: Int): String {
        if (text.indexOf('\\', from) !in from until to) return text.substring(from, to)
        val out = StringBuilder(to - from)
        var i = from
        while (i < to) {
            val c = text[i]
            if (c != '\\' || i + 1 >= to) {
                out.append(c)
                i += 1
                continue
            }
            val escaped = text[i + 1]
            if (escaped == 'u' && i + 6 <= to && isHex(text, i + 2, i + 6)) {
                out.append(text.substring(i + 2, i + 6).toInt(16).toChar())
                i += 6
                continue
            }
            out.append(
                when (escaped) {
                    'b' -> '\b'
                    'f' -> '\u000C'
                    'n' -> '\n'
                    'r' -> '\r'
                    't' -> '\t'
                    else -> escaped
                }
            )
            i += 2
        }
        return out.toString()
    }

    private fun isHex(text: String, from: Int, to: Int): Boolean {
        for (i in from until to) {
            val c = text[i]
            if (c !in '0'..'9' && c !in 'a'..'f' && c !in 'A'..'F') return false
        }
        return true
    }
}
