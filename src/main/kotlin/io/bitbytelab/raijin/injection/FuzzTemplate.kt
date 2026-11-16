package io.bitbytelab.raijin.injection

import io.bitbytelab.raijin.safety.RequestHygiene
import kotlinx.serialization.json.Json

/** Where a `FUZZ` marker sits in the request; decides how a payload must be written to arrive intact. */
enum class FuzzContext(val id: String) {
    /** Request line, before `?`. */
    URL_PATH("url_path"),

    /** Request line, after `?`. */
    URL_QUERY("url_query"),

    /** `application/x-www-form-urlencoded` body. */
    FORM("form"),

    /** JSON body, inside a string literal. */
    JSON_STRING("json_string"),

    /** JSON body, outside any string (a bare value such as `{"id": FUZZ}`). */
    JSON_VALUE("json_value"),

    /** XML body. */
    XML("xml"),

    /** `Cookie` header. */
    COOKIE("cookie"),

    /** Any other header line. */
    HEADER("header"),

    /** Anything else (multipart or opaque body, request method): written as is. */
    RAW("raw"),
}

/**
 * The `encoding` tool parameter: [AUTO] writes each marker in the encoding its [FuzzContext]
 * needs; the other values force one encoder on every marker.
 */
enum class PayloadEncoding(val id: String) {
    AUTO("auto"),
    RAW("raw"),
    URL("url"),
    JSON("json"),
    XML("xml");

    companion object {
        val ids: List<String> = PayloadEncoding.entries.map { it.id }

        fun fromId(id: String?): PayloadEncoding? {
            val wanted = id?.trim().orEmpty()
            return PayloadEncoding.entries.firstOrNull { it.id.equals(wanted, ignoreCase = true) }
        }
    }
}

private enum class BodyKind { JSON, FORM, XML, OPAQUE }

/**
 * A raw request with its `FUZZ` markers located and classified, so a payload can be written at
 * each one in the encoding its position needs and the Content-Length kept in step. Expects
 * canonical line endings ([RequestHygiene.normalizeCrlf]).
 *
 * Automatic encoding only protects the request's structure (request line, JSON or XML document,
 * header line). A `%XX` sequence already in a payload is kept, so pre-encoded payloads are not
 * double-encoded; [PayloadEncoding.RAW] sends every byte as written.
 */
class FuzzTemplate private constructor(
    private val request: String,
    private val points: List<Point>,
    private val bodyStart: Int,
) {
    private data class Point(val offset: Int, val context: FuzzContext)

    private data class Edit(val start: Int, val end: Int, val text: String)

    val hasMarker: Boolean get() = points.isNotEmpty()

    /** Distinct contexts of the markers, in request order. */
    val contexts: List<FuzzContext> get() = points.map { it.context }.distinct()

    /** True when every marker sits in an XML body. */
    val inXmlBody: Boolean get() = points.isNotEmpty() && points.all { it.context == FuzzContext.XML }

    /** The request with [payload] at every marker. */
    fun render(payload: String, encoding: PayloadEncoding = PayloadEncoding.AUTO): String =
        rewrite(points.map { Edit(it.offset, it.offset + MARKER.length, encode(payload, it.context, encoding)) })

    /** [payload] as [render] writes it at the first marker: the text to replay through `http_fuzz`. */
    fun encoded(payload: String, encoding: PayloadEncoding = PayloadEncoding.AUTO): String =
        points.firstOrNull()?.let { encode(payload, it.context, encoding) } ?: payload

    /**
     * Query/form markers rewritten from `key=FUZZ` to one `key[op]=value` pair per entry of
     * [operators] (`key[$gt]=&key[$lt]=~`), the bracket syntax PHP and Express `qs` turn into an
     * operator object. Null unless every marker is the value of a named query or form parameter.
     */
    fun renderKeyOperators(operators: List<Pair<String, String>>): String? {
        if (points.isEmpty() || operators.isEmpty()) return null
        val edits = points.map { point ->
            if (point.context != FuzzContext.URL_QUERY && point.context != FuzzContext.FORM) return null
            val keyStart = parameterStart(point)
            val eq = request.indexOf('=', keyStart)
            if (eq <= keyStart || eq >= point.offset) return null
            val key = request.substring(keyStart, eq)
            val pairs = operators.joinToString("&") { (op, operand) ->
                key + percentEncode("[$op]", QUERY_SAFE) + "=" + percentEncode(operand, QUERY_SAFE)
            }
            Edit(keyStart, point.offset + MARKER.length, pairs)
        }
        return rewrite(edits)
    }

    /**
     * JSON-body markers replaced by the raw JSON [value]; a marker that is a whole string
     * (`"FUZZ"`) loses its quotes, so `{"user":"FUZZ"}` becomes `{"user":{"$gt":""}}`. Null
     * unless every marker is a JSON value on its own.
     */
    fun renderJsonValue(value: String): String? {
        if (points.isEmpty()) return null
        val edits = points.map { point ->
            val end = point.offset + MARKER.length
            when (point.context) {
                FuzzContext.JSON_VALUE -> Edit(point.offset, end, value)
                FuzzContext.JSON_STRING -> {
                    val wholeString = request[point.offset - 1] == '"' && end < request.length && request[end] == '"'
                    if (!wholeString) return null
                    Edit(point.offset - 1, end + 1, value)
                }
                else -> return null
            }
        }
        return rewrite(edits)
    }

    /**
     * XML-body rewrite for entity probes: a DOCTYPE carrying [declarations] is inserted ahead of
     * the root element and every marker becomes the raw [reference] (`&name;`). Null when the
     * markers are not all in an XML body, the body already has a DOCTYPE, or no root element
     * precedes the first marker.
     */
    fun renderXmlEntity(declarations: String, reference: String): String? {
        if (!inXmlBody || bodyStart < 0) return null
        if (request.indexOf("<!DOCTYPE", bodyStart, ignoreCase = true) >= 0) return null
        val root = XML_ROOT.find(request, bodyStart) ?: return null
        if (root.range.first > points.first().offset) return null
        val doctype = Edit(root.range.first, root.range.first, "<!DOCTYPE ${root.groupValues[1]} [$declarations]>")
        return rewrite(listOf(doctype) + points.map { Edit(it.offset, it.offset + MARKER.length, reference) })
    }

    /** Start of the `key=value` pair that holds [point]. */
    private fun parameterStart(point: Point): Int {
        val form = point.context == FuzzContext.FORM
        val floor = if (form) bodyStart else request.indexOf(' ') + 1
        var at = point.offset
        while (at > floor && request[at - 1] != '&' && (form || request[at - 1] != '?')) at--
        return at
    }

    private fun rewrite(edits: List<Edit>): String {
        val out = StringBuilder(request.length + 64)
        var cursor = 0
        for ((start, end, text) in edits.sortedBy { it.start }) {
            if (start < cursor) continue
            out.append(request, cursor, start).append(text)
            cursor = end
        }
        out.append(request, cursor, request.length)
        val text = out.toString()
        // One charset for the Content-Length count and the bytes the bridge sends.
        return RequestHygiene.fixContentLength(text, utf8Body = RequestHygiene.wireCharset(text) == Charsets.UTF_8).request
    }

    companion object {
        const val MARKER = "FUZZ"

        private const val HEX = "0123456789ABCDEF"

        /** Characters left as typed in a query or form value; everything else is percent-encoded. */
        private const val QUERY_SAFE = "-._~!$'()*,/:@"

        /** As [QUERY_SAFE] plus the delimiters that are plain data in a path segment. */
        private const val PATH_SAFE = "-._~!$&'()*+,;=:@/"

        /** Bodies longer than this are not sniffed for a form shape when no content type says so. */
        private const val MAX_SNIFF = 65_536

        private val CONTENT_TYPE = Regex("(?im)^Content-Type[ \\t]*:[ \\t]*([^\\r\\n]*)")
        private val XML_ROOT = Regex("<([A-Za-z_][A-Za-z0-9_.:-]*)")
        private val JSON_NUMBER = Regex("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?")

        fun parse(normalizedRequest: String): FuzzTemplate {
            val headerEnd = normalizedRequest.indexOf("\r\n\r\n")
            val bodyStart = if (headerEnd >= 0) headerEnd + 4 else -1
            val lineEnd = normalizedRequest.indexOf("\r\n").let { if (it < 0) normalizedRequest.length else it }
            val headEnd = if (bodyStart >= 0) bodyStart else normalizedRequest.length
            val body = if (bodyStart >= 0) bodyKind(normalizedRequest, headerEnd, bodyStart) else BodyKind.OPAQUE
            val points = ArrayList<Point>()
            var at = normalizedRequest.indexOf(MARKER)
            while (at >= 0) {
                val context = when {
                    at < lineEnd -> requestLineContext(normalizedRequest, lineEnd, at)
                    at < headEnd -> headerContext(normalizedRequest, at)
                    else -> bodyContext(normalizedRequest, bodyStart, at, body)
                }
                points += Point(at, context)
                at = normalizedRequest.indexOf(MARKER, at + MARKER.length)
            }
            return FuzzTemplate(normalizedRequest, points, bodyStart)
        }

        private fun requestLineContext(request: String, lineEnd: Int, at: Int): FuzzContext {
            val targetStart = request.indexOf(' ') + 1
            if (targetStart !in 1..lineEnd || at < targetStart) return FuzzContext.RAW
            val lastSpace = request.lastIndexOf(' ', lineEnd - 1)
            val targetEnd = if (lastSpace >= targetStart && request.startsWith("HTTP/", lastSpace + 1)) lastSpace else lineEnd
            if (at >= targetEnd) return FuzzContext.RAW
            val query = request.indexOf('?', targetStart)
            return if (query in 0 until at) FuzzContext.URL_QUERY else FuzzContext.URL_PATH
        }

        private fun headerContext(request: String, at: Int): FuzzContext {
            val lineStart = request.lastIndexOf("\r\n", at).let { if (it < 0) 0 else it + 2 }
            val colon = request.indexOf(':', lineStart)
            val name = if (colon in lineStart until at) request.substring(lineStart, colon).trim() else ""
            return if (name.equals("Cookie", ignoreCase = true)) FuzzContext.COOKIE else FuzzContext.HEADER
        }

        private fun bodyKind(request: String, headerEnd: Int, bodyStart: Int): BodyKind {
            val contentType = CONTENT_TYPE.find(request.substring(0, headerEnd))?.groupValues?.get(1)?.lowercase().orEmpty()
            return when {
                "json" in contentType -> BodyKind.JSON
                "x-www-form-urlencoded" in contentType -> BodyKind.FORM
                "multipart/" in contentType -> BodyKind.OPAQUE
                "xml" in contentType -> BodyKind.XML
                else -> sniff(request.substring(bodyStart).trim())
            }
        }

        /** Body kind by shape, for a request whose Content-Type is missing or says nothing useful. */
        private fun sniff(body: String): BodyKind = when {
            body.startsWith("{") || body.startsWith("[") -> BodyKind.JSON
            body.startsWith("<") -> BodyKind.XML
            body.length <= MAX_SNIFF && body.none { it.isWhitespace() } && body.substringBefore('&').indexOf('=') > 0 -> BodyKind.FORM
            else -> BodyKind.OPAQUE
        }

        private fun bodyContext(request: String, bodyStart: Int, at: Int, kind: BodyKind): FuzzContext = when (kind) {
            BodyKind.JSON -> if (insideJsonString(request, bodyStart, at)) FuzzContext.JSON_STRING else FuzzContext.JSON_VALUE
            BodyKind.FORM -> FuzzContext.FORM
            BodyKind.XML -> FuzzContext.XML
            BodyKind.OPAQUE -> FuzzContext.RAW
        }

        private fun insideJsonString(request: String, from: Int, to: Int): Boolean {
            var inString = false
            var escaped = false
            for (i in from until to) {
                val ch = request[i]
                when {
                    escaped -> escaped = false
                    ch == '\\' -> escaped = true
                    ch == '"' -> inString = !inString
                }
            }
            return inString
        }

        private fun encode(payload: String, context: FuzzContext, encoding: PayloadEncoding): String = when (encoding) {
            PayloadEncoding.RAW -> payload
            PayloadEncoding.URL -> percentEncode(payload, QUERY_SAFE)
            PayloadEncoding.JSON -> jsonEscape(payload)
            PayloadEncoding.XML -> xmlEscape(payload)
            PayloadEncoding.AUTO -> when (context) {
                FuzzContext.URL_PATH -> percentEncode(payload, PATH_SAFE)
                FuzzContext.URL_QUERY, FuzzContext.FORM -> percentEncode(payload, QUERY_SAFE)
                FuzzContext.JSON_STRING -> jsonEscape(payload)
                FuzzContext.JSON_VALUE -> if (isJsonValue(payload)) payload else "\"" + jsonEscape(payload) + "\""
                FuzzContext.XML -> xmlEscape(payload)
                FuzzContext.COOKIE -> headerSafe(payload, cookie = true)
                FuzzContext.HEADER -> headerSafe(payload, cookie = false)
                FuzzContext.RAW -> payload
            }
        }

        /** Percent-encodes every UTF-8 byte outside ASCII alphanumerics and [safe], keeping existing `%XX` sequences. */
        private fun percentEncode(payload: String, safe: String): String {
            val out = StringBuilder(payload.length + 16)
            var i = 0
            while (i < payload.length) {
                val ch = payload[i]
                if (ch in 'a'..'z' || ch in 'A'..'Z' || ch in '0'..'9' || safe.indexOf(ch) >= 0) {
                    out.append(ch)
                    i++
                } else if (ch == '%' && i + 2 < payload.length && isHexDigit(payload[i + 1]) && isHexDigit(payload[i + 2])) {
                    out.append(payload, i, i + 3)
                    i += 3
                } else {
                    val width = Character.charCount(payload.codePointAt(i))
                    for (byte in payload.substring(i, i + width).toByteArray(Charsets.UTF_8)) {
                        val value = byte.toInt() and 0xFF
                        out.append('%').append(HEX[value shr 4]).append(HEX[value and 0x0F])
                    }
                    i += width
                }
            }
            return out.toString()
        }

        private fun isHexDigit(ch: Char): Boolean = ch in '0'..'9' || ch in 'a'..'f' || ch in 'A'..'F'

        private fun jsonEscape(payload: String): String = buildString(payload.length + 8) {
            for (ch in payload) {
                when {
                    ch == '\\' -> append("\\\\")
                    ch == '"' -> append("\\\"")
                    ch == '\n' -> append("\\n")
                    ch == '\r' -> append("\\r")
                    ch == '\t' -> append("\\t")
                    ch.code < 0x20 -> append("\\u00").append(HEX[ch.code shr 4]).append(HEX[ch.code and 0x0F])
                    else -> append(ch)
                }
            }
        }

        /** True when [payload] can stand as a JSON value without quoting (number, literal, or a valid document). */
        private fun isJsonValue(payload: String): Boolean {
            val text = payload.trim()
            if (text == "true" || text == "false" || text == "null" || JSON_NUMBER.matches(text)) return true
            if (text.isEmpty() || (text[0] != '{' && text[0] != '[' && text[0] != '"')) return false
            return try {
                Json.parseToJsonElement(text)
                true
            } catch (_: Exception) {
                false
            }
        }

        private fun xmlEscape(payload: String): String = buildString(payload.length + 16) {
            for (ch in payload) {
                when (ch) {
                    '&' -> append("&amp;")
                    '<' -> append("&lt;")
                    '>' -> append("&gt;")
                    '"' -> append("&quot;")
                    '\'' -> append("&apos;")
                    else -> append(ch)
                }
            }
        }

        /** Keeps a payload on its header line: CR/LF are percent-encoded, and `;` too inside a cookie value. */
        private fun headerSafe(payload: String, cookie: Boolean): String = buildString(payload.length + 8) {
            for (ch in payload) {
                when {
                    ch == '\r' -> append("%0D")
                    ch == '\n' -> append("%0A")
                    cookie && ch == ';' -> append("%3B")
                    else -> append(ch)
                }
            }
        }
    }
}
