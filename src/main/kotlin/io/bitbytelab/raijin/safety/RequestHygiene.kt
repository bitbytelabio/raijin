package io.bitbytelab.raijin.safety

import java.nio.charset.Charset

/**
 * Input hygiene for `http_send_request`-style tools (GitHub issue #7).
 *
 * A raw CR/LF in a structured input (method, url, header) — commonly a stray newline emitted by an
 * LLM — reaches the HTTP/2 `:path` pseudo-header or splits a header, so Burp flags the request as
 * **"kettled"** and the server rejects it (`RST_STREAM` PROTOCOL_ERROR). [stripCrlf] removes those
 * two chars, and only those, before the request is built (the actual fix), and [scan] reports what was cleaned so
 * the agent can self-correct.
 *
 * Only the STRUCTURED build path is sanitized. `raw_request` only gets its header block's line endings
 * canonicalized ([normalizeCrlf]) and `http_send_raw_bytes` / `http_send_pipeline` stay byte-exact, so
 * intentional CRLF (request-smuggling / header-injection research) remains possible. Pure + tested.
 */
object RequestHygiene {

    /**
     * Removes raw CR and LF from [s], and nothing else: a stray newline in an LLM-supplied
     * url/method/header would otherwise land in the HTTP/2 `:path` or split a header and get the
     * request kettled / `RST_STREAM`'d. Every other byte (NUL, VT, other C0 chars) reaches the wire.
     */
    fun stripCrlf(s: String): String {
        if (s.indexOf('\r') < 0 && s.indexOf('\n') < 0) return s   // clean → no allocation
        return buildString(s.length) { for (ch in s) if (ch != '\r' && ch != '\n') append(ch) }
    }

    private val REAL_HEADER_END = Regex("\\r?\\n\\r?\\n")
    private val ESCAPED_HEADER_END = Regex("""(?:\\r\\n|\\n)(?:\\r\\n|\\n)""")
    private val BARE_LF = Regex("(?<!\\r)\\n")

    /**
     * Canonicalizes the line endings of a raw HTTP message's request/status line and header
     * block to CRLF so Montoya's strict parser delimits them (issue #7, request-line variant seen
     * in `repeater_send` / `intruder_send` / `organizer_send` / `sitemap_add_request` /
     * `analyze_insertion_points`). A bare-LF request never splits the request line from the
     * headers, so the remainder folds into the HTTP/2 `:path` and Burp flags it **"kettled"**.
     *
     * Only the header block is touched: everything after the first blank line (`\r\n\r\n`,
     * `\n\n`, ...) is kept byte for byte, so a JSON body's `\n` escapes, a body's own line
     * endings and its Content-Length all survive. A message with no real line break at all
     * (escaped "\r\n" / "\n" sequences that survived JSON transport) has its header block
     * unescaped the same way, again leaving the body as typed. An already-CRLF message is
     * returned unchanged.
     */
    fun normalizeCrlf(raw: String): String {
        if (raw.contains('\n')) {
            val sep = REAL_HEADER_END.find(raw)
            return if (sep != null) {
                val end = sep.range.last + 1
                val headers = raw.substring(0, end).replace(BARE_LF, "\r\n")
                headers + raw.substring(end)
            } else {
                raw.replace(BARE_LF, "\r\n")
            }
        }
        // Single-line string (possibly JSON-escaped): unescape line endings only in the header
        // section (or the whole string if no header-body separator is present) so JSON escapes
        // like \n inside the body are preserved intact.
        val escSep = ESCAPED_HEADER_END.find(raw)
        return if (escSep != null) {
            val end = escSep.range.last + 1
            val headers = raw.substring(0, end)
                .replace("\\r\\n", "\r\n")
                .replace("\\n", "\n")
                .replace(BARE_LF, "\r\n")
            headers + raw.substring(end)
        } else {
            raw.replace("\\r\\n", "\r\n")
                .replace("\\n", "\n")
                .replace(BARE_LF, "\r\n")
        }
    }

    /**
     * Maps a byte offset in [raw] to its position after [normalizeCrlf], so Intruder
     * payload positions stay aligned when bare-LF endings expand to CRLF. Because the
     * normalization is a left-to-right rewrite, the normalized length of the prefix up
     * to [offset] is that offset's new position. A no-op (returns [offset]) when the
     * request is already CRLF.
     */
    fun adjustedOffset(raw: String, offset: Int): Int =
        normalizeCrlf(raw.substring(0, offset.coerceIn(0, raw.length))).length

    data class ContentLengthFix(
        val request: String,
        val rewrittenFrom: Int? = null,
        val rewrittenTo: Int? = null
    )

    private val CONTENT_LENGTH_REGEX = Regex("(?im)^Content-Length:[ \\t]*(\\d+)[ \\t]*$")
    private val CONTENT_LENGTH_LINE_REGEX = Regex("(?im)^[^\\S\\r\\n]*Content-Length[^\\r\\n:]*:")
    private val TRANSFER_ENCODING_LINE_REGEX = Regex("(?im)^[^\\S\\r\\n]*Transfer-Encoding[^\\r\\n:]*:")

    /**
     * Recomputes the Content-Length header on a raw HTTP request to match the actual
     * body size in bytes ([Charsets.UTF_8] when [utf8Body] is true, else [Charsets.ISO_8859_1];
     * pass the charset the request is sent with, see [wireCharset]). Only the digits change.
     * Returns the original request unchanged if there is no body section, no Content-Length
     * header, multiple Content-Length headers (CL.CL smuggling), or any Transfer-Encoding header
     * (CL.TE / TE.CL smuggling), so deliberate desync payloads are never silently altered.
     */
    fun fixContentLength(rawRequest: String, utf8Body: Boolean = false): ContentLengthFix {
        val boundary = rawRequest.indexOf("\r\n\r\n")
        if (boundary < 0) return ContentLengthFix(rawRequest)

        val headerSection = rawRequest.substring(0, boundary)
        val bodySection = rawRequest.substring(boundary + 4)

        // Preserve deliberate desync/smuggling headers (CL.TE, TE.CL, CL.CL, obfuscated CL).
        if (TRANSFER_ENCODING_LINE_REGEX.containsMatchIn(headerSection)) return ContentLengthFix(rawRequest)
        if (CONTENT_LENGTH_LINE_REGEX.findAll(headerSection).count() != 1) return ContentLengthFix(rawRequest)

        val clMatch = CONTENT_LENGTH_REGEX.find(headerSection) ?: return ContentLengthFix(rawRequest)
        val digits = clMatch.groups[1] ?: return ContentLengthFix(rawRequest)
        val declaredLength = digits.value.toIntOrNull() ?: return ContentLengthFix(rawRequest)
        val charset = if (utf8Body) Charsets.UTF_8 else Charsets.ISO_8859_1
        val actualLength = bodySection.toByteArray(charset).size
        if (declaredLength == actualLength) return ContentLengthFix(rawRequest)

        val fixedHeader = headerSection.replaceRange(digits.range, actualLength.toString())
        return ContentLengthFix("$fixedHeader\r\n\r\n$bodySection", declaredLength, actualLength)
    }

    /**
     * Charset request text goes on the wire with. ISO-8859-1 sends every char up to U+00FF as
     * exactly that byte (how Burp holds raw bytes in a String); a char above U+00FF has no
     * single-byte form, so the whole message is then sent as UTF-8. Content-Length must be
     * counted in the same charset.
     */
    fun wireCharset(text: CharSequence): Charset =
        if (text.any { it.code > 0xFF }) Charsets.UTF_8 else Charsets.ISO_8859_1

    /**
     * Decodes literal `\r\n` / `\n` escapes into real line breaks for the byte-level tools
     * (`http_send_raw_bytes`, `http_send_pipeline`), throughout the message so a smuggled request
     * in the body gets its CRLFs too. Only a message without any real CR or LF is decoded: once
     * the text has real line breaks the caller writes real line endings, so every character stays
     * as typed (a JSON body's `\n` escape stays two characters). Never turns LF into CRLF.
     */
    fun unescapeLineEndings(raw: String): String =
        if (raw.indexOf('\n') >= 0 || raw.indexOf('\r') >= 0) raw
        else raw.replace("\\r\\n", "\r\n").replace("\\n", "\n")

    /**
     * Decodes hex-encoded bytes (`474554 202f`; whitespace between digits is ignored).
     * @throws IllegalArgumentException naming the problem for an odd digit count or a non-hex character.
     */
    fun decodeHex(hex: String): ByteArray {
        val digits = hex.filterNot { it.isWhitespace() }
        require(digits.length % 2 == 0) { "hex input has an odd number of digits (${digits.length}); every byte needs two" }
        return ByteArray(digits.length / 2) { i ->
            val hi = hexDigit(digits[2 * i])
            val lo = hexDigit(digits[2 * i + 1])
            require(hi >= 0 && lo >= 0) { "hex input has a non-hex character in byte $i ('${digits.substring(2 * i, 2 * i + 2)}')" }
            ((hi shl 4) or lo).toByte()
        }
    }

    private fun hexDigit(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> -1
    }

    /** Advisory: reports raw CR/LF found (and removed by [stripCrlf]) so the agent notices; no other byte is touched. */
    fun scan(method: String?, url: String?, headers: Map<String, String>?): List<String> {
        val out = mutableListOf<String>()

        if (method != null && HeaderSafety.containsCrlf(method)) {
            out += "a raw CR/LF was removed from the request method before sending."
        }
        if (url != null && HeaderSafety.containsCrlf(url)) {
            out += "a raw newline was removed from the url before sending — it would otherwise reach " +
                "the HTTP/2 :path and get the request kettled/rejected. Percent-encode it (%0A) if intended."
        }
        headers?.forEach { (name, value) ->
            if (HeaderSafety.containsCrlf(name)) {
                out += "a raw CR/LF was removed from a request header name before sending."
            }
            if (HeaderSafety.containsCrlf(value)) {
                out += "a raw newline was removed from header \"$name\" before sending — it would " +
                    "otherwise kettle the request or split headers. Percent-encode it (%0A) if intended."
            }
        }
        return out
    }
}
