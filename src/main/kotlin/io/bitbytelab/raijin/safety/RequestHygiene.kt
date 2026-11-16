package io.bitbytelab.raijin.safety

/**
 * Input hygiene for `http_send_request`-style tools (GitHub issue #7).
 *
 * A raw CR/LF in a structured input (method, url, header) — commonly a stray newline emitted by an
 * LLM — reaches the HTTP/2 `:path` pseudo-header or splits a header, so Burp flags the request as
 * **"kettled"** and the server rejects it (`RST_STREAM` PROTOCOL_ERROR). [stripControl] removes those
 * control chars before the request is built (the actual fix), and [scan] reports what was cleaned so
 * the agent can self-correct.
 *
 * Only the STRUCTURED build path is sanitized; `raw_request` / `http_send_raw_bytes` stay verbatim so
 * intentional CRLF (request-smuggling / header-injection research) remains possible. Pure + tested.
 */
object RequestHygiene {

    /**
     * Removes raw CR/LF and other C0 control chars (tab excepted) from [s]. A stray newline in an
     * LLM-supplied url/method/header would otherwise land in the HTTP/2 `:path` or split a header and
     * get the request kettled / `RST_STREAM`'d. Keeps everything printable (code >= 32) plus tab.
     */
    fun stripControl(s: String): String {
        if (s.none { it != '\t' && it.code < 32 }) return s   // clean → no allocation
        return buildString(s.length) { for (ch in s) if (ch == '\t' || ch.code >= 32) append(ch) }
    }

    /**
     * Canonicalizes a raw HTTP message's line endings to CRLF so Montoya's strict
     * parser delimits the request line and headers correctly (issue #7, request-line
     * variant seen in `repeater_send` / `intruder_send` / `organizer_send` /
     * `sitemap_add_request` / `analyze_insertion_points`).
     *
     * Callers (and LLMs) frequently supply requests with bare-LF endings, or with the
     * escaped "\r\n" / "\n" sequences that survive JSON transport.
     * `HttpRequest.httpRequest(service, string)` is strict about CRLF: a bare-LF
     * request never splits the request line from the headers, so the whole remainder
     * folds into the HTTP/2 `:path` pseudo-header and Burp flags the request as
     * **"kettled"** ("There is a newline in this header's value: :path"). Normalizing
     * to CRLF up front is what makes such a request valid.
     *
     * Unlike [stripControl] this only fixes delimiters (it preserves content), so it is
     * safe on the "send this request into Burp" paths and leaves an already-CRLF
     * request byte-identical. Byte-exact tools (`http_send_raw_bytes` / `raw_request`)
     * still bypass it so intentional smuggling bytes are untouched.
     */
    private val REAL_HEADER_END = Regex("\\r?\\n\\r?\\n")
    private val ESCAPED_HEADER_END = Regex("""(?:\\r\\n|\\n)(?:\\r\\n|\\n)""")
    private val BARE_LF = Regex("(?<!\\r)\\n")

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

    private val CONTENT_LENGTH_REGEX = Regex("(?im)^Content-Length:\\s*(\\d+)\\s*$")
    private val CONTENT_LENGTH_LINE_REGEX = Regex("(?im)^[^\\S\\r\\n]*Content-Length[^\\r\\n:]*:")
    private val TRANSFER_ENCODING_LINE_REGEX = Regex("(?im)^[^\\S\\r\\n]*Transfer-Encoding[^\\r\\n:]*:")

    /**
     * Recomputes the Content-Length header on a raw HTTP request to match the actual
     * body size in bytes ([Charsets.UTF_8] when [utf8Body] is true, else [Charsets.ISO_8859_1]).
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
        val declaredLength = clMatch.groupValues[1].toIntOrNull() ?: return ContentLengthFix(rawRequest)
        val charset = if (utf8Body) Charsets.UTF_8 else Charsets.ISO_8859_1
        val actualLength = bodySection.toByteArray(charset).size
        if (declaredLength == actualLength) return ContentLengthFix(rawRequest)

        val fixedHeader = CONTENT_LENGTH_REGEX.replaceFirst(headerSection, "Content-Length: $actualLength")
        return ContentLengthFix("$fixedHeader\r\n\r\n$bodySection", declaredLength, actualLength)
    }

    /** Advisory: reports raw CR/LF found (and removed by [stripControl]) so the agent notices. */
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
