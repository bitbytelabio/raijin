package io.bitbytelab.raijin.recon

import io.bitbytelab.raijin.safety.RequestHygiene
import kotlin.random.Random

/**
 * A request as it is written to the wire: origin-form [target] (path and query), ordered
 * [headers], [body]. The recon and web-probe engines plan their probes as these plain values, so
 * what each probe sends can be read (and tested) before anything reaches Burp.
 */
data class ProbeRequest(
    val method: String,
    val target: String,
    val headers: List<Pair<String, String>>,
    val body: String = "",
) {
    /** Path part of [target], without the query string. */
    val path: String get() = target.substringBefore('?')

    /** Query string of [target] without the `?`, or null when there is none. */
    val query: String? get() = target.indexOf('?').let { if (it < 0) null else target.substring(it + 1) }

    fun header(name: String): String? = headers.firstOrNull { it.first.equals(name, ignoreCase = true) }?.second

    /** Sets header [name]: the first header of that name (any case) is replaced in place, further ones dropped. */
    fun withHeader(name: String, value: String): ProbeRequest {
        val out = ArrayList<Pair<String, String>>(headers.size + 1)
        var placed = false
        for (header in headers) {
            if (!header.first.equals(name, ignoreCase = true)) {
                out.add(header)
            } else if (!placed) {
                out.add(name to value)
                placed = true
            }
        }
        if (!placed) out.add(name to value)
        return copy(headers = out)
    }

    fun withHeaders(pairs: Iterable<Pair<String, String>>): ProbeRequest =
        pairs.fold(this) { request, (name, value) -> request.withHeader(name, value) }

    fun withoutHeader(name: String): ProbeRequest =
        copy(headers = headers.filterNot { it.first.equals(name, ignoreCase = true) })

    /** Replaces the body; a Content-Length written for the old one is dropped so [render] counts again. */
    fun withBody(body: String): ProbeRequest = withoutHeader("Content-Length").copy(body = body)

    /** Appends [pairs] (`name=value`, already encoded) to the query string. */
    fun withQuery(pairs: String): ProbeRequest =
        if (pairs.isEmpty()) this else copy(target = target + (if (target.contains('?')) "&" else "?") + pairs)

    /** Replaces the path, keeping the query string. */
    fun withPath(path: String): ProbeRequest = copy(target = path + (query?.let { "?$it" } ?: ""))

    /** Adds [pairs] (`name=value`) to the Cookie header, after any cookies already there. */
    fun withCookies(pairs: String): ProbeRequest {
        if (pairs.isEmpty()) return this
        val existing = header("Cookie")?.trim()?.trimEnd(';').orEmpty()
        return withHeader("Cookie", if (existing.isEmpty()) pairs else "$existing; $pairs")
    }

    /**
     * The request as HTTP/1.1 text. Content-Length is added when the request has a body (or a
     * method that takes one) and declares neither Content-Length nor Transfer-Encoding; every
     * header is otherwise written exactly as it is, so an odd one reaches the wire as given.
     */
    fun render(): String {
        val head = StringBuilder(256 + body.length)
        head.append(method).append(' ').append(target).append(" HTTP/1.1\r\n")
        for ((name, value) in headers) head.append(name).append(": ").append(value).append("\r\n")
        val declaresLength = headers.any {
            it.first.equals("Content-Length", ignoreCase = true) || it.first.equals("Transfer-Encoding", ignoreCase = true)
        }
        if (!declaresLength && (body.isNotEmpty() || method.uppercase() in BODY_METHODS)) {
            // Counted in the charset the whole message is sent with (RequestHygiene.wireCharset).
            val charset = if (RequestHygiene.wireCharset(head) == Charsets.UTF_8) Charsets.UTF_8 else RequestHygiene.wireCharset(body)
            head.append("Content-Length: ").append(body.toByteArray(charset).size).append("\r\n")
        }
        return head.append("\r\n").append(body).toString()
    }

    private companion object {
        val BODY_METHODS = setOf("POST", "PUT", "PATCH")
    }
}

/** The pieces of an absolute http(s) URL, split as text so an unusual path or query stays as typed. */
data class UrlParts(val scheme: String, val host: String, val port: Int?, val path: String, val query: String?) {
    val secure: Boolean get() = scheme == "https"

    /** `scheme://host[:port]`, the port only when the URL names one. */
    val origin: String get() = "$scheme://$host" + (port?.let { ":$it" } ?: "")

    /** Directory of the path, ending in `/`. */
    val directory: String get() = path.substring(0, path.lastIndexOf('/') + 1)

    companion object {
        fun parse(url: String): UrlParts? {
            val text = url.trim()
            val schemeEnd = text.indexOf("://")
            if (schemeEnd <= 0) return null
            val scheme = text.substring(0, schemeEnd).lowercase()
            if (scheme != "http" && scheme != "https") return null
            val rest = text.substring(schemeEnd + 3).substringBefore('#')
            val authorityEnd = rest.indexOfFirst { it == '/' || it == '?' }.let { if (it < 0) rest.length else it }
            val authority = rest.substring(0, authorityEnd).substringAfterLast('@')
            // An IPv6 literal keeps its brackets; a port is whatever follows the last colon outside them.
            val portSep = authority.lastIndexOf(':').takeIf { it > authority.lastIndexOf(']') }
            val host = (if (portSep == null) authority else authority.substring(0, portSep)).lowercase()
            if (host.isEmpty()) return null
            val port = if (portSep == null) null else authority.substring(portSep + 1).toIntOrNull() ?: return null
            val tail = rest.substring(authorityEnd)
            val queryStart = tail.indexOf('?')
            val path = (if (queryStart < 0) tail else tail.substring(0, queryStart)).ifEmpty { "/" }
            return UrlParts(scheme, host, port, path, if (queryStart < 0) null else tail.substring(queryStart + 1))
        }
    }
}

/** Text helpers shared by the probe engines. */
object ProbeText {
    private const val TOKEN_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"

    /** A random lower-case token of [length] characters, starting with a letter. */
    fun token(random: Random, length: Int): String = buildString(length) {
        append(TOKEN_ALPHABET[random.nextInt(26)])
        repeat(length - 1) { append(TOKEN_ALPHABET[random.nextInt(TOKEN_ALPHABET.length)]) }
    }

    /**
     * Percent-encodes what would break a `name=value` pair apart or change its meaning on the
     * way: space, `&`, `=`, `#`, `+`, `;`, control characters and non-ASCII. Everything else,
     * `%` included, is left as typed, so an already-encoded or deliberately odd name stays so.
     */
    fun encodePairPart(text: String): String {
        if (text.all { it.code in 0x21..0x7E && it !in PAIR_BREAKERS }) return text
        val out = StringBuilder(text.length + 8)
        for (byte in text.toByteArray(Charsets.UTF_8)) {
            val code = byte.toInt() and 0xFF
            if (code in 0x21..0x7E && code.toChar() !in PAIR_BREAKERS) {
                out.append(code.toChar())
            } else {
                out.append('%').append(HEX[code shr 4]).append(HEX[code and 0x0F])
            }
        }
        return out.toString()
    }

    /** `name=value` pairs joined by [separator], each part encoded by [encodePairPart]. */
    fun pairs(params: List<Pair<String, String>>, separator: String): String =
        params.joinToString(separator) { (name, value) -> encodePairPart(name) + "=" + encodePairPart(value) }

    private const val PAIR_BREAKERS = "&=#+;"
    private const val HEX = "0123456789ABCDEF"
}
