package io.bitbytelab.raijin.bridge

import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import io.bitbytelab.raijin.core.asBodyString
import io.bitbytelab.raijin.core.asBooleanSafe
import io.bitbytelab.raijin.core.asHeaders
import io.bitbytelab.raijin.safety.RequestHygiene
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * Builds the Montoya requests the HTTP tools send: from raw request text, from a URL with
 * structured headers and body, or as a native HTTP/2 request whose header list (pseudo-headers
 * included) is sent as given.
 */
internal object HttpRequestBuilder {

    private val HEADER_BLOCK_END = Regex("\\r?\\n\\r?\\n")

    /** The build error of a request object with neither target. */
    const val MISSING_TARGET = "Either 'url' or 'raw_request' must be provided"

    /** Start of the build error of a URL without scheme and host. */
    const val URL_NOT_ABSOLUTE = "url must be absolute"

    private val SCHEME = Regex("^[A-Za-z][A-Za-z0-9+.-]*://")

    /** Whether [url] starts with `scheme://`. */
    fun hasScheme(url: String): Boolean = SCHEME.containsMatchIn(url.trim())

    /**
     * [url] with `https://` and with `http://`, for a URL written without a scheme (`example.com`,
     * `//example.com`); empty for a path (`/admin`), which names no host to guess, and for text
     * that would not parse as a URL with a host (`not a url`), so no guess fails again.
     */
    fun schemeGuesses(url: String): List<String> {
        val t = url.trim()
        if (t.isEmpty() || (t.startsWith('/') && !t.startsWith("//"))) return emptyList()
        if (t.any { it.isWhitespace() || it.isISOControl() }) return emptyList()
        val rest = t.trimStart('/')
        val host = runCatching { java.net.URI("https://$rest").host }.getOrNull()
        if (host.isNullOrBlank()) return emptyList()
        return listOf("https://$rest", "http://$rest")
    }

    /**
     * Builds a request from either [rawRequest] or [url] plus structured parts.
     *
     * - Raw CR/LF, and only CR/LF, is stripped from the structured inputs (url, method, header
     *   names and values): a stray newline from an LLM would otherwise reach the HTTP/2 `:path` or
     *   split a header and get the request kettled (issue #7). [RequestHygiene.scan] reports what
     *   was removed. Every other byte is sent as given. Raw request text and the byte-level tools
     *   keep their CR/LF.
     * - [rawRequest] gets its header block's line endings canonicalized and, unless
     *   [autoFixContentLength] is false, its Content-Length recomputed (recorded in [fixReport]).
     *   Its target is [url]'s scheme and authority when a url is given too, else the Host header;
     *   explicit [host] / [port] / [useTls] win, and without port information it defaults to TLS on
     *   443 (80 when [useTls] is false). [headers] are applied on top of it.
     * - [url] is split leniently ([splitUrl]): the request target is sent exactly as written, and
     *   the Host header is the URL's authority; [host] / [port] only change where the connection
     *   goes.
     * - [url] with [preserveHeaders] (default) builds the complete request text with the caller's
     *   headers byte-exact, so Burp's default User-Agent/Accept/... are not injected; with
     *   [preserveHeaders] false Burp's `httpRequestFromUrl` defaults are kept and [headers] layered
     *   on.
     */
    fun build(
        url: String?,
        method: String?,
        headers: Map<String, String>?,
        body: String?,
        rawRequest: String?,
        host: String?,
        port: Int?,
        useTls: Boolean?,
        preserveHeaders: Boolean = true,
        autoFixContentLength: Boolean = true,
        fixReport: MutableMap<String, JsonElement>? = null,
    ): HttpRequest {
        val cUrl = url?.let { RequestHygiene.stripCrlf(it) }
        val cMethod = method?.let { RequestHygiene.stripCrlf(it) }
        val cHeaders =
            headers?.entries?.associate {
                RequestHygiene.stripCrlf(it.key) to RequestHygiene.stripCrlf(it.value)
            }

        var request: HttpRequest =
            when {
                rawRequest != null ->
                    fromRawRequest(
                        rawRequest,
                        cUrl,
                        host,
                        port,
                        useTls,
                        autoFixContentLength,
                        fixReport,
                    )
                cUrl != null && preserveHeaders ->
                    fromUrlPreservingHeaders(
                        cUrl,
                        cMethod,
                        cHeaders.orEmpty(),
                        body,
                        host,
                        port,
                        useTls,
                    )
                cUrl != null -> fromUrlMontoya(cUrl, cMethod, cHeaders, body, host, port, useTls)
                else -> throw IllegalArgumentException(MISSING_TARGET)
            }

        // For raw_request: extra (sanitized) header overrides via the headers map.
        if (rawRequest != null) {
            cHeaders?.forEach { (name, value) -> request = request.withHeader(name, value) }
        }
        return request
    }

    /** Fields of http_send_request that a batch item or chain step cannot carry. */
    val UNSUPPORTED_ITEM_FIELDS =
        listOf("http2_headers", "follow_redirects", "sni", "verify_tls", "response_timeout_ms")

    /**
     * Builds a request from a request object as `http_send_requests_parallel` items and
     * `http_send_request_chain` steps carry it: `raw_request`, or `url` / `method` / `headers` /
     * `body`, plus optional `host` / `port` / `use_tls`, `auto_fix_content_length` and
     * `preserve_headers` (both default true). [fixReport] receives the item's
     * `content_length_rewritten`, `headers_warning` and hygiene `warnings`.
     *
     * @throws IllegalArgumentException for a field only http_send_request supports
     *   ([UNSUPPORTED_ITEM_FIELDS]).
     */
    fun fromObject(
        obj: JsonObject,
        fixReport: MutableMap<String, JsonElement>? = null,
    ): HttpRequest {
        UNSUPPORTED_ITEM_FIELDS.firstOrNull { obj[it] != null && obj[it] !is JsonNull }
            ?.let {
                throw IllegalArgumentException(
                    "$it is not supported per item here; use http_send_request",
                )
            }
        val url = obj["url"]?.jsonPrimitive?.contentOrNull
        val method = obj["method"]?.jsonPrimitive?.contentOrNull
        val parsed = obj["headers"].asHeaders()
        require(parsed.unparsed == 0) {
            "'headers' could not be read (${parsed.warning}); pass {\"X-Foo\":\"bar\"} or [\"X-Foo: bar\"]"
        }
        val headers = parsed.map
        val headersWarning = parsed.warning
        if (fixReport != null) {
            headersWarning?.let { fixReport["headers_warning"] = JsonPrimitive(it) }
            val hygiene = RequestHygiene.scan(method, url, headers)
            if (hygiene.isNotEmpty())
                fixReport["warnings"] = JsonArray(hygiene.map { JsonPrimitive(it) })
        }
        return build(
            url = url,
            method = method,
            headers = headers,
            body = obj["body"].asBodyString(),
            rawRequest = obj["raw_request"]?.jsonPrimitive?.contentOrNull,
            host = obj["host"]?.jsonPrimitive?.contentOrNull,
            port = obj["port"]?.jsonPrimitive?.intOrNull,
            useTls = obj["use_tls"]?.jsonPrimitive?.booleanOrNull,
            preserveHeaders = obj["preserve_headers"].asBooleanSafe() ?: true,
            autoFixContentLength = obj["auto_fix_content_length"].asBooleanSafe() ?: true,
            fixReport = fixReport,
        )
    }

    /**
     * A native HTTP/2 request (Montoya `HttpRequest.http2Request`): [fields] are its header list,
     * pseudo-headers included, sent in the order given without any check, so a test can repeat,
     * reorder, omit or malform them. When [fields] holds no pseudo-header at all, `:method`,
     * `:scheme`, `:authority` and `:path` are derived from [url] / [method] / the target and put
     * first.
     *
     * The target is [host] / [port] / [useTls] when given, else the URL's, else the `:authority`
     * and `:scheme` fields'. The body is sent as given (no Content-Length is added: include a
     * `content-length` field to send one).
     */
    fun http2(
        url: String?,
        method: String?,
        fields: List<Pair<String, String>>,
        body: String?,
        host: String?,
        port: Int?,
        useTls: Boolean?,
    ): HttpRequest {
        val target = http2Target(url, host, port, useTls, fields)
        val list = http2Fields(url, method, target, fields)
        val service = HttpService.httpService(target.host, target.port, target.tls)
        val bytes = body?.let { it.toByteArray(RequestHygiene.wireCharset(it)) } ?: ByteArray(0)
        return HttpRequest.http2Request(
            service,
            list.map { (name, value) -> HttpHeader.httpHeader(name, value) },
            BurpByteArray.byteArray(*bytes),
        )
    }

    /** Where a native HTTP/2 request goes. */
    data class Target(val host: String, val port: Int, val tls: Boolean)

    /** See [http2]: explicit overrides, then the URL, then the `:authority` / `:scheme` fields. */
    fun http2Target(
        url: String?,
        host: String?,
        port: Int?,
        useTls: Boolean?,
        fields: List<Pair<String, String>>,
    ): Target {
        val parts = url?.let { splitUrl(it) }
        val urlHost = parts?.authority?.let { parseHostValue(it) }
        val fieldScheme = fields.firstOrNull { it.first == ":scheme" }?.second
        val authority =
            fields
                .firstOrNull { it.first == ":authority" }
                ?.second
                ?.let { parseHostValue(it.trim()) }
        val tls =
            useTls
                ?: parts?.scheme?.equals("https", ignoreCase = true)
                ?: fieldScheme?.let { !it.equals("http", ignoreCase = true) }
                ?: true
        val resolvedHost =
            host
                ?: urlHost?.first
                ?: authority?.first
                ?: throw IllegalArgumentException(
                    "An HTTP/2 request needs a target: give 'url', 'host', or an ':authority' field",
                )
        val resolvedPort =
            port
                ?: urlHost?.second
                ?: (if (host == null && urlHost == null) authority?.second else null)
                ?: if (tls) 443 else 80
        return Target(resolvedHost, resolvedPort, tls)
    }

    /**
     * The header list of a native HTTP/2 request; see [http2]. `:path` and `:authority` are the
     * URL's as written.
     */
    fun http2Fields(
        url: String?,
        method: String?,
        target: Target,
        fields: List<Pair<String, String>>,
    ): List<Pair<String, String>> {
        if (fields.any { it.first.startsWith(":") }) return fields
        val parts = url?.let { splitUrl(it) }
        val path = parts?.target ?: url?.takeIf { it.startsWith("/") } ?: "/"
        return listOf(
            ":method" to (method?.takeIf { it.isNotBlank() } ?: "GET"),
            ":scheme" to (if (target.tls) "https" else "http"),
            ":authority" to (parts?.authority?.ifEmpty { null } ?: authority(target)),
            ":path" to path,
        ) + fields
    }

    /** An absolute URL split without decoding or re-encoding anything; see [splitUrl]. */
    internal data class UrlParts(val scheme: String, val authority: String, val target: String)

    private val URL_SPLIT = Regex("^([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)([^#]*)")

    /**
     * Splits `scheme://authority/target` leniently: hosts with `_`, targets with spaces, `|`, `{`
     * or `<script>` all pass, byte for byte. The authority loses any `userinfo@`; an empty target
     * is `/` and a bare `?query` gets a leading `/`. Null when [url] is not absolute.
     */
    internal fun splitUrl(url: String): UrlParts? {
        val m = URL_SPLIT.find(url) ?: return null
        val authority = m.groupValues[2].substringAfterLast('@')
        val raw = m.groupValues[3]
        val target =
            when {
                raw.isEmpty() -> "/"
                raw.startsWith("?") -> "/$raw"
                else -> raw
            }
        return UrlParts(m.groupValues[1], authority, target)
    }

    private fun authority(target: Target): String {
        val literal =
            if (target.host.contains(':') && !target.host.startsWith("[")) "[${target.host}]"
            else target.host
        val defaultPort = (target.tls && target.port == 443) || (!target.tls && target.port == 80)
        return if (defaultPort) literal else "$literal:${target.port}"
    }

    /**
     * A raw request sent as written. Its target: [url]'s scheme and authority when given (explicit
     * overrides win), else the Host header, defaulting to TLS:443 (80 when [useTls] is false).
     */
    private fun fromRawRequest(
        rawRequest: String,
        url: String?,
        host: String?,
        port: Int?,
        useTls: Boolean?,
        autoFixContentLength: Boolean,
        fixReport: MutableMap<String, JsonElement>?,
    ): HttpRequest {
        // Bare-LF agent output would fold the whole message into the HTTP/2 :path (issue #7);
        // normalizing must come before the Content-Length fix, which keys on "\r\n\r\n".
        val normalized = RequestHygiene.normalizeCrlf(rawRequest)
        // One charset for the Content-Length count and the bytes on the wire.
        val charset = RequestHygiene.wireCharset(normalized)
        val cleaned =
            if (autoFixContentLength) {
                val fix =
                    RequestHygiene.fixContentLength(
                        normalized,
                        utf8Body = charset == Charsets.UTF_8,
                    )
                if (fix.rewrittenFrom != null && fixReport != null) {
                    fixReport["content_length_rewritten"] = buildJsonObject {
                        put("from", fix.rewrittenFrom)
                        put("to", fix.rewrittenTo)
                    }
                }
                fix.request
            } else {
                normalized
            }
        val bytes = BurpByteArray.byteArray(*cleaned.toByteArray(charset))

        if (url != null) {
            val (svcHost, svcPort, svcTls) = resolveService(url, host, port, useTls)
            return HttpRequest.httpRequest(HttpService.httpService(svcHost, svcPort, svcTls), bytes)
        }

        val hostMatch = parseHostHeader(cleaned)
        val resolvedHost = host ?: hostMatch?.first ?: return HttpRequest.httpRequest(bytes)
        val hostHeaderPort = if (host == null) hostMatch?.second else null

        // Modern web default: TLS:443 unless the caller says otherwise.
        val effectivePort = port ?: hostHeaderPort ?: if (useTls == false) 80 else 443
        val effectiveTls = useTls ?: (effectivePort != 80)
        return HttpRequest.httpRequest(
            HttpService.httpService(resolvedHost, effectivePort, effectiveTls),
            bytes,
        )
    }

    /** The complete request text built from the URL with the caller's headers byte-exact. */
    private fun fromUrlPreservingHeaders(
        url: String,
        method: String?,
        headers: Map<String, String>,
        body: String?,
        hostOverride: String?,
        portOverride: Int?,
        tlsOverride: Boolean?,
    ): HttpRequest {
        val (svcHost, svcPort, svcTls) =
            resolveService(url, hostOverride, portOverride, tlsOverride)
        val rawHttp =
            constructRawHttpRequest(url, method ?: "GET", headers, body, svcHost, svcPort, svcTls)
        val bytes =
            BurpByteArray.byteArray(*rawHttp.toByteArray(RequestHygiene.wireCharset(rawHttp)))
        return HttpRequest.httpRequest(HttpService.httpService(svcHost, svcPort, svcTls), bytes)
    }

    /** Burp's `httpRequestFromUrl` (with its default headers) and the caller's headers on top. */
    private fun fromUrlMontoya(
        url: String,
        method: String?,
        headers: Map<String, String>?,
        body: String?,
        hostOverride: String?,
        portOverride: Int?,
        tlsOverride: Boolean?,
    ): HttpRequest {
        var req = HttpRequest.httpRequestFromUrl(url)
        if (method != null) req = req.withMethod(method)
        if (body != null) req = req.withBody(body)
        headers?.forEach { (n, v) -> req = req.withHeader(n, v) }
        if (hostOverride != null || portOverride != null || tlsOverride != null) {
            // Same resolution as the preserve-headers path, so an override means the same on both;
            // Montoya's own URL parse supplies the host when java.net.URI cannot.
            val montoyaHost =
                try {
                    req.httpService()?.host()
                } catch (_: Exception) {
                    null
                }
            val (svcHost, svcPort, svcTls) =
                resolveService(url, hostOverride, portOverride, tlsOverride, montoyaHost)
            req = req.withService(HttpService.httpService(svcHost, svcPort, svcTls))
        }
        return req
    }

    /**
     * (host, port, tls) from a URL and optional overrides. Without a port override or an explicit
     * port in the URL, the port is the default for the resolved TLS setting.
     */
    private fun resolveService(
        url: String,
        hostOverride: String?,
        portOverride: Int?,
        tlsOverride: Boolean?,
        fallbackHost: String? = null,
    ): Triple<String, Int, Boolean> {
        val parts = splitUrl(url)
        val urlHost = parts?.authority?.let { parseHostValue(it) }
        val tls =
            tlsOverride
                ?: (parts?.scheme?.equals("https", ignoreCase = true)
                    ?: url.startsWith("https", ignoreCase = true))
        val host =
            hostOverride
                ?: urlHost?.first
                ?: fallbackHost
                ?: throw IllegalArgumentException("$URL_NOT_ABSOLUTE (scheme://host/path): $url")
        val port = portOverride ?: urlHost?.second ?: if (tls) 443 else 80
        return Triple(host, port, tls)
    }

    /**
     * Constructs a complete raw HTTP/1.1 request from structured parameters. Caller headers are
     * kept exactly; Host and Content-Length are only added when missing.
     */
    fun constructRawHttpRequest(
        url: String,
        method: String,
        headers: Map<String, String>,
        body: String?,
        host: String,
        port: Int,
        tls: Boolean,
    ): String {
        // The target goes out exactly as written: no decoding, no re-encoding, never replaced by
        // "/".
        val parts = splitUrl(url)
        val requestTarget = parts?.target ?: url.ifEmpty { "/" }

        // Host is the URL's authority as written; a host/port override only moves the connection.
        val hostHeader =
            parts?.authority?.ifEmpty { null }
                ?: run {
                    val isDefaultPort = (tls && port == 443) || (!tls && port == 80)
                    // A bare IPv6 literal (host override "::1") gets its brackets back for the Host
                    // header.
                    val hostLiteral =
                        if (host.contains(':') && !host.startsWith("[")) "[$host]" else host
                    if (isDefaultPort) hostLiteral else "$hostLiteral:$port"
                }

        val sb = StringBuilder()
        sb.append("$method $requestTarget HTTP/1.1\r\n")

        val hasHost = headers.keys.any { it.equals("Host", ignoreCase = true) }
        if (!hasHost) sb.append("Host: $hostHeader\r\n")

        headers.forEach { (k, v) -> sb.append("$k: $v\r\n") }

        val hasContentLength = headers.keys.any { it.equals("Content-Length", ignoreCase = true) }
        val hasTransferEncoding =
            headers.keys.any { it.equals("Transfer-Encoding", ignoreCase = true) }
        if (body != null && !hasContentLength && !hasTransferEncoding) {
            // Counted in the charset the whole request is sent with: a wide char anywhere (even in
            // a header) sends the body's Latin-1 chars as two UTF-8 bytes each.
            val charset =
                if (RequestHygiene.wireCharset(sb) == Charsets.UTF_8) Charsets.UTF_8
                else RequestHygiene.wireCharset(body)
            sb.append("Content-Length: ${body.toByteArray(charset).size}\r\n")
        }

        sb.append("\r\n")
        if (body != null) sb.append(body)
        return sb.toString()
    }

    /**
     * Host and port named by the first `Host` header of [raw]'s header block, never read past the
     * blank line (a smuggled request's Host in the body is not the target) nor across a line break.
     * Handles `example.com:8080`, `[::1]:8443` and a bare IPv6 literal; a missing or invalid port
     * is null.
     */
    fun parseHostHeader(raw: String): Pair<String, Int?>? {
        val headerEnd = HEADER_BLOCK_END.find(raw)?.range?.first ?: raw.length
        for (rawLine in raw.substring(0, headerEnd).split('\n')) {
            val line = rawLine.removeSuffix("\r")
            val colon = line.indexOf(':')
            if (colon <= 0 || !line.substring(0, colon).equals("Host", ignoreCase = true)) continue
            return parseHostValue(line.substring(colon + 1).trim())
        }
        return null
    }

    /**
     * Host and port of a Host header value or URL authority (`h`, `h:8080`, `[::1]:8443`, bare
     * IPv6).
     */
    internal fun parseHostValue(value: String): Pair<String, Int?>? {
        if (value.isEmpty() || value.any { it.isWhitespace() }) return null
        if (value.startsWith("[")) {
            val close = value.indexOf(']')
            if (close <= 1) return null
            val port =
                value
                    .substring(close + 1)
                    .takeIf { it.startsWith(":") }
                    ?.let { parsePort(it.substring(1)) }
            return value.substring(1, close) to port
        }
        val colon = value.indexOf(':')
        return when {
            colon < 0 -> value to null
            value.indexOf(':', colon + 1) >= 0 ->
                value to null // bare IPv6 literal: every colon is the address's
            colon == 0 -> null
            else -> value.substring(0, colon) to parsePort(value.substring(colon + 1))
        }
    }

    private fun parsePort(s: String): Int? =
        s.takeIf { it.isNotEmpty() && it.all { c -> c in '0'..'9' } }
            ?.toIntOrNull()
            ?.takeIf { it in 1..65535 }
}
