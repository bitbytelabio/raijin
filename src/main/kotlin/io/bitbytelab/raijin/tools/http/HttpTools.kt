package io.bitbytelab.raijin.tools.http

import burp.api.montoya.core.ToolType
import io.bitbytelab.raijin.bridge.AuditAuthRules
import io.bitbytelab.raijin.bridge.HttpBridge
import io.bitbytelab.raijin.bridge.HttpRequestBuilder
import io.bitbytelab.raijin.bridge.HttpSendOptions
import io.bitbytelab.raijin.core.asBodyString
import io.bitbytelab.raijin.core.asHeaders
import io.bitbytelab.raijin.core.asStringList
import io.bitbytelab.raijin.core.asStringMap
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.safety.ScopeGate
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.state.TrafficRule
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.*

/**
 * Registers the HTTP MCP tools onto the given [Server]: sending, the cookie jar, response analysis,
 * traffic rules and raw bytes here; pipelining in [HttpPipelineTools]; fuzzing and race testing in
 * [HttpAttackTools].
 *
 * Each tool checks its arguments ([ToolArgs]: closed value sets, malformed values) before
 * delegating to the [HttpBridge], clamps out-of-range numbers with a note, and answers through
 * [toolJsonResult] / [toolError], so every failure is flagged `isError` and an exception never
 * escapes the handler.
 */
object HttpTools {

    /**
     * Default per-request timeout when caller does not pass timeout_ms. Prevents agents from
     * hanging indefinitely on unresponsive targets or stuck SSE streams. Override with the
     * RAIJIN_DEFAULT_TIMEOUT_MS env var at extension load time.
     */
    internal val DEFAULT_TIMEOUT_MS: Long =
        System.getenv("RAIJIN_DEFAULT_TIMEOUT_MS")?.toLongOrNull() ?: 25_000L

    internal val HTTP_MODES = listOf("AUTO", "HTTP_1", "HTTP_2", "HTTP_2_IGNORE_ALPN")
    private val DIRECTIONS = listOf("request", "response")
    private val RULE_ACTIONS = listOf("modify", "drop", "spoof_response")

    /** A `Host` header line in a raw request's head. */
    private val RAW_HOST_HEADER = Regex("(?im)^host[ \\t]*:")

    internal val PORTS = 1..65_535
    internal val LENGTHS = 0..Int.MAX_VALUE

    private const val TIMEOUT_DESCRIPTION =
        "0 = default, -1 = no hard timeout, max 600000, default 25000"

    private const val URL_NOT_ABSOLUTE = HttpRequestBuilder.URL_NOT_ABSOLUTE

    /**
     * `invalid_arguments` for a `url` written without a scheme, with both schemes as
     * `did_you_mean`; no `retry`, since the sender must not pick the scheme. Null when [url] has
     * one (or is absent): then the build error stands.
     */
    private fun schemeError(url: String?): CallToolResult? {
        if (url == null || HttpRequestBuilder.hasScheme(url)) return null
        return io.bitbytelab.raijin.tools.ToolArgs.error(
            "invalid_arguments",
            "http_send_request: 'url' must be absolute (scheme://host/path), got \"$url\".",
        ) {
            put("param", "url")
            put("got", url)
            putJsonArray("did_you_mean") {
                HttpRequestBuilder.schemeGuesses(url).forEach { add(it) }
            }
        }
    }

    fun register(server: Server, bridge: HttpBridge, stateManager: StateManager) {
        val toolTypes = ToolType.entries.map { it.name }

        // ---------------------------------------------------------------
        // 1. http_send_request
        // ---------------------------------------------------------------
        server.addTool(
            name = "http_send_request",
            description =
                """Send an HTTP request through Burp Suite. Build from URL + method + headers + body, from a raw HTTP request string, or as a native HTTP/2 request with full control of its header list (pseudo-headers included). Supports HTTP/1.1, HTTP/2, connection reuse and Burp's request options.

Parameters:
- url (string): target URL (use this OR raw_request)
- method (string): HTTP method (default GET)
- headers (object): map of header name → value. Caller-supplied headers are preserved byte-exact (Burp's default User-Agent/Accept etc. are NOT injected when headers are provided).
- body (string OR object/array): request body. If object/array, it is serialized to compact JSON automatically.
- raw_request (string): raw HTTP request text. When supplied without explicit port/use_tls, defaults to TLS:443 (modern web default). Bare LF line endings in the request line and headers become CRLF; the body is sent as typed. Content-Length is auto-recomputed if it does not match body bytes.
- http2_headers (array of {name, value} or [name, value]): a native HTTP/2 request whose header list is sent as given, pseudo-headers included (":method", ":path", ":authority", ":scheme"): repeat, reorder, omit or malform them; CR/LF and uppercase names reach the wire. When the list has no pseudo-header, the four are derived from url/method and put first. Use with url (or host/port/use_tls) and body, not with raw_request or headers; sent with http_mode HTTP_2 (default) or HTTP_2_IGNORE_ALPN. No Content-Length is added: include a "content-length" field to send one.
- host, port (int, 1-65535), use_tls (bool): explicit service overrides
- http_mode (string): "AUTO" | "HTTP_1" | "HTTP_2" | "HTTP_2_IGNORE_ALPN". HTTP/3 is not available here or anywhere through Montoya — use Turbo (turbo_run.start with Engine.HTTP3) for HTTP/3.
- connection_id (string): pins/reuses one Montoya connection, but the request still fully completes (response received) before this call returns — no pipelining. For multi-request-per-socket pipelining use http_send_pipeline.
- follow_redirects (string): "never" | "always" | "same_host" | "in_scope" — Burp follows redirects and returns the final exchange (default: Burp's default, which does not follow).
- sni (string): TLS server name to send instead of the host.
- response_timeout_ms (int, 0 = Burp's default, -1 = none): Burp's own timeout for reading the response; on expiry Burp gives up and has_response is false.
- verify_tls (bool, default false): make Burp verify the target's TLS certificate.
- max_response_length (int): truncate response body in result
- timeout_ms (number, $TIMEOUT_DESCRIPTION): hard timeout. Returns is_timeout=true and close_reason="timeout" on expiry. Montoya has no partial-read API, so a failed/timed-out send cannot report bytes_received or distinguish fin/rst — use http_send_pipeline when that detail matters.
- preserve_headers (bool, default true): when false, falls back to Burp's httpRequestFromUrl which adds default headers
- auto_fix_content_length (bool, default true): when false, uses raw_request CL as-is. When true and the declared Content-Length didn't match the body, the result includes content_length_rewritten:{from,to}.

Out-of-range numbers are clamped and reported in notes. Returns full response with headers, body, status code, and timing; reauthenticated:<macro> when a session login macro re-established the session and sent the request again.""" +
                    "\n\n" +
                    ScopeGate.TOOL_NOTE +
                    " A followed redirect that lands outside scope is flagged (scope_warning), never blocked.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            property("url", "string", "Target URL (use this OR raw_request)")
                            property("method", "string", "HTTP method (default GET)")
                            property("headers", "object", "Map of header name to value")
                            property(
                                "body",
                                "string",
                                "Request body (string, or object/array serialized to JSON)",
                            )
                            property("raw_request", "string", "Raw HTTP request text")
                            putJsonObject("http2_headers") {
                                put("type", "array")
                                put(
                                    "description",
                                    "Native HTTP/2 header list sent as given, pseudo-headers included: [{\"name\":\":path\",\"value\":\"/x\"}] or [[\":path\",\"/x\"]]",
                                )
                            }
                            property("host", "string", "Explicit target hostname override")
                            property(
                                "port",
                                "integer",
                                "Explicit target port override (1-65535)",
                                minimum = 1,
                                maximum = 65535,
                            )
                            property("use_tls", "boolean", "Whether to use HTTPS (TLS)")
                            enumProperty(
                                "http_mode",
                                HTTP_MODES,
                                "HTTP version to use (default AUTO)",
                            )
                            property("connection_id", "string", "Reuse a prior connection")
                            enumProperty(
                                "follow_redirects",
                                HttpSendOptions.REDIRECTS.keys.toList(),
                                "Let Burp follow redirects (default: not followed)",
                            )
                            property("sni", "string", "TLS server name to send instead of the host")
                            property(
                                "response_timeout_ms",
                                "integer",
                                "Burp's own response read timeout (0 = Burp's default, -1 = none)",
                            )
                            property(
                                "verify_tls",
                                "boolean",
                                "Verify the target's TLS certificate (default false)",
                            )
                            property(
                                "max_response_length",
                                "integer",
                                "Truncate response body in result",
                            )
                            property(
                                "timeout_ms",
                                "number",
                                "Hard timeout in milliseconds ($TIMEOUT_DESCRIPTION)",
                            )
                            property(
                                "preserve_headers",
                                "boolean",
                                "Preserve caller headers byte-exact (default true)",
                            )
                            property(
                                "auto_fix_content_length",
                                "boolean",
                                "Recompute Content-Length to match body (default true)",
                            )
                        },
                    required = emptyList(),
                ),
        ) { request ->
            try {
                val args = ToolArgs(request.params.arguments ?: emptyMap())

                val url = args.string("url")
                // raw_request keeps an empty value (payload), but "" next to a url is a strict
                // client's filler, not a request to send.
                val rawRequest =
                    args.string("raw_request")?.takeUnless { it.isEmpty() && url != null }
                if (url != null && args.string("raw_request") == "") {
                    args.notes += "ignored empty 'raw_request' next to 'url'"
                }
                val http2Fields = parseHttp2Headers(args["http2_headers"])
                if (url == null && rawRequest == null && http2Fields == null) {
                    return@addTool toolError("Either 'url' or 'raw_request' must be provided")
                }
                val method = args.string("method")
                val body = args["body"].asBodyString()
                val host = args.string("host")
                val port = args.int("port", PORTS)
                val useTls = args.bool("use_tls")
                val httpMode = args.enum("http_mode", HTTP_MODES)
                val connectionId = args.string("connection_id")
                val maxResponseLength = args.clampedInt("max_response_length", LENGTHS)
                val timeoutMs = args.timeoutMs("timeout_ms", DEFAULT_TIMEOUT_MS)
                val preserveHeaders = args.bool("preserve_headers") ?: true
                val autoFixContentLength = args.bool("auto_fix_content_length") ?: true
                val options =
                    HttpSendOptions(
                        redirects =
                            args
                                .enum(
                                    "follow_redirects",
                                    HttpSendOptions.REDIRECTS.keys.toList(),
                                    "always" to "never",
                                )
                                ?.let { HttpSendOptions.REDIRECTS.getValue(it) },
                        sni = args.string("sni"),
                        responseTimeoutMs = args.responseTimeoutMs("response_timeout_ms"),
                        verifyTls = args.bool("verify_tls") ?: false,
                    )

                // Headers parsing — accepts object, array-of-pairs, array-of-{name,value}, "Name:
                // value"
                // strings, raw header block. A request missing a header the caller gave is not the
                // request
                // they meant: any entry that cannot be read refuses the call, nothing is sent.
                val headersInput = args["headers"]
                val parsedHeaders = headersInput.asHeaders()
                if (parsedHeaders.unparsed > 0) {
                    return@addTool io.bitbytelab.raijin.tools.ToolArgs.error(
                        "invalid_type",
                        "http_send_request: 'headers' could not be read (${parsedHeaders.warning}); nothing was sent. " +
                            "Pass {\"X-Foo\":\"bar\"} or [\"X-Foo: bar\"].",
                    ) {
                        put("param", "headers")
                        put("got", headersInput ?: JsonNull)
                        put(
                            "expected",
                            "object of name to value, or list of \"Name: value\" strings",
                        )
                    }
                }
                val headers = parsedHeaders.map
                val headersWarning = parsedHeaders.warning
                if (
                    rawRequest != null &&
                        url == null &&
                        host == null &&
                        !RAW_HOST_HEADER.containsMatchIn(
                            rawRequest.substringBefore("\n\n").substringBefore("\r\n\r\n"),
                        )
                ) {
                    return@addTool io.bitbytelab.raijin.tools.ToolArgs.error(
                        "missing_parameter",
                        "http_send_request: raw_request has no Host header, so there is nowhere to send it; " +
                            "add a Host header or pass 'host' (with 'port' and 'use_tls').",
                    ) {
                        put("param", "host")
                        putJsonObject("example") {
                            put("raw_request", "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                            put("host", "example.com")
                            put("port", 443)
                            put("use_tls", true)
                        }
                    }
                }

                val result =
                    bridge.sendRequest(
                        url,
                        method,
                        headers,
                        body,
                        rawRequest,
                        host,
                        port,
                        useTls,
                        httpMode,
                        connectionId,
                        maxResponseLength,
                        timeoutMs,
                        preserveHeaders,
                        autoFixContentLength,
                        http2Fields,
                        options,
                    )
                if (
                    (result["error"] as? JsonPrimitive)
                        ?.contentOrNull
                        ?.contains(URL_NOT_ABSOLUTE) == true
                ) {
                    schemeError(url)?.let {
                        return@addTool it
                    }
                }
                when ((result["error"] as? JsonPrimitive)?.contentOrNull) {
                    "Failed to send request: Invalid data." ->
                        return@addTool io.bitbytelab.raijin.tools.ToolArgs.error(
                            "invalid_arguments",
                            "http_send_request: Burp could not read the request to send (Invalid data.); " +
                                "nothing was sent. Pass 'url', or a full request in 'raw_request'.",
                        ) {
                            put("param", "raw_request")
                        }
                    "Failed to send request: Invalid service." ->
                        return@addTool io.bitbytelab.raijin.tools.ToolArgs.error(
                            "invalid_arguments",
                            "http_send_request: Burp refused the target (Invalid service.); nothing was sent. " +
                                "Check 'host' and 'port'.",
                        ) {
                            put("param", "host")
                        }
                }

                val augmented =
                    if (headersWarning != null) {
                        buildJsonObject {
                            result.forEach { (k, v) -> put(k, v) }
                            put("headers_warning", headersWarning)
                        }
                    } else result

                // What reached the wire when the call left it implicit.
                if (
                    rawRequest != null &&
                        !args.has("use_tls") &&
                        (result["request_secure"] as? JsonPrimitive)?.booleanOrNull == true
                ) {
                    args.notes +=
                        "raw_request without use_tls: sent over TLS; pass use_tls:false for plain HTTP"
                }
                if (url != null && rawRequest != null) {
                    args.notes +=
                        "url and raw_request both given: sent raw_request as written; url only chose host, port and TLS"
                }
                (headersInput as? JsonObject)
                    ?.filterValues { it is JsonPrimitive && !it.isString && it !is JsonNull }
                    ?.keys
                    ?.takeIf { it.isNotEmpty() }
                    ?.let {
                        args.notes +=
                            "sent non-string header value(s) of ${it.joinToString(", ")} as text"
                    }

                // Sent but nothing came back: an error, with every request field kept. Done here
                // and not in the bridge, whose other callers (probes) keep the plain result.
                val noResponse = (augmented["no_response"] as? JsonPrimitive)?.contentOrNull
                val sent =
                    if (
                        (augmented["has_response"] as? JsonPrimitive)?.booleanOrNull == false &&
                            "error" !in augmented
                    ) {
                        JsonObject(
                            linkedMapOf<String, JsonElement>(
                                "error" to
                                    JsonPrimitive(
                                        "http_send_request: ${noResponse ?: "no response"}.",
                                    ),
                                "code" to JsonPrimitive("no_response"),
                            ) + augmented,
                        )
                    } else augmented
                toolJsonResult(args.withNotes(sent))
            } catch (e: Exception) {
                val message = e.message ?: "Unknown error"
                val rawUrl = (request.params.arguments?.get("url") as? JsonPrimitive)?.contentOrNull
                if (URL_NOT_ABSOLUTE in message)
                    schemeError(rawUrl)?.let {
                        return@addTool it
                    }
                toolError(message)
            }
        }

        // ---------------------------------------------------------------
        // 2. http_send_requests_parallel
        // ---------------------------------------------------------------
        server.addTool(
            name = "http_send_requests_parallel",
            description =
                """Send multiple HTTP requests in parallel through Burp Suite. Each request in the array can specify url, method, headers, body (string or object), or raw_request.

Mixed hosts are supported: requests are grouped by HTTP service (host+port+tls) and dispatched per-group, then merged back into the original input order. Per-group dispatch failures do not abort the batch — failed slots come back with error/phase fields.

Parameters:
- requests (array, required): per-request objects with url, method, headers, body, raw_request, host, port, use_tls, auto_fix_content_length and preserve_headers (both default true). http2_headers, follow_redirects, sni, verify_tls and response_timeout_ms are http_send_request only: an item carrying one fails to build. Each item reports its own content_length_rewritten, headers_warning and warnings (raw CR/LF removed). A group that times out or fails marks only its own items; groups not started before timeout_ms ran out come back not_sent.
- http_mode (string): "AUTO" | "HTTP_1" | "HTTP_2" | "HTTP_2_IGNORE_ALPN"
- max_response_length (int): truncate response bodies
- timeout_ms (number, $TIMEOUT_DESCRIPTION): hard timeout for the entire batch

Returns array of results in original order, plus group_timings_ms and groups_dispatched.""" +
                    "\n\n" +
                    ScopeGate.TOOL_NOTE +
                    " Checked per item: a refused item carries out_of_scope and is not sent, the others go out.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("requests") {
                                put("type", "array")
                                putJsonObject("items") { put("type", "object") }
                                put(
                                    "description",
                                    "Per-request objects: url, method, headers, body, raw_request, host, port, use_tls, auto_fix_content_length, preserve_headers",
                                )
                            }
                            enumProperty(
                                "http_mode",
                                HTTP_MODES,
                                "HTTP version for every request (default AUTO)",
                            )
                            property("max_response_length", "integer", "Truncate response bodies")
                            property(
                                "timeout_ms",
                                "number",
                                "Hard timeout for the entire batch in milliseconds ($TIMEOUT_DESCRIPTION)",
                            )
                        },
                    required = listOf("requests"),
                ),
        ) { request ->
            try {
                val args = ToolArgs(request.params.arguments ?: emptyMap())

                val requests =
                    args.objectList("requests", "request")
                        ?: return@addTool toolError(
                            "Parameter 'requests' is required (array of request objects)",
                        )
                val httpMode = args.enum("http_mode", HTTP_MODES)
                val maxResponseLength = args.clampedInt("max_response_length", LENGTHS)
                val timeoutMs = args.timeoutMs("timeout_ms", DEFAULT_TIMEOUT_MS)

                toolJsonResult(
                    args.withNotes(
                        bridge.sendRequestsParallel(
                            requests,
                            httpMode,
                            maxResponseLength,
                            timeoutMs,
                        ),
                    ),
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 3. http_send_request_chain
        // ---------------------------------------------------------------
        server.addTool(
            name = "http_send_request_chain",
            description =
                "Send a chain of HTTP requests sequentially with variable extraction between steps. Each step can extract values from its response with a regex (first capture group), a JSONPath or an XPath, and inject them into later steps via {{variable}} placeholders. Useful for CSRF tokens, session tokens, and multi-step workflows. A step's extract rules are checked before its request is sent; timeout_ms bounds each step. Optional connection_id pins/reuses one Montoya connection across every step — steps stay fully sequential either way (no pipelining); for genuine multi-request-per-socket pipelining use http_send_pipeline instead. A step reports extract_missed (rules that matched nothing) and unresolved_placeholders ({{x}} left after substitution); success needs a response. " +
                    ScopeGate.TOOL_NOTE +
                    " Checked per step.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("steps") {
                                put("type", "array")
                                putJsonObject("items") { put("type", "object") }
                                put(
                                    "description",
                                    "Array of step objects with url/raw_request and an optional 'extract' key. 'extract' MUST be an ARRAY of {name, pattern | json_path | xpath, from} objects (from = \"body\" (default) or \"header\"; a header rule takes a pattern over the 'Name: value' lines, every Set-Cookie included), e.g. extract:[{\"name\":\"csrf\",\"pattern\":\"name=csrf value=([^ ]+)\"},{\"name\":\"jwt\",\"json_path\":\"$.data.token\"}]. Passing a single object instead of an array is rejected with a validation error.",
                                )
                            }
                            enumProperty(
                                "http_mode",
                                HTTP_MODES,
                                "HTTP version for every step (default AUTO)",
                            )
                            property(
                                "stop_on_error",
                                "boolean",
                                "Stop the chain on the first error (default true)",
                            )
                            property(
                                "connection_id",
                                "string",
                                "Pin/reuse one connection across every step (sequential, not pipelined)",
                            )
                            property(
                                "timeout_ms",
                                "number",
                                "Hard timeout per step in milliseconds ($TIMEOUT_DESCRIPTION)",
                            )
                        },
                    required = listOf("steps"),
                ),
        ) { request ->
            try {
                val args = ToolArgs(request.params.arguments ?: emptyMap())

                val steps =
                    args.objectList("steps", "step")
                        ?: return@addTool toolError(
                            "Parameter 'steps' is required (array of step objects with url/raw_request and optional extract definitions)",
                        )
                val httpMode = args.enum("http_mode", HTTP_MODES)
                val stopOnError = args.bool("stop_on_error") ?: true
                val connectionId = args.string("connection_id")
                val timeoutMs = args.timeoutMs("timeout_ms", DEFAULT_TIMEOUT_MS)

                toolJsonResult(
                    args.withNotes(
                        bridge.sendRequestChain(
                            steps,
                            httpMode,
                            stopOnError,
                            connectionId,
                            timeoutMs,
                        ),
                    ),
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 4. http_cookie_jar_get
        // ---------------------------------------------------------------
        server.addTool(
            name = "http_cookie_jar_get",
            description =
                "Get cookies from Burp Suite's cookie jar. Optionally filter by domain substring.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            property("domain", "string", "Optional domain substring filter")
                        },
                    required = emptyList(),
                ),
        ) { request ->
            try {
                val args = ToolArgs(request.params.arguments ?: emptyMap())
                toolJsonResult(bridge.getCookieJar(args.string("domain")))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 5. http_cookie_jar_set
        // ---------------------------------------------------------------
        server.addTool(
            name = "http_cookie_jar_set",
            description = "Set a cookie in Burp Suite's cookie jar.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            property("name", "string", "Cookie name")
                            property("value", "string", "Cookie value")
                            property("domain", "string", "Cookie domain")
                            property("path", "string", "Cookie path (default /)")
                            property(
                                "expiration",
                                "string",
                                "Optional cookie expiration, ISO-8601 date-time with offset (e.g. 2027-01-01T00:00:00Z)",
                            )
                        },
                    required = listOf("name", "value", "domain"),
                ),
        ) { request ->
            try {
                val args = ToolArgs(request.params.arguments ?: emptyMap())

                val name =
                    args.string("name") ?: return@addTool toolError("Parameter 'name' is required")
                val value =
                    args.string("value")
                        ?: return@addTool toolError("Parameter 'value' is required")
                val domain =
                    args.string("domain")
                        ?: return@addTool toolError("Parameter 'domain' is required")
                val path = args.string("path") ?: "/"

                toolJsonResult(
                    bridge.setCookie(name, value, domain, path, args.string("expiration")),
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // http_cookie_jar_delete
        // ---------------------------------------------------------------
        // A cookie really named `<name>` (an example run as written) stays deletable.
        io.bitbytelab.raijin.tools.ToolArgs.literalValues["http_cookie_jar_delete"] =
            { a: JsonObject ->
                (a["domain"] as? JsonPrimitive)
                    ?.takeIf { it.isString }
                    ?.content
                    ?.let(bridge::cookieLiterals) ?: emptySet()
            }
        server.addTool(
            name = "http_cookie_jar_delete",
            description =
                "Delete a cookie from Burp Suite's cookie jar. Montoya has no delete API for this — it's " +
                    "implemented by setting the cookie to expire in the past, then re-reading the jar to confirm the " +
                    "entry is actually gone (reported in 'deleted'); if Burp retains an expired record instead of " +
                    "dropping it, this is reported honestly rather than claiming success.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            property("name", "string", "Cookie name")
                            property("domain", "string", "Cookie domain")
                            property("path", "string", "Cookie path (default /)")
                        },
                    required = listOf("name", "domain"),
                ),
        ) { request ->
            try {
                val args = ToolArgs(request.params.arguments ?: emptyMap())
                val name =
                    args.string("name") ?: return@addTool toolError("Parameter 'name' is required")
                val domain =
                    args.string("domain")
                        ?: return@addTool toolError("Parameter 'domain' is required")
                val path = args.string("path") ?: "/"

                toolJsonResult(bridge.deleteCookie(name, domain, path))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 6. http_analyze_keywords
        // ---------------------------------------------------------------
        server.addTool(
            name = "http_analyze_keywords",
            description =
                "Analyze an HTTP response for keyword occurrences using Burp's built-in keyword analysis engine. Useful for identifying which keywords vary across multiple responses (e.g., during content discovery).",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            property("response", "string", "Raw HTTP response string")
                            putJsonObject("keywords") {
                                put("type", "array")
                                putJsonObject("items") { put("type", "string") }
                                put("description", "Array of keyword strings")
                            }
                            property(
                                "case_sensitive",
                                "boolean",
                                "Whether matching is case-sensitive (default false)",
                            )
                        },
                    required = listOf("response", "keywords"),
                ),
        ) { request ->
            try {
                val args = ToolArgs(request.params.arguments ?: emptyMap())

                val response =
                    args.string("response")
                        ?: return@addTool toolError(
                            "Parameter 'response' is required (raw HTTP response string)",
                        )
                val keywords =
                    args["keywords"].asStringList()
                        ?: return@addTool toolError(
                            "Parameter 'keywords' is required (array of keyword strings)",
                        )
                val caseSensitive = args.bool("case_sensitive") ?: false

                toolJsonResult(bridge.analyzeKeywords(response, keywords, caseSensitive))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 7. http_analyze_variations
        // ---------------------------------------------------------------
        server.addTool(
            name = "http_analyze_variations",
            description =
                "Analyze variations across multiple HTTP responses. Identifies which response attributes (status code, content length, headers, body content, etc.) vary and which are invariant. Useful for identifying valid vs. invalid responses in fuzzing/scanning.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("responses") {
                                put("type", "array")
                                putJsonObject("items") { put("type", "string") }
                                put(
                                    "description",
                                    "Array of raw HTTP response strings (at least 2)",
                                )
                            }
                        },
                    required = listOf("responses"),
                ),
        ) { request ->
            try {
                val args = ToolArgs(request.params.arguments ?: emptyMap())

                val responses =
                    args["responses"].asStringList()
                        ?: return@addTool toolError(
                            "Parameter 'responses' is required (array of raw HTTP response strings)",
                        )
                if (responses.size < 2) {
                    return@addTool toolError(
                        "At least 2 responses are required for variation analysis",
                    )
                }

                toolJsonResult(bridge.analyzeVariations(responses))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 8. http_set_traffic_rule
        // ---------------------------------------------------------------
        server.addTool(
            name = "http_set_traffic_rule",
            description =
                "Register a global HTTP traffic rule. Rules apply to all HTTP traffic (not just proxy). action=modify (default) adds/removes/replaces headers, " +
                    "written exactly as given: a header line or value may carry CR/LF, odd spacing or no colon (a second injected line, an obfuscated " +
                    "Transfer-Encoding, ...). action=drop or action=spoof_response (direction=request only) suppress the request entirely before it is sent, via Burp's Montoya API 2026.7+ " +
                    "(RequestToBeSentAction.drop()/.spoof()) — on an older Burp these fall back to sending the request unmodified and report it via a " +
                    "'http.traffic_rule.degraded' event. If rule_id matches an existing rule, it is replaced. Raijin's own unauthenticated probes " +
                    "(auth_diff, autorize, idor_hunt) only get rules whose tool_filter names EXTENSIONS.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            property(
                                "rule_id",
                                "string",
                                "Rule ID; if it matches an existing rule it is replaced (auto-generated if omitted)",
                            )
                            enumProperty("direction", DIRECTIONS, "Traffic the rule applies to")
                            property(
                                "match_url",
                                "string",
                                "Regex matched against the request URL (case-insensitive)",
                            )
                            property("match_host", "string", "Host glob (*.example.com) or regex")
                            property(
                                "match_header",
                                "string",
                                "Regex matched against the 'Name: value' header lines (case-insensitive)",
                            )
                            enumProperty(
                                "action",
                                RULE_ACTIONS,
                                "modify (default) | drop | spoof_response. drop/spoof_response only take effect when direction=request; needs Burp's Montoya API 2026.7+ (falls back to sending the request on an older Burp).",
                            )
                            property(
                                "modify_add_header",
                                "string",
                                "Header line to add, written as given ('Name: value', or anything else incl. CR/LF) (action=modify)",
                            )
                            property(
                                "modify_remove_header",
                                "string",
                                "Header to remove (action=modify)",
                            )
                            property(
                                "modify_replace_header",
                                "object",
                                "Map of header name to replacement value, written as given (action=modify)",
                            )
                            property(
                                "spoof_response",
                                "string",
                                "Raw HTTP response text to return without sending the request (action=spoof_response, direction=request)",
                            )
                            putJsonObject("tool_filter") {
                                put("type", "array")
                                putJsonObject("items") {
                                    put("type", "string")
                                    putJsonArray("enum") { toolTypes.forEach { add(it) } }
                                }
                                put(
                                    "description",
                                    "Only apply to traffic from these Burp tools (default: every tool). Raijin's internal unauthenticated probes run as EXTENSIONS and only get a rule whose tool_filter names EXTENSIONS.",
                                )
                            }
                            property(
                                "enabled",
                                "boolean",
                                "Whether the rule is active (default true)",
                            )
                        },
                    required = listOf("direction"),
                ),
        ) { request ->
            try {
                val args = ToolArgs(request.params.arguments ?: emptyMap())

                val ruleId = args.string("rule_id") ?: stateManager.generateId("trule")
                val direction =
                    args.enum("direction", DIRECTIONS)
                        ?: return@addTool toolError(
                            "Parameter 'direction' is required ('request' or 'response')",
                        )
                val action = args.enum("action", RULE_ACTIONS) ?: "modify"
                val spoofResponse = args.string("spoof_response")
                if (action == "spoof_response" && spoofResponse.isNullOrBlank()) {
                    return@addTool toolError(
                        "action=spoof_response requires 'spoof_response' (raw HTTP response text)",
                    )
                }
                if (action != "modify" && direction == "response") {
                    return@addTool toolError(
                        "action=drop/spoof_response only apply to direction=request (a response has already been received by the time a direction=response rule runs — use action=modify with modify_replace_header/modify_add_header to rewrite it instead)",
                    )
                }

                val matchUrl = args.string("match_url")
                val matchHeader = args.string("match_header")
                for ((param, pattern) in
                    listOf("match_url" to matchUrl, "match_header" to matchHeader)) {
                    if (pattern == null) continue
                    SafeRegex.validate(pattern, ignoreCase = true)?.let {
                        return@addTool toolError("Parameter '$param' is not a valid regex: $it")
                    }
                }

                val replaceInput = args["modify_replace_header"]
                val replaceHeader = replaceInput?.let {
                    it.asStringMap()
                        ?: return@addTool toolError(
                            "Parameter 'modify_replace_header' must be an object of header name to value",
                        )
                }
                if (replaceHeader?.keys?.any { it.isEmpty() } == true) {
                    return@addTool toolError("modify_replace_header: a header name cannot be empty")
                }

                val toolFilter =
                    args["tool_filter"]?.let { element ->
                        val names =
                            element.asStringList()
                                ?: return@addTool toolError(
                                    "Parameter 'tool_filter' must be an array of Burp tool names",
                                )
                        names
                            .map { name ->
                                toolTypes.firstOrNull { it.equals(name.trim(), ignoreCase = true) }
                                    ?: return@addTool toolError(
                                        "tool_filter: unknown tool '$name'. Allowed: ${toolTypes.joinToString(", ")}",
                                    )
                            }
                            .toSet()
                            .ifEmpty { null }
                    }

                val rule =
                    TrafficRule(
                        ruleId = ruleId,
                        direction = direction,
                        matchUrl = matchUrl,
                        matchHost = args.string("match_host"),
                        matchHeader = matchHeader,
                        modifyAddHeader = args.string("modify_add_header"),
                        modifyRemoveHeader = args.string("modify_remove_header"),
                        modifyReplaceHeader = replaceHeader,
                        enabled = args.bool("enabled") ?: true,
                        action = action,
                        spoofResponse = spoofResponse,
                        toolFilter = toolFilter,
                    )

                // Remove existing rule with same ID, then add the new one
                stateManager.trafficRules.removeIf { it.ruleId == ruleId }
                stateManager.trafficRules.add(rule)

                toolJsonResult(
                    buildJsonObject {
                        put("rule_set", true)
                        put("rule_id", ruleId)
                        put("direction", direction)
                        put("action", action)
                        put("total_rules", stateManager.trafficRules.size)
                    },
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 9. http_list_traffic_rules
        // ---------------------------------------------------------------
        server.addTool(
            name = "http_list_traffic_rules",
            description = "List all registered global HTTP traffic modification rules.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList()),
        ) { _ ->
            try {
                val rules = stateManager.trafficRules.toList()
                toolJsonResult(
                    buildJsonObject {
                        put("total", rules.size)
                        put(
                            "rules",
                            buildJsonArray { rules.forEach { add(serializeTrafficRule(it)) } },
                        )
                    },
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 10. http_remove_traffic_rule
        // ---------------------------------------------------------------
        server.addTool(
            name = "http_remove_traffic_rule",
            description = "Remove a global HTTP traffic modification rule by its rule ID.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            property("rule_id", "string", "The rule ID to remove")
                        },
                    required = listOf("rule_id"),
                ),
        ) { request ->
            try {
                val args = ToolArgs(request.params.arguments ?: emptyMap())
                val ruleId =
                    args.string("rule_id")
                        ?: return@addTool toolError("Parameter 'rule_id' is required")
                // An audit auth rule goes with its -strip companion.
                val removed = AuditAuthRules.removeRules(stateManager, ruleId)

                toolJsonResult(
                    buildJsonObject {
                        put("rule_id", ruleId)
                        put("removed", removed)
                        put("remaining_rules", stateManager.trafficRules.size)
                    },
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 11. http_send_raw_bytes
        // ---------------------------------------------------------------
        server.addTool(
            name = "http_send_raw_bytes",
            description =
                "Send a raw byte-level HTTP request for HTTP request smuggling and CRLF injection testing. Accepts either hex-encoded bytes (raw_request_hex; whitespace between digits is ignored) or request text (raw_request). Preserves exact byte sequences without normalization: raw_request's literal \\r\\n / \\n escapes are decoded only when the text contains no real line break, and a character above U+00FF sends the whole text as UTF-8 (use raw_request_hex for exact bytes). Requires host, port, and use_tls parameters. Sends ONE request and reads ONE response (Montoya's api.http().sendRequest has no partial-read API, so a failed/timed-out send cannot report bytes_received or distinguish fin/rst — it only returns is_timeout and close_reason=\"timeout\"|\"error\"). HTTP/2/3 and kettled H2-smuggling escape fields (^~, ^xNN, ...) are not available here — this is HTTP/1 only; for those, or for sending several requests over one socket and reading back several responses, use http_send_pipeline (HTTP/1.1 pipelining) or Turbo (turbo_start_run with Engine.HTTP2/HTTP3, kettled=True). " +
                    ScopeGate.TOOL_NOTE,
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            property(
                                "raw_request_hex",
                                "string",
                                "Hex-encoded request bytes (use this OR raw_request)",
                            )
                            property(
                                "raw_request",
                                "string",
                                "Request text; literal \\r\\n escapes are decoded only when it has no real line breaks",
                            )
                            property("host", "string", "Target hostname")
                            property(
                                "port",
                                "integer",
                                "Target port number (1-65535, default 443, or 80 with use_tls=false)",
                                minimum = 1,
                                maximum = 65535,
                            )
                            property("use_tls", "boolean", "Whether to use HTTPS (TLS)")
                            property("tls", "boolean", "Alias for use_tls")
                            property("https", "boolean", "Alias for use_tls")
                            enumProperty(
                                "http_mode",
                                HTTP_MODES,
                                "HTTP version to use (default HTTP_1, so the bytes keep HTTP/1 framing; notes say when the response still came back over HTTP/2)",
                            )
                            property(
                                "max_response_length",
                                "integer",
                                "Truncate response body in result",
                            )
                            property(
                                "timeout_ms",
                                "number",
                                "Hard timeout in milliseconds ($TIMEOUT_DESCRIPTION)",
                            )
                        },
                    required = listOf("host"),
                ),
        ) { request ->
            try {
                val args = ToolArgs(request.params.arguments ?: emptyMap())

                val rawHex = args.string("raw_request_hex")
                val rawString = args.string("raw_request")
                val host =
                    args.string("host") ?: return@addTool toolError("Parameter 'host' is required")
                if (rawHex == null && rawString == null) {
                    return@addTool toolError(
                        "Either 'raw_request_hex' or 'raw_request' must be provided",
                    )
                }
                val port = args.portOrDefault(PORTS)
                val useTls = args.tls(port)
                val httpMode = args.enum("http_mode", HTTP_MODES)
                val maxResponseLength = args.clampedInt("max_response_length", LENGTHS)
                val timeoutMs = args.timeoutMs("timeout_ms", DEFAULT_TIMEOUT_MS)

                toolJsonResult(
                    args.withNotes(
                        bridge.sendRawBytes(
                            rawHex,
                            rawString,
                            host,
                            port,
                            useTls,
                            httpMode,
                            maxResponseLength,
                            timeoutMs,
                        ),
                    ),
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 12. http_send_pipeline (raw-socket pipelining, its own file)
        // ---------------------------------------------------------------
        HttpPipelineTools.register(server, bridge.pipeline)

        // ---------------------------------------------------------------
        // 13-14. http_fuzz, http_race (their own file)
        // ---------------------------------------------------------------
        HttpAttackTools.register(server, bridge)
    }

    /**
     * The `http2_headers` list: an array of `{name, value}` objects or `[name, value]` pairs, or an
     * object (its members in order). Names and values are taken as given.
     */
    internal fun parseHttp2Headers(element: JsonElement?): List<Pair<String, String>>? =
        when (element) {
            null,
            JsonNull -> null
            is JsonObject ->
                element.entries.map { (name, value) -> name to text(value, "http2_headers.$name") }
            is JsonArray ->
                element
                    .mapIndexed { i, item ->
                        when (item) {
                            is JsonObject -> {
                                val name = item["name"]?.let { text(it, "http2_headers[$i].name") }
                                val value =
                                    item["value"]?.let { text(it, "http2_headers[$i].value") }
                                require(name != null && value != null) {
                                    "http2_headers[$i] needs 'name' and 'value'"
                                }
                                name to value
                            }
                            is JsonArray -> {
                                require(item.size == 2) {
                                    "http2_headers[$i] must be a [name, value] pair"
                                }
                                text(item[0], "http2_headers[$i][0]") to
                                    text(item[1], "http2_headers[$i][1]")
                            }
                            else ->
                                throw IllegalArgumentException(
                                    "http2_headers[$i] must be {name, value} or [name, value]",
                                )
                        }
                    }
                    .also { require(it.isNotEmpty()) { "http2_headers must not be empty" } }
            else ->
                throw IllegalArgumentException(
                    "http2_headers must be an array of {name, value} objects or [name, value] pairs",
                )
        }

    private fun text(element: JsonElement, what: String): String =
        (element as? JsonPrimitive)?.takeUnless { it is JsonNull }?.content
            ?: throw IllegalArgumentException("$what must be a string")

    // ---------------------------------------------------------------
    // Helper: serialize a TrafficRule to JSON
    // ---------------------------------------------------------------

    private fun serializeTrafficRule(rule: TrafficRule): JsonObject {
        return buildJsonObject {
            put("rule_id", rule.ruleId)
            put("direction", rule.direction)
            put("action", rule.action)
            put("enabled", rule.enabled)
            if (rule.matchUrl != null) put("match_url", rule.matchUrl)
            if (rule.matchHost != null) put("match_host", rule.matchHost)
            if (rule.matchHeader != null) put("match_header", rule.matchHeader)
            if (rule.modifyAddHeader != null) put("modify_add_header", rule.modifyAddHeader)
            if (rule.modifyRemoveHeader != null)
                put("modify_remove_header", rule.modifyRemoveHeader)
            if (rule.modifyReplaceHeader != null) {
                put(
                    "modify_replace_header",
                    buildJsonObject {
                        rule.modifyReplaceHeader.forEach { (k, v) -> put(k, v) }
                    },
                )
            }
            if (rule.modifySetCookies != null) {
                put(
                    "modify_set_cookies",
                    buildJsonObject {
                        rule.modifySetCookies.forEach { (k, v) -> put(k, v) }
                    },
                )
            }
            if (rule.spoofResponse != null) put("spoof_response", rule.spoofResponse)
            if (rule.toolFilter != null)
                put("tool_filter", buildJsonArray { rule.toolFilter.forEach { add(it) } })
        }
    }
}
