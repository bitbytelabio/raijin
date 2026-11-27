package io.bitbytelab.raijin.tools.http

import io.bitbytelab.raijin.bridge.HttpPipelineBridge
import io.bitbytelab.raijin.bridge.HttpPipelineFraming
import io.bitbytelab.raijin.bridge.PipelineRequestSpec
import io.bitbytelab.raijin.core.asStringList
import io.bitbytelab.raijin.safety.RequestHygiene
import io.bitbytelab.raijin.safety.ScopeGate
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject

/**
 * The raw-socket HTTP/1.1 pipelining tools over [HttpPipelineBridge]: `http_send_pipeline` (several
 * requests on one connection of Raijin's own, outside Burp's one-request-one-response model) and
 * `http_pipeline_connections` (the connections it keeps open for later calls).
 */
internal object HttpPipelineTools {

    private val PIPELINE_HTTP_MODES = listOf("HTTP_1")
    private val WRITE_MODES = listOf("concat", "single_write")

    private val PORTS = 1..65_535
    private val WRITE_PAUSES_MS = 0L..60_000L
    private val PAUSES_MS = 0L..60_000L
    private val MAX_RESPONSES = 1..1_000
    private val PIPELINE_TIMEOUTS_MS = 1L..ToolArgs.MAX_TIMEOUT_MS
    private val LENGTHS = 0..Int.MAX_VALUE
    private val RAW_HEX_BYTES = 0..HttpPipelineFraming.DEFAULT_MAX_RESPONSE_BYTES

    fun register(server: Server, pipeline: HttpPipelineBridge) {
        registerSend(server, pipeline)
        registerConnections(server, pipeline)
    }

    private fun registerSend(server: Server, pipeline: HttpPipelineBridge) {
        server.addTool(
            name = "http_send_pipeline",
            description =
                """Send multiple raw HTTP/1.1 requests over ONE socket connection and read back multiple responses in order. Unlike every other http_* tool (which goes through Burp's Montoya API, strictly one request in / one response out), this opens its own raw socket — needed for HTTP desync / request-smuggling research (0.CL, stage1+stage2 probes) where a server may respond to one request with two responses, or where you need to observe exactly what came back before a connection died.

HTTP/1.1 only — http_mode must be omitted or "HTTP_1". HTTP/2, HTTP/3 and kettled H2-smuggling escape fields are Turbo-only: use turbo_run.start with Engine.HTTP2 / Engine.HTTP3 / kettled=True for those.

Never auto-fixes Content-Length — a deliberately wrong declared length is the point of this tool. If you want byte-exact control without a wrong Content-Length tripping you up, compute it yourself.

Responses are read while the requests are still being written, so a response that starts before its request is fully sent (during a pause, or between writes) is caught and timed. Response framing is strict: a negative, non-numeric or conflicting Content-Length, a bad chunk size, or chunk data without its CRLF stops reading with close_reason "error" and the reason in error, instead of guessing. Chunked trailers are read up to their blank line and returned per response.

Parameters:
- host, port (1-65535), use_tls/tls/https (alias): target. use_tls defaults to true when port is 443.
- sni (string): TLS server name to send instead of the default (host); "" sends none. Ignored without TLS.
- requests (array, required): each item has raw_request (literal \r\n escapes are decoded only when the text has no real line break) or raw_request_hex (hex-encoded bytes), same convention as http_send_raw_bytes, and optionally pauses (as in Turbo):
  - pause_before (int): n > 0 sends the first n-1 bytes, then pauses; n < 0 holds the last |n| bytes back for the pause. Clamped into the request.
  - pause_markers (array of strings): pause after every occurrence of each string in the request bytes (same \r\n escape convention as raw_request).
  - pause_ms (0-60000, default 1000): length of each pause. A pause ends early as soon as response bytes arrive, or when the server closes the connection.
- write_mode: "concat" (default; all requests written in one burst, split only at pauses) or "single_write" (one write+flush per request, with write_pause_ms between them).
- max_responses (int, 1-1000): how many responses to read before stopping (default: number of requests sent — but a 0.CL probe may produce MORE responses than requests, or fewer; set this explicitly for that case).
- idle_timeout_ms (default 2000): stop when no bytes arrive for this long after the last request byte was written.
- total_timeout_ms (default 15000): hard cap for the whole call (connect, write and read).
- keep_open (bool, default false): keep the socket open after this call so a LATER http_send_pipeline call can reuse it via connection_id. Only honored when every requested response framed cleanly, every request byte was written, and the server keeps the connection (no Connection: close, close-delimited body, or HTTP/1.0 response without keep-alive) — anything else closes the socket. Bytes received past the last returned response are handed to the next call.
- connection_id (string): reuse a socket kept open by a prior keep_open=true call. It is reused only for the same host, port, TLS and sni; otherwise it is closed, a fresh connection is opened and connection_id_target_mismatch:true is reported. This registry is separate from Montoya's own connection_id on http_send_request — different transport layers, not interchangeable. If the id is unknown (closed, evicted after 120s idle, or never existed) a fresh connection is opened and connection_reused:false is reported, rather than erroring. http_state.pipeline_connections lists and closes kept connections.
- max_response_length (int): truncate each response body in the result.
- decode_content (bool, default false): show each body with its Content-Encoding (gzip, x-gzip, deflate, br; several undone last to first) undone. br is decoded only where a bounded, streaming decoder backs it; until then it reports decode_error instead of risking an unbounded decompression.
- raw_hex_max_bytes (int, 0-10000000, default 65536): cap on each raw hex dump; 0 leaves them out.

Out-of-range numbers are clamped into range and reported in notes.

Returns:
- responses: array of {index, status_line, status_code, headers, body, framing, trailers, warnings, raw_response_hex, raw_response_bytes, raw_response_truncated, first_byte_ms, last_byte_ms, ttfb_ms, ttlb_ms, decoded_codings, decode_error}. raw_response_hex is the bytes exactly as received: any 1xx before the response, status line, headers, body with its chunk framing and trailers. body is UTF-8 text when the bytes are valid UTF-8, else one char per byte. first_byte_ms/last_byte_ms: when its first/last byte arrived. ttfb_ms/ttlb_ms: the same, counted from when the request with the same index was completely written; negative means the response started before that request was fully sent (a desync signal); absent when no request with that index was completely written. decoded_codings/decode_error: what decode_content undid, and why it stopped short.
- requests: per request {index, bytes, bytes_written, write_start_ms, write_end_ms, pauses: [{offset, at_ms, duration_ms, ended_by: "pause_ms"|"data"|"connection_closed"|"stopped"}]}.
- partial_response: {index, raw_response_hex, raw_response_bytes, raw_response_truncated, first_byte_ms, last_byte_ms} — the bytes of the unfinished response when reading stopped on fin, rst, idle, total_timeout or error.
- unparsed: {bytes, raw_hex, raw_truncated, kept_for_next_call} — bytes received past the last returned response.
- write_error: why not every request byte was written (e.g. the server closed the connection early); the responses read are still returned.
- connection_id, connection_reused, bytes_sent, bytes_received, responses_received, close_reason ("max_responses"|"idle"|"total_timeout"|"fin"|"rst"|"error"|"switching_protocols"), connection_open.
All *_ms are milliseconds with microsecond precision, counted from the first request byte written unless stated otherwise.""" +
                    "\n\n" +
                    ScopeGate.TOOL_NOTE +
                    " The URL checked is the first request's.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
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
                            property(
                                "sni",
                                "string",
                                "TLS server name to send instead of host; \"\" sends none",
                            )
                            enumProperty(
                                "http_mode",
                                PIPELINE_HTTP_MODES,
                                "Must be omitted or \"HTTP_1\" — HTTP/2 and HTTP/3 are Turbo-only",
                            )
                            putJsonObject("requests") {
                                put("type", "array")
                                putJsonObject("items") {
                                    put("type", "object")
                                    putJsonObject("properties") {
                                        property(
                                            "raw_request",
                                            "string",
                                            "Request text (literal \\r\\n escapes decoded only when it has no real line break)",
                                        )
                                        property(
                                            "raw_request_hex",
                                            "string",
                                            "Request bytes, hex-encoded",
                                        )
                                        property(
                                            "pause_before",
                                            "integer",
                                            "n > 0: send the first n-1 bytes, then pause; n < 0: hold the last |n| bytes back for the pause",
                                        )
                                        putJsonObject("pause_markers") {
                                            put("type", "array")
                                            putJsonObject("items") { put("type", "string") }
                                            put(
                                                "description",
                                                "Pause after every occurrence of each string in the request",
                                            )
                                        }
                                        property(
                                            "pause_ms",
                                            "integer",
                                            "Length of each pause (0-60000, default 1000); ends early when response bytes arrive",
                                        )
                                    }
                                }
                                put(
                                    "description",
                                    "Array of {raw_request} or {raw_request_hex} items, with optional pause_before / pause_markers / pause_ms, sent over one connection",
                                )
                            }
                            enumProperty(
                                "write_mode",
                                WRITE_MODES,
                                "\"concat\" (default) or \"single_write\"",
                            )
                            property(
                                "write_pause_ms",
                                "number",
                                "Pause between writes in single_write mode (0-60000)",
                            )
                            property(
                                "max_responses",
                                "integer",
                                "How many responses to read (1-1000, default: number of requests)",
                            )
                            property(
                                "idle_timeout_ms",
                                "number",
                                "Stop when no bytes arrive for this long after the last request byte was written (1-600000, default 2000)",
                            )
                            property(
                                "total_timeout_ms",
                                "number",
                                "Hard cap for the whole call (1-600000, default 15000)",
                            )
                            property(
                                "keep_open",
                                "boolean",
                                "Keep the socket open for a later call to reuse via connection_id (default false)",
                            )
                            property(
                                "connection_id",
                                "string",
                                "Reuse a socket kept open by a prior keep_open=true call (same host, port, TLS and sni only)",
                            )
                            property(
                                "max_response_length",
                                "integer",
                                "Truncate each response body in the result",
                            )
                            property(
                                "decode_content",
                                "boolean",
                                "Show bodies with their Content-Encoding (gzip, deflate) undone (default false)",
                            )
                            property(
                                "raw_hex_max_bytes",
                                "integer",
                                "Cap on each raw hex dump (0-10000000, default 65536; 0 leaves them out)",
                            )
                        },
                    required = listOf("host", "requests"),
                ),
        ) { request ->
            try {
                val args = ToolArgs(request.params.arguments ?: emptyMap())

                val host =
                    args.string("host") ?: return@addTool toolError("Parameter 'host' is required")
                val requests =
                    requestSpecs(args)
                        ?: return@addTool toolError(
                            "Parameter 'requests' is required (array of {raw_request} or {raw_request_hex} objects)",
                        )
                val port = args.portOrDefault(PORTS)
                val useTls = args.tls(port)
                val httpMode = args.enum("http_mode", PIPELINE_HTTP_MODES)
                val writeMode = args.enum("write_mode", WRITE_MODES) ?: "concat"
                val writePauseMs = args.clampedLong("write_pause_ms", WRITE_PAUSES_MS) ?: 0L
                val maxResponses = args.clampedInt("max_responses", MAX_RESPONSES)
                val idleTimeoutMs =
                    args.clampedLong("idle_timeout_ms", PIPELINE_TIMEOUTS_MS) ?: 2000L
                val totalTimeoutMs =
                    args.clampedLong("total_timeout_ms", PIPELINE_TIMEOUTS_MS) ?: 15000L
                val keepOpen = args.bool("keep_open") ?: false
                val connectionId = args.string("connection_id")
                val maxResponseLength = args.clampedInt("max_response_length", LENGTHS)
                val sni = args.string("sni")
                val decodeContent = args.bool("decode_content") ?: false
                val rawHexMaxBytes =
                    args.clampedInt("raw_hex_max_bytes", RAW_HEX_BYTES)
                        ?: HttpPipelineBridge.DEFAULT_RAW_HEX_MAX_BYTES

                toolJsonResult(
                    args.withNotes(
                        pipeline.send(
                            host,
                            port,
                            useTls,
                            httpMode,
                            requests,
                            writeMode,
                            writePauseMs,
                            maxResponses,
                            idleTimeoutMs,
                            totalTimeoutMs,
                            keepOpen,
                            connectionId,
                            maxResponseLength,
                            sni,
                            decodeContent,
                            rawHexMaxBytes,
                        ),
                    ),
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }

    private fun registerConnections(server: Server, pipeline: HttpPipelineBridge) {
        server.addTool(
            name = "http_pipeline_connections",
            description =
                """List the connections http_send_pipeline keeps open for reuse (keep_open: true), optionally closing some first.

A connection an http_send_pipeline call is using right now is busy: closing leaves it open and reports it under busy, unless force is true, which closes it and makes that call end with a read or write error. A connection no call has used for 120 s is closed automatically (checked every 30 s).

Parameters:
- close (array of connection ids): close these first.
- close_all (bool, default false): close every kept connection first.
- force (bool, default false): also close busy connections.

Returns: connections (those still kept: connection_id, host, port, use_tls, sni when one was given, age_ms, idle_ms, busy, evicts_in_ms for one not in use) and, when closing, closed, unknown and busy (ids).""",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("close") {
                                put("type", "array")
                                putJsonObject("items") { put("type", "string") }
                                put("description", "Connection ids to close")
                            }
                            property(
                                "close_all",
                                "boolean",
                                "Close every kept connection (default false)",
                            )
                            property(
                                "force",
                                "boolean",
                                "Also close connections a running call is using; that call then fails (default false)",
                            )
                        },
                ),
        ) { request ->
            try {
                val args = ToolArgs(request.params.arguments ?: emptyMap())
                val close =
                    args["close"]
                        ?.let { element ->
                            element.asStringList()
                                ?: throw IllegalArgumentException(
                                    "'close' must be an array of connection ids",
                                )
                        }
                        .orEmpty()
                val closeAll = args.bool("close_all") ?: false
                val force = args.bool("force") ?: false
                toolJsonResult(args.withNotes(pipeline.connections(close, closeAll, force)))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }

    /**
     * The `requests` items as the bridge sends them, or null when absent. A malformed item throws
     * naming it (`requests[1]: ...`); an item's clamped numbers add notes to [args], prefixed the
     * same way.
     */
    private fun requestSpecs(args: ToolArgs): List<PipelineRequestSpec>? =
        args.objectList("requests", "request")?.mapIndexed { index, item ->
            requestSpec(index, item, args.notes)
        }

    private fun requestSpec(
        index: Int,
        item: JsonObject,
        notes: MutableList<String>,
    ): PipelineRequestSpec =
        try {
            val itemArgs = ToolArgs(item)
            val bytes = requestBytes(itemArgs)
            require(bytes.isNotEmpty()) { "the request is empty" }
            val pauseBefore =
                itemArgs.clampedLong("pause_before", -bytes.size.toLong()..bytes.size + 1L)?.toInt()
                    ?: 0
            // A UTF-8 request holds é as two bytes: its markers are matched in that encoding too.
            val requestUtf8 =
                itemArgs.string("raw_request_hex") == null &&
                    itemArgs.string("raw_request")?.let {
                        RequestHygiene.wireCharset(RequestHygiene.unescapeLineEndings(it))
                    } == Charsets.UTF_8
            val markers = pauseMarkers(itemArgs["pause_markers"], requestUtf8)
            val pauseMs =
                itemArgs.clampedLong("pause_ms", PAUSES_MS) ?: PipelineRequestSpec.DEFAULT_PAUSE_MS
            val offsets =
                PipelineRequestSpec.pauseOffsets(bytes, pauseBefore, markers.map { it.second })
            markers
                .filter { (_, marker) -> PipelineRequestSpec.indexOf(bytes, marker, 0) < 0 }
                .forEach { (text, _) ->
                    itemArgs.notes +=
                        "pause marker '$text' does not occur in the request; it adds no pause."
                }
            if (offsets.isEmpty() && itemArgs.has("pause_ms")) {
                itemArgs.notes +=
                    "pause_ms has no effect: there is no pause_before or matching pause marker."
            }
            notes += itemArgs.notes.map { "requests[$index]: $it" }
            PipelineRequestSpec(bytes, offsets, pauseMs)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("requests[$index]: ${e.message}", e)
        }

    private fun requestBytes(item: ToolArgs): ByteArray {
        item.string("raw_request_hex")?.let {
            return RequestHygiene.decodeHex(it)
        }
        val text =
            item.string("raw_request")
                ?: throw IllegalArgumentException("must have 'raw_request' or 'raw_request_hex'")
        return RequestHygiene.unescapeLineEndings(text).let {
            it.toByteArray(RequestHygiene.wireCharset(it))
        }
    }

    /**
     * `pause_markers` as (text as given, bytes to match), after the same `\r\n` escape decoding as
     * `raw_request`: in the charset the request goes out in ([requestUtf8]), else ISO-8859-1, or
     * UTF-8 for text with a char above U+00FF.
     */
    private fun pauseMarkers(
        element: JsonElement?,
        requestUtf8: Boolean,
    ): List<Pair<String, ByteArray>> {
        val texts =
            element?.let {
                it.asStringList()
                    ?: throw IllegalArgumentException("'pause_markers' must be an array of strings")
            } ?: return emptyList()
        return texts.mapIndexed { k, text ->
            val marker = RequestHygiene.unescapeLineEndings(text)
            require(marker.isNotEmpty()) { "pause_markers[$k] is empty" }
            text to
                marker.toByteArray(
                    if (requestUtf8) Charsets.UTF_8 else RequestHygiene.wireCharset(marker),
                )
        }
    }
}
