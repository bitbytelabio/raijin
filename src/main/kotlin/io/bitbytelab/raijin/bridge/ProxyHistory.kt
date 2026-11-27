package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.MimeType
import burp.api.montoya.proxy.ProxyHistoryFilter
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketHistoryFilter
import burp.api.montoya.proxy.ProxyWebSocketMessage
import io.bitbytelab.raijin.bridge.ProxyBridge.Companion.MAX_PAGE_SIZE
import io.bitbytelab.raijin.bridge.ProxyBridge.Companion.safe
import io.bitbytelab.raijin.core.BodyText
import io.bitbytelab.raijin.core.HistoryCriteria
import io.bitbytelab.raijin.core.ProxyHistorySearch
import io.bitbytelab.raijin.core.SensitiveHeaders
import io.bitbytelab.raijin.core.StatusCodeRange
import io.bitbytelab.raijin.core.WebSocketHistoryCriteria
import io.bitbytelab.raijin.safety.SafeRegex
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.serialization.json.*

/**
 * Longest request, response or URL text a history search runs its regex over; longer ones are
 * counted as skipped_oversize.
 */
private const val MAX_SEARCH_INPUT = 5_000_000

/**
 * The proxy history reads of [ProxyBridge]: the HTTP and WebSocket history, filtered or searched
 * with a regex and served a page at a time. A message Burp cannot parse never fails a read: a
 * filter that needs the unreadable value skips it, and a listing reports it as far as it can.
 */
internal class ProxyHistory(private val api: MontoyaApi) {

    /**
     * Returns a slice of the HTTP proxy history with optional filtering.
     *
     * @param startIndex Zero-based offset into the filtered history.
     * @param count Maximum number of items to return; clamped to 0..[MAX_PAGE_SIZE] with a note in
     *   the result.
     * @param host Optional hostname filter (case-insensitive substring match).
     * @param method Optional HTTP method filter (exact, case-insensitive).
     * @param statusCode Optional exact status code filter.
     * @param mimeType Optional MIME type filter (case-insensitive name match).
     * @param inScopeOnly When true, only return in-scope items.
     * @param includeRequest Whether to include the full request text.
     * @param includeResponse Whether to include the full response text.
     * @param statusCodeRange Optional "min-max" range string for status codes.
     * @return JSON object with total count, returned count, and items array.
     */
    fun getHistory(
        startIndex: Int,
        count: Int,
        host: String?,
        method: String?,
        statusCode: Int?,
        mimeType: String?,
        inScopeOnly: Boolean,
        includeRequest: Boolean,
        includeResponse: Boolean,
        statusCodeRange: String?,
        maxResponseLength: Int?,
        includeHeaders: Boolean = true,
    ): JsonObject {
        // Resolve the optional MIME type filter up front so an unrecognized value
        // produces a clear error instead of silently dropping the filter (which
        // would return ALL history as if it matched).
        val resolvedMimeType: MimeType? =
            if (mimeType != null) {
                resolveMimeType(mimeType)
                    ?: return buildJsonObject {
                        put(
                            "error",
                            "Unknown mime_type: $mimeType. Valid values: ${mimeTypeValidValues()}",
                        )
                    }
            } else {
                null
            }

        // Validate the status-code range ONCE, up front — a malformed range now
        // returns a clear error instead of silently dropping the filter (which used
        // to return items outside the caller's intended range).
        val resolvedRange: StatusCodeRange.Range? =
            when (val r = StatusCodeRange.parse(statusCodeRange)) {
                is StatusCodeRange.Result.None -> null
                is StatusCodeRange.Result.Ok -> r.range
                is StatusCodeRange.Result.Invalid ->
                    return buildJsonObject { put("error", r.message) }
            }

        val criteria = HistoryCriteria(host, method, statusCode, resolvedRange)
        val filter = ProxyHistoryFilter { item ->
            try {
                if (inScopeOnly && !item.request().isInScope()) return@ProxyHistoryFilter false
                if (resolvedMimeType != null && item.mimeType() != resolvedMimeType)
                    return@ProxyHistoryFilter false
                // Each value is read only when its criterion is set, and guarded: a malformed
                // request throws from host()/method() and must not abort the whole read.
                criteria.matches(
                    host = if (criteria.host != null) safe { item.httpService().host() } else null,
                    method =
                        if (criteria.method != null) safe { item.finalRequest().method() }
                        else null,
                    status = if (criteria.needsStatus) responseStatus(item) else null,
                )
            } catch (_: Exception) {
                false
            }
        }

        val allItems = api.proxy().history(filter)
        val notes = mutableListOf<String>()
        val safeStart = ProxyLimits.clamp("start_index", startIndex, 0, Int.MAX_VALUE, notes)
        val slice =
            page(allItems, safeStart, ProxyLimits.clamp("count", count, 0, MAX_PAGE_SIZE, notes))

        return buildJsonObject {
            put("total_filtered", allItems.size)
            put("start_index", safeStart)
            put("returned", slice.size)
            nextStart(safeStart, slice.size, allItems.size)?.let { put("next_start_index", it) }
            put(
                "items",
                buildJsonArray {
                    slice.forEachIndexed { i, item ->
                        add(
                            serializeHistoryItem(
                                item,
                                safeStart + i,
                                includeRequest,
                                includeResponse,
                                maxResponseLength ?: 200_000,
                                includeHeaders,
                            ),
                        )
                    }
                },
            )
            putNotes(notes)
        }
    }

    /**
     * Searches proxy history using a regex pattern.
     *
     * @param pattern Regex pattern to match.
     * @param searchIn Where to search: "request", "response", or "both".
     * @param caseSensitive Whether the regex is case-sensitive.
     * @param maxResults Maximum number of matching items to return; clamped to 0..[MAX_PAGE_SIZE]
     *   with a note in the result.
     * @param inScopeOnly When true, only search in-scope items.
     * @param includeRequest Whether to include the full request text.
     * @param includeResponse Whether to include the full response text.
     * @return JSON object with match count and items array.
     */
    fun searchHistory(
        pattern: String,
        searchIn: String,
        caseSensitive: Boolean,
        maxResults: Int,
        inScopeOnly: Boolean,
        includeRequest: Boolean,
        includeResponse: Boolean,
        maxResponseLength: Int?,
        startIndex: Int = 0,
    ): JsonObject {
        val ignoreCase = !caseSensitive
        SafeRegex.validate(pattern, ignoreCase = ignoreCase)?.let { err ->
            return buildJsonObject {
                put("error", "proxy_history_search: 'pattern' is not a valid regex ($err).")
            }
        }
        val t = ProxyHistorySearch.targets(searchIn)
        val oversize = AtomicInteger()
        fun hit(text: String): Boolean {
            if (text.length > MAX_SEARCH_INPUT) {
                oversize.incrementAndGet()
                return false
            }
            return SafeRegex.containsMatchIn(
                pattern,
                text,
                ignoreCase = ignoreCase,
                maxInputLen = MAX_SEARCH_INPUT,
            )
        }

        val filter = ProxyHistoryFilter { item ->
            try {
                if (inScopeOnly && !item.request().isInScope()) return@ProxyHistoryFilter false

                var found = false
                if (t.url) {
                    // Match against the fully-reconstructed URL (scheme+host+path+query),
                    // which the request text does not expose as one contiguous string.
                    val url = safe { item.request().url() } ?: ""
                    found = hit(url)
                }
                if (!found && t.request) {
                    found = hit(safe { item.request().toString() } ?: "")
                }
                if (!found && t.response && item.hasResponse()) {
                    found = hit(safe { item.response().toString() } ?: "")
                }
                found
            } catch (_: Exception) {
                false
            }
        }

        val matches = api.proxy().history(filter)
        val notes = mutableListOf<String>()
        val safeStart = ProxyLimits.clamp("start_index", startIndex, 0, Int.MAX_VALUE, notes)
        val limited =
            page(
                matches,
                safeStart,
                ProxyLimits.clamp("max_results", maxResults, 0, MAX_PAGE_SIZE, notes),
            )

        return buildJsonObject {
            put("total_matches", matches.size)
            put("start_index", safeStart)
            put("returned", limited.size)
            nextStart(safeStart, limited.size, matches.size)?.let { put("next_start_index", it) }
            if (oversize.get() > 0) put("skipped_oversize", oversize.get())
            put("pattern", pattern)
            put("search_in", searchIn)
            put(
                "items",
                buildJsonArray {
                    limited.forEachIndexed { i, item ->
                        add(
                            serializeHistoryItem(
                                item,
                                safeStart + i,
                                includeRequest,
                                includeResponse,
                                maxResponseLength ?: 200_000,
                            ),
                        )
                    }
                },
            )
            putNotes(notes)
        }
    }

    /**
     * The start_index of the next page, or null when [returned] items from [start] reach [total].
     */
    private fun nextStart(start: Int, returned: Int, total: Int): Int? =
        (start.toLong() + returned).takeIf { returned > 0 && it < total }?.toInt()

    /**
     * Returns WebSocket proxy history with optional filtering.
     *
     * @param startIndex Zero-based offset.
     * @param count Maximum number of items; clamped to 0..[MAX_PAGE_SIZE] with a note in the
     *   result.
     * @param host Optional hostname filter.
     * @param direction Optional direction filter: "client_to_server", "server_to_client" or "both"
     *   (any case).
     * @param webSocketId Optional Burp id of one proxied connection (`websocket_id` of an item).
     * @param url Optional case-insensitive substring of the upgrade request's URL.
     * @return JSON object with items array.
     */
    fun getWebSocketHistory(
        startIndex: Int,
        count: Int,
        host: String?,
        direction: String?,
        webSocketId: Int?,
        url: String?,
    ): JsonObject {
        val dirName =
            when (val d = WebSocketHistoryCriteria.parseDirection(direction)) {
                is WebSocketHistoryCriteria.DirectionFilter.All -> null
                is WebSocketHistoryCriteria.DirectionFilter.Only -> d.name
                is WebSocketHistoryCriteria.DirectionFilter.Invalid ->
                    return buildJsonObject { put("error", d.message) }
            }
        val criteria = WebSocketHistoryCriteria(host, dirName, webSocketId, url)

        val allItems = api.proxy().webSocketHistory { item -> matchesCriteria(criteria, item) }
        val notes = mutableListOf<String>()
        val safeStart = ProxyLimits.clamp("start_index", startIndex, 0, Int.MAX_VALUE, notes)
        val slice =
            page(allItems, safeStart, ProxyLimits.clamp("count", count, 0, MAX_PAGE_SIZE, notes))

        return buildJsonObject {
            put("total_filtered", allItems.size)
            put("start_index", safeStart)
            put("returned", slice.size)
            put(
                "items",
                buildJsonArray {
                    slice.forEach { item -> add(serializeWebSocketItem(item)) }
                },
            )
            putNotes(notes)
        }
    }

    /**
     * Searches WebSocket proxy history using a regex pattern on message payloads.
     *
     * @param pattern Regex pattern.
     * @param direction Optional direction filter.
     * @param maxResults Maximum results; clamped to 0..[MAX_PAGE_SIZE] with a note in the result.
     * @param webSocketId Optional Burp id of one proxied connection.
     * @param url Optional case-insensitive substring of the upgrade request's URL.
     * @return JSON object with match results.
     */
    fun searchWebSocketHistory(
        pattern: String,
        direction: String?,
        maxResults: Int,
        webSocketId: Int?,
        url: String?,
        startIndex: Int = 0,
    ): JsonObject {
        SafeRegex.validate(pattern, ignoreCase = true)?.let { err ->
            return buildJsonObject {
                put(
                    "error",
                    "proxy_websocket_history_search: 'pattern' is not a valid regex ($err).",
                )
            }
        }
        val dirName =
            when (val d = WebSocketHistoryCriteria.parseDirection(direction)) {
                is WebSocketHistoryCriteria.DirectionFilter.All -> null
                is WebSocketHistoryCriteria.DirectionFilter.Only -> d.name
                is WebSocketHistoryCriteria.DirectionFilter.Invalid ->
                    return buildJsonObject { put("error", d.message) }
            }
        val criteria = WebSocketHistoryCriteria(null, dirName, webSocketId, url)
        val oversize = AtomicInteger()

        val filter = ProxyWebSocketHistoryFilter { item ->
            try {
                if (!matchesCriteria(criteria, item)) return@ProxyWebSocketHistoryFilter false
                val payloadText = safe { item.payload().toString() } ?: ""
                if (payloadText.length > MAX_SEARCH_INPUT) {
                    oversize.incrementAndGet()
                    return@ProxyWebSocketHistoryFilter false
                }
                SafeRegex.containsMatchIn(
                    pattern,
                    payloadText,
                    ignoreCase = true,
                    maxInputLen = MAX_SEARCH_INPUT,
                )
            } catch (_: Exception) {
                false
            }
        }

        val matches = api.proxy().webSocketHistory(filter)
        val notes = mutableListOf<String>()
        val safeStart = ProxyLimits.clamp("start_index", startIndex, 0, Int.MAX_VALUE, notes)
        val limited =
            page(
                matches,
                safeStart,
                ProxyLimits.clamp("max_results", maxResults, 0, MAX_PAGE_SIZE, notes),
            )

        return buildJsonObject {
            put("total_matches", matches.size)
            put("start_index", safeStart)
            put("returned", limited.size)
            nextStart(safeStart, limited.size, matches.size)?.let { put("next_start_index", it) }
            if (oversize.get() > 0) put("skipped_oversize", oversize.get())
            put("pattern", pattern)
            put(
                "items",
                buildJsonArray {
                    limited.forEach { item -> add(serializeWebSocketItem(item)) }
                },
            )
            putNotes(notes)
        }
    }

    /**
     * Whether [item] passes [criteria]. Each value is read only when its criterion is set, and
     * guarded: a message Burp cannot describe never matches a criterion that needs the value.
     */
    private fun matchesCriteria(
        criteria: WebSocketHistoryCriteria,
        item: ProxyWebSocketMessage,
    ): Boolean =
        try {
            criteria.matches(
                upgradeHost =
                    if (criteria.host != null) safe { item.upgradeRequest()?.httpService()?.host() }
                    else null,
                direction =
                    if (criteria.direction != null) safe { item.direction().name } else null,
                webSocketId =
                    if (criteria.webSocketId != null) safe { item.webSocketId() } else null,
                upgradeUrl =
                    if (criteria.url != null) safe { item.upgradeRequest()?.url() } else null,
            )
        } catch (_: Exception) {
            false
        }

    // ---------------------------------------------------------------
    // Serialization helpers
    // ---------------------------------------------------------------

    /**
     * Serializes a [ProxyHttpRequestResponse] to a [JsonObject]. Every accessor is guarded: a
     * request Burp cannot parse (MalformedRequestException from method()/url()/path()) is reported
     * with `malformed_request` instead of failing the whole history read.
     */
    private fun serializeHistoryItem(
        item: ProxyHttpRequestResponse,
        position: Int,
        includeRequest: Boolean,
        includeResponse: Boolean,
        maxResponseLength: Int? = null,
        includeHeaders: Boolean = true,
    ): JsonObject {
        return buildJsonObject {
            // id: Burp's own message id (stable); index: the item's place in this filtered list
            // (pages with start_index).
            safe { item.id() }?.let { put("id", it) }
            put("index", position)
            safe { item.httpService() }
                ?.let { service ->
                    put("host", service.host())
                    put("port", service.port())
                    put("secure", service.secure())
                }
            val method = safe { item.finalRequest().method() }
            val url = safe { item.finalRequest().url() }
            val path = safe { item.finalRequest().path() }
            method?.let { put("method", it) }
            url?.let { put("url", it) }
            path?.let { put("path", it) }
            if (method == null || url == null || path == null) put("malformed_request", true)
            safe { item.edited() }?.let { put("edited", it) }
            safe { item.mimeType().name }?.let { put("mime_type", it) }
            val hasResponse = safe { item.hasResponse() } ?: false
            put("has_response", hasResponse)

            // Timing
            try {
                val time = item.time()
                if (time != null) put("time", time.toString())
            } catch (_: Exception) {}

            // Timing data
            try {
                val td = item.timingData()
                if (td != null) {
                    put(
                        "timing",
                        buildJsonObject {
                            put(
                                "time_to_first_byte_ms",
                                td.timeBetweenRequestSentAndStartOfResponse().toMillis(),
                            )
                            put(
                                "time_to_complete_ms",
                                td.timeBetweenRequestSentAndEndOfResponse().toMillis(),
                            )
                        },
                    )
                }
            } catch (_: Exception) {}

            // Response metadata
            if (hasResponse) {
                try {
                    val resp = item.response()
                    put("status_code", resp.statusCode().toInt())
                    put("response_length", resp.body().length())
                    put("response_mime_type", resp.mimeType().name)
                } catch (_: Exception) {}
            }

            // Annotations
            try {
                val ann = item.annotations()
                if (ann.hasNotes()) put("comment", ann.notes())
                if (ann.hasHighlightColor()) put("highlight", ann.highlightColor().name)
            } catch (_: Exception) {}

            // Request headers — names/shape always preserved for recon; the VALUES of
            // credential-bearing headers (Cookie, Authorization, …) are redacted unless the
            // caller explicitly requested full request material (issue #20).
            if (includeHeaders)
                try {
                    put(
                        "request_headers",
                        buildJsonArray {
                            item.request().headers().forEach { h ->
                                add(
                                    buildJsonObject {
                                        put("name", h.name())
                                        put(
                                            "value",
                                            SensitiveHeaders.value(
                                                h.name(),
                                                h.value(),
                                                includeRequest,
                                            ),
                                        )
                                    },
                                )
                            }
                        },
                    )
                } catch (_: Exception) {}

            // Full request text. Routed through BodyText so a binary body (a file upload) can
            // never put an unencodable lone surrogate into the JSON — see issue #12.
            if (includeRequest) {
                try {
                    val r =
                        BodyText.render(
                            item.request().toString(),
                            maxResponseLength,
                            label = "request body",
                        )
                    put("request", r.text)
                    if (r.binary) put("request_binary", true)
                    if (r.truncated) put("request_truncated", true)
                } catch (_: Exception) {
                    put("request", "")
                }
            }

            // Full response text. A binary body (font/image/archive) is replaced by a placeholder
            // rather than string-converted: doing the latter corrupted the WHOLE batch's JSON for
            // the client, not just this item (issue #12).
            if (includeResponse && hasResponse) {
                try {
                    val mime = safe { item.response().mimeType().name }
                    val r =
                        BodyText.render(
                            item.response().toString(),
                            maxResponseLength,
                            mime,
                            "response body",
                        )
                    put("response", r.text)
                    if (r.binary) put("response_binary", true)
                    if (r.truncated) put("response_truncated", true)
                } catch (_: Exception) {
                    put("response", "")
                }
            }
        }
    }

    /** Serializes a [ProxyWebSocketMessage] to a [JsonObject]. */
    private fun serializeWebSocketItem(item: ProxyWebSocketMessage): JsonObject {
        return buildJsonObject {
            safe { item.id() }?.let { put("id", it) }
            safe { item.webSocketId() }?.let { put("websocket_id", it) }
            safe { item.direction().name }?.let { put("direction", it) }
            safe { item.listenerPort() }?.let { put("listener_port", it) }

            try {
                val time = item.time()
                if (time != null) put("time", time.toString())
            } catch (_: Exception) {}

            try {
                val payload = item.payload()
                // Binary WebSocket frames are the same JSON hazard as binary HTTP bodies (issue
                // #12).
                val r = BodyText.render(payload.toString(), label = "payload")
                put("payload", r.text)
                if (r.binary) put("payload_binary", true)
                if (r.truncated) put("payload_truncated", true)
                put("payload_length", payload.length())
            } catch (_: Exception) {
                put("payload", "")
                put("payload_length", 0)
            }

            try {
                val editedPayload = item.editedPayload()
                if (editedPayload != null) {
                    put(
                        "edited_payload",
                        BodyText.render(editedPayload.toString(), label = "payload").text,
                    )
                }
            } catch (_: Exception) {}

            try {
                val ann = item.annotations()
                if (ann.hasNotes()) put("comment", ann.notes())
                if (ann.hasHighlightColor()) put("highlight", ann.highlightColor().name)
            } catch (_: Exception) {}

            try {
                val upgradeReq = item.upgradeRequest()
                if (upgradeReq != null) {
                    put("upgrade_url", upgradeReq.url())
                    put("upgrade_host", upgradeReq.httpService().host())
                }
            } catch (_: Exception) {}
        }
    }

    /** Status code of [item]'s response, or null when it has none or it cannot be read. */
    private fun responseStatus(item: ProxyHttpRequestResponse): Int? =
        if (item.hasResponse()) safe { item.response().statusCode().toInt() } else null

    /**
     * Up to [count] (capped at [MAX_PAGE_SIZE]) items from [from], as a view (no copy of the list).
     */
    private fun <T> page(items: List<T>, from: Int, count: Int): List<T> {
        val start = from.coerceIn(0, items.size)
        val end =
            (start.toLong() + count.coerceIn(0, MAX_PAGE_SIZE))
                .coerceAtMost(items.size.toLong())
                .toInt()
        return items.subList(start, end)
    }

    private fun JsonObjectBuilder.putNotes(notes: List<String>) {
        if (notes.isNotEmpty()) put("notes", buildJsonArray { notes.forEach { add(it) } })
    }

    /**
     * Resolves a caller-supplied MIME type string to a [MimeType] enum constant.
     *
     * Accepts both the Montoya enum constant names (e.g. "JSON", "HTML") and a set of common
     * content-type / alias spellings (e.g. "application/json", "text/html", "javascript"). Returns
     * null if it cannot be resolved.
     */
    private fun resolveMimeType(input: String): MimeType? {
        val normalized = input.trim()

        // Direct enum constant match (case-insensitive), e.g. "JSON", "PLAIN_TEXT".
        try {
            return MimeType.valueOf(normalized.uppercase())
        } catch (_: Exception) {
            // fall through to alias resolution
        }

        // Common content-type strings and short aliases mapped to enum constants.
        return when (normalized.lowercase()) {
            "application/json",
            "json",
            "text/json" -> MimeType.JSON
            "text/html",
            "html",
            "application/xhtml+xml",
            "xhtml" -> MimeType.HTML
            "text/plain",
            "plain",
            "text" -> MimeType.PLAIN_TEXT
            "text/css",
            "css" -> MimeType.CSS
            "application/javascript",
            "text/javascript",
            "javascript",
            "js",
            "script" -> MimeType.SCRIPT
            "application/xml",
            "text/xml",
            "xml" -> MimeType.XML
            "application/yaml",
            "text/yaml",
            "yaml",
            "yml" -> MimeType.YAML
            "text/event-stream",
            "sse" -> MimeType.SSE
            "application/rtf",
            "text/rtf",
            "rtf" -> MimeType.RTF
            "image/svg+xml",
            "svg" -> MimeType.IMAGE_SVG_XML
            "image/png",
            "png" -> MimeType.IMAGE_PNG
            "image/jpeg",
            "image/jpg",
            "jpeg",
            "jpg" -> MimeType.IMAGE_JPEG
            "image/gif",
            "gif" -> MimeType.IMAGE_GIF
            "image/bmp",
            "bmp" -> MimeType.IMAGE_BMP
            "image/tiff",
            "tiff",
            "tif" -> MimeType.IMAGE_TIFF
            else -> null
        }
    }

    /** A human-readable hint listing the accepted MIME type values, for error messages. */
    private fun mimeTypeValidValues(): String {
        val constants = MimeType.values().joinToString(", ") { it.name }
        return "$constants (also accepts common aliases such as application/json, text/html, " +
            "text/plain, application/javascript, application/xml, and image content-types like " +
            "image/png, image/jpeg, image/gif, image/svg+xml)"
    }
}
