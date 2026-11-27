package io.bitbytelab.raijin.tools.http

import io.bitbytelab.raijin.bridge.FuzzResponseFilter
import io.bitbytelab.raijin.bridge.HttpBridge
import io.bitbytelab.raijin.bridge.HttpFuzzPlan
import io.bitbytelab.raijin.bridge.HttpFuzzRunner
import io.bitbytelab.raijin.bridge.HttpRace
import io.bitbytelab.raijin.bridge.HttpResponseClusters
import io.bitbytelab.raijin.bridge.PayloadEncoders
import io.bitbytelab.raijin.core.PayloadLibraries
import io.bitbytelab.raijin.core.asJsonObjectSafe
import io.bitbytelab.raijin.core.asStringList
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.safety.ScopeGate
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

/**
 * The attack tools over [HttpBridge]: `http_fuzz` (Burp Intruder's four attack types, concurrency,
 * rate limit, payload encoders, response filters, response clustering) and `http_race`
 * (synchronised release: HTTP/2 single-packet or HTTP/1.1 last-byte).
 */
internal object HttpAttackTools {

    private val CONCURRENCY = 1..50

    /**
     * Body chars kept per listed exchange with report=all when the caller gives no
     * max_response_length.
     */
    private const val FUZZ_BODY_CAP = 20_000
    private val RATE_LIMIT = 0.0..1_000.0
    private val SIMILARITY = 0.0..100.0
    private val MAX_REQUESTS = 1L..100_000L
    private const val DEFAULT_MAX_REQUESTS = 10_000L
    private val RACE_COUNTS = 1..1_000

    fun register(server: Server, bridge: HttpBridge) {
        registerFuzz(server, bridge)
        registerRace(server, bridge)
    }

    private fun registerFuzz(server: Server, bridge: HttpBridge) {
        server.addTool(
            name = "http_fuzz",
            description =
                """Fuzz an HTTP request like Burp Intruder: payloads placed at injection points, sent through Burp, every response clustered.

Injection points (first that applies):
1. Marker pairs: wrap values with § (or a custom marker): GET /api?id=§1§&name=§test§ HTTP/1.1\r\n... Each §value§ pair is a position; a position not being fuzzed keeps its value without the markers. An odd number of markers is rejected. Takes precedence over the FUZZ keyword when both appear.
2. FUZZ keyword: used only when there are no § marker pairs. Every FUZZ is an injection point. Example: GET /api?id=FUZZ HTTP/1.1\r\nHost: target.com\r\n\r\n
3. positions: non-overlapping [start, end) offsets into the request string as given.

attack_mode (Intruder's attack types):
- sniper (default): one payload set; each position in turn takes every payload, the others keep their value (with FUZZ, every occurrence takes the payload at once).
- battering_ram: one payload set; every position takes the same payload.
- pitchfork: one set per position, walked in step (request n = n-th payload of every set; as many requests as the smallest set).
- cluster_bomb: one set per position, every combination (position 1 turns fastest).
Payload sets: payloads (+ payload_library) form one set; for pitchfork/cluster_bomb give payload_sets instead (set i -> position i; with fewer sets than positions the last set is reused). encoders (e.g. ["url"], ["base64","url"]) run on each payload before it is placed: ${PayloadEncoders.names.joinToString(", ")}.

Use \r\n line endings (bare LF in the request line and headers is converted; the body is sent as typed). Content-Length is recomputed after each substitution, counted in the bytes sent (left alone with Transfer-Encoding or several Content-Length headers, for the whole run when an injection point sits on the Content-Length line, and with auto_fix_content_length=false); a request goes out as ISO-8859-1 (one byte per char), or as UTF-8 when it holds a char above U+00FF. concurrency (1-50, default 1) requests in flight, rate_limit requests/second (0 = unlimited). timeout_ms bounds each request; a failed or timed-out request is reported in its entry and the run goes on. stop_on_match ({status_codes: [int], body_regex: string}) stops after the first matching response (stopped_early:true). max_requests caps the run (default 10000).

Every response is clustered (summary: same status and bodies at least cluster_similarity % alike, default 90; timing outliers). Filters only shorten the list (hidden responses still count in the summary): hide_status [int], filter_length [int or "min-max"] (body bytes), grep_regex (keep only matches), hide_regex. report: "all" (default, every kept exchange in full), "clusters" (one line per kept request plus one full exchange per cluster), "summary" (summary only). With report=all and no max_response_length, each listed body is capped at 20000 chars. Out-of-range numbers are clamped and reported in notes.""" +
                    "\n\n" +
                    ScopeGate.TOOL_NOTE +
                    " The URL checked is the first planned request's.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            property(
                                "request",
                                "string",
                                "Request string with FUZZ keyword or § markers",
                            )
                            property("host", "string", "Target hostname")
                            property(
                                "port",
                                "integer",
                                "Target port number (1-65535; default: the Host header's port when it names host, else 443, or 80 with use_tls=false)",
                                minimum = 1,
                                maximum = 65535,
                            )
                            property("use_tls", "boolean", "Whether to use HTTPS (TLS)")
                            property("tls", "boolean", "Alias for use_tls")
                            property("https", "boolean", "Alias for use_tls")
                            enumProperty(
                                "http_mode",
                                HttpTools.HTTP_MODES,
                                "HTTP version to use (default AUTO)",
                            )
                            enumProperty(
                                "attack_mode",
                                HttpFuzzPlan.AttackMode.ids,
                                "Intruder attack type (default sniper)",
                            )
                            property("marker", "string", "Custom injection marker (default §)")
                            putJsonObject("positions") {
                                put("type", "array")
                                putJsonObject("items") {
                                    put("type", "array")
                                    putJsonObject("items") { put("type", "integer") }
                                }
                                put(
                                    "description",
                                    "Optional [start, end) offset pairs into the request string",
                                )
                            }
                            putJsonObject("payloads") {
                                put("type", "array")
                                putJsonObject("items") { put("type", "string") }
                                put("description", "Payload set 1 (sniper/battering_ram)")
                            }
                            enumProperty(
                                "payload_library",
                                PayloadLibraries.names(),
                                "Built-in payload set merged into 'payloads'",
                            )
                            putJsonObject("payload_sets") {
                                put("type", "array")
                                put(
                                    "description",
                                    "One set per position (pitchfork/cluster_bomb): each an array of strings, a library name, or {payloads: [...], library: name}",
                                )
                            }
                            putJsonObject("encoders") {
                                put("type", "array")
                                putJsonObject("items") {
                                    put("type", "string")
                                    putJsonArray("enum") {
                                        PayloadEncoders.names.forEach { add(it) }
                                    }
                                }
                                put("description", "Encoders applied to each payload, in order")
                            }
                            property(
                                "concurrency",
                                "integer",
                                "Requests in flight at once (1-50, default 1)",
                            )
                            property(
                                "rate_limit",
                                "number",
                                "Most requests started per second (0 = unlimited, max 1000)",
                            )
                            putJsonObject("hide_status") {
                                put("type", "array")
                                putJsonObject("items") { put("type", "integer") }
                                put(
                                    "description",
                                    "Status codes to leave out of the results (0 = no response)",
                                )
                            }
                            putJsonObject("filter_length") {
                                put("type", "array")
                                put(
                                    "description",
                                    "Body lengths in bytes to leave out: integers or \"min-max\" strings",
                                )
                            }
                            property(
                                "grep_regex",
                                "string",
                                "List only responses matching this regex (status line, headers, body)",
                            )
                            property(
                                "hide_regex",
                                "string",
                                "Leave out responses matching this regex",
                            )
                            enumProperty(
                                "report",
                                HttpFuzzRunner.REPORTS,
                                "How much of each exchange is listed (default all)",
                            )
                            property(
                                "cluster_similarity",
                                "number",
                                "Body similarity (0-100 %) for two responses to share a cluster (default 90)",
                            )
                            property(
                                "max_requests",
                                "integer",
                                "Cap on the requests sent (1-100000, default 10000)",
                            )
                            property(
                                "auto_fix_content_length",
                                "boolean",
                                "Recompute Content-Length after each substitution (default true); false sends every request as rendered",
                            )
                            property("max_response_length", "integer", "Truncate response bodies")
                            putJsonObject("stop_on_match") {
                                put("type", "object")
                                put(
                                    "description",
                                    "Stop after the first matching response: {status_codes: [int], body_regex: string}",
                                )
                            }
                            property(
                                "timeout_ms",
                                "number",
                                "Hard timeout per request in milliseconds (0 = default, -1 = no hard timeout, max 600000, default 25000)",
                                minimum = -1,
                            )
                        },
                    required = listOf("request", "host"),
                ),
        ) { request ->
            try {
                val args = ToolArgs(request.params.arguments ?: emptyMap())

                val reqStr =
                    args.string("request")
                        ?: return@addTool toolError("Parameter 'request' is required")
                val host =
                    args.string("host") ?: return@addTool toolError("Parameter 'host' is required")
                val port = args.targetPort(HttpTools.PORTS, host, reqStr)
                val useTls = args.tls(port)
                val httpMode = args.enum("http_mode", HttpTools.HTTP_MODES)
                val attackMode =
                    HttpFuzzPlan.AttackMode.of(
                        args.enum("attack_mode", HttpFuzzPlan.AttackMode.ids),
                    ) ?: HttpFuzzPlan.AttackMode.SNIPER
                val report =
                    args.enum("report", HttpFuzzRunner.REPORTS) ?: HttpFuzzRunner.REPORT_ALL
                // Every exchange in full, for up to 100000 requests: bound the bodies unless the
                // caller chose a size.
                val maxResponseLength =
                    args.clampedInt("max_response_length", HttpTools.LENGTHS)
                        ?: if (report == HttpFuzzRunner.REPORT_ALL) {
                            args.notes +=
                                "bodies capped at $FUZZ_BODY_CAP chars; pass max_response_length to change"
                            FUZZ_BODY_CAP
                        } else {
                            null
                        }
                val marker = args.string("marker")
                val timeoutMs = args.timeoutMs("timeout_ms", HttpTools.DEFAULT_TIMEOUT_MS)

                val stopOnMatch =
                    args["stop_on_match"]?.let {
                        it.asJsonObjectSafe()
                            ?: return@addTool toolError(
                                "Parameter 'stop_on_match' must be an object {status_codes: [int], body_regex: string}",
                            )
                    }
                val stopOnStatusCodes = parseStatusCodes(stopOnMatch?.get("status_codes"))
                val stopOnBodyRegex = stopOnMatch?.get("body_regex")?.jsonPrimitive?.contentOrNull

                val positions = parsePositions(args["positions"])
                val payloadSets = payloadSets(args)
                val encoders =
                    args["encoders"]
                        ?.let {
                            it.asStringList()
                                ?: return@addTool toolError(
                                    "Parameter 'encoders' must be an array of encoder names",
                                )
                        }
                        .orEmpty()
                PayloadEncoders.unknown(encoders)?.let {
                    return@addTool toolError(
                        "encoders: unknown encoder '$it'. Allowed: ${PayloadEncoders.names.joinToString(", ")}",
                    )
                }

                val grepRegex = args.string("grep_regex")
                val hideRegex = args.string("hide_regex")
                for ((param, pattern) in
                    listOf("grep_regex" to grepRegex, "hide_regex" to hideRegex)) {
                    if (pattern == null) continue
                    SafeRegex.validate(pattern)?.let {
                        return@addTool toolError("Parameter '$param' is not a valid regex: $it")
                    }
                }
                val filter =
                    FuzzResponseFilter(
                        hideStatus =
                            FuzzResponseFilter.parseStatuses(args["hide_status"], "hide_status"),
                        hideLengths = FuzzResponseFilter.parseLengths(args["filter_length"]),
                        grepRegex = grepRegex,
                        hideRegex = hideRegex,
                    )
                val maxRequests =
                    args.clampedLong("max_requests", MAX_REQUESTS) ?: DEFAULT_MAX_REQUESTS
                val runOptions =
                    HttpFuzzRunner.Options(
                        concurrency = args.clampedInt("concurrency", CONCURRENCY) ?: 1,
                        ratePerSecond = args.clampedDouble("rate_limit", RATE_LIMIT) ?: 0.0,
                        stopOnStatusCodes = stopOnStatusCodes,
                        stopOnBodyRegex = stopOnBodyRegex,
                        filter = filter,
                        report = report,
                        clusterSimilarity =
                            args.clampedDouble("cluster_similarity", SIMILARITY)
                                ?: HttpResponseClusters.DEFAULT_SIMILARITY,
                        payloadsCount = payloadSets.first().size,
                    )

                toolJsonResult(
                    args.withNotes(
                        bridge.fuzz(
                            reqStr,
                            host,
                            port,
                            useTls,
                            positions,
                            payloadSets,
                            marker,
                            attackMode,
                            encoders,
                            maxRequests,
                            httpMode,
                            maxResponseLength,
                            timeoutMs,
                            runOptions,
                            autoFixContentLength = args.bool("auto_fix_content_length") ?: true,
                        ),
                    ),
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }

    private fun registerRace(server: Server, bridge: HttpBridge) {
        server.addTool(
            name = "http_race",
            description =
                """Race condition tester (TOCTOU, double-spend, limit bypass): releases N requests at once behind a real synchronisation barrier, then clusters the responses.

sync:
- "single_packet" (default): the HTTP/2 single-packet attack through Burp's synchronised parallel sender (the engine behind Repeater's "send group in parallel" and Turbo's gated Engine.BURP2): the final frames of every request leave in one TCP packet, so network jitter cannot separate them. Needs a target that speaks HTTP/2 (http_mode HTTP_2_IGNORE_ALPN forces it without ALPN). Exchanges go through Burp (site map, session rules).
- "last_byte": HTTP/1.1 last-byte synchronisation on Raijin's own connections: each request on its own connection, written except its final byte; once every connection is primed (the barrier) the final bytes go out back to back. Reports per request ttfb_ms/ttlb_ms from its release and the release spread. Bypasses Burp (no session rules, not in the site map); sni sets the TLS server name. At most 256 connections. Chosen by default when http_mode is HTTP_1.

Use the FUZZ keyword with 'payloads' for one request per payload (payloads wins over 'count'); Content-Length is recomputed after substitution in the bytes sent (auto_fix_content_length=false sends it as written); a request goes out as ISO-8859-1, or as UTF-8 when it holds a char above U+00FF. timeout_ms bounds the whole batch.

analysis: responses clustered by status code and body similarity (cluster_similarity %, default 90) with timing outliers. race_condition_likely is true when identical requests were answered in more than one way; with payloads compare the clusters with the payloads instead. An equivalent set of responses does not rule a race out: check the application state too. Out-of-range numbers are clamped and reported in notes.""" +
                    "\n\n" +
                    ScopeGate.TOOL_NOTE,
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            property(
                                "request",
                                "string",
                                "Request string (use FUZZ keyword for varied payloads)",
                            )
                            property("host", "string", "Target hostname")
                            property(
                                "port",
                                "integer",
                                "Target port number (1-65535; default: the Host header's port when it names host, else 443, or 80 with use_tls=false)",
                                minimum = 1,
                                maximum = 65535,
                            )
                            property("use_tls", "boolean", "Whether to use HTTPS (TLS)")
                            property("tls", "boolean", "Alias for use_tls")
                            property("https", "boolean", "Alias for use_tls")
                            property(
                                "count",
                                "integer",
                                "Number of simultaneous requests (1-1000, default 10)",
                            )
                            property(
                                "auto_fix_content_length",
                                "boolean",
                                "Recompute Content-Length (default true); false sends the request as written",
                            )
                            putJsonObject("payloads") {
                                put("type", "array")
                                putJsonObject("items") { put("type", "string") }
                                put("description", "Optional payloads for FUZZ keyword")
                            }
                            enumProperty(
                                "sync",
                                HttpRace.Sync.ids,
                                "Synchronisation: single_packet (HTTP/2, default) or last_byte (HTTP/1.1)",
                            )
                            enumProperty(
                                "http_mode",
                                HttpTools.HTTP_MODES,
                                "HTTP_1 selects last_byte; HTTP_2_IGNORE_ALPN forces HTTP/2 without ALPN",
                            )
                            property(
                                "sni",
                                "string",
                                "TLS server name for last_byte connections (\"\" = none)",
                            )
                            property(
                                "cluster_similarity",
                                "number",
                                "Body similarity (0-100 %) for two responses to share a cluster (default 90)",
                            )
                            property("max_response_length", "integer", "Truncate response bodies")
                            property(
                                "timeout_ms",
                                "number",
                                "Hard timeout for the whole batch in milliseconds (0 = default, -1 = no hard timeout, max 600000, default 25000)",
                                minimum = -1,
                            )
                        },
                    required = listOf("request", "host"),
                ),
        ) { request ->
            try {
                val args = ToolArgs(request.params.arguments ?: emptyMap())
                val reqStr =
                    args.string("request")
                        ?: return@addTool toolError("Parameter 'request' is required")
                val host =
                    args.string("host") ?: return@addTool toolError("Parameter 'host' is required")
                val port = args.targetPort(HttpTools.PORTS, host, reqStr)
                val useTls = args.tls(port)
                val count = args.clampedInt("count", RACE_COUNTS) ?: 10
                val payloads =
                    args["payloads"]?.let {
                        it.asStringList()
                            ?: return@addTool toolError(
                                "Parameter 'payloads' must be an array of strings",
                            )
                    }
                val httpMode = args.enum("http_mode", HttpTools.HTTP_MODES)
                val sync =
                    HttpRace.Sync.of(args.enum("sync", HttpRace.Sync.ids))
                        ?: if (httpMode == "HTTP_1") HttpRace.Sync.LAST_BYTE
                        else HttpRace.Sync.SINGLE_PACKET
                if (sync == HttpRace.Sync.SINGLE_PACKET && httpMode == "HTTP_1") {
                    return@addTool toolError(
                        "sync=single_packet is an HTTP/2 technique: http_mode HTTP_1 needs sync=last_byte",
                    )
                }
                if (
                    sync == HttpRace.Sync.LAST_BYTE &&
                        httpMode != null &&
                        httpMode.startsWith("HTTP_2")
                ) {
                    return@addTool toolError(
                        "sync=last_byte sends HTTP/1.1: drop http_mode or use HTTP_1",
                    )
                }
                val sni = args.string("sni")
                if (sni != null && sync != HttpRace.Sync.LAST_BYTE) {
                    return@addTool toolError(
                        "'sni' applies to sync=last_byte only (Burp's parallel sender takes no SNI)",
                    )
                }
                val similarity =
                    args.clampedDouble("cluster_similarity", SIMILARITY)
                        ?: HttpResponseClusters.DEFAULT_SIMILARITY
                val maxResponseLength = args.clampedInt("max_response_length", HttpTools.LENGTHS)
                val timeoutMs = args.timeoutMs("timeout_ms", HttpTools.DEFAULT_TIMEOUT_MS)

                toolJsonResult(
                    args.withNotes(
                        bridge.raceCondition(
                            reqStr,
                            host,
                            port,
                            useTls,
                            count,
                            payloads,
                            sync,
                            httpMode,
                            sni,
                            maxResponseLength,
                            timeoutMs,
                            similarity,
                            autoFixContentLength = args.bool("auto_fix_content_length") ?: true,
                        ),
                    ),
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }

    /**
     * The payload sets of a fuzz call: `payload_sets` when given, else one set from `payloads` plus
     * `payload_library`.
     */
    private fun payloadSets(args: ToolArgs): List<List<String>> {
        val setsInput = args["payload_sets"]
        if (setsInput != null) {
            require(!args.has("payloads") && !args.has("payload_library")) {
                "Give either 'payload_sets' or 'payloads'/'payload_library', not both"
            }
            val sets =
                setsInput as? JsonArray
                    ?: throw IllegalArgumentException(
                        "'payload_sets' must be an array of payload sets",
                    )
            require(sets.isNotEmpty()) { "'payload_sets' must contain at least one set" }
            return sets.mapIndexed { i, item -> payloadSet(item, "payload_sets[$i]") }
        }
        val library = args.enum("payload_library", PayloadLibraries.names())
        val payloads =
            args["payloads"]
                ?.let {
                    it.asStringList()
                        ?: throw IllegalArgumentException(
                            "Parameter 'payloads' must be an array of strings",
                        )
                }
                .orEmpty() + library?.let { PayloadLibraries.get(it) }.orEmpty()
        require(payloads.isNotEmpty()) {
            "Provide 'payloads' (array) and/or 'payload_library' (${PayloadLibraries.names().joinToString("|")}), or 'payload_sets'"
        }
        return listOf(payloads)
    }

    private fun payloadSet(item: JsonElement, name: String): List<String> {
        val set =
            when (item) {
                is JsonArray ->
                    item.asStringList() ?: throw IllegalArgumentException("$name must hold strings")
                is JsonPrimitive -> library(item.contentOrNull, name)
                is JsonObject -> {
                    val listed =
                        item["payloads"]?.let {
                            it.asStringList()
                                ?: throw IllegalArgumentException(
                                    "$name.payloads must be an array of strings",
                                )
                        }
                    listed.orEmpty() +
                        (item["library"]?.let {
                                library((it as? JsonPrimitive)?.contentOrNull, "$name.library")
                            })
                            .orEmpty()
                }
            }
        require(set.isNotEmpty()) { "$name is empty: every payload set needs at least one payload" }
        return set
    }

    private fun library(name: String?, what: String): List<String> =
        name?.let { PayloadLibraries.get(it) }
            ?: throw IllegalArgumentException(
                "$what: unknown payload library '$name'. Allowed: ${PayloadLibraries.names().joinToString(", ")}",
            )

    private fun parsePositions(element: JsonElement?): List<Pair<Int, Int>>? {
        if (element == null || element is JsonNull) return null
        val items =
            element as? JsonArray
                ?: throw IllegalArgumentException(
                    "'positions' must be an array of [start, end] integer pairs",
                )
        return items.mapIndexed { i, item ->
            val pair = (item as? JsonArray)?.map { (it as? JsonPrimitive)?.intOrNull }
            val start = pair?.getOrNull(0)
            val end = pair?.getOrNull(1)
            require(pair?.size == 2 && start != null && end != null) {
                "positions[$i] must be a [start, end] pair of integers"
            }
            start to end
        }
    }

    private fun parseStatusCodes(element: JsonElement?): List<Int>? {
        if (element == null || element is JsonNull) return null
        val codes = (element as? JsonArray)?.map { (it as? JsonPrimitive)?.intOrNull }
        require(codes != null && codes.none { it == null }) {
            "stop_on_match.status_codes must be an array of integers"
        }
        return codes.filterNotNull()
    }
}
