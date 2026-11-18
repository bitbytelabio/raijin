package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.proxy.ProxyHistoryFilter
import burp.api.montoya.websocket.BinaryMessage
import burp.api.montoya.websocket.TextMessage
import burp.api.montoya.websocket.extension.ExtensionWebSocket
import burp.api.montoya.websocket.extension.ExtensionWebSocketMessageHandler
import io.bitbytelab.raijin.core.BodyText
import io.bitbytelab.raijin.graphql.BatchAttack
import io.bitbytelab.raijin.graphql.EngineFingerprinter
import io.bitbytelab.raijin.graphql.GQLSchema
import io.bitbytelab.raijin.graphql.GraphQl
import io.bitbytelab.raijin.graphql.ReachabilityGuard
import io.bitbytelab.raijin.graphql.SchemaCache
import io.bitbytelab.raijin.graphql.bruteforcer.SchemaBruteforcer
import io.bitbytelab.raijin.graphql.scanners.CyclesScanner
import io.bitbytelab.raijin.graphql.scanners.POIScanner
import io.bitbytelab.raijin.graphql.subscriptions.OpenResult
import io.bitbytelab.raijin.graphql.subscriptions.ProbeEvent
import io.bitbytelab.raijin.graphql.subscriptions.ProbeSocket
import io.bitbytelab.raijin.graphql.subscriptions.SubscriptionEndpoint
import io.bitbytelab.raijin.graphql.subscriptions.SubscriptionProbe
import io.bitbytelab.raijin.graphql.subscriptions.SubscriptionProtocol
import io.bitbytelab.raijin.safety.BoundedHttp
import io.bitbytelab.raijin.safety.ScopeGate
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * GraphQL security recon: introspection enumeration and, when introspection is
 * disabled, "Did you mean" field-suggestion enumeration; schema-driven scans, batched
 * queries, engine fingerprinting, schema reconstruction and a WebSocket subscription probe.
 * Scope-gated.
 */
class GraphQlBridge(private val api: MontoyaApi) {

    private val scopeGate = ScopeGate(api)

    private data class ProbeResponse(val status: Int, val contentType: String?, val body: String)

    private val schemaCache = SchemaCache<GQLSchema>()

    companion object {
        private val AUTO_HEADER_NAMES = setOf("authorization", "cookie", "x-api-key", "x-auth-token")
        private val CREDENTIAL_HEADER_NAMES = setOf("authorization", "cookie")

        /**
         * The identity headers of one request: several `Cookie` lines become one, joined with "; ";
         * any other repeated header keeps its last value.
         */
        internal fun mergeAutoHeaders(headers: List<Pair<String, String>>): Map<String, String> {
            val out = LinkedHashMap<String, String>()
            val names = HashMap<String, String>()
            for ((name, value) in headers) {
                val key = name.lowercase()
                if (key !in AUTO_HEADER_NAMES) continue
                val shown = names.getOrPut(key) { name }
                val previous = out[shown]
                out[shown] = if (key == "cookie" && previous != null) "$previous; $value" else value
            }
            return out
        }

        /** [explicit] plus the [auto] headers it does not name (compared without case), so none is sent twice. */
        internal fun withAutoHeaders(explicit: Map<String, String>, auto: Map<String, String>): Map<String, String> {
            val taken = explicit.keys.mapTo(HashSet()) { it.lowercase() }
            return auto.filterKeys { it.lowercase() !in taken } + explicit
        }

        /** How much of a response body `batch_attack` echoes back. */
        private const val MAX_RESPONSE_BODY_CHARS = 20_000

        /** Upper bound on one WebSocket upgrade of the subscription probe. */
        private const val WS_CONNECT_TIMEOUT_MS = 10_000L
    }

    /**
     * Looks up the most recent Proxy-history request to [url]'s host and lifts its
     * identity-bearing headers (auth/session), so a caller can opt into reusing
     * credentials already observed on the wire instead of supplying them by hand.
     */
    private fun autoHeadersForHost(url: String): Map<String, String> {
        // A host with an underscore (a Docker service) is left out of URI.host; the authority keeps it.
        val host = try {
            java.net.URI(url).let { it.host ?: it.rawAuthority?.substringAfterLast('@')?.substringBefore(':') }
        } catch (_: Exception) {
            null
        }?.takeIf { it.isNotEmpty() } ?: return emptyMap()
        return try {
            val filter = ProxyHistoryFilter { it.host().equals(host, ignoreCase = true) }
            // The newest request that carried credentials: a later anonymous one (a static file) has none to lend.
            val withCredentials = api.proxy().history(filter).asReversed().firstOrNull { item ->
                runCatching { item.request().headers().any { it.name().lowercase() in CREDENTIAL_HEADER_NAMES } }.getOrDefault(false)
            } ?: return emptyMap()
            mergeAutoHeaders(withCredentials.request().headers().map { it.name() to it.value() })
        } catch (_: Exception) { emptyMap() }
    }

    /** Explicit [headers] always win, by name in any case; auto-populated ones (when [autoHeaders]) only fill gaps. */
    private fun resolveHeaders(url: String, headers: Map<String, String>?, autoHeaders: Boolean): Map<String, String> {
        if (!autoHeaders) return headers ?: emptyMap()
        return withAutoHeaders(headers.orEmpty(), autoHeadersForHost(url))
    }

    fun probe(url: String, headers: Map<String, String>? = null, autoHeaders: Boolean = false): JsonObject {
        val check = scopeGate.check(url)
        if (check.blocked) return check.denyJson()
        val effHeaders = resolveHeaders(url, headers, autoHeaders)
        val result: JsonObject = try {
            val introResp = postQuery(url, GraphQl.INTROSPECTION_QUERY, effHeaders)
            val introJson = try { Json.parseToJsonElement(introResp.body).jsonObject } catch (_: Exception) { null }

            if (introResp.status == 0) {
                // No HTTP response at all says nothing about GraphQL: report that instead of sending
                // the second probe and concluding "not_graphql" about a target that never answered.
                unreachable(url)
            } else if ((introJson?.get("data") as? JsonObject)?.get("__schema") != null) {
                // `as? JsonObject` returns null for JsonNull / non-objects, so error-only or
                // null-valued introspection responses fall through to the suggestion path safely.
                buildJsonObject {
                    put("endpoint", url)
                    put("verdict", "introspection_enabled")
                    put("introspection", GraphQl.summarize(introJson))
                    put("note", "Introspection is ENABLED — full schema disclosed; enumerate mutations for high-impact operations.")
                }
            } else {
                val badResp = postQuery(url, "query { zzNonexistentField_mcp1234 }", effHeaders)
                val badJson = try { Json.parseToJsonElement(badResp.body).jsonObject } catch (_: Exception) { null }

                // Neither POST parsed with the GraphQL response envelope (top-level data/errors)
                // — this almost certainly isn't a GraphQL endpoint at all, as opposed to a real
                // one with introspection locked down. Without this check both cases look
                // identical: no __schema, no suggestions.
                if (!GraphQl.looksLikeGraphQlResponse(introJson) && !GraphQl.looksLikeGraphQlResponse(badJson)) {
                    buildJsonObject {
                        put("endpoint", url)
                        put("verdict", "not_graphql")
                        put("introspection_status", introResp.status)
                        put(
                            "note",
                            "This endpoint does not respond like a GraphQL server — neither POST returned a JSON " +
                                "body with a top-level 'data' or 'errors' key (the GraphQL response envelope). " +
                                "Re-check the URL; this is NOT the same as introspection being disabled on a real " +
                                "GraphQL server."
                        )
                    }
                } else {
                    val suggestions = extractErrorMessages(badResp.body).flatMap { GraphQl.extractSuggestions(it) }
                    buildJsonObject {
                        put("endpoint", url)
                        put("verdict", "introspection_disabled")
                        put("introspection", buildJsonObject { put("introspection_enabled", false) })
                        put("field_suggestions_enabled", suggestions.isNotEmpty())
                        put("suggestions", buildJsonArray { suggestions.forEach { add(it) } })
                        put(
                            "note",
                            if (suggestions.isNotEmpty())
                                "Introspection disabled, but field suggestions leak schema — enumerate fields via 'Did you mean'."
                            else
                                "Introspection disabled and no field suggestions detected."
                        )
                    }
                }
            }
        } catch (e: Exception) {
            buildJsonObject { put("error", "GraphQL probe failed: ${e.message}") }
        }
        return check.annotate(result)
    }

    /**
     * Generates example queries/mutations/subscriptions from the live schema (depth-limited SDL
     * text per operation) — ported from InQL's `GQLQueryPrinter`, fed by a schema built from a
     * full introspection fetch (not [probe]'s lightweight one, which lacks the field/argument
     * detail schema modeling needs).
     */
    fun queryTemplates(
        url: String,
        maxDepth: Int,
        headers: Map<String, String>? = null,
        autoHeaders: Boolean = false,
        refreshSchema: Boolean = false,
    ): JsonObject {
        val check = scopeGate.check(url)
        if (check.blocked) return check.denyJson()
        val result = try {
            val (schema, err) = fetchFullSchema(url, resolveHeaders(url, headers, autoHeaders), refreshSchema)
            if (schema == null) return check.annotate(buildJsonObject { put("error", err) })
            buildJsonObject {
                put("endpoint", url)
                put("max_depth", maxDepth)
                put("queries", buildJsonObject { schema.queries.keys.forEach { put(it, schema.operationAsText(it, GQLSchema.OperationType.QUERY, maxDepth) ?: "") } })
                put("mutations", buildJsonObject { schema.mutations.keys.forEach { put(it, schema.operationAsText(it, GQLSchema.OperationType.MUTATION, maxDepth) ?: "") } })
                put("subscriptions", buildJsonObject { schema.subscriptions.keys.forEach { put(it, schema.operationAsText(it, GQLSchema.OperationType.SUBSCRIPTION, maxDepth) ?: "") } })
            }
        } catch (e: Exception) {
            buildJsonObject { put("error", "Query template generation failed: ${e.message}") }
        }
        return check.annotate(result)
    }

    /**
     * Flags security-interesting fields by name (auth/privileged/pii/payment/database/debugging/
     * files), deprecated fields, and custom scalars — ported from InQL's `POIScanner`.
     */
    fun poiScan(
        url: String,
        categories: Set<String>?,
        customKeywords: List<String>?,
        headers: Map<String, String>? = null,
        autoHeaders: Boolean = false,
        refreshSchema: Boolean = false,
    ): JsonObject {
        val check = scopeGate.check(url)
        if (check.blocked) return check.denyJson()
        val result = try {
            val (schema, err) = fetchFullSchema(url, resolveHeaders(url, headers, autoHeaders), refreshSchema)
            if (schema == null) return check.annotate(buildJsonObject { put("error", err) })
            val scanner = POIScanner(schema, categories ?: POIScanner.DEFAULT_CATEGORIES, customKeywords ?: emptyList())
            val found = scanner.scan()
            buildJsonObject {
                put("endpoint", url)
                put("categories_scanned", buildJsonArray { (categories ?: POIScanner.DEFAULT_CATEGORIES).forEach { add(it) } })
                put("flagged_count", found.values.sumOf { it.size })
                put("flagged", buildJsonObject {
                    found.forEach { (category, fields) ->
                        put(category, buildJsonArray {
                            fields.forEach { f ->
                                add(buildJsonObject {
                                    put("query_type", f.queryType)
                                    put("path", f.path)
                                    f.description?.let { put("description", it) }
                                })
                            }
                        })
                    }
                })
            }
        } catch (e: Exception) {
            buildJsonObject { put("error", "POI scan failed: ${e.message}") }
        }
        return check.annotate(result)
    }

    /**
     * Lists the cycles of the schema's type graph — types that can recurse into themselves
     * (deep-nesting/DoS risk). See [CyclesScanner] for what counts as a cycle and how the list is bounded.
     */
    fun cyclesScan(
        url: String,
        headers: Map<String, String>? = null,
        autoHeaders: Boolean = false,
        refreshSchema: Boolean = false,
    ): JsonObject {
        val check = scopeGate.check(url)
        if (check.blocked) return check.denyJson()
        val result = try {
            val (schema, err) = fetchFullSchema(url, resolveHeaders(url, headers, autoHeaders), refreshSchema)
            if (schema == null) return check.annotate(buildJsonObject { put("error", err) })
            val scanner = CyclesScanner(schema).detect()
            val cycles = scanner.cyclesAsStrings()
            val cyclicTypes = scanner.cyclicTypes()
            buildJsonObject {
                put("endpoint", url)
                put("cycle_count", cycles.size)
                put("truncated", scanner.truncated)
                put("cyclic_types", buildJsonArray { cyclicTypes.forEach { add(it) } })
                put("cycles", buildJsonArray { cycles.forEach { add(it) } })
                put(
                    "note",
                    when {
                        cyclicTypes.isEmpty() -> "No self-recursive type cycles found."
                        scanner.truncated ->
                            "These types can recurse into themselves — a deeply/recursively nested query against them is a DoS " +
                                "risk if the server doesn't cap query depth/complexity. Each cycle is a path from a root " +
                                "operation type that ends on a type it already went through. The list was cut at " +
                                "${cycles.size} cycles (shortest first); 'cyclic_types' is complete."
                        else ->
                            "These types can recurse into themselves — a deeply/recursively nested query against them is a DoS " +
                                "risk if the server doesn't cap query depth/complexity. Each cycle is a path from a root " +
                                "operation type that ends on a type it already went through."
                    }
                )
            }
        } catch (e: Exception) {
            buildJsonObject { put("error", "Cycle scan failed: ${e.message}") }
        }
        return check.annotate(result)
    }

    /**
     * Expands a `$[INT:first:last]`/`$[LIST]` placeholder in [template] into a batched/aliased
     * GraphQL query (see [BatchAttack]) — for 2FA brute force, IDOR enumeration, or rate-limit
     * bypass testing. Generates only by default; pass [send] to also fire it at [url].
     */
    fun batchAttack(
        url: String,
        template: String,
        values: List<String>?,
        send: Boolean,
        headers: Map<String, String>? = null,
        autoHeaders: Boolean = false,
    ): JsonObject {
        val expanded = try {
            BatchAttack.expand(template, values)
        } catch (e: BatchAttack.ExpansionException) {
            return buildJsonObject { put("error", e.message ?: "The template could not be expanded.") }
        } ?: return buildJsonObject {
            put(
                "error",
                if (values.isNullOrEmpty() && template.contains("\$[LIST]")) {
                    "The template uses \$[LIST] but 'values' is empty: pass the values to substitute."
                } else {
                    "No \$[INT:first:last] or \$[LIST] placeholder found (immediately before a '{' selection set) in the template."
                }
            )
        }

        if (!send) {
            return buildJsonObject {
                put("operations_generated", expanded.count)
                put("query", expanded.query)
            }
        }

        val check = scopeGate.check(url)
        if (check.blocked) return check.denyJson()
        val resp = postQuery(url, expanded.query, resolveHeaders(url, headers, autoHeaders))
        val result = buildJsonObject {
            put("endpoint", url)
            put("operations_generated", expanded.count)
            put("query", expanded.query)
            if (resp.status == 0) {
                put("error", unreachableMessage(url))
            } else {
                put("status", resp.status)
                put("response_body", BodyText.render(resp.body, MAX_RESPONSE_BODY_CHARS).text)
            }
        }
        return check.annotate(result)
    }

    /**
     * Detects the GraphQL backend engine (Apollo, Hasura, graphql-java, ...) by sending a
     * sequence of malformed/edge-case queries and matching each engine's distinctive error
     * text — ported from InQL's `Fingerprinter`. Stops at the first match, or as soon as the
     * target turns out not to answer (see [guardedSender]).
     */
    fun fingerprintEngine(url: String, headers: Map<String, String>? = null, autoHeaders: Boolean = false): JsonObject {
        val check = scopeGate.check(url)
        if (check.blocked) return check.denyJson()
        val effHeaders = resolveHeaders(url, headers, autoHeaders)
        val result = try {
            val outcome = EngineFingerprinter.detect(guardedSender(url, effHeaders))
            if (outcome.unreachable) {
                unreachable(url)
            } else {
                buildJsonObject {
                    put("endpoint", url)
                    put("engine", outcome.engine)
                    put("checked", outcome.checked)
                    put(
                        "note",
                        if (outcome.engine != null) "Backend engine fingerprinted as '${outcome.engine}' from a distinctive error signature."
                        else "No known engine signature matched after ${outcome.checked} checks."
                    )
                }
            }
        } catch (e: Exception) {
            buildJsonObject { put("error", "Engine fingerprinting failed: ${e.message}") }
        }
        return check.annotate(result)
    }

    /**
     * Reconstructs the schema by probing wordlists and parsing "did you mean"/type-mismatch
     * error messages — for targets with introspection disabled. Ported from InQL's Clairvoyance-
     * style `Bruteforcer`. Noisy and request-heavy: every field/type/arg guess is a live request,
     * so the run stops after [maxRequests] of them and returns the schema found so far.
     */
    fun bruteforceSchema(
        url: String,
        headers: Map<String, String>? = null,
        autoHeaders: Boolean = false,
        bucketSize: Int = 64,
        depthLimit: Int = 2,
        bruteforceArguments: Boolean = true,
        maxRequests: Int = SchemaBruteforcer.DEFAULT_MAX_REQUESTS,
    ): JsonObject {
        val check = scopeGate.check(url)
        if (check.blocked) return check.denyJson()
        val effHeaders = resolveHeaders(url, headers, autoHeaders)
        val result = try {
            val reconstruction = SchemaBruteforcer(
                sendQuery = guardedSender(url, effHeaders),
                bucketSize = bucketSize,
                depthLimit = depthLimit,
                bruteforceArguments = bruteforceArguments,
                maxRequests = maxRequests,
            ).run()
            val stopped = reconstruction.stopped
            if (stopped == SchemaBruteforcer.StopReason.UNREACHABLE && reconstruction.types.isEmpty()) {
                unreachable(url)
            } else {
                buildJsonObject {
                    put("endpoint", url)
                    put("requests_sent", reconstruction.requestsSent)
                    put("partial", stopped != null)
                    if (stopped != null) put("stopped_by", stopped.name.lowercase())
                    put("types", reconstruction.typesAsJson())
                    put(
                        "note",
                        "Reconstructed ${reconstruction.types.size} type(s) from error-message analysis " +
                            "(no introspection used). Field/type coverage depends on wordlist hits — treat this as a " +
                            "lower bound on the real schema, not a complete one." +
                            when (stopped) {
                                SchemaBruteforcer.StopReason.REQUEST_BUDGET ->
                                    " The run stopped at its budget of $maxRequests requests, so types and fields are " +
                                        "missing: raise 'max_requests', or lower 'depth_limit', to go further."
                                SchemaBruteforcer.StopReason.UNREACHABLE ->
                                    " The target stopped answering during the run, so types and fields are missing."
                                null -> ""
                            }
                    )
                }
            }
        } catch (e: Exception) {
            buildJsonObject { put("error", "Schema bruteforcing failed: ${e.message}") }
        }
        return check.annotate(result)
    }

    /**
     * Probes GraphQL subscriptions over WebSocket at [url] (`ws(s)://`, or the `http(s)://` URL of
     * the GraphQL endpoint): which of the two protocols' handshakes the server acknowledges,
     * whether `connection_init` needs credentials, and whether an operation can be started. See
     * [SubscriptionProbe] for the sessions it runs.
     *
     * Credentials are the caller's headers and [connectionPayload]. The anonymous sessions send
     * neither: of the headers they keep only those that identify nobody
     * ([SubscriptionEndpoint.anonymousHeaders]: Host, Origin, User-Agent), since a credential can
     * hide under any name (`x-hasura-admin-secret`, `apikey`).
     *
     * @param subscriptionQuery operation to start after `connection_ack`; null lets the probe pick one.
     * @param waitMs bound on each wait for a server message.
     */
    fun subscriptionProbe(
        url: String,
        headers: Map<String, String>? = null,
        autoHeaders: Boolean = false,
        subscriptionQuery: String? = null,
        connectionPayload: JsonObject? = null,
        waitMs: Long = SubscriptionProbe.DEFAULT_WAIT_MS,
    ): JsonObject {
        val endpoint = SubscriptionEndpoint.parse(url)
            .getOrElse { return buildJsonObject { put("error", it.message ?: "Invalid URL '$url'") } }
        val check = scopeGate.check(endpoint.httpUrl)
        if (check.blocked) return check.denyJson()
        val identified = resolveHeaders(endpoint.httpUrl, headers, autoHeaders)
        val anonymous = SubscriptionEndpoint.anonymousHeaders(identified)
        val result = try {
            SubscriptionProbe(
                open = { protocol, authenticated -> openSocket(endpoint, protocol, if (authenticated) identified else anonymous) },
                operation = subscriptionQuery?.takeIf { it.isNotBlank() },
                connectionPayload = connectionPayload,
                hasCredentials = anonymous.size != identified.size || !connectionPayload.isNullOrEmpty(),
                waitMs = waitMs,
            ).run().toJson(endpoint.wsUrl)
        } catch (e: Exception) {
            buildJsonObject { put("error", "Subscription probe failed: ${e.message}") }
        }
        return check.annotate(result)
    }

    /**
     * Performs one WebSocket upgrade, bounded by [WS_CONNECT_TIMEOUT_MS]. The socket is handed to
     * [MontoyaProbeSocket] on the thread that created it, so an upgrade that only completes after
     * the timeout still gets its socket closed rather than leaked.
     */
    private fun openSocket(
        endpoint: SubscriptionEndpoint,
        protocol: SubscriptionProtocol,
        headers: Map<String, String>,
    ): OpenResult {
        val socket = MontoyaProbeSocket()
        val result = BoundedHttp.runBounded(WS_CONNECT_TIMEOUT_MS) { upgrade(endpoint, protocol, headers, socket) }
        if (result !is OpenResult.Opened) socket.close()
        return result ?: OpenResult.Refused.of(OpenResult.Refused.TIMEOUT, detail = "no answer within $WS_CONNECT_TIMEOUT_MS ms")
    }

    private fun upgrade(
        endpoint: SubscriptionEndpoint,
        protocol: SubscriptionProtocol,
        headers: Map<String, String>,
        socket: MontoyaProbeSocket,
    ): OpenResult = try {
        val key = Base64.getEncoder().encodeToString(ByteArray(16).also { SecureRandom().nextBytes(it) })
        val request = HttpRequest.httpRequest(
            HttpService.httpService(endpoint.host, endpoint.port, endpoint.secure),
            endpoint.upgradeRequest(protocol.subprotocol, headers, key),
        )
        val creation = api.websockets().createWebSocket(request)
        val response = creation.upgradeResponse().orElse(null)
        val httpStatus = response?.statusCode()?.toInt()
        val webSocket = creation.webSocket().orElse(null)
        if (webSocket == null) {
            OpenResult.Refused.of(creation.status()?.name ?: "UNKNOWN", httpStatus)
        } else {
            socket.attach(webSocket)
            val selected = try { response?.headerValue("Sec-WebSocket-Protocol") } catch (_: Exception) { null }
            OpenResult.Opened(socket, httpStatus, selected)
        }
    } catch (e: Exception) {
        OpenResult.Refused.of(OpenResult.Refused.ERROR, detail = e.message ?: e.javaClass.simpleName)
    }

    /**
     * Fetches the FULL official introspection query (needed for schema modeling) and builds a
     * [GQLSchema]. The failure message distinguishes a connection failure (couldn't reach the
     * endpoint at all — `status == 0`) from a real HTTP response that just doesn't parse into a
     * schema (introspection genuinely disabled/malformed) — conflating the two previously made a
     * bad URL/unreachable host look identical to "introspection may be disabled". Successful
     * fetches are cached per (url, headers) in [schemaCache], bypassable via [refreshSchema].
     */
    private fun fetchFullSchema(
        url: String,
        headers: Map<String, String> = emptyMap(),
        refreshSchema: Boolean = false,
    ): Pair<GQLSchema?, String?> {
        if (!refreshSchema) schemaCache.get(url, headers)?.let { return it to null }
        val resp = postQuery(url, graphql.introspection.IntrospectionQuery.INTROSPECTION_QUERY, headers)
        if (resp.status == 0) {
            return null to unreachableMessage(url)
        }
        if (resp.body.isBlank()) {
            return null to "Endpoint returned an empty response body (HTTP ${resp.status}); introspection may be disabled."
        }
        val schema = try { GQLSchema(resp.body) } catch (_: Exception) { null }
        if (schema != null) schemaCache.put(url, headers, schema)
        return schema to (
            if (schema == null) "Could not build a schema from this endpoint's introspection response (HTTP ${resp.status}); introspection may be disabled."
            else null
        )
    }

    private fun unreachableMessage(url: String): String =
        "Could not reach $url (no HTTP response: the connection failed or timed out) — check the URL and that the target is reachable."

    private fun unreachable(url: String): JsonObject = buildJsonObject {
        put("error", unreachableMessage(url))
        put("endpoint", url)
        put("unreachable", true)
    }

    /**
     * A query sender for the modes that send many requests. It throws
     * [io.bitbytelab.raijin.graphql.TargetUnreachableException] once the target stops answering
     * (see [ReachabilityGuard]), so those modes end with one error instead of waiting out a timeout
     * for every request they still had to send.
     */
    private fun guardedSender(url: String, headers: Map<String, String>): (String) -> String {
        val guard = ReachabilityGuard()
        return { query ->
            val response = postQuery(url, query, headers)
            guard.record(response.status)
            response.body
        }
    }

    private fun postQuery(url: String, query: String, headers: Map<String, String> = emptyMap()): ProbeResponse {
        return try {
            val body = buildJsonObject { put("query", query) }.toString()
            val req = headers.entries.fold(
                HttpRequest.httpRequestFromUrl(url)
                    .withMethod("POST")
                    .withAddedHeader("Content-Type", "application/json")
                    .withBody(body)
            ) { r, (name, value) -> r.withAddedHeader(name, value) }
            val resp = BoundedHttp.send(api, req)?.response()
            ProbeResponse(
                status = resp?.statusCode()?.toInt() ?: 0,
                contentType = try { resp?.headerValue("Content-Type") } catch (_: Exception) { null },
                body = resp?.bodyToString() ?: ""
            )
        } catch (_: Exception) { ProbeResponse(0, null, "") }
    }

    private fun extractErrorMessages(body: String): List<String> = try {
        Json.parseToJsonElement(body).jsonObject["errors"]?.jsonArray
            ?.mapNotNull { it.jsonObject["message"]?.jsonPrimitive?.contentOrNull } ?: emptyList()
    } catch (_: Exception) { emptyList() }
}

/**
 * [ProbeSocket] over a Montoya extension WebSocket: server frames and the close are queued for
 * [receive]. [close] may come before [attach] (an upgrade abandoned at its timeout); the socket
 * is then closed the moment it arrives.
 */
private class MontoyaProbeSocket : ProbeSocket {
    private val events = LinkedBlockingQueue<ProbeEvent>()
    private var webSocket: ExtensionWebSocket? = null
    private var closed = false

    @Synchronized
    fun attach(ws: ExtensionWebSocket) {
        if (closed) {
            runCatching { ws.close() }
            return
        }
        webSocket = ws
        ws.registerMessageHandler(object : ExtensionWebSocketMessageHandler {
            override fun textMessageReceived(textMessage: TextMessage) = enqueue(textMessage.payload())

            // Both protocols are JSON text; a server that frames it as binary is still read.
            override fun binaryMessageReceived(binaryMessage: BinaryMessage) =
                enqueue(String(binaryMessage.payload().bytes, Charsets.UTF_8))

            override fun onClose() {
                events.offer(ProbeEvent.Closed)
            }
        })
    }

    /** Frames nobody reads are dropped past a bound, so a chatty stream cannot grow the queue without limit. */
    private fun enqueue(text: String) {
        if (events.size < MAX_QUEUED_FRAMES) events.offer(ProbeEvent.Text(text))
    }

    override fun send(text: String) {
        val ws = synchronized(this) { webSocket } ?: throw IllegalStateException("WebSocket is closed")
        ws.sendTextMessage(text)
    }

    override fun receive(timeoutMs: Long): ProbeEvent? = try {
        events.poll(timeoutMs, TimeUnit.MILLISECONDS)
    } catch (_: InterruptedException) {
        Thread.currentThread().interrupt()
        ProbeEvent.Closed
    }

    @Synchronized
    override fun close() {
        closed = true
        webSocket?.let { ws -> runCatching { ws.close() } }
        webSocket = null
    }

    private companion object {
        const val MAX_QUEUED_FRAMES = 256
    }
}
