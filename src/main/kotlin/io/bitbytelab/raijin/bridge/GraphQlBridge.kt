package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.proxy.ProxyHistoryFilter
import io.bitbytelab.raijin.safety.BoundedHttp
import burp.api.montoya.http.message.requests.HttpRequest
import io.bitbytelab.raijin.graphql.BatchAttack
import io.bitbytelab.raijin.graphql.EngineFingerprinter
import io.bitbytelab.raijin.graphql.GQLSchema
import io.bitbytelab.raijin.graphql.GraphQl
import io.bitbytelab.raijin.graphql.bruteforcer.SchemaBruteforcer
import io.bitbytelab.raijin.graphql.scanners.CyclesScanner
import io.bitbytelab.raijin.graphql.scanners.POIScanner
import io.bitbytelab.raijin.safety.ScopeGate
import java.time.Duration
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
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
 * disabled, "Did you mean" field-suggestion enumeration. Scope-gated.
 */
class GraphQlBridge(private val api: MontoyaApi) {

    private val scopeGate = ScopeGate(api)

    private data class ProbeResponse(val status: Int, val contentType: String?, val body: String)

    private val schemaCache = ConcurrentHashMap<String, Pair<GQLSchema, Instant>>()

    companion object {
        private val SCHEMA_CACHE_TTL: Duration = Duration.ofMinutes(10)
        private val AUTO_HEADER_NAMES = setOf("authorization", "cookie", "x-api-key", "x-auth-token")
    }

    /**
     * Looks up the most recent Proxy-history request to [url]'s host and lifts its
     * identity-bearing headers (auth/session), so a caller can opt into reusing
     * credentials already observed on the wire instead of supplying them by hand.
     */
    private fun autoHeadersForHost(url: String): Map<String, String> {
        val host = try { java.net.URI(url).host } catch (_: Exception) { null } ?: return emptyMap()
        return try {
            val filter = ProxyHistoryFilter { it.host().equals(host, ignoreCase = true) }
            api.proxy().history(filter).lastOrNull()
                ?.request()
                ?.headers()
                ?.filter { it.name().lowercase() in AUTO_HEADER_NAMES }
                ?.associate { it.name() to it.value() }
                ?: emptyMap()
        } catch (_: Exception) { emptyMap() }
    }

    /** Explicit [headers] always win; auto-populated ones (when [autoHeaders]) only fill gaps. */
    private fun resolveHeaders(url: String, headers: Map<String, String>?, autoHeaders: Boolean): Map<String, String> {
        if (!autoHeaders) return headers ?: emptyMap()
        val auto = autoHeadersForHost(url)
        return if (headers.isNullOrEmpty()) auto else auto + headers
    }

    fun probe(url: String, headers: Map<String, String>? = null, autoHeaders: Boolean = false): JsonObject {
        val check = scopeGate.check(url)
        check.deny?.let { return it }
        val effHeaders = resolveHeaders(url, headers, autoHeaders)
        val result: JsonObject = try {
            val introResp = postQuery(url, GraphQl.INTROSPECTION_QUERY, effHeaders)
            val introJson = try { Json.parseToJsonElement(introResp.body).jsonObject } catch (_: Exception) { null }

            // `as? JsonObject` returns null for JsonNull / non-objects, so error-only or
            // null-valued introspection responses fall through to the suggestion path safely.
            if ((introJson?.get("data") as? JsonObject)?.get("__schema") != null) {
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
        return if (check.warning != null) JsonObject(result + ("scope_warning" to JsonPrimitive(check.warning))) else result
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
        check.deny?.let { return it }
        val result = try {
            val (schema, err) = fetchFullSchema(url, resolveHeaders(url, headers, autoHeaders), refreshSchema)
            if (schema == null) return buildJsonObject { put("error", err) }
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
        return withScopeWarning(result, check.warning)
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
        check.deny?.let { return it }
        val result = try {
            val (schema, err) = fetchFullSchema(url, resolveHeaders(url, headers, autoHeaders), refreshSchema)
            if (schema == null) return buildJsonObject { put("error", err) }
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
        return withScopeWarning(result, check.warning)
    }

    /** Flags types that can recurse into themselves (deep-nesting/DoS risk) — ported from InQL's `CyclesScanner`. */
    fun cyclesScan(
        url: String,
        headers: Map<String, String>? = null,
        autoHeaders: Boolean = false,
        refreshSchema: Boolean = false,
    ): JsonObject {
        val check = scopeGate.check(url)
        check.deny?.let { return it }
        val result = try {
            val (schema, err) = fetchFullSchema(url, resolveHeaders(url, headers, autoHeaders), refreshSchema)
            if (schema == null) return buildJsonObject { put("error", err) }
            val cycles = CyclesScanner(schema).detect().cyclesAsStrings()
            buildJsonObject {
                put("endpoint", url)
                put("cycle_count", cycles.size)
                put("cycles", buildJsonArray { cycles.forEach { add(it) } })
                put(
                    "note",
                    if (cycles.isNotEmpty())
                        "These types can recurse into themselves — a deeply/recursively nested query against them is a DoS risk if the server doesn't cap query depth/complexity."
                    else "No self-recursive type cycles found."
                )
            }
        } catch (e: Exception) {
            buildJsonObject { put("error", "Cycle scan failed: ${e.message}") }
        }
        return withScopeWarning(result, check.warning)
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
        val expanded = BatchAttack.expand(template, values)
            ?: return buildJsonObject { put("error", "No \$[INT:first:last] or \$[LIST] placeholder found (immediately before a '{' selection set) in the template.") }

        if (!send) {
            return buildJsonObject {
                put("operations_generated", expanded.count)
                put("query", expanded.query)
            }
        }

        val check = scopeGate.check(url)
        check.deny?.let { return it }
        val resp = postQuery(url, expanded.query, resolveHeaders(url, headers, autoHeaders))
        val result = buildJsonObject {
            put("endpoint", url)
            put("operations_generated", expanded.count)
            put("query", expanded.query)
            put("status", resp.status)
            put("response_body", resp.body.take(20_000))
        }
        return withScopeWarning(result, check.warning)
    }

    /**
     * Detects the GraphQL backend engine (Apollo, Hasura, graphql-java, ...) by sending a
     * sequence of malformed/edge-case queries and matching each engine's distinctive error
     * text — ported from InQL's `Fingerprinter`. Stops at the first match.
     */
    fun fingerprintEngine(url: String, headers: Map<String, String>? = null, autoHeaders: Boolean = false): JsonObject {
        val check = scopeGate.check(url)
        check.deny?.let { return it }
        val effHeaders = resolveHeaders(url, headers, autoHeaders)
        val result = try {
            val outcome = EngineFingerprinter.detect { query -> postQuery(url, query, effHeaders).body }
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
        } catch (e: Exception) {
            buildJsonObject { put("error", "Engine fingerprinting failed: ${e.message}") }
        }
        return withScopeWarning(result, check.warning)
    }

    /**
     * Reconstructs the schema by probing wordlists and parsing "did you mean"/type-mismatch
     * error messages — for targets with introspection disabled. Ported from InQL's Clairvoyance-
     * style `Bruteforcer`. Noisy and request-heavy: every field/type/arg guess is a live request.
     */
    fun bruteforceSchema(
        url: String,
        headers: Map<String, String>? = null,
        autoHeaders: Boolean = false,
        bucketSize: Int = 64,
        depthLimit: Int = 2,
        bruteforceArguments: Boolean = true,
    ): JsonObject {
        val check = scopeGate.check(url)
        check.deny?.let { return it }
        val effHeaders = resolveHeaders(url, headers, autoHeaders)
        val result = try {
            val reconstruction = SchemaBruteforcer(
                sendQuery = { query -> postQuery(url, query, effHeaders).body },
                bucketSize = bucketSize,
                depthLimit = depthLimit,
                bruteforceArguments = bruteforceArguments,
            ).run()
            buildJsonObject {
                put("endpoint", url)
                put("requests_sent", reconstruction.requestsSent)
                put("types", reconstruction.typesAsJson())
                put(
                    "note",
                    "Reconstructed ${reconstruction.types.size} type(s) from error-message analysis " +
                        "(no introspection used). Field/type coverage depends on wordlist hits — treat this as a " +
                        "lower bound on the real schema, not a complete one."
                )
            }
        } catch (e: Exception) {
            buildJsonObject { put("error", "Schema bruteforcing failed: ${e.message}") }
        }
        return withScopeWarning(result, check.warning)
    }

    /**
     * Fetches the FULL official introspection query (needed for schema modeling) and builds a
     * [GQLSchema]. The failure message distinguishes a connection failure (couldn't reach the
     * endpoint at all — `status == 0`) from a real HTTP response that just doesn't parse into a
     * schema (introspection genuinely disabled/malformed) — conflating the two previously made a
     * bad URL/unreachable host look identical to "introspection may be disabled". Successful
     * fetches are cached per (url, headers) for [SCHEMA_CACHE_TTL], bypassable via [refreshSchema].
     */
    private fun fetchFullSchema(
        url: String,
        headers: Map<String, String> = emptyMap(),
        refreshSchema: Boolean = false,
    ): Pair<GQLSchema?, String?> {
        val cacheKey = "$url|${headers.hashCode()}"
        if (!refreshSchema) {
            schemaCache[cacheKey]?.let { (schema, fetchedAt) ->
                if (Duration.between(fetchedAt, Instant.now()) < SCHEMA_CACHE_TTL) return schema to null
            }
        }
        val resp = postQuery(url, graphql.introspection.IntrospectionQuery.INTROSPECTION_QUERY, headers)
        if (resp.status == 0) {
            return null to "Could not reach $url (connection failed) — check the URL and that the target is reachable."
        }
        if (resp.body.isBlank()) {
            return null to "Endpoint returned an empty response body (HTTP ${resp.status}); introspection may be disabled."
        }
        val schema = try { GQLSchema(resp.body) } catch (_: Exception) { null }
        if (schema != null) schemaCache[cacheKey] = schema to Instant.now()
        return schema to (
            if (schema == null) "Could not build a schema from this endpoint's introspection response (HTTP ${resp.status}); introspection may be disabled."
            else null
        )
    }

    private fun withScopeWarning(result: JsonObject, warning: String?): JsonObject =
        if (warning != null) JsonObject(result + ("scope_warning" to JsonPrimitive(warning))) else result

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
