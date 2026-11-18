package io.bitbytelab.raijin.tools.graphql

import io.bitbytelab.raijin.bridge.GraphQlBridge
import io.bitbytelab.raijin.core.ClampedInt
import io.bitbytelab.raijin.core.EnumValidation
import io.bitbytelab.raijin.core.asBooleanSafe
import io.bitbytelab.raijin.core.asClampedInt
import io.bitbytelab.raijin.core.withClampReport
import io.bitbytelab.raijin.core.asJsonObjectSafe
import io.bitbytelab.raijin.core.asStringList
import io.bitbytelab.raijin.core.asStringMapResult
import io.bitbytelab.raijin.graphql.BatchAttack
import io.bitbytelab.raijin.graphql.bruteforcer.SchemaBruteforcer
import io.bitbytelab.raijin.graphql.scanners.POIScanner
import io.bitbytelab.raijin.graphql.subscriptions.SubscriptionProbe
import io.bitbytelab.raijin.safety.ScopeGate
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

/** Registers the `graphql_probe` MCP tool. */
object GraphQlTools {

    private const val DEFAULT_MODE = "probe"

    private val MODES = listOf(
        DEFAULT_MODE, "query_templates", "poi_scan", "cycles_scan", "batch_attack", "fingerprint_engine",
        "bruteforce_schema", "subscription_probe",
    )

    private const val MAX_QUERY_DEPTH = 20
    private const val MAX_BUCKET_SIZE = 500
    private const val MAX_DEPTH_LIMIT = 10
    private const val MAX_REQUEST_BUDGET = 100_000

    fun register(server: Server, bridge: GraphQlBridge) {
        server.addTool(
            name = "graphql_probe",
            description = "Probe or exploit a GraphQL endpoint; pick 'mode'. probe (default): three outcomes in " +
                "'verdict' — introspection_enabled (full schema disclosed, summarized); introspection_disabled (a " +
                "real GraphQL server, introspection off — 'Did you mean' field suggestions tried as a fallback); " +
                "not_graphql (neither probe got a GraphQL-shaped response — re-check the URL). query_templates: " +
                "generates a runnable example query/mutation/subscription per schema field (needs introspection " +
                "enabled). poi_scan: flags security-interesting fields by name (auth/privileged/pii/payment/" +
                "database/debugging/files), deprecated fields, and custom scalars, each at the shortest path " +
                "that reaches it (through interfaces and unions too). cycles_scan: lists every cycle of the type " +
                "graph (types that recurse into themselves: deep-nesting/DoS risk), shortest first, as paths from " +
                "a root type, plus 'cyclic_types'. batch_attack: expands a \$[INT:first:last] or " +
                "\$[LIST] placeholder in 'template' into N aliased sub-operations in one request — for 2FA brute " +
                "force, IDOR enumeration, or rate-limit-bypass testing; generates only unless 'send' is true; at " +
                "most ${BatchAttack.MAX_OPERATIONS} sub-operations per call. " +
                "fingerprint_engine: detects the GraphQL backend engine (Apollo, Hasura, graphql-java, ...) from " +
                "malformed-query error signatures. bruteforce_schema: reconstructs the schema from error-message " +
                "analysis when introspection is disabled — noisy and request-heavy (wordlist guesses are sent in " +
                "buckets, each a live request built to fail validation, so a spec-compliant server executes none " +
                "of them); it stops after 'max_requests' and returns the partial schema. " +
                "subscription_probe: probes GraphQL subscriptions over WebSocket at 'url' (ws(s):// or the " +
                "http(s):// endpoint) — tries the graphql-transport-ws protocol (graphql-ws library) and the " +
                "legacy subscriptions-transport-ws one (subprotocol 'graphql-ws'), and reports per protocol " +
                "whether the handshake is acknowledged, whether connection_init needs credentials " +
                "('init_requires_auth': an anonymous session is compared with one carrying your identity " +
                "headers and 'connection_payload'), and whether a subscription operation is accepted; every " +
                "socket is closed. Every mode accepts 'headers' and 'auto_headers' for auth; query_templates/" +
                "poi_scan/cycles_scan additionally cache the fetched schema (bypass with 'refresh_schema'). An " +
                "unreachable target is reported as one error instead of a verdict. " +
                ScopeGate.TOOL_NOTE,
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url") { put("type", "string"); put("description", "GraphQL endpoint URL (e.g. https://target/graphql); subscription_probe also takes ws:// and wss://") }
                    putJsonObject("mode") {
                        put("type", "string")
                        putJsonArray("enum") { MODES.forEach { add(it) } }
                        put("description", "probe (default) | query_templates | poi_scan | cycles_scan | batch_attack | fingerprint_engine | bruteforce_schema | subscription_probe")
                    }
                    putJsonObject("max_depth") {
                        put("type", "integer"); put("minimum", 0); put("maximum", MAX_QUERY_DEPTH)
                        put("description", "query_templates: recursion depth limit (default 6)")
                    }
                    putJsonObject("categories") {
                        put("type", "array")
                        putJsonObject("items") {
                            put("type", "string")
                            putJsonArray("enum") { POIScanner.availableCategories().forEach { add(it) } }
                        }
                        put("description", "poi_scan: keyword categories to flag; omit for the default set ${POIScanner.DEFAULT_CATEGORIES}")
                    }
                    putJsonObject("custom_keywords") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "poi_scan: extra field-name keywords to flag, matched literally and case-insensitively as a whole name or a whole _-separated part of one") }
                    putJsonObject("template") { put("type", "string"); put("description", "batch_attack: a GraphQL query body containing \$[INT:first:last] or \$[LIST]") }
                    putJsonObject("values") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "batch_attack: values to substitute for a \$[LIST] placeholder") }
                    putJsonObject("send") { put("type", "boolean"); put("description", "batch_attack: also send the generated request (default false: generate only)") }
                    putJsonObject("headers") { put("type", "object"); put("description", "Extra headers (e.g. Authorization, Cookie) to send on every request this call makes. Explicit entries always override auto_headers.") }
                    putJsonObject("auto_headers") { put("type", "boolean"); put("description", "Auto-fill identity headers (Authorization/Cookie/X-Api-Key/X-Auth-Token) from the most recent Proxy-history request to this host (default false)") }
                    putJsonObject("refresh_schema") { put("type", "boolean"); put("description", "query_templates/poi_scan/cycles_scan: bypass the cached schema and re-fetch introspection (default false)") }
                    putJsonObject("bucket_size") {
                        put("type", "integer"); put("minimum", 1); put("maximum", MAX_BUCKET_SIZE)
                        put("description", "bruteforce_schema: wordlist guesses per request, aliased together (default 64)")
                    }
                    putJsonObject("depth_limit") {
                        put("type", "integer"); put("minimum", 0); put("maximum", MAX_DEPTH_LIMIT)
                        put("description", "bruteforce_schema: max nesting depth to recurse into discovered object types (default 2)")
                    }
                    putJsonObject("bruteforce_arguments") { put("type", "boolean"); put("description", "bruteforce_schema: fall back to a wordlist brute force for argument names when the cheap probes find none (default true)") }
                    putJsonObject("max_requests") {
                        put("type", "integer"); put("minimum", 1); put("maximum", MAX_REQUEST_BUDGET)
                        put("description", "bruteforce_schema: request budget; the run stops there and returns the partial schema (default ${SchemaBruteforcer.DEFAULT_MAX_REQUESTS})")
                    }
                    putJsonObject("subscription_query") { put("type", "string"); put("description", "subscription_probe: operation to start after connection_ack (default: a no-argument subscription field found by introspection over the socket, else '${SubscriptionProbe.DEFAULT_OPERATION}')") }
                    putJsonObject("connection_payload") { put("type", "object"); put("description", "subscription_probe: connection_init payload carrying credentials (e.g. {\"Authorization\": \"Bearer ...\"}); sent only in the authenticated session") }
                    putJsonObject("wait_ms") {
                        put("type", "integer"); put("minimum", SubscriptionProbe.MIN_WAIT_MS); put("maximum", SubscriptionProbe.MAX_WAIT_MS)
                        put("description", "subscription_probe: how long to wait for each server message, in milliseconds (default ${SubscriptionProbe.DEFAULT_WAIT_MS})")
                    }
                },
                required = listOf("url")
            )
        ) { request ->
            try {
                val a = request.params.arguments ?: emptyMap()
                val url = a["url"].text()?.takeIf { it.isNotBlank() }
                    ?: return@addTool toolError("Parameter 'url' is required")
                val mode = a["mode"].text()?.trim()?.lowercase()?.takeIf { it.isNotEmpty() } ?: DEFAULT_MODE
                EnumValidation.error(mode, MODES.toSet(), "mode")?.let { return@addTool toolJsonResult(it) }

                val (headers, headersWarning) = a["headers"].asStringMapResult()
                val autoHeaders = a["auto_headers"].asBooleanSafe() ?: false
                val refreshSchema = a["refresh_schema"].asBooleanSafe() ?: false

                // Limits out of range are clamped and reported (<name>_clamped_to), not refused.
                val clamps = ArrayList<Pair<String, ClampedInt?>>()
                fun clamped(name: String, min: Int, max: Int): ClampedInt? =
                    a[name].asClampedInt(name, min, max).getOrThrow().also { clamps.add(name to it) }

                val result = when (mode) {
                    "query_templates" -> {
                        val maxDepth = clamped("max_depth", 0, MAX_QUERY_DEPTH)?.value ?: 6
                        bridge.queryTemplates(url, maxDepth, headers, autoHeaders, refreshSchema)
                    }
                    "poi_scan" -> {
                        val available = POIScanner.availableCategories()
                        val categories = a["categories"].asStringList()?.map { it.trim().lowercase() }?.filter { it.isNotEmpty() }
                        categories?.forEach { category ->
                            EnumValidation.error(category, available, "categories")?.let { return@addTool toolJsonResult(it) }
                        }
                        bridge.poiScan(url, categories?.toSet(), a["custom_keywords"].asStringList(), headers, autoHeaders, refreshSchema)
                    }
                    "cycles_scan" -> bridge.cyclesScan(url, headers, autoHeaders, refreshSchema)
                    "batch_attack" -> {
                        val template = a["template"].text()?.takeIf { it.isNotBlank() }
                            ?: return@addTool toolError("Parameter 'template' is required for mode=batch_attack")
                        bridge.batchAttack(url, template, a["values"].asStringList(), a["send"].asBooleanSafe() ?: false, headers, autoHeaders)
                    }
                    "fingerprint_engine" -> bridge.fingerprintEngine(url, headers, autoHeaders)
                    "bruteforce_schema" -> {
                        val bucketSize = clamped("bucket_size", 1, MAX_BUCKET_SIZE)?.value ?: 64
                        val depthLimit = clamped("depth_limit", 0, MAX_DEPTH_LIMIT)?.value ?: 2
                        val maxRequests = clamped("max_requests", 1, MAX_REQUEST_BUDGET)?.value
                            ?: SchemaBruteforcer.DEFAULT_MAX_REQUESTS
                        bridge.bruteforceSchema(
                            url, headers, autoHeaders, bucketSize, depthLimit,
                            a["bruteforce_arguments"].asBooleanSafe() ?: true, maxRequests,
                        )
                    }
                    "subscription_probe" -> {
                        val waitMs = clamped("wait_ms", SubscriptionProbe.MIN_WAIT_MS.toInt(), SubscriptionProbe.MAX_WAIT_MS.toInt())
                            ?.value?.toLong() ?: SubscriptionProbe.DEFAULT_WAIT_MS
                        val rawPayload = a["connection_payload"]
                        val connectionPayload = rawPayload.asJsonObjectSafe()
                        if (rawPayload != null && rawPayload !is JsonNull && connectionPayload == null) {
                            return@addTool toolError("Parameter 'connection_payload' must be a JSON object")
                        }
                        bridge.subscriptionProbe(url, headers, autoHeaders, a["subscription_query"].text(), connectionPayload, waitMs)
                    }
                    else -> bridge.probe(url, headers, autoHeaders)
                }
                var reported = if (headersWarning == null) result else JsonObject(result + ("headers_warning" to JsonPrimitive(headersWarning)))
                clamps.forEach { (name, arg) -> reported = reported.withClampReport(name, arg) }
                toolJsonResult(reported)
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }

    /** The text of a primitive JSON argument; null when it is absent, JSON null, an object or an array. */
    private fun JsonElement?.text(): String? = (this as? JsonPrimitive)?.contentOrNull
}
