package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.safety.BoundedHttp
import burp.api.montoya.http.message.requests.HttpRequest
import io.bitbytelab.raijin.graphql.GraphQl
import io.bitbytelab.raijin.safety.ScopeGate
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

    fun probe(url: String): JsonObject {
        val check = scopeGate.check(url)
        check.deny?.let { return it }
        val result: JsonObject = try {
            val introResp = postQuery(url, GraphQl.INTROSPECTION_QUERY)
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
                val badResp = postQuery(url, "query { zzNonexistentField_mcp1234 }")
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

    private fun postQuery(url: String, query: String): ProbeResponse {
        return try {
            val body = buildJsonObject { put("query", query) }.toString()
            val req = HttpRequest.httpRequestFromUrl(url)
                .withMethod("POST")
                .withAddedHeader("Content-Type", "application/json")
                .withBody(body)
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
