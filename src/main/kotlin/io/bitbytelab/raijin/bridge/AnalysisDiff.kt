package io.bitbytelab.raijin.bridge

import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import io.bitbytelab.raijin.bridge.AnalysisBridge.Companion.describeException
import io.bitbytelab.raijin.bridge.AnalysisBridge.Companion.normalizeCrlfMessage
import io.bitbytelab.raijin.core.TextSimilarity
import kotlinx.serialization.json.*

/** Offline comparison of two raw HTTP requests or two raw HTTP responses for [AnalysisBridge]. */
internal object AnalysisDiff {

    /**
     * Compares two requests or two responses, identifying differences in
     * status codes, headers, and body content.
     *
     * @param item1 First raw HTTP request or response.
     * @param item2 Second raw HTTP request or response.
     * @param type "request" or "response".
     */
    fun diff(item1: String, item2: String, type: String): JsonObject {
        if (item1.isBlank() || item2.isBlank()) {
            return buildJsonObject {
                put("error", "Both item1 and item2 must be non-empty raw HTTP messages for type='$type'.")
            }
        }
        return when (type.lowercase()) {
            "request" -> diffRequests(item1, item2)
            "response" -> diffResponses(item1, item2)
            else -> buildJsonObject { put("error", "Invalid type: $type. Must be 'request' or 'response'.") }
        }
    }

    /**
     * Compares two raw HTTP requests.
     */
    private fun diffRequests(raw1: String, raw2: String): JsonObject {
        val req1: HttpRequest
        val req2: HttpRequest
        try {
            req1 = HttpRequest.httpRequest(normalizeCrlfMessage(raw1))
            req2 = HttpRequest.httpRequest(normalizeCrlfMessage(raw2))
        } catch (e: Exception) {
            return buildJsonObject { put("error", "Failed to parse request: ${describeException(e)}") }
        }

        val headerDiffs = diffHeaders(
            req1.headers().associate { it.name() to it.value() },
            req2.headers().associate { it.name() to it.value() }
        )

        val paramDiffs = buildJsonArray {
            val params1 = req1.parameters().associate { "${it.type().name}:${it.name()}" to it.value() }
            val params2 = req2.parameters().associate { "${it.type().name}:${it.name()}" to it.value() }
            val allKeys = params1.keys + params2.keys
            for (key in allKeys) {
                val v1 = params1[key]
                val v2 = params2[key]
                if (v1 != v2) {
                    addJsonObject {
                        put("parameter", key)
                        put("item1_value", v1 ?: "(absent)")
                        put("item2_value", v2 ?: "(absent)")
                        put("change", when {
                            v1 == null -> "added"
                            v2 == null -> "removed"
                            else -> "modified"
                        })
                    }
                }
            }
        }

        val body1 = req1.bodyToString()
        val body2 = req2.bodyToString()
        val bodySimilarity = TextSimilarity.dice(body1, body2)

        return buildJsonObject {
            put("type", "request")
            put("method_match", req1.method() == req2.method())
            put("item1_method", req1.method())
            put("item2_method", req2.method())
            put("path_match", req1.path() == req2.path())
            put("item1_path", req1.path())
            put("item2_path", req2.path())
            put("header_differences", headerDiffs)
            put("parameter_differences", paramDiffs)
            put("body_match", body1 == body2)
            put("body_similarity_percent", bodySimilarity)
            put("item1_body_length", body1.length)
            put("item2_body_length", body2.length)
        }
    }

    /**
     * Compares two raw HTTP responses.
     */
    private fun diffResponses(raw1: String, raw2: String): JsonObject {
        val resp1: HttpResponse
        val resp2: HttpResponse
        try {
            resp1 = HttpResponse.httpResponse(normalizeCrlfMessage(raw1))
            resp2 = HttpResponse.httpResponse(normalizeCrlfMessage(raw2))
        } catch (e: Exception) {
            return buildJsonObject { put("error", "Failed to parse response: ${describeException(e)}") }
        }

        val headerDiffs = diffHeaders(
            resp1.headers().associate { it.name() to it.value() },
            resp2.headers().associate { it.name() to it.value() }
        )

        val body1 = resp1.bodyToString()
        val body2 = resp2.bodyToString()
        val bodySimilarity = TextSimilarity.dice(body1, body2)

        return buildJsonObject {
            put("type", "response")
            put("status_code_match", resp1.statusCode() == resp2.statusCode())
            put("item1_status_code", resp1.statusCode())
            put("item2_status_code", resp2.statusCode())
            put("header_differences", headerDiffs)
            put("body_match", body1 == body2)
            put("body_similarity_percent", bodySimilarity)
            put("item1_body_length", body1.length)
            put("item2_body_length", body2.length)
            put("item1_mime_type", resp1.statedMimeType()?.toString() ?: "unknown")
            put("item2_mime_type", resp2.statedMimeType()?.toString() ?: "unknown")
        }
    }

    /**
     * Compares two header maps and produces an array of differences.
     */
    private fun diffHeaders(
        headers1: Map<String, String>,
        headers2: Map<String, String>
    ): JsonArray {
        return buildJsonArray {
            val allKeys = headers1.keys + headers2.keys
            for (key in allKeys) {
                val v1 = headers1[key]
                val v2 = headers2[key]
                if (v1 != v2) {
                    addJsonObject {
                        put("header", key)
                        put("item1_value", v1 ?: "(absent)")
                        put("item2_value", v2 ?: "(absent)")
                        put("change", when {
                            v1 == null -> "added"
                            v2 == null -> "removed"
                            else -> "modified"
                        })
                    }
                }
            }
        }
    }
}
