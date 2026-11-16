package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import io.bitbytelab.raijin.bridge.AnalysisBridge.Companion.describeException
import io.bitbytelab.raijin.bridge.AnalysisBridge.Companion.normalizeCrlfMessage
import io.bitbytelab.raijin.core.BodyText
import io.bitbytelab.raijin.core.TextSimilarity
import io.bitbytelab.raijin.safety.BoundedHttp
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.safety.ScopeGate
import kotlinx.serialization.json.*

/**
 * `auth_diff` for [AnalysisBridge]: one request sent as each identity, scope-gated and marked as
 * an internal replay ([BoundedHttp.sendInternal]), and the answers compared.
 */
internal class AnalysisAuthDiff(private val api: MontoyaApi) {

    private val scopeGate = ScopeGate(api)

    /**
     * Auth level diffing: sends the same request as each identity and compares the responses to
     * detect authorization issues. Identities are applied by [AuthIdentityApplier]; a level that
     * gets no HTTP response (timeout, connection error) is reported under `errors` and takes no
     * part in the comparison.
     *
     * @param request Base HTTP request string
     * @param host Target host
     * @param port Target port
     * @param useTls Use TLS
     * @param authLevels Identity objects: name plus header_name/header_value, headers and/or
     *   remove_headers; a name of none / unauth / anonymous sends the request without credentials
     * @param compareFields What to compare: any of [AUTH_DIFF_FIELDS] (default: all)
     * @param deniedRegex Optional regex; a response whose body matches it is treated as denied
     *   whatever its status (applications that refuse with a 200)
     */
    fun authDiff(
        request: String,
        host: String,
        port: Int,
        useTls: Boolean,
        authLevels: List<JsonObject>,
        compareFields: List<String>?,
        deniedRegex: String?
    ): JsonObject {
        if (request.isBlank()) {
            return buildJsonObject {
                put("error", "Empty request: provide a raw HTTP request (e.g. 'GET /api/resource HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n').")
            }
        }
        if (authLevels.size < 2) {
            return buildJsonObject {
                put("error", "Provide at least 2 auth levels to compare, e.g. an authenticated level plus {\"name\":\"none\"}.")
            }
        }
        val fields = compareFields?.map { it.trim().lowercase() }?.filter { it.isNotEmpty() }?.takeIf { it.isNotEmpty() }
            ?: AUTH_DIFF_FIELDS
        fields.firstOrNull { it !in AUTH_DIFF_FIELDS }?.let { bad ->
            return buildJsonObject {
                put("error", "Parameter 'compare_fields' has invalid value '$bad'. Allowed: ${AUTH_DIFF_FIELDS.joinToString(", ")}")
            }
        }
        deniedRegex?.let { pattern ->
            SafeRegex.validate(pattern, ignoreCase = true)?.let { err ->
                return buildJsonObject { put("error", "Invalid denied_regex: $err") }
            }
        }
        val identities = authLevels.mapIndexed { i, level -> AuthIdentityApplier.parse(level, defaultName = "level_${i + 1}") }
        AuthIdentityApplier.indistinguishableError(identities)?.let { err ->
            return buildJsonObject { put("error", err) }
        }
        return try {
            val scope = scopeGate.check((if (useTls) "https" else "http") + "://$host:$port/")
            scope.deny?.let { return it }
            val service = HttpService.httpService(host, port, useTls)
            // Normalize request
            val baseRequest = normalizeCrlfMessage(request)
            val identityHeaders = AuthIdentityApplier.identityHeaders(identities)

            // Every level hits the same path (only headers vary across the loop below) — used
            // only for AuthDiffVerdict's static-asset downgrade (file-extension fallback).
            val sharedUrl = try { HttpRequest.httpRequest(service, baseRequest).url() } catch (_: Exception) { null }

            val results = mutableListOf<AuthLevelResponse>()
            val errors = mutableListOf<String>()

            for (identity in identities) {
                try {
                    val applied = AuthIdentityApplier.apply(baseRequest, identity, identityHeaders)
                    val httpRequest = HttpRequest.httpRequest(
                        service, BurpByteArray.byteArray(*AuthIdentityApplier.wireBytes(applied.request))
                    )

                    val startTime = System.nanoTime()
                    val resp = BoundedHttp.sendInternal(api, httpRequest)?.response()
                    val elapsed = (System.nanoTime() - startTime) / 1_000_000

                    val status = resp?.statusCode()?.toInt() ?: 0
                    // No response, or one without a status: a failed level, not a level that answered "0".
                    if (resp == null || status == 0) {
                        errors.add(levelFailure(identity.name, elapsed))
                        continue
                    }
                    results.add(AuthLevelResponse(
                        level = identity.name,
                        statusCode = status,
                        bodyLength = resp.body()?.length() ?: 0,
                        body = resp.bodyToString() ?: "",
                        headers = resp.headers()?.associate { it.name() to it.value() } ?: emptyMap(),
                        responseTimeMs = elapsed,
                        contentType = try { resp.headerValue("Content-Type") } catch (_: Exception) { null },
                        location = try { resp.headerValue("Location") } catch (_: Exception) { null },
                        applied = applied,
                        sentUnchanged = identity.sendsRequestUnchanged
                    ))
                } catch (e: Exception) {
                    errors.add("Level '${identity.name}' failed: ${describeException(e)}")
                }
            }

            val report = authDiffReport(results, errors, fields, sharedUrl, deniedRegex)
            scope.warning?.let { JsonObject(report + ("scope_warning" to JsonPrimitive(it))) } ?: report
        } catch (e: Exception) {
            buildJsonObject { put("error", "Auth diff failed: ${describeException(e)}") }
        }
    }

    companion object {
        /** Response fields `auth_diff` can compare between two levels. */
        val AUTH_DIFF_FIELDS = listOf("status_code", "body_length", "body", "headers")

        private const val PREVIEW_CHARS = 500

        /** The `errors` entry for a level that produced no HTTP response within [elapsedMs]. */
        fun levelFailure(levelName: String, elapsedMs: Long, timeoutMs: Long = BoundedHttp.DEFAULT_TIMEOUT_MS): String =
            if (elapsedMs >= timeoutMs) {
                "Level '$levelName' failed: timed out after $elapsedMs ms without a response"
            } else {
                "Level '$levelName' failed: no response received (connection error)"
            }

        /**
         * Builds the `auth_diff` result from the levels that answered. Pure: the bridge only
         * supplies what came back, so the comparison and the verdict are unit tested.
         *
         * @param fields which of [AUTH_DIFF_FIELDS] to compare pairwise.
         * @param url the shared target URL, for the static-asset downgrade.
         * @param deniedRegex an already validated caller pattern that marks a response as denied.
         */
        fun authDiffReport(
            results: List<AuthLevelResponse>,
            errors: List<String>,
            fields: List<String> = AUTH_DIFF_FIELDS,
            url: String? = null,
            deniedRegex: String? = null
        ): JsonObject {
            val differences = mutableListOf<JsonObject>()

            // Compare each pair
            for (i in results.indices) {
                for (j in i + 1 until results.size) {
                    val a = results[i]
                    val b = results[j]
                    val diffs = mutableListOf<JsonObject>()

                    if ("status_code" in fields && a.statusCode != b.statusCode) {
                        diffs.add(buildJsonObject {
                            put("field", "status_code")
                            put(a.level, a.statusCode)
                            put(b.level, b.statusCode)
                        })
                    }
                    if ("body_length" in fields && a.bodyLength != b.bodyLength) {
                        diffs.add(buildJsonObject {
                            put("field", "body_length")
                            put(a.level, a.bodyLength)
                            put(b.level, b.bodyLength)
                            put("length_diff", kotlin.math.abs(a.bodyLength - b.bodyLength))
                        })
                    }
                    if ("body" in fields && a.body != b.body) {
                        diffs.add(buildJsonObject {
                            put("field", "body_content")
                            put("similarity_percent", TextSimilarity.dice(a.body, b.body))
                            put("bodies_identical", false)
                        })
                    }
                    if ("headers" in fields) {
                        val diffHeaders = (a.headers.keys + b.headers.keys).distinct().filter { a.headers[it] != b.headers[it] }
                        if (diffHeaders.isNotEmpty()) {
                            diffs.add(buildJsonObject {
                                put("field", "headers")
                                put("different_headers", buildJsonArray { diffHeaders.forEach { add(it) } })
                            })
                        }
                    }

                    if (diffs.isNotEmpty()) {
                        differences.add(buildJsonObject {
                            put("level_a", a.level)
                            put("level_b", b.level)
                            put("differences", buildJsonArray { diffs.forEach { add(it) } })
                        })
                    }
                }
            }

            // Security analysis
            val verdict = AuthDiffVerdict.assess(
                results.map { AuthDiffVerdict.LevelResult(it.level, it.statusCode, it.body, it.contentType, it.location) },
                similarity = TextSimilarity::dice,
                url = url,
                denied = { level ->
                    AuthDenialHeuristic.looksDenied(level.body) || (
                        deniedRegex != null && SafeRegex.containsMatchIn(
                            deniedRegex, level.body, ignoreCase = true,
                            maxInputLen = AnalysisResponseSearch.SEARCH_MAX_BODY_CHARS
                        )
                        )
                }
            )

            val notes = mutableListOf<String>()
            results.filter { it.sentUnchanged }.forEach {
                notes += "Level '${it.level}' sets no header and is not named none/unauth/anonymous: it was sent with the request's own credentials."
            }
            if (results.size < 2) notes += "Fewer than two levels answered, so nothing could be compared: see errors."

            return buildJsonObject {
                put("auth_levels_tested", results.size)
                put("responses", buildJsonArray {
                    results.forEach { r ->
                        add(buildJsonObject {
                            put("level", r.level)
                            put("status_code", r.statusCode)
                            put("body_length", r.bodyLength)
                            put("response_time_ms", r.responseTimeMs)
                            r.location?.takeIf { it.isNotBlank() }?.let { put("redirect_location", it) }
                            r.applied?.let { applied ->
                                if (applied.set.isNotEmpty()) put("headers_set", strings(applied.set))
                                if (applied.removed.isNotEmpty()) put("headers_removed", strings(applied.removed))
                                if (applied.keptCredentials.isNotEmpty()) put("credential_headers_kept", strings(applied.keptCredentials))
                            }
                            put("body_preview", BodyText.render(r.body, PREVIEW_CHARS, label = "response body").text)
                        })
                    }
                })
                put("differences", buildJsonArray { differences.forEach { add(it) } })
                put("findings", buildJsonArray {
                    verdict.forEach {
                        add(buildJsonObject {
                            put("severity", it.severity)
                            put("id", it.id)
                            put("detail", it.detail)
                        })
                    }
                })
                put("all_same_status", results.map { it.statusCode }.distinct().size == 1)
                put("all_same_body", results.map { it.body }.distinct().size == 1)
                if (notes.isNotEmpty()) put("notes", strings(notes))
                if (errors.isNotEmpty()) put("errors", strings(errors))
            }
        }

        private fun strings(values: List<String>): JsonArray = buildJsonArray { values.forEach { add(it) } }
    }
}

/**
 * One auth level's answer, as [AnalysisAuthDiff.authDiffReport] compares it.
 *
 * @param applied what [AuthIdentityApplier] did to the request for this level.
 * @param sentUnchanged the level changed nothing about the request (it carries the captured credentials).
 */
internal data class AuthLevelResponse(
    val level: String,
    val statusCode: Int,
    val body: String,
    val bodyLength: Int = body.length,
    val headers: Map<String, String> = emptyMap(),
    val responseTimeMs: Long = 0,
    val contentType: String? = null,
    val location: String? = null,
    val applied: AuthIdentityApplier.Applied? = null,
    val sentUnchanged: Boolean = false
)
