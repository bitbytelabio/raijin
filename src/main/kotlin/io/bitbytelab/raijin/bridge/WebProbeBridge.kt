package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.safety.BoundedHttp
import burp.api.montoya.http.message.requests.HttpRequest
import io.bitbytelab.raijin.core.EnumValidation
import io.bitbytelab.raijin.safety.ScopeGate
import io.bitbytelab.raijin.webprobe.CacheProbe
import io.bitbytelab.raijin.webprobe.CacheSignals
import io.bitbytelab.raijin.webprobe.CorsAnalysis
import io.bitbytelab.raijin.webprobe.Fingerprint
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** Quick web-misconfig recon: CORS policy probing, web cache probing, and tech/WAF fingerprinting. Scope-gated. */
class WebProbeBridge(private val api: MontoyaApi) {

    companion object {
        const val CHECK_POISONING = "poisoning"
        const val CHECK_DECEPTION = "deception"
        val CACHE_CHECKS: List<String> = listOf(CHECK_POISONING, CHECK_DECEPTION)
        const val DEFAULT_CACHE_REQUESTS = 150

        private val SEVERITY_ORDER = listOf("info", "low", "medium", "high", "critical")
    }

    private val scopeGate = ScopeGate(api)
    private val transport = ProbeTransport(api)

    private fun highest(severities: List<String>): String? = severities.maxByOrNull { SEVERITY_ORDER.indexOf(it) }

    /**
     * Probes CORS by sending crafted Origin headers ([CorsAnalysis.origins]: an unrelated origin,
     * `null`, and origins built from the target's host), each as a plain GET and as a preflight,
     * and classifying the Access-Control-* response headers.
     */
    fun corsProbe(url: String): JsonObject {
        val check = scopeGate.check(url)
        if (check.blocked) return check.denyJson()
        return check.annotate(corsProbeChecked(url))
    }

    private fun corsProbeChecked(url: String): JsonObject {
        return try {
            val seed = transport.seed(url)
            val issues = ArrayList<JsonObject>()
            val severities = ArrayList<String>()
            var answered = 0
            var corsEnabled = false
            var reflectsAny = false
            var skipped = 0
            val tests = buildJsonArray {
                for (test in CorsAnalysis.origins(url)) {
                    // A server that echoes any origin echoes the crafted ones too: they add nothing.
                    if (reflectsAny && test.kind != CorsAnalysis.ARBITRARY && test.kind != CorsAnalysis.NULL) {
                        skipped++
                        continue
                    }
                    val response = transport.send(seed.service, seed.request.withHeader("Origin", test.origin))
                    val preflightResponse = transport.send(
                        seed.service,
                        seed.request.copy(method = "OPTIONS")
                            .withHeader("Origin", test.origin)
                            .withHeader("Access-Control-Request-Method", CorsAnalysis.PREFLIGHT_METHOD)
                            .withHeader("Access-Control-Request-Headers", CorsAnalysis.PREFLIGHT_HEADER),
                    )
                    if (response != null || preflightResponse != null) {
                        answered++
                    } else if (answered == 0) {
                        // The first origin got nothing back at all: the rest would only wait out timeouts.
                        return buildJsonObject { put("error", "target unreachable: no response to GET or preflight") }
                    }

                    val acao = response?.header("access-control-allow-origin")
                    val acac = response?.header("access-control-allow-credentials")
                    val vary = response?.header("vary")
                    val verdict = CorsAnalysis.assess(test, acao, acac)
                    val missingVary = CorsAnalysis.missingVary(test, acao, vary)
                    val preflight = preflightResponse?.let {
                        CorsAnalysis.Preflight(
                            it.status,
                            it.header("access-control-allow-origin"),
                            it.header("access-control-allow-credentials"),
                            it.header("access-control-allow-methods"),
                            it.header("access-control-allow-headers"),
                        )
                    }
                    val preflightMaxAge = preflightResponse?.header("access-control-max-age")
                    val preflightVerdict = preflight?.let { CorsAnalysis.assessPreflight(test, it) }
                    if (acao != null || preflight?.acao != null) corsEnabled = true
                    if (test.kind == CorsAnalysis.ARBITRARY &&
                        (verdict?.id?.startsWith("reflected_origin") == true || preflightVerdict?.id?.startsWith("preflight_reflected_origin") == true)
                    ) {
                        reflectsAny = true
                    }
                    for ((severity, id, detail) in listOfNotNull(verdict, missingVary, preflightVerdict)) {
                        severities.add(severity)
                        issues.add(buildJsonObject {
                            put("id", id)
                            put("severity", severity)
                            put("origin", test.origin)
                            put("detail", detail)
                        })
                    }

                    add(buildJsonObject {
                        put("kind", test.kind)
                        put("origin", test.origin)
                        put("status", response?.status)
                        put("acao", acao)
                        put("acac", acac)
                        put("vary", vary)
                        if (verdict != null) {
                            put("severity", verdict.severity)
                            put("id", verdict.id)
                            put("detail", verdict.detail)
                        }
                        if (missingVary != null) put("missing_vary_origin", true)
                        if (preflight != null) {
                            put("preflight", buildJsonObject {
                                put("status", preflight.status)
                                put("acao", preflight.acao)
                                put("acac", preflight.acac)
                                put("allow_methods", preflight.allowMethods)
                                put("allow_headers", preflight.allowHeaders)
                                put("max_age", preflightMaxAge)
                                if (preflightVerdict != null) {
                                    put("severity", preflightVerdict.severity)
                                    put("id", preflightVerdict.id)
                                    put("detail", preflightVerdict.detail)
                                }
                            })
                        }
                    })
                }
            }
            if (answered == 0) return buildJsonObject { put("error", "No response from $url") }
            buildJsonObject {
                put("url", url)
                put("vulnerable", issues.isNotEmpty())
                put("highest_severity", highest(severities))
                put("cors_enabled", corsEnabled)
                put("issues", buildJsonArray { issues.forEach { add(it) } })
                put("tests", tests)
                if (skipped > 0) {
                    put("skipped_note", "$skipped origins built from the target's host were not sent: the server echoes any origin, so they would be echoed too.")
                }
            }
        } catch (e: Exception) {
            buildJsonObject { put("error", "CORS probe failed: ${e.message}") }
        }
    }

    /**
     * Probes [url] for web cache poisoning and web cache deception ([CacheProbe]).
     *
     * @param checks which of [CACHE_CHECKS] to run (null or empty: both).
     * @param headers request headers of a logged-in user; every request carries them except the
     *   ones made as a visitor without a session.
     * @param probeHeaders further header inputs to try, as `name` or `name~value`.
     * @param probeCookies further cookie inputs to try, as `name` or `name~value`.
     */
    fun cacheProbe(
        url: String,
        checks: List<String>? = null,
        headers: Map<String, String> = emptyMap(),
        probeHeaders: List<String> = emptyList(),
        probeCookies: List<String> = emptyList(),
        maxRequests: Int = DEFAULT_CACHE_REQUESTS,
    ): JsonObject {
        val wanted = checks.orEmpty().map { it.trim().lowercase() }.filter { it.isNotEmpty() }.ifEmpty { CACHE_CHECKS }
        for (name in wanted) EnumValidation.error(name, CACHE_CHECKS.toSet(), "checks")?.let { return it }
        val check = scopeGate.check(url)
        if (check.blocked) return check.denyJson()
        return check.annotate(cacheProbeChecked(url, wanted, headers, probeHeaders, probeCookies, maxRequests))
    }

    private fun cacheProbeChecked(
        url: String,
        wanted: List<String>,
        headers: Map<String, String>,
        probeHeaders: List<String>,
        probeCookies: List<String>,
        maxRequests: Int,
    ): JsonObject {
        return try {
            val seed = transport.seed(url)
            val config = CacheProbe.Config(
                host = seed.service.host(),
                poisoning = CHECK_POISONING in wanted,
                deception = CHECK_DECEPTION in wanted,
                maxRequests = maxRequests,
                extraHeaders = probeHeaders,
                extraCookies = probeCookies,
            )
            val report = CacheProbe(seed.request, headers.toList(), config) { request, anonymous ->
                transport.send(seed.service, request, internal = anonymous)
            }.run()
            report.error?.let { message -> return buildJsonObject { put("error", "$message: $url") } }

            val origin = (if (seed.service.secure()) "https" else "http") + "://" + (seed.request.header("Host") ?: seed.service.host())
            val severities = report.poisoning.map { it.severity } + report.deception.map { it.severity }
            buildJsonObject {
                put("url", url)
                put("vulnerable", report.poisoning.any { it.verdict == CacheProbe.CONFIRMED } || report.deception.any { it.verdict == CacheProbe.CONFIRMED })
                put("highest_severity", highest(severities))
                put("cache", buildJsonObject {
                    put("cached", report.cached)
                    put("vendor", report.first?.vendor ?: report.repeat?.vendor)
                    report.first?.let { put("first_request", observation(it)) }
                    report.repeat?.let { put("second_request", observation(it)) }
                    put("cache_buster", buildJsonObject {
                        put("param", report.busterParam)
                        put("effective", report.busterEffective)
                    })
                    if (report.busterEffective == false) {
                        put("unkeyed_query_string", true)
                        put("note", "The cache ignores the query string. Any input reflected from the query is then stored for everyone; test it by hand.")
                    }
                })
                put("poisoning", buildJsonObject {
                    put("inputs_tested", report.poisoningTested)
                    report.poisoningSkipped?.let { put("skipped", it) }
                    put("findings", buildJsonArray {
                        report.poisoning.forEach { finding ->
                            add(buildJsonObject {
                                put("input", finding.input.kind)
                                put("name", finding.input.name)
                                put("value", finding.value)
                                put("verdict", finding.verdict)
                                put("severity", finding.severity)
                                put("effects", buildJsonArray { finding.effects.forEach { add(it) } })
                                put("cache_key", finding.cacheKey)
                                if (finding.keyedByVary) put("keyed_by_vary", true)
                                put("detail", finding.detail)
                            })
                        }
                    })
                })
                put("deception", buildJsonObject {
                    put("variants_tested", report.deceptionTested)
                    report.deceptionSkipped?.let { put("skipped", it) }
                    report.sessionDependent?.let { put("session_dependent", it) }
                    put("findings", buildJsonArray {
                        report.deception.forEach { finding ->
                            add(buildJsonObject {
                                put("technique", finding.technique)
                                put("url", origin + finding.target)
                                put("verdict", finding.verdict)
                                put("severity", finding.severity)
                                put("cache_state", finding.state.name.lowercase())
                                put("detail", finding.detail)
                            })
                        }
                    })
                    if (report.sessionDependent == false && config.deception && report.deceptionSkipped == null) {
                        put("note", "The target answers the same with and without a session here. Pass the logged-in user's request headers as 'headers' to prove that a private page is stored.")
                    }
                })
                put("requests_sent", report.requests)
                report.stopped?.let { put("stopped", it) }
            }
        } catch (e: Exception) {
            buildJsonObject { put("error", "Cache probe failed: ${e.message}") }
        }
    }

    private fun observation(observed: CacheSignals.Observation): JsonObject = buildJsonObject {
        put("state", observed.state.name.lowercase())
        put("age", observed.age)
        put("cache_control_storable", observed.storable)
        put("evidence", buildJsonArray { observed.evidence.forEach { add(it) } })
    }

    /** Fingerprints tech / WAF / framework from a single GET. */
    fun fingerprint(url: String): JsonObject {
        val check = scopeGate.check(url)
        if (check.blocked) return check.denyJson()
        return check.annotate(fingerprintChecked(url))
    }

    private fun fingerprintChecked(url: String): JsonObject {
        return try {
            val resp = BoundedHttp.send(api, HttpRequest.httpRequestFromUrl(url))?.response()
                ?: return buildJsonObject { put("error", "No response from $url") }
            val headers = resp.headers().groupBy({ it.name().lowercase() }, { it.value() }).mapValues { it.value.joinToString("; ") }
            val body = try { resp.bodyToString() } catch (_: Exception) { "" }
            val techs = Fingerprint.detect(headers, body)
            buildJsonObject {
                put("url", url)
                put("status", resp.statusCode().toInt())
                put("technologies", buildJsonArray { techs.forEach { add(it) } })
            }
        } catch (e: Exception) {
            buildJsonObject { put("error", "Fingerprint failed: ${e.message}") }
        }
    }
}
