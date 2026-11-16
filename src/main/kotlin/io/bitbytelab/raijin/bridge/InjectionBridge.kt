package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.collaborator.Interaction
import burp.api.montoya.collaborator.InteractionType
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import io.bitbytelab.raijin.injection.FuzzTemplate
import io.bitbytelab.raijin.injection.InjectionClass
import io.bitbytelab.raijin.injection.InjectionProbe
import io.bitbytelab.raijin.injection.Observation
import io.bitbytelab.raijin.injection.OobChannel
import io.bitbytelab.raijin.injection.OobHub
import io.bitbytelab.raijin.injection.PayloadEncoding
import io.bitbytelab.raijin.safety.BoundedHttp
import io.bitbytelab.raijin.safety.RequestHygiene
import io.bitbytelab.raijin.safety.ScopeGate
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

/**
 * Guided injection probe with confirmation oracles. The caller marks the injection point with
 * the FUZZ keyword; [InjectionProbe] sends class-specific payloads and reports only what an
 * oracle confirmed against a baseline, with the evidence. This bridge supplies the Burp side:
 * the scope gate, the HTTP exchange, and the Collaborator client behind the out-of-band checks
 * (blind SSRF, XXE and command injection), which are skipped with a reason when Burp has none.
 */
class InjectionBridge(private val api: MontoyaApi) {

    private val scopeGate = ScopeGate(api)
    private val oobLock = Any()
    private var oobHub: OobHub? = null

    /**
     * @param classes subset of [InjectionClass.accepted]; null or empty tests every class.
     * @param delaySeconds sleep asked of time-based payloads. Raise it for a target with jitter
     *   or one that clamps short sleeps.
     * @param encoding a [PayloadEncoding] id; null encodes each FUZZ for its position.
     * @param baseValue benign value the baseline carries at FUZZ and appended payloads keep as
     *   their prefix. The parameter's real value makes TRUE conditions reproduce the normal page.
     * @param oob false skips the Collaborator checks.
     * @param oobWaitSeconds how long to wait for out-of-band interactions after the last probe.
     * @param timeBudgetSeconds no new probe starts after this long; unfinished classes are reported.
     */
    fun probe(
        request: String,
        host: String,
        port: Int,
        useTls: Boolean,
        classes: List<String>?,
        delaySeconds: Int = 5,
        encoding: String? = null,
        baseValue: String = "1",
        oob: Boolean = true,
        oobWaitSeconds: Int = 5,
        timeBudgetSeconds: Int = 300,
    ): JsonObject {
        val target = (if (useTls) "https" else "http") + "://$host:$port"
        scopeGate.deny("$target/")?.let { return it }
        return try {
            val selection = InjectionClass.select(classes)
            selection.error?.let { return failure(it) }
            val mode = PayloadEncoding.fromId(encoding ?: PayloadEncoding.AUTO.id)
                ?: return failure("Parameter 'encoding' has invalid value '$encoding'. Allowed: ${PayloadEncoding.ids.joinToString(", ")}")
            outOfRange("delay_seconds", delaySeconds, DELAY_SECONDS)?.let { return failure(it) }
            outOfRange("oob_wait_seconds", oobWaitSeconds, OOB_WAIT_SECONDS)?.let { return failure(it) }
            outOfRange("time_budget_seconds", timeBudgetSeconds, TIME_BUDGET_SECONDS)?.let { return failure(it) }
            val template = FuzzTemplate.parse(RequestHygiene.normalizeCrlf(request))
            if (!template.hasMarker) return failure(InjectionProbe.NO_MARKER)

            val service = HttpService.httpService(host, port, useTls)
            val wantsOob = selection.classes.any { it in InjectionProbe.OOB_CLASSES }
            val (hub, oobProblem) = when {
                !wantsOob -> null to null
                !oob -> null to "disabled by the caller (oob=false)"
                else -> collaborator()
            }
            val channel = hub?.channel()
            val report = try {
                InjectionProbe(
                    template,
                    InjectionProbe.Settings(
                        classes = selection.classes,
                        encoding = mode,
                        baseValue = baseValue,
                        delaySeconds = delaySeconds,
                        targetHost = host,
                        oobWaitMs = oobWaitSeconds * 1000L,
                        timeBudgetMs = timeBudgetSeconds * 1000L,
                        oobUnavailable = oobProblem,
                    ),
                    oob = channel,
                ) { raw, timeoutMs -> exchange(service, raw, timeoutMs) }.run()
            } finally {
                if (hub != null && channel != null) hub.release(channel)
            }
            // Also when this call ran no out-of-band check: an earlier call's interactions may have arrived since.
            val late = synchronized(oobLock) { oobHub }?.late().orEmpty()

            buildJsonObject {
                put("target", target)
                if (report.error == null) {
                    putJsonArray("injection_context") { template.contexts.forEach { add(it.id) } }
                    put("encoding", mode.id)
                    put("base_value", baseValue)
                    put("delay_seconds", delaySeconds)
                }
                report.toJson().forEach { (key, value) -> put(key, value) }
                if (wantsOob && report.error == null) {
                    putJsonObject("oob") {
                        put("available", hub != null)
                        if (oobProblem != null) put("unavailable_reason", oobProblem)
                        if (hub != null) {
                            put("probes_sent", report.oobProbes)
                            put("waited_seconds", oobWaitSeconds)
                        }
                    }
                }
                if (late.isNotEmpty()) {
                    // Interactions for payloads of earlier calls that arrived after those calls returned.
                    putJsonArray("late_oob_interactions") {
                        for ((purpose, oobHost, interaction) in late) {
                            addJsonObject {
                                put("probe", purpose)
                                put("oob_host", oobHost)
                                put("type", interaction.type)
                                put("client_ip", interaction.clientIp)
                                put("timestamp", interaction.timestamp)
                                if (interaction.detail.isNotEmpty()) put("detail", interaction.detail)
                            }
                        }
                    }
                }
                if (report.error == null) put("note", NOTE)
            }
        } catch (e: Exception) {
            failure("Injection probe failed: ${e.message}")
        }
    }

    private fun failure(message: String): JsonObject = buildJsonObject { put("error", message) }

    private fun outOfRange(name: String, value: Int, range: IntRange): String? =
        if (value in range) null else "Parameter '$name' must be between ${range.first} and ${range.last} (got $value)"

    /**
     * One bounded exchange. The request goes out as explicit bytes in the charset its
     * Content-Length was counted in ([RequestHygiene.wireCharset]). No response within
     * [timeoutMs] is status 0, which no oracle accepts.
     */
    private fun exchange(service: HttpService, raw: String, timeoutMs: Long): Observation {
        val started = System.nanoTime()
        val result = try {
            val bytes = raw.toByteArray(RequestHygiene.wireCharset(raw))
            BoundedHttp.send(api, HttpRequest.httpRequest(service, BurpByteArray.byteArray(*bytes)), timeoutMs)
        } catch (_: Exception) {
            null
        }
        val wallMs = (System.nanoTime() - started) / 1_000_000
        val response = try { result?.response() } catch (_: Exception) { null } ?: return Observation(status = 0, elapsedMs = wallMs)
        return try {
            val body = response.bodyToString()
            Observation(
                status = response.statusCode().toInt(),
                headers = response.headers().map { it.name() to it.value() },
                body = if (body.length > MAX_BODY) body.substring(0, MAX_BODY) else body,
                elapsedMs = burpElapsedMs(result) ?: wallMs,
            )
        } catch (_: Exception) {
            Observation(status = 0, elapsedMs = wallMs)
        }
    }

    /**
     * Burp's own request-sent-to-response-end time, which leaves out connection setup and the
     * wait for a worker thread, so a slow handshake does not look like an injected delay.
     */
    private fun burpElapsedMs(result: HttpRequestResponse?): Long? = try {
        result?.timingData()?.orElse(null)?.timeBetweenRequestSentAndEndOfResponse()?.toMillis()
    } catch (_: Exception) {
        null
    }

    /**
     * The shared Collaborator hub, created on first use, or the reason there is none (Community
     * Edition, Collaborator disabled). A client that stops issuing payloads is dropped, so the
     * next call creates one for the current Collaborator settings.
     */
    private fun collaborator(): Pair<OobHub?, String?> = synchronized(oobLock) {
        oobHub?.let { return@synchronized it to null }
        val edition = try { api.burpSuite().version().edition() } catch (_: Exception) { null }
        if (edition == BurpSuiteEdition.COMMUNITY_EDITION) {
            return@synchronized null to "Burp Collaborator needs Burp Suite Professional (this is Community Edition)"
        }
        try {
            val client = api.collaborator().createClient()
            val hub = OobHub(
                generate = {
                    try {
                        client.generatePayload().let { OobChannel.Payload(it.id().toString(), it.toString()) }
                    } catch (e: Exception) {
                        synchronized(oobLock) { oobHub = null }
                        null
                    }
                },
                fetch = { client.allInteractions.map(::describe) },
            )
            oobHub = hub
            hub to null
        } catch (e: UnsupportedOperationException) {
            null to "Burp Collaborator is not available in this edition of Burp Suite"
        } catch (e: IllegalStateException) {
            null to "Burp Collaborator is disabled in the project settings (${e.message})"
        } catch (e: Exception) {
            null to "a Burp Collaborator client could not be created (${e.message})"
        }
    }

    private fun describe(interaction: Interaction): OobChannel.Interaction {
        val type = interaction.type()
        val detail = try {
            when (type) {
                InteractionType.HTTP -> interaction.httpDetails().orElse(null)?.requestResponse()?.request()?.let { "${it.method()} ${it.path()}" }
                InteractionType.DNS -> interaction.dnsDetails().orElse(null)?.queryType()?.name
                else -> null
            }
        } catch (_: Exception) {
            null
        }
        return OobChannel.Interaction(
            payloadId = interaction.id().toString(),
            type = type.name.lowercase(),
            clientIp = try { interaction.clientIp()?.hostAddress } catch (_: Exception) { null } ?: "",
            timestamp = try { interaction.timeStamp()?.toString() } catch (_: Exception) { null } ?: "",
            detail = detail ?: "",
        )
    }

    companion object {
        val DELAY_SECONDS = 1..30
        val OOB_WAIT_SECONDS = 0..60
        val TIME_BUDGET_SECONDS = 10..3600

        /** Response bodies are compared up to this many characters. */
        private const val MAX_BODY = 500_000

        private const val NOTE =
            "Each finding was confirmed by an oracle against the baseline (the same request with base_value at FUZZ) and " +
                "carries its evidence. To re-check one, put evidence.sent_payload at FUZZ as it is (it is already encoded " +
                "for that position), or send evidence.request when the probe rewrote the request. confidence: certain = " +
                "the response holds proof, firm = behaviour reproduced under controls, tentative = a precondition only."

        /**
         * [payload] substituted at every `FUZZ` of [normalizedRequest] in the encoding its
         * position needs, with Content-Length updated ([FuzzTemplate]).
         */
        internal fun preparePayloadRequest(normalizedRequest: String, payload: String): String =
            FuzzTemplate.parse(normalizedRequest).render(payload)
    }
}
