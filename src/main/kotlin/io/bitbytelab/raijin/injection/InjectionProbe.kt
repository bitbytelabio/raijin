package io.bitbytelab.raijin.injection

import io.bitbytelab.raijin.core.BodyText
import io.bitbytelab.raijin.core.TextSimilarity
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

private const val TOKEN_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"

/** A marker that is safe as a word, a tag name, an attribute name and a header name. */
private fun randomToken(): String = buildString(12) {
    append("rjn")
    repeat(9) { append(TOKEN_ALPHABET.random()) }
}

/**
 * The injection probe itself, free of Burp: it sends requests through [exchange], takes two
 * baselines, then runs each requested class's payloads against the oracles. A finding needs a
 * response ([Observation.answered]) that differs from the baseline in a way the payload explains,
 * and timing or boolean evidence is repeated under a control first. The run stops early when the
 * target stops answering or [Settings.timeBudgetMs] is used up.
 *
 * @param oob out-of-band channel for blind SSRF / XXE / command injection, or null to skip those checks.
 * @param newToken source of unique markers (fixed in tests).
 * @param pause waits between out-of-band polls.
 * @param exchange sends one raw request and returns what came back within `timeoutMs`.
 */
class InjectionProbe(
    private val template: FuzzTemplate,
    private val settings: Settings,
    private val oob: OobChannel? = null,
    private val newToken: () -> String = ::randomToken,
    private val nanoTime: () -> Long = System::nanoTime,
    private val pause: (Long) -> Unit = { Thread.sleep(it) },
    private val exchange: (request: String, timeoutMs: Long) -> Observation,
) {
    /**
     * @param baseValue benign value the baseline carries at `FUZZ`; appended payloads keep it as their prefix.
     * @param targetHost the tested host, used in open-redirect allow-list bypasses.
     * @param oobUnavailable why there is no out-of-band channel, for the report.
     */
    data class Settings(
        val classes: List<InjectionClass> = InjectionClass.entries.toList(),
        val encoding: PayloadEncoding = PayloadEncoding.AUTO,
        val baseValue: String = "1",
        val delaySeconds: Int = 5,
        val targetHost: String = "",
        val oobWaitMs: Long = 5_000,
        val timeBudgetMs: Long = 300_000,
        val requestTimeoutMs: Long = 30_000,
        val oobUnavailable: String? = null,
    )

    data class Report(
        val error: String? = null,
        val findings: List<Finding> = emptyList(),
        val notes: List<String> = emptyList(),
        val classesCompleted: List<InjectionClass> = emptyList(),
        val classesNotCompleted: List<InjectionClass> = emptyList(),
        val probesSent: Int = 0,
        val baselines: List<Observation> = emptyList(),
        val oobProbes: Int = 0,
        val stoppedEarly: String? = null,
        val durationMs: Long = 0,
    ) {
        fun toJson(): JsonObject = buildJsonObject {
            if (error != null) {
                put("error", error)
                put("probes_sent", probesSent)
                return@buildJsonObject
            }
            putJsonArray("classes_tested") { classesCompleted.forEach { add(it.id) } }
            if (classesNotCompleted.isNotEmpty()) {
                putJsonArray("classes_not_completed") { classesNotCompleted.forEach { add(it.id) } }
            }
            if (stoppedEarly != null) put("stopped_early", stoppedEarly)
            put("probes_sent", probesSent)
            put("duration_ms", durationMs)
            baselines.firstOrNull()?.let { first ->
                putJsonObject("baseline") {
                    put("status", first.status)
                    put("length", first.body.length)
                    putJsonArray("elapsed_ms") { baselines.forEach { add(it.elapsedMs) } }
                }
            }
            put("confirmed_count", findings.count { it.confidence != Confidence.TENTATIVE })
            put("tentative_count", findings.count { it.confidence == Confidence.TENTATIVE })
            putJsonArray("findings") { findings.forEach { add(it.toJson()) } }
            if (notes.isNotEmpty()) putJsonArray("notes") { notes.forEach { add(it) } }
        }
    }

    private class Halt(val reason: String) : RuntimeException(reason)

    /** A request ready to send and the payload it carries; [structural] when the request was rewritten beyond `FUZZ`. */
    private class Condition(val request: String, val payload: String, val structural: Boolean)

    private class Pending(
        val cls: InjectionClass,
        val technique: String,
        val condition: Condition,
        val issued: OobChannel.Payload,
        val response: Observation,
        val control: Boolean = false,
    )

    private val findings = ArrayList<Finding>()
    private val notes = LinkedHashSet<String>()
    private val pending = ArrayList<Pending>()
    private val baselineRequest = template.render(settings.baseValue, settings.encoding)
    private var baselines: List<Observation> = emptyList()
    private var baselineBodies: List<String> = emptyList()
    private var baselineMs = 0L
    private var startedAt = 0L
    private var sent = 0
    private var unanswered = 0
    private var oobSkipped = false

    fun run(): Report {
        startedAt = nanoTime()
        if (!template.hasMarker) return Report(error = NO_MARKER)
        baselines = takeBaselines()
        if (baselines.size < 2) {
            return Report(
                error = "The baseline request (FUZZ=${settings.baseValue}) got ${baselines.size} response(s) in $BASELINE_ATTEMPTS attempts: " +
                    "the target is unreachable or unstable, so nothing was tested.",
                probesSent = sent,
            )
        }
        baselineBodies = baselines.map { it.body }
        baselineMs = baselines.maxOf { it.elapsedMs }
        if (baselines.first().status >= 400) {
            notes += "The baseline request returned HTTP ${baselines.first().status}. Check the path, parameters and session: every oracle compares against it."
        }

        val completed = ArrayList<InjectionClass>()
        var stoppedEarly: String? = null
        try {
            for (cls in settings.classes) {
                when (cls) {
                    InjectionClass.SQLI -> sqli()
                    InjectionClass.NOSQLI -> nosqli()
                    InjectionClass.CMDI -> cmdi()
                    InjectionClass.SSTI -> computed(InjectionClass.SSTI, "expression evaluation", InjectionPayloads.sstiArithmetic)
                    InjectionClass.LFI -> lfi()
                    InjectionClass.XXE -> xxe()
                    InjectionClass.SSRF -> ssrf()
                    InjectionClass.XSS -> xss()
                    InjectionClass.OPEN_REDIRECT -> openRedirect()
                    InjectionClass.CRLF -> crlf()
                }
                completed += cls
            }
        } catch (halt: Halt) {
            stoppedEarly = halt.reason
        }
        resolveOutOfBand(wait = stoppedEarly == null)
        if (oobSkipped) {
            notes += "Out-of-band checks were skipped: ${settings.oobUnavailable ?: "no out-of-band channel"}. In-band oracles still ran."
        }
        return Report(
            findings = findings.toList(),
            notes = notes.toList(),
            classesCompleted = completed,
            classesNotCompleted = settings.classes - completed.toSet(),
            probesSent = sent,
            baselines = baselines,
            oobProbes = pending.size,
            stoppedEarly = stoppedEarly,
            durationMs = elapsedMs(),
        )
    }

    // ---------------------------------------------------------------
    // Sending
    // ---------------------------------------------------------------

    private fun elapsedMs(): Long = (nanoTime() - startedAt) / 1_000_000

    private fun takeBaselines(): List<Observation> {
        val answered = ArrayList<Observation>()
        var attempts = 0
        while (attempts < BASELINE_ATTEMPTS && answered.size < 2) {
            attempts++
            val answer = exchange(baselineRequest, settings.requestTimeoutMs)
            sent++
            if (answer.answered) answered += answer
        }
        return answered
    }

    private fun transmit(request: String, timeoutMs: Long = settings.requestTimeoutMs): Observation {
        if (elapsedMs() >= settings.timeBudgetMs) throw Halt("the time budget of ${settings.timeBudgetMs / 1000}s ran out")
        val answer = exchange(request, timeoutMs)
        sent++
        if (answer.answered) {
            unanswered = 0
        } else {
            unanswered++
            if (unanswered >= MAX_UNANSWERED) {
                // The target, or just these payloads? The baseline request tells them apart.
                val alive = exchange(baselineRequest, settings.requestTimeoutMs)
                sent++
                if (!alive.answered) {
                    throw Halt("the target stopped responding ($MAX_UNANSWERED probes in a row, then the baseline request, got no response)")
                }
                unanswered = 0
                notes += "Some probes got no response while the baseline request still answers: something in front of the target probably drops them"
            }
        }
        return answer
    }

    // ---------------------------------------------------------------
    // Evidence
    // ---------------------------------------------------------------

    private fun clip(text: String, max: Int = MAX_EVIDENCE_TEXT): String = BodyText.stripLoneSurrogates(BodyText.truncate(text, max))

    private fun JsonObjectBuilder.observation(key: String, o: Observation, more: JsonObjectBuilder.() -> Unit = {}) {
        putJsonObject(key) {
            put("status", o.status)
            put("elapsed_ms", o.elapsedMs)
            put("length", o.body.length)
            more()
        }
    }

    /**
     * What every finding carries: where `FUZZ` sits and how the payload was written there (or the
     * whole request when it was rewritten), then the baseline next to the probe response.
     * [baseline] and [observed] add what the oracle compared.
     */
    private fun evidence(
        condition: Condition,
        response: Observation?,
        baseline: JsonObjectBuilder.() -> Unit = {},
        observed: JsonObjectBuilder.() -> Unit = {},
        more: JsonObjectBuilder.() -> Unit = {},
    ): JsonObject = buildJsonObject {
        if (condition.structural) {
            put("request", clip(condition.request, MAX_EVIDENCE_REQUEST))
        } else {
            put("sent_payload", clip(template.encoded(condition.payload, settings.encoding), MAX_EVIDENCE_REQUEST))
        }
        observation("baseline", baselines.first(), baseline)
        if (response != null) observation("probe", response, observed)
        more()
    }

    private fun plain(payload: String): Condition = Condition(template.render(payload, settings.encoding), payload, structural = false)

    private fun similarity(o: Observation): Double =
        TextSimilarity.dice(BodyText.truncate(baselines.first().body, MAX_SIMILARITY_INPUT), BodyText.truncate(o.body, MAX_SIMILARITY_INPUT))

    // ---------------------------------------------------------------
    // Shared techniques
    // ---------------------------------------------------------------

    /**
     * Time-based check with its double check: a payload that answers late is sent again asking
     * for no delay, then once more with the delay ([InjectionOracle.timingVerdict]).
     */
    private fun timeBased(cls: InjectionClass, candidates: List<InjectionPayloads.Enclosed>) {
        val delay = settings.delaySeconds
        val timeoutMs = maxOf(settings.requestTimeoutMs, delay * 3_000L + 10_000L)
        val seen = HashSet<String>()
        var unconfirmed = 0
        for (candidate in candidates) {
            val delayed = plain(InjectionPayloads.timed(candidate.text, settings.baseValue, delay))
            if (!seen.add(delayed.request)) continue
            val first = transmit(delayed.request, timeoutMs)
            if (!InjectionOracle.delayed(baselineMs, first, delay)) continue
            val control = plain(InjectionPayloads.timed(candidate.text, settings.baseValue, 0))
            val controlResponse = transmit(control.request, timeoutMs)
            val repeat =
                if (InjectionOracle.fastControl(baselineMs, controlResponse, delay)) transmit(delayed.request, timeoutMs)
                else Observation.NO_RESPONSE
            val verdict = InjectionOracle.timingVerdict(baselineMs, first, controlResponse, repeat, delay)
            if (verdict.confirmed) {
                findings += Finding(
                    cls, "time-based", "high", Confidence.FIRM,
                    "The response is late by the injected ${delay}s delay: ${verdict.reason}",
                    delayed.payload,
                    evidence(
                        delayed, repeat,
                        baseline = { putJsonArray("elapsed_ms_samples") { baselines.forEach { add(it.elapsedMs) } } },
                        more = {
                            put("delay_seconds", delay)
                            observation("first_probe", first)
                            observation("zero_delay_control", controlResponse) { put("payload", control.payload) }
                        },
                    ),
                )
                return
            }
            notes += "${cls.id} time-based: '${delayed.payload}' was slow once but not confirmed (${verdict.reason})"
            unconfirmed++
            if (unconfirmed >= MAX_UNCONFIRMED_DELAYS) {
                notes += "${cls.id} time-based: response times are too unstable to judge, the remaining timing payloads were skipped"
                return
            }
        }
    }

    private fun textCondition(candidate: InjectionPayloads.Enclosed): (Int, Boolean) -> Condition? = { round, truth ->
        plain(InjectionPayloads.boolean(candidate.text, settings.baseValue, round, truth))
    }

    /**
     * Blind boolean check. Each candidate yields a TRUE and a FALSE request per round; the first
     * round screens, and a finding needs [InjectionOracle.booleanDifferential] to hold over all
     * [BOOLEAN_ROUNDS] rounds, each with different literals.
     */
    private fun booleanBased(cls: InjectionClass, technique: String, candidates: List<(Int, Boolean) -> Condition?>) {
        for (candidate in candidates) {
            val trues = ArrayList<Observation>()
            val falses = ArrayList<Observation>()
            var shown: Pair<Condition, Condition>? = null
            var verdict: InjectionOracle.BooleanVerdict? = null
            for (round in 0 until BOOLEAN_ROUNDS) {
                val whenTrue = candidate(round, true) ?: break
                val whenFalse = candidate(round, false) ?: break
                if (shown == null) shown = whenTrue to whenFalse
                val trueResponse = transmit(whenTrue.request)
                if (!trueResponse.answered) {
                    verdict = null
                    break
                }
                trues += trueResponse
                falses += transmit(whenFalse.request)
                verdict = InjectionOracle.booleanDifferential(baselines, trues, falses)
                if (verdict == null) break
            }
            val confirmed = verdict ?: continue
            val (whenTrue, whenFalse) = shown ?: continue
            if (trues.size < BOOLEAN_ROUNDS) continue
            val side =
                if (confirmed.polarity == "false_diverges") "the FALSE condition changes the response and the TRUE one does not"
                else "the TRUE condition changes the response and the FALSE one does not"
            findings += Finding(
                cls, technique, "high", Confidence.FIRM,
                "TRUE and FALSE conditions were told apart in $BOOLEAN_ROUNDS rounds with different literals: $side",
                whenTrue.payload,
                evidence(
                    whenTrue, null,
                    more = {
                        put("true_payload", whenTrue.payload)
                        put("false_payload", whenFalse.payload)
                        if (whenFalse.structural) {
                            put("false_request", clip(whenFalse.request, MAX_EVIDENCE_REQUEST))
                        } else {
                            put("false_sent_payload", clip(template.encoded(whenFalse.payload, settings.encoding), MAX_EVIDENCE_REQUEST))
                        }
                        put("polarity", confirmed.polarity)
                        putJsonArray("distinguishing_tokens") { confirmed.tokens.forEach { add(it) } }
                        put("true_similarity_to_baseline", similarity(trues.first()))
                        put("false_similarity_to_baseline", similarity(falses.first()))
                        putJsonArray("rounds") {
                            for (round in trues.indices) {
                                addJsonObject {
                                    observation("true", trues[round])
                                    observation("false", falses[round])
                                }
                            }
                        }
                    },
                ),
            )
            return
        }
    }

    /**
     * Arithmetic the server must compute (`A*B` in a template expression or a shell). The result
     * has to be new against the baseline, and a second pair of operands has to give its own
     * result, which a number the page merely happens to contain cannot do.
     */
    private fun computed(cls: InjectionClass, technique: String, candidates: List<String>) {
        val expected = product(FIRST_OPERANDS)
        val confirmExpected = product(SECOND_OPERANDS)
        for (candidate in candidates) {
            val first = plain(InjectionPayloads.arithmetic(candidate, settings.baseValue, FIRST_OPERANDS.first, FIRST_OPERANDS.second))
            val response = transmit(first.request)
            if (!response.answered || !InjectionOracle.novelEvaluation(baselineBodies, response.body, expected)) continue
            val second = plain(InjectionPayloads.arithmetic(candidate, settings.baseValue, SECOND_OPERANDS.first, SECOND_OPERANDS.second))
            val confirmation = transmit(second.request)
            if (!confirmation.answered || !InjectionOracle.novelEvaluation(baselineBodies, confirmation.body, confirmExpected)) {
                notes += "${cls.id}: $expected appeared for '${first.payload}' but a second calculation was not evaluated; not reported"
                continue
            }
            findings += Finding(
                cls, technique, "high", Confidence.CERTAIN,
                "The server computed the injected arithmetic twice: " +
                    "${FIRST_OPERANDS.first}*${FIRST_OPERANDS.second}=$expected and ${SECOND_OPERANDS.first}*${SECOND_OPERANDS.second}=$confirmExpected",
                first.payload,
                evidence(
                    first, response,
                    baseline = { put("contains_result", false) },
                    observed = { put("contains_result", expected) },
                    more = {
                        observation("confirmation", confirmation) {
                            put("payload", second.payload)
                            put("contains_result", confirmExpected)
                        }
                    },
                ),
            )
            return
        }
    }

    /** Sends each of [candidates] with its own out-of-band host; [resolveOutOfBand] turns interactions into findings. */
    private fun outOfBand(cls: InjectionClass, technique: String, candidates: List<String>, control: String? = null) {
        val channel = oob
        if (channel == null) {
            oobSkipped = true
            return
        }
        val all = candidates.map { it to false } + listOfNotNull(control?.let { it to true })
        for ((candidate, isControl) in all) {
            val issued = channel.issue("${cls.id} $technique: $candidate")
            if (issued == null) {
                notes += "The out-of-band channel stopped issuing payloads; the remaining ${cls.id} out-of-band probes were skipped"
                return
            }
            val condition = plain(candidate.replace("{host}", issued.host).replace("{base}", settings.baseValue))
            pending += Pending(cls, technique, condition, issued, transmit(condition.request), isControl)
        }
    }

    private fun resolveOutOfBand(wait: Boolean) {
        val channel = oob ?: return
        if (pending.isEmpty()) return
        val hits = HashMap<String, MutableList<OobChannel.Interaction>>()
        fun collect() {
            for (interaction in channel.collect()) hits.getOrPut(interaction.payloadId) { ArrayList() } += interaction
        }
        collect()
        var polls = if (wait) (settings.oobWaitMs / OOB_POLL_INTERVAL_MS).toInt() else 0
        while (polls-- > 0 && !pending.all { entry -> hits[entry.issued.id].orEmpty().any { it.type == "http" } }) {
            pause(OOB_POLL_INTERVAL_MS)
            collect()
        }

        // An inert mention of a host that still gets resolved or fetched means that kind of
        // interaction happens without the vulnerability, so it proves nothing for that class.
        val expectedAnyway = HashMap<InjectionClass, MutableSet<String>>()
        for (entry in pending) {
            if (entry.control) expectedAnyway.getOrPut(entry.cls) { HashSet() } += hits[entry.issued.id].orEmpty().map { it.type }
        }
        for (entry in pending) {
            if (entry.control) continue
            val discounted = expectedAnyway[entry.cls].orEmpty()
            val interactions = hits[entry.issued.id].orEmpty().filter { it.type !in discounted }
            if (interactions.isEmpty()) {
                if (hits[entry.issued.id].orEmpty().isNotEmpty()) {
                    notes += "${entry.cls.id} out-of-band: '${entry.condition.payload}' got ${discounted.joinToString("/")} interactions, " +
                        "but so did a host that was only mentioned in the value, so they do not show the vulnerability"
                }
                continue
            }
            val types = interactions.map { it.type }.distinct()
            val fetched = "http" in types
            // A DNS lookup is all `nslookup` does; for a URL it shows resolution but not a fetch.
            val certain = fetched || entry.cls == InjectionClass.CMDI
            findings += Finding(
                entry.cls, entry.technique,
                if (certain || entry.cls != InjectionClass.SSRF) "high" else "medium",
                if (certain) Confidence.CERTAIN else Confidence.FIRM,
                "The out-of-band host carried only by this probe received ${types.joinToString(" and ")} interaction(s)" +
                    (if (certain) "" else ": the name was resolved, a fetch was not observed"),
                entry.condition.payload,
                evidence(
                    entry.condition, entry.response,
                    baseline = { put("interactions", 0) },
                    more = {
                        put("oob_host", entry.issued.host)
                        putJsonArray("interactions") {
                            for ((_, type, clientIp, timestamp, detail) in interactions.take(MAX_EVIDENCE_INTERACTIONS)) {
                                addJsonObject {
                                    put("type", type)
                                    put("client_ip", clientIp)
                                    put("timestamp", timestamp)
                                    if (detail.isNotEmpty()) put("detail", clip(detail))
                                }
                            }
                        }
                    },
                ),
            )
        }
    }

    // ---------------------------------------------------------------
    // Classes
    // ---------------------------------------------------------------

    private fun sqli() {
        val base = settings.baseValue
        for (breaker in InjectionPayloads.sqlBreakers) {
            val broken = plain(base + breaker)
            val response = transmit(broken.request)
            if (!response.answered) continue
            val match = InjectionOracle.novelSqlError(baselineBodies, response.body) ?: continue
            // A doubled quote is an escaped literal: the error going away shows the quote reached the SQL parser.
            val quote = breaker.firstOrNull { it == '\'' || it == '"' }
            val doubled = quote?.let { plain(base + it + it) }
            val doubledResponse = doubled?.let { transmit(it.request) }
            val balanced = doubledResponse != null && doubledResponse.answered && InjectionOracle.sqlErrorMatch(doubledResponse.body) == null
            findings += Finding(
                InjectionClass.SQLI, "error-based", "high", if (balanced) Confidence.CERTAIN else Confidence.FIRM,
                "A ${match.kind} error appears when the value is followed by $breaker" +
                    (if (balanced) " and is gone when the quote is doubled" else ""),
                broken.payload,
                evidence(
                    broken, response,
                    baseline = { put("sql_error", false) },
                    observed = {
                        put("sql_error", match.kind)
                        put("match", match.excerpt)
                    },
                    more = {
                        if (doubled != null && doubledResponse != null) {
                            observation("doubled_quote", doubledResponse) {
                                put("payload", doubled.payload)
                                put("sql_error", !balanced)
                            }
                        }
                    },
                ),
            )
            break
        }
        timeBased(InjectionClass.SQLI, InjectionPayloads.sqlTime)
        booleanBased(InjectionClass.SQLI, "boolean-based", InjectionPayloads.sqlBoolean.map { textCondition(it) })
    }

    private fun nosqli() {
        val base = settings.baseValue
        for (breaker in InjectionPayloads.nosqlBreakers) {
            val broken = plain(base + breaker)
            val response = transmit(broken.request)
            if (!response.answered) continue
            val match = InjectionOracle.novelNosqlError(baselineBodies, response.body) ?: continue
            findings += Finding(
                InjectionClass.NOSQLI, "error-based", "high", Confidence.FIRM,
                "A ${match.kind} error appears when the value is followed by $breaker",
                broken.payload,
                evidence(
                    broken, response,
                    baseline = { put("query_error", false) },
                    observed = {
                        put("query_error", match.kind)
                        put("match", match.excerpt)
                    },
                ),
            )
            break
        }
        booleanBased(InjectionClass.NOSQLI, "boolean-based (server-side JavaScript)", InjectionPayloads.nosqlBoolean.map { textCondition(it) })
        if (template.renderKeyOperators(listOf("\$eq" to "")) == null && template.renderJsonValue("1") == null) {
            notes += "nosqli operator injection needs FUZZ to be the value of a query/form parameter or a JSON value; skipped for this injection point"
        } else {
            booleanBased(InjectionClass.NOSQLI, "operator injection", InjectionPayloads.nosqlOperators.map { operatorCondition(it) })
        }
        timeBased(InjectionClass.NOSQLI, InjectionPayloads.nosqlTime)
    }

    private fun operatorCondition(candidate: InjectionPayloads.OperatorProbe): (Int, Boolean) -> Condition? = { round, truth ->
        candidate.conditions(settings.baseValue, round, truth)?.let { operators ->
            val json = buildJsonObject {
                for ((op, operand) in operators) {
                    if (candidate.numeric) put(op, operand.toLongOrNull() ?: operand.toBigDecimal()) else put(op, operand)
                }
            }.toString()
            // A query or form value always arrives as a string: number operands need a JSON body.
            val keyed = if (candidate.numeric) null else template.renderKeyOperators(operators)
            (keyed ?: template.renderJsonValue(json))?.let { Condition(it, "${candidate.label}: $json", structural = true) }
        }
    }

    private fun cmdi() {
        val seen = HashSet<String>()
        var shown = false
        for (candidate in InjectionPayloads.cmdOutput) {
            val command = plain(candidate.replace("{base}", settings.baseValue))
            if (!seen.add(command.request)) continue
            val response = transmit(command.request)
            if (!response.answered) continue
            val match = InjectionOracle.novelCommandOutput(baselineBodies, response.body) ?: continue
            findings += Finding(
                InjectionClass.CMDI, "output-based", "high", Confidence.CERTAIN,
                "The response contains the output of the injected id command",
                command.payload,
                evidence(
                    command, response,
                    baseline = { put("command_output", false) },
                    observed = { put("match", match.excerpt) },
                ),
            )
            shown = true
            break
        }
        if (!shown) computed(InjectionClass.CMDI, "output-based (shell arithmetic)", InjectionPayloads.cmdArithmetic)
        timeBased(InjectionClass.CMDI, InjectionPayloads.cmdTime)
        outOfBand(InjectionClass.CMDI, "out-of-band", InjectionPayloads.cmdOob, control = "{base}.{host}")
    }

    private fun lfi() {
        val seen = HashSet<String>()
        for (candidate in InjectionPayloads.fileRead) {
            val read = plain(candidate)
            if (!seen.add(read.request)) continue
            val response = transmit(read.request)
            if (!response.answered) continue
            val match = InjectionOracle.novelFileMarker(baselineBodies, response.body) ?: continue
            findings += Finding(
                InjectionClass.LFI, "file read", "high", Confidence.CERTAIN,
                "The response contains the contents of a system file (${match.kind})",
                read.payload,
                evidence(
                    read, response,
                    baseline = { put("file_marker", false) },
                    observed = {
                        put("file_marker", match.kind)
                        put("match", match.excerpt)
                    },
                ),
            )
            return
        }
    }

    /**
     * An entity probe: a DOCTYPE inside the request's own XML body when `FUZZ` sits in one,
     * otherwise a whole document in place of `FUZZ` (written raw when the body is the document).
     */
    private fun entityCondition(declarations: String, reference: String): Condition {
        template.renderXmlEntity(declarations, reference)?.let {
            return Condition(it, "<!DOCTYPE ... [$declarations]> with $reference at FUZZ", structural = true)
        }
        val document = "<?xml version=\"1.0\"?><!DOCTYPE r [$declarations]><r>$reference</r>"
        val encoding = if (template.inXmlBody) PayloadEncoding.RAW else settings.encoding
        return Condition(template.render(document, encoding), document, structural = template.inXmlBody)
    }

    private fun xxe() {
        var read = false
        for (file in InjectionPayloads.xxeFiles) {
            val entity = entityCondition("<!ENTITY rjx SYSTEM \"$file\">", "&rjx;")
            val response = transmit(entity.request)
            if (!response.answered) continue
            val match = InjectionOracle.novelFileMarker(baselineBodies, response.body) ?: continue
            findings += Finding(
                InjectionClass.XXE, "external entity file read", "high", Confidence.CERTAIN,
                "An external entity pointing at $file was resolved and its contents returned (${match.kind})",
                entity.payload,
                evidence(
                    entity, response,
                    baseline = { put("file_marker", false) },
                    observed = {
                        put("file_marker", match.kind)
                        put("match", match.excerpt)
                    },
                ),
            )
            read = true
            break
        }

        if (!read) {
            // XInclude works where the value is copied into a server-side document and no DOCTYPE can be set.
            val include = "<xi:include xmlns:xi=\"http://www.w3.org/2001/XInclude\" parse=\"text\" href=\"file:///etc/passwd\"/>"
            val encoding = if (template.inXmlBody) PayloadEncoding.RAW else settings.encoding
            val included = Condition(template.render(include, encoding), include, structural = template.inXmlBody)
            val response = transmit(included.request)
            val match = if (response.answered) InjectionOracle.novelFileMarker(baselineBodies, response.body) else null
            if (match != null) {
                findings += Finding(
                    InjectionClass.XXE, "xinclude file read", "high", Confidence.CERTAIN,
                    "An XInclude element was processed and the file it names returned (${match.kind})",
                    included.payload,
                    evidence(
                        included, response,
                        baseline = { put("file_marker", false) },
                        observed = {
                            put("file_marker", match.kind)
                            put("match", match.excerpt)
                        },
                    ),
                )
                read = true
            }
        }

        if (!read) {
            // An entity built from another one: the expanded text is in the response only if the parser expanded it.
            val token = newToken()
            val expanded = token + "z" + token
            val entity = entityCondition("<!ENTITY rja \"$token\"><!ENTITY rjx \"&rja;z&rja;\">", "&rjx;")
            val response = transmit(entity.request)
            if (response.answered && InjectionOracle.novelText(baselineBodies, response.body, expanded)) {
                findings += Finding(
                    InjectionClass.XXE, "internal entity expansion", "low", Confidence.TENTATIVE,
                    "The XML parser accepts a DOCTYPE and expands entities declared in it; an external entity was not confirmed in-band",
                    entity.payload,
                    evidence(
                        entity, response,
                        baseline = { put("contains_expansion", false) },
                        observed = { put("contains_expansion", expanded) },
                    ),
                )
            }
        }
        if (read) return

        val channel = oob
        if (channel == null) {
            oobSkipped = true
            return
        }
        val probes = listOf(
            Triple("out-of-band external entity", "<!ENTITY rjx SYSTEM \"http://{host}/\">", "&rjx;"),
            Triple("out-of-band parameter entity", "<!ENTITY % rjp SYSTEM \"http://{host}/\"> %rjp;", settings.baseValue),
            // Control: the URL as an ordinary entity value, which no parser fetches.
            Triple("", "<!ENTITY rjx \"http://{host}/\">", "&rjx;"),
        )
        for ((technique, declarations, reference) in probes) {
            val issued = channel.issue("xxe ${technique.ifEmpty { "control" }}")
            if (issued == null) {
                notes += "The out-of-band channel stopped issuing payloads; the remaining xxe out-of-band probes were skipped"
                return
            }
            val entity = entityCondition(declarations.replace("{host}", issued.host), reference)
            pending += Pending(InjectionClass.XXE, technique, entity, issued, transmit(entity.request), control = technique.isEmpty())
        }
    }

    private fun ssrf() {
        for (candidate in InjectionPayloads.ssrfInBand) {
            val fetch = plain(candidate)
            val response = transmit(fetch.request)
            if (!response.answered) continue
            val match = InjectionOracle.novelInternalContent(baselineBodies, response.body) ?: continue
            findings += Finding(
                InjectionClass.SSRF, "in-band", "high", Confidence.CERTAIN,
                "The response contains what only a server-side fetch of $candidate returns (${match.kind})",
                fetch.payload,
                evidence(
                    fetch, response,
                    baseline = { put("internal_content", false) },
                    observed = {
                        put("internal_content", match.kind)
                        put("match", match.excerpt)
                    },
                ),
            )
            break
        }
        outOfBand(InjectionClass.SSRF, "out-of-band", InjectionPayloads.ssrfOob)
    }

    private fun xss() {
        val canary = newToken()
        val reflected = transmit(plain(canary).request)
        if (!reflected.answered) return
        if (baselineBodies.any { it.contains(canary, ignoreCase = true) }) return
        val clean = XssOracle.reflections(reflected.body, canary)
        if (clean.isEmpty()) {
            notes += "xss: the probe value is not reflected in the response"
            return
        }
        val contentType = reflected.header("Content-Type")
        if (!XssOracle.rendersAsHtml(contentType, reflected.body)) {
            notes += "xss: the value is reflected, but in a ${contentType ?: "non-HTML"} response a browser does not render as a document"
            return
        }

        val head = newToken()
        val tail = newToken()
        val separator = newToken().takeLast(5)
        val survivalProbe = plain(XssOracle.survivalProbe(head, tail, separator))
        val survived = transmit(survivalProbe.request)
        if (!survived.answered) return
        val survivals = XssOracle.survival(survived.body, head, tail, separator)
        if (survivals.isEmpty()) {
            notes += "xss: the reflection did not come back intact once special characters were added (HTTP ${survived.status}): filtered, truncated or blocked"
            return
        }
        // Positions come from the clean reflection; when the two responses reflect a different
        // number of times they are read from the second one, where earlier injected characters
        // may already have changed the structure.
        val positions =
            if (clean.size == survivals.size) clean
            else XssOracle.reflections(survived.body, head).let { disturbed ->
                survivals.mapNotNull { survival -> disturbed.firstOrNull { it.offset == survival.offset } }
            }
        if (positions.size != survivals.size) {
            notes += "xss: the value is reflected but its positions could not be matched between probes; not assessed"
            return
        }

        val tried = HashSet<String>()
        var reported = 0
        for ((index, reflection) in positions.withIndex()) {
            if (!tried.add("${reflection.kind.id}:${reflection.tag}:${reflection.attribute}")) continue
            val fates = survivals[index].fates
            val token = newToken()
            val breakout = XssOracle.breakout(reflection, fates, token) ?: continue
            val proof = breakout.proof?.let { plain(it) }
            val proofResponse = proof?.let { transmit(it.request) }
            if (proof != null && (proofResponse == null || !proofResponse.answered || XssOracle.reflections(proofResponse.body, token).none(breakout.confirms))) {
                notes += "xss: ${reflection.kind.id} looked escapable (${breakout.reason}) but '${proof.payload}' did not arrive in the new position; not reported"
                continue
            }
            val shown = proof ?: survivalProbe
            findings += Finding(
                InjectionClass.XSS, "reflected", "high", Confidence.FIRM,
                "The value is reflected in ${reflection.kind.id} and can leave that context: ${breakout.reason}. " +
                    "Script execution was not observed (no browser); a filter or Content-Security-Policy can still stop it.",
                shown.payload,
                evidence(
                    shown, proofResponse ?: survived,
                    baseline = { put("reflects_probe_value", false) },
                    more = {
                        putJsonObject("reflection") {
                            put("context", reflection.kind.id)
                            if (reflection.tag.isNotEmpty()) put("tag", reflection.tag)
                            if (reflection.attribute.isNotEmpty()) put("attribute", reflection.attribute)
                            put("content_type", contentType ?: "")
                            put("content_security_policy", reflected.header("Content-Security-Policy") != null)
                        }
                        putJsonObject("characters") {
                            for ((ch, fate) in fates) put(if (ch == ' ') "space" else ch.toString(), fate.id)
                        }
                        put("characters_payload", survivalProbe.payload)
                        put("escape_confirmed_by", if (proof != null) "proof payload arrived in the new position" else "character survival")
                        put("example_payload", breakout.example)
                    },
                ),
            )
            reported++
            if (reported >= MAX_XSS_FINDINGS) break
        }
        if (reported == 0 && notes.none { it.startsWith("xss:") }) {
            notes += "xss: the value is reflected (${positions.map { it.kind.id }.distinct().joinToString(", ")}) " +
                "but the characters needed to leave that context come back encoded"
        }
    }

    private fun openRedirect() {
        val canary = newToken() + ".example.com"
        val seen = HashSet<String>()
        for (candidate in InjectionPayloads.openRedirect) {
            val redirect = plain(candidate.replace("{canary}", canary).replace("{target}", settings.targetHost))
            if (!seen.add(redirect.request)) continue
            val response = transmit(redirect.request)
            val hit = InjectionOracle.novelRedirect(baselines, response, canary) ?: continue
            val confidence = when (hit.via) {
                "location_header" -> Confidence.CERTAIN
                "script" -> Confidence.TENTATIVE
                else -> Confidence.FIRM
            }
            findings += Finding(
                InjectionClass.OPEN_REDIRECT, hit.via, "low", confidence,
                "The response redirects the browser to the supplied host $canary (${hit.via})",
                redirect.payload,
                evidence(
                    redirect, response,
                    baseline = {
                        put("redirects_to_canary", false)
                        baselines.first().header("Location")?.let { put("location", clip(it)) }
                    },
                    observed = {
                        put("redirect_via", hit.via)
                        put("redirect_target", clip(hit.target))
                    },
                ),
            )
            return
        }
    }

    private fun crlf() {
        val header = "X-" + newToken()
        val seen = HashSet<String>()
        for (candidate in InjectionPayloads.crlf) {
            val split = plain(candidate.replace("{header}", header).replace("{base}", settings.baseValue))
            if (!seen.add(split.request)) continue
            val response = transmit(split.request)
            val value = InjectionOracle.novelHeader(baselines, response, header) ?: continue
            findings += Finding(
                InjectionClass.CRLF, "response header injection", "high", Confidence.CERTAIN,
                "The response carries the injected header $header: the value ended a header line and started a new one",
                split.payload,
                evidence(
                    split, response,
                    baseline = { put("has_injected_header", false) },
                    observed = {
                        put("injected_header", header)
                        put("injected_header_value", clip(value))
                    },
                ),
            )
            return
        }
    }

    companion object {
        /** Classes with an out-of-band check. */
        val OOB_CLASSES: Set<InjectionClass> = setOf(InjectionClass.CMDI, InjectionClass.XXE, InjectionClass.SSRF)

        const val NO_MARKER = "Mark the injection point with the FUZZ keyword in the request string."

        private const val BASELINE_ATTEMPTS = 3
        private const val MAX_UNANSWERED = 3
        private const val MAX_UNCONFIRMED_DELAYS = 2
        private const val BOOLEAN_ROUNDS = 3
        private const val MAX_XSS_FINDINGS = 3
        private const val OOB_POLL_INTERVAL_MS = 1_000L
        private const val MAX_EVIDENCE_TEXT = 300
        private const val MAX_EVIDENCE_REQUEST = 4_000
        private const val MAX_EVIDENCE_INTERACTIONS = 5
        private const val MAX_SIMILARITY_INPUT = 50_000

        private val FIRST_OPERANDS = 1337 to 1337
        private val SECOND_OPERANDS = 2713 to 4219

        private fun product(operands: Pair<Int, Int>): String = (operands.first.toLong() * operands.second).toString()
    }
}
