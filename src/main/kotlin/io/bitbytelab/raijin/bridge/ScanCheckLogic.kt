package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.core.BodyText
import io.bitbytelab.raijin.core.EnumValidation
import io.bitbytelab.raijin.core.asJsonObjectList
import io.bitbytelab.raijin.safety.SafeRegex
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive

/** A check definition the caller got wrong. The message goes back to the agent as is. */
internal class InvalidCheckException(message: String) : Exception(message)

/**
 * What a condition can look at, detached from Montoya so the same logic judges a scanner
 * message, a proxy history item and a test fixture.
 */
internal data class CheckExchange(
    val requestUrl: String = "",
    val requestHeaders: String = "",
    val requestBody: String = "",
    val hasResponse: Boolean = false,
    val statusCode: Int = 0,
    val responseHeaders: String = "",
    val responseBody: String = "",
    val responseLength: Int = 0,
) {
    /** This request paired with [other]'s response: the exchange as it would be had the response not changed. */
    fun withResponseOf(other: CheckExchange): CheckExchange = copy(
        hasResponse = other.hasResponse,
        statusCode = other.statusCode,
        responseHeaders = other.responseHeaders,
        responseBody = other.responseBody,
        responseLength = other.responseLength,
    )
}

internal enum class MatchMode { ALL, ANY }

/** @property type `matches` (regex), `contains` or `equals`. */
internal data class CheckCondition(
    val location: String,
    val pattern: String,
    val type: String,
    val negate: Boolean = false,
    val ignoreCase: Boolean = true,
) {
    val onResponse: Boolean get() = location in ScanCheckLogic.RESPONSE_LOCATIONS
}

/**
 * @property conditions what the response to [payload] has to show. A step without any primes the
 *   target (stores or sets up something a later step reads): being answered is all it has to do.
 * @property stopIfNoMatch true: the step is required and the chain ends without it; false: the step is optional.
 */
internal data class ActiveStep(
    val payload: String,
    val conditions: List<CheckCondition>,
    val mode: MatchMode = MatchMode.ALL,
    val stopIfNoMatch: Boolean = true,
) {
    /** Whether the step looks at the response at all: only such a step can be evidence. */
    val judgesResponse: Boolean get() = conditions.any { it.onResponse }
}

internal data class PassiveRule(val conditions: List<CheckCondition>, val mode: MatchMode = MatchMode.ALL)

/**
 * A custom scan check as registered: its name, what it reports, and its passive and/or active part.
 *
 * @property name the registration name; one check per name.
 * @property severity one of [ScanCheckLogic.SEVERITIES].
 * @property confidence one of [ScanCheckLogic.CONFIDENCES].
 */
internal data class CheckDefinition(
    val name: String,
    val issueName: String,
    val description: String,
    val detail: String,
    val remediation: String,
    val severity: String,
    val confidence: String,
    val passive: PassiveRule? = null,
    val active: List<ActiveStep>? = null,
) {
    val mode: String
        get() = when {
            passive != null && active != null -> "both"
            active != null -> "active"
            else -> "passive"
        }
}

/**
 * What one step of an active check did.
 *
 * @property answered a response came back for the step's payload.
 * @property novel the step matched, and would not have against the baseline response.
 */
internal data class StepTrace(val step: Int, val answered: Boolean, val matched: Boolean, val novel: Boolean)

/**
 * @property evidence what `send` returned for every step that matched, in step order.
 * @property novelPayloads payloads of the steps whose match the baseline response does not produce.
 */
internal class ActiveResult<T>(
    val report: Boolean,
    val reason: String,
    val trace: List<StepTrace>,
    val evidence: List<T>,
    val novelPayloads: List<String>,
)

/** Parsing, evaluation and consolidation rules of custom scan checks. Pure: no Burp objects. */
internal object ScanCheckLogic {

    val RESPONSE_LOCATIONS: Set<String> =
        linkedSetOf("response_body", "response_headers", "status_code", "response_length")
    val LOCATIONS: Set<String> = RESPONSE_LOCATIONS + linkedSetOf("request_body", "request_headers", "request_url")
    val CONDITION_TYPES: Set<String> = linkedSetOf("matches", "contains", "equals")
    val MATCH_MODES: Set<String> = linkedSetOf("all", "any")
    val SEVERITIES: Set<String> = linkedSetOf("high", "medium", "low", "information")
    val CONFIDENCES: Set<String> = linkedSetOf("certain", "firm", "tentative")

    // ---------------------------------------------------------------
    // Definition parsing
    // ---------------------------------------------------------------

    /** The canonical severity for [value] (`info` is accepted for `information`). */
    fun severity(value: String?, param: String = "severity"): String {
        val v = value?.trim()?.lowercase()
        if (v == "info") return "information"
        requireEnum(value, SEVERITIES, param, required = true)
        return v!!
    }

    fun confidence(value: String?, param: String = "confidence"): String {
        requireEnum(value, CONFIDENCES, param, required = true)
        return value!!.trim().lowercase()
    }

    /** `all` unless [value] says `any`. */
    fun matchMode(value: String?, param: String = "match_mode"): MatchMode {
        requireEnum(value, MATCH_MODES, param, required = false)
        return if (value?.trim().equals("any", ignoreCase = true)) MatchMode.ANY else MatchMode.ALL
    }

    /** Parses condition objects `{location, pattern, condition_type, negate}`; [at] names the list in error messages. */
    fun conditions(raw: List<JsonObject>, at: String): List<CheckCondition> = raw.mapIndexed { i, c ->
        val where = "$at[$i]"
        val location = string(c["location"])
        requireEnum(location, LOCATIONS, "$where.location", required = true)
        val typeRaw = string(c["condition_type"])
        requireEnum(typeRaw, CONDITION_TYPES, "$where.condition_type", required = false)
        val type = typeRaw?.trim()?.lowercase().takeUnless { it.isNullOrEmpty() } ?: "matches"
        val pattern = string(c["pattern"]) ?: throw InvalidCheckException("$where.pattern is required")
        if (pattern.isEmpty() && type != "equals") {
            throw InvalidCheckException("$where.pattern is empty; an empty '$type' pattern matches every message")
        }
        if (type == "matches") {
            SafeRegex.validate(pattern, ignoreCase = true)?.let {
                throw InvalidCheckException("Invalid regex in $where.pattern: $it")
            }
        }
        CheckCondition(location!!.trim().lowercase(), pattern, type, negate = bool(c["negate"]) ?: false)
    }

    /**
     * Parses step objects `{payload, response_conditions[], match_mode, stop_if_no_match}`.
     * A step without `match_mode` combines its conditions with [defaultMode].
     */
    fun steps(raw: List<JsonObject>, defaultMode: MatchMode): List<ActiveStep> {
        val steps = raw.mapIndexed { i, s ->
            val payload = string(s["payload"])
                ?: throw InvalidCheckException("steps[$i].payload is required and must be a string")
            val listed = s["response_conditions"]
            val conditionObjects = if (listed == null || listed is JsonNull) {
                emptyList<JsonObject>()
            } else {
                listed.asJsonObjectList()?.takeIf { listed !is JsonArray || it.size == listed.size }
                    ?: throw InvalidCheckException("steps[$i].response_conditions must be an array of condition objects")
            }
            ActiveStep(
                payload = payload,
                conditions = conditions(conditionObjects, "steps[$i].response_conditions"),
                mode = string(s["match_mode"])?.let { matchMode(it, "steps[$i].match_mode") } ?: defaultMode,
                stopIfNoMatch = bool(s["stop_if_no_match"]) ?: true,
            )
        }
        if (steps.none { it.judgesResponse }) {
            throw InvalidCheckException(
                "No step has a response_conditions entry on the response " +
                    "(${RESPONSE_LOCATIONS.joinToString(", ")}). An active check only reports what a payload " +
                    "changes in the response, so this one could never report."
            )
        }
        return steps
    }

    private fun requireEnum(value: String?, allowed: Set<String>, param: String, required: Boolean) {
        EnumValidation.error(value, allowed, param, required)?.let {
            throw InvalidCheckException(it.getValue("error").jsonPrimitive.content)
        }
    }

    private fun string(element: JsonElement?): String? = (element as? JsonPrimitive)?.contentOrNull

    private fun bool(element: JsonElement?): Boolean? = (element as? JsonPrimitive)?.booleanOrNull

    // ---------------------------------------------------------------
    // Evaluation
    // ---------------------------------------------------------------

    fun matches(condition: CheckCondition, exchange: CheckExchange): Boolean {
        // Without a response there is nothing to judge, and negation must not read that as a hit.
        if (condition.onResponse && !exchange.hasResponse) return false
        val text = textAt(condition.location, exchange)
        val hit = when (condition.type) {
            "contains" -> text.contains(condition.pattern, ignoreCase = condition.ignoreCase)
            "equals" -> text.equals(condition.pattern, ignoreCase = condition.ignoreCase)
            else -> SafeRegex.containsMatchIn(condition.pattern, regexInput(text), ignoreCase = condition.ignoreCase)
        }
        return hit != condition.negate
    }

    /**
     * Whether [conditions] hold for [exchange] under [mode]. No conditions hold in either mode: a
     * priming step without any has done its part once it is answered.
     */
    fun satisfied(conditions: List<CheckCondition>, mode: MatchMode, exchange: CheckExchange): Boolean = when {
        conditions.isEmpty() -> true
        mode == MatchMode.ANY -> conditions.any { matches(it, exchange) }
        else -> conditions.all { matches(it, exchange) }
    }

    /** The parts of a message [conditions] look at: all that has to be read to judge them. */
    fun locations(conditions: Collection<CheckCondition>): Set<String> = conditions.mapTo(HashSet()) { it.location }

    /**
     * Runs the steps of an active check in order and decides whether it may report.
     *
     * It reports only when some step matched in a way the baseline response does not: the step's
     * conditions are evaluated again on the probe's own request paired with the baseline response,
     * so nothing but what the payload changed in the response counts as evidence. A step whose
     * probe gets no response never matches. A step that does not look at the response (a priming
     * step) matches once it is answered, but is never evidence itself.
     *
     * A match that passes that test is confirmed against [control] before it counts: a fresh
     * response to the unmodified request. A page that has changed since the baseline was recorded
     * (or answers the check's own requests differently from the scanner's) then does not pass for
     * something the payload did.
     *
     * Both are taken before the first payload is sent. A payload can change what the unmodified
     * request returns from then on (a stored comment, a saved profile field), and a control
     * fetched after it would show the payload's own effect and explain the evidence away.
     *
     * @param baseline the recorded response to the unmodified request, or null when there is none.
     *   Called once, before the first payload.
     * @param send sends one payload; returns what came back plus the caller's evidence object, or
     *   null when nothing did.
     * @param control fetches the unmodified request's response now, or null when that is not
     *   possible. Called once, after [baseline] and before the first payload.
     */
    fun <T> runActive(
        steps: List<ActiveStep>,
        baseline: () -> CheckExchange?,
        send: (payload: String) -> Pair<CheckExchange, T>?,
        control: () -> CheckExchange? = { null },
    ): ActiveResult<T> {
        val base = baseline()?.takeIf { it.hasResponse }
        val fresh = control()?.takeIf { it.hasResponse }
        val trace = ArrayList<StepTrace>(steps.size)
        val evidence = ArrayList<T>()
        val novelPayloads = ArrayList<String>()

        /** Whether [exchange]'s request would have matched [step] had it been answered with [response]. */
        fun explainedBy(response: CheckExchange, step: ActiveStep, exchange: CheckExchange): Boolean =
            satisfied(step.conditions, step.mode, exchange.withResponseOf(response))

        for ((i, step) in steps.withIndex()) {
            val probe = send(step.payload)?.takeIf { it.first.hasResponse }
            if (probe == null) {
                trace += StepTrace(i + 1, answered = false, matched = false, novel = false)
                if (step.stopIfNoMatch) {
                    return ActiveResult(false, "step ${i + 1} got no response", trace, evidence, novelPayloads)
                }
                continue
            }
            val (exchange, proof) = probe
            val matched = satisfied(step.conditions, step.mode, exchange)
            val novel = matched && step.judgesResponse &&
                base?.let { !explainedBy(it, step, exchange) } == true &&
                fresh?.let { explainedBy(it, step, exchange) } != true
            trace += StepTrace(i + 1, answered = true, matched = matched, novel = novel)
            if (!matched) {
                if (step.stopIfNoMatch) {
                    return ActiveResult(false, "step ${i + 1} did not match", trace, evidence, novelPayloads)
                }
                continue
            }
            evidence += proof
            if (novel) novelPayloads += step.payload
        }

        val reason = when {
            novelPayloads.isNotEmpty() -> "a step matched and the unmodified request's response does not"
            trace.none { it.matched && steps[it.step - 1].judgesResponse } -> "no step that looks at the response matched"
            else -> "every match is also produced by the unmodified request, or there is no response to compare with"
        }
        return ActiveResult(novelPayloads.isNotEmpty(), reason, trace, evidence, novelPayloads)
    }

    /** A short piece of the text a non-negated [condition] matched on, or null when it did not match. */
    fun excerpt(condition: CheckCondition, exchange: CheckExchange, radius: Int = 40): String? {
        if (condition.negate || (condition.onResponse && !exchange.hasResponse)) return null
        val text = textAt(condition.location, exchange)
        val range = when (condition.type) {
            "contains" -> text.indexOf(condition.pattern, ignoreCase = condition.ignoreCase)
                .takeIf { it >= 0 }?.let { it until it + condition.pattern.length }
            "equals" -> if (text.equals(condition.pattern, ignoreCase = condition.ignoreCase)) text.indices else null
            else -> SafeRegex.find(condition.pattern, regexInput(text), ignoreCase = condition.ignoreCase)?.range
        } ?: return null
        val from = (range.first - radius).coerceAtLeast(0)
        val to = (range.last + 1 + radius).coerceIn(from, text.length)
        return BodyText.stripLoneSurrogates(BodyText.truncate(text.substring(from, to), MAX_EXCERPT))
    }

    private fun textAt(location: String, x: CheckExchange): String = when (location) {
        "response_body" -> x.responseBody
        "response_headers" -> x.responseHeaders
        "status_code" -> if (x.hasResponse) x.statusCode.toString() else ""
        "response_length" -> x.responseLength.toString()
        "request_body" -> x.requestBody
        "request_headers" -> x.requestHeaders
        "request_url" -> x.requestUrl
        else -> ""
    }

    /** SafeRegex answers "no match" for an oversize input, which a negated condition would read as a hit. */
    private fun regexInput(text: String): String =
        if (text.length > SafeRegex.DEFAULT_MAX_INPUT_LEN) text.substring(0, SafeRegex.DEFAULT_MAX_INPUT_LEN) else text

    private const val MAX_EXCERPT = 240

    // ---------------------------------------------------------------
    // Issue text and consolidation
    // ---------------------------------------------------------------

    /** Stable short id of an insertion point; issue details carry it so consolidation can tell two apart. */
    fun insertionPointRef(name: String, type: String): String = "%08x".format("$type\u0000$name".hashCode())

    /** [detail] followed by the payloads that produced the evidence and the insertion point they went into. */
    fun activeDetail(detail: String, insertionPoint: String, insertionPointType: String, payloads: List<String>): String =
        buildString {
            append(detail)
            if (detail.isNotEmpty()) append("<br><br>")
            append(if (payloads.size == 1) "Payload" else "Payloads").append(" that changed the response: ")
            append(payloads.joinToString(", ") { "<code>${htmlEscape(it)}</code>" })
            append("<br>Insertion point: <b>").append(htmlEscape(insertionPoint)).append("</b> (")
            append(htmlEscape(insertionPointType)).append(", ip:")
            append(insertionPointRef(insertionPoint, insertionPointType)).append(')')
        }

    /**
     * Whether a new issue repeats an existing one: same name, same URL path and, when both came
     * from an insertion point, the same one. Two parameters with the same flaw on one path stay
     * two issues; the same parameter scanned twice stays one.
     */
    fun isDuplicate(
        existingName: String?,
        existingUrl: String?,
        existingDetail: String?,
        newName: String?,
        newUrl: String?,
        newDetail: String?,
    ): Boolean {
        if (existingName != newName || urlPath(existingUrl) != urlPath(newUrl)) return false
        val existingPoint = insertionPointOf(existingDetail)
        val newPoint = insertionPointOf(newDetail)
        return existingPoint == null || newPoint == null || existingPoint == newPoint
    }

    private val INSERTION_POINT_REF = Regex("\\bip:([0-9a-f]{8})\\b")

    private fun insertionPointOf(detail: String?): String? =
        detail?.let { INSERTION_POINT_REF.findAll(it).lastOrNull()?.groupValues?.get(1) }

    private fun urlPath(url: String?): String = url.orEmpty().substringBefore('#').substringBefore('?')

    fun htmlEscape(text: String): String = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
}
