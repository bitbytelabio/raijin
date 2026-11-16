package io.bitbytelab.raijin.core

import kotlin.math.abs
import kotlin.math.max
import kotlin.math.min

/**
 * One observed HTTP response, reduced to what matters for behavior-diff comparison. [headers] maps
 * lower-cased header names to their value (a repeated header's values joined by a newline); it
 * stays empty for callers that only compare status and body.
 */
data class ProbeResult(val status: Int, val body: String, val headers: Map<String, String> = emptyMap()) {

    /** Value of response header [name] (any case), or null when the response has none. */
    fun header(name: String): String? = headers[name.lowercase()]

    companion object {
        /** Builds a result from header pairs as received: names are lower-cased, repeats joined by a newline. */
        fun of(status: Int, body: String, headers: Iterable<Pair<String, String>>): ProbeResult {
            val merged = LinkedHashMap<String, String>()
            for ((name, value) in headers) {
                val key = name.lowercase()
                val previous = merged[key]
                merged[key] = if (previous == null) value else previous + "\n" + value
            }
            return ProbeResult(status, body, merged)
        }
    }
}

/**
 * Behavior-diff oracle: flags a candidate as "interesting" when it measurably changes server
 * behavior compared to a baseline, without requiring the candidate's value to be reflected
 * verbatim in the response — the gap plain reflection-probing (see [io.bitbytelab.raijin.bridge.ReconBridge.paramMine])
 * leaves open, since a parameter can influence control flow (auth checks, cache keys, feature
 * flags) without ever echoing its value back.
 */
object BehavioralDiff {

    /**
     * Response headers that show a different server path even when status and body agree: a new
     * redirect target, a cache answering differently, a cookie being set.
     */
    val SIGNAL_HEADERS: List<String> = listOf("location", "x-cache", "set-cookie")

    private const val DEFAULT_SIMILARITY = 98.0

    /** Bodies are compared on a prefix: the bigram metric gains nothing from more text and costs linear time. */
    private const val MAX_SIMILARITY_CHARS = 100_000

    /** Samples kept for body comparison; later ones still widen the length and similarity bounds. */
    private const val MAX_SAMPLES = 8

    /** Smallest length tolerance once the samples have shown that the body length moves at all. */
    private const val MIN_NOISE_TOLERANCE = 8

    fun changed(
        baseline: ProbeResult,
        candidate: ProbeResult,
        similarityThreshold: Double = DEFAULT_SIMILARITY,
        noiseThresholdBytes: Int = 0,
    ): Boolean {
        if (baseline.status != candidate.status) return true
        if (TextSimilarity.dice(baseline.body, candidate.body) < similarityThreshold) return true
        if (noiseThresholdBytes > 0 && abs(baseline.body.length - candidate.body.length) > noiseThresholdBytes) return true
        return false
    }

    /** [changed] that also counts a difference in any of the response [headers] (see [headerDiff]). */
    fun changed(
        baseline: ProbeResult,
        candidate: ProbeResult,
        headers: Collection<String>,
        similarityThreshold: Double = DEFAULT_SIMILARITY,
        noiseThresholdBytes: Int = 0,
    ): Boolean =
        changed(baseline, candidate, similarityThreshold, noiseThresholdBytes) ||
            headerDiff(baseline, candidate, headers).isNotEmpty()

    /**
     * Names among [headers] that differ between the two responses. `Set-Cookie` is compared by the
     * cookie names it sets, since the values (session ids) differ on every response.
     */
    fun headerDiff(
        baseline: ProbeResult,
        candidate: ProbeResult,
        headers: Collection<String> = SIGNAL_HEADERS,
    ): List<String> = headers.map { it.lowercase() }.distinct().filter { name ->
        comparable(name, baseline.headers[name]) != comparable(name, candidate.headers[name])
    }

    /**
     * What repeated responses to the same request agree on. Built from two or more samples so
     * that whatever moves on its own (tokens, timestamps, rotating content, session cookies) is
     * left out of the comparison instead of being reported as a behavior change.
     */
    class Baseline internal constructor(
        /** Samples kept for body comparison. */
        val samples: List<ProbeResult>,
        /** Number of samples the bounds were learned from. */
        val sampleCount: Int,
        /** The status every sample returned, or null when they disagree. */
        val status: Int?,
        /** Lowest body similarity (0..100) seen between two samples: the response's own noise level. */
        val similarityFloor: Double,
        val minLength: Int,
        val maxLength: Int,
        private val headerRules: Map<String, HeaderRule>,
    ) {
        /** Similarity below which a body counts as different. */
        val similarityThreshold: Double
            get() = min(DEFAULT_SIMILARITY, similarityFloor - max(1.0, (100.0 - similarityFloor) / 2))

        /** How far a body length may sit outside the sampled range and still be noise. */
        val lengthTolerance: Int
            get() = if (maxLength == minLength) 0 else max(2 * (maxLength - minLength), MIN_NOISE_TOLERANCE)

        /** Headers the samples agree on, so a difference in them is a signal. */
        val comparedHeaders: List<String> get() = headerRules.keys.toList()

        /** This baseline with one more response to the same request taken into account. */
        fun plus(sample: ProbeResult): Baseline {
            var floor = similarityFloor
            for (kept in samples) floor = min(floor, similarity(kept.body, sample.body))
            val rules = LinkedHashMap<String, HeaderRule>()
            for ((name, rule) in headerRules) rule.narrowedBy(name, sample.headers[name])?.let { rules[name] = it }
            return Baseline(
                samples = if (samples.size < MAX_SAMPLES) samples + sample else samples,
                sampleCount = sampleCount + 1,
                status = if (sample.status == status) status else null,
                similarityFloor = floor,
                minLength = min(minLength, sample.body.length),
                maxLength = max(maxLength, sample.body.length),
                headerRules = rules,
            )
        }

        internal fun headerReasons(candidate: ProbeResult, into: MutableList<String>) {
            for ((name, rule) in headerRules) {
                val expected = if (rule.exact) rule.value else rule.shape
                val actual = if (rule.exact) candidate.headers[name]?.trim() else shapeOf(name, candidate.headers[name])
                if (expected != actual) into += headerReason(name, expected, actual)
            }
        }

        internal fun headerReasons(control: ProbeResult, candidate: ProbeResult, into: MutableList<String>) {
            for ((name, rule) in headerRules) {
                val before = if (rule.exact) control.headers[name]?.trim() else shapeOf(name, control.headers[name])
                val after = if (rule.exact) candidate.headers[name]?.trim() else shapeOf(name, candidate.headers[name])
                if (before != after) into += headerReason(name, before, after)
            }
        }
    }

    /**
     * How one header is compared: by its [exact] value while every sample carried the same one,
     * else by its [shape] (present or not; for `Set-Cookie` the cookie names).
     */
    internal class HeaderRule(val exact: Boolean, val value: String?, val shape: String?) {
        /** The rule after seeing [observed] in another sample; null once the samples agree on nothing. */
        fun narrowedBy(name: String, observed: String?): HeaderRule? {
            val observedShape = shapeOf(name, observed)
            if (exact && observed?.trim() == value) return this
            return if (observedShape == shape) HeaderRule(false, null, shape) else null
        }
    }

    /** A baseline of [samples] (at least one), comparing the response [headers] they agree on. */
    fun baseline(samples: List<ProbeResult>, headers: Collection<String> = SIGNAL_HEADERS): Baseline {
        require(samples.isNotEmpty()) { "a baseline needs at least one sample" }
        val first = samples.first()
        val rules = LinkedHashMap<String, HeaderRule>()
        for (name in headers.map { it.lowercase() }.distinct()) {
            val value = first.headers[name]
            rules[name] = HeaderRule(true, value?.trim(), shapeOf(name, value))
        }
        var baseline = Baseline(listOf(first), 1, first.status, 100.0, first.body.length, first.body.length, rules)
        for (sample in samples.drop(1)) baseline = baseline.plus(sample)
        return baseline
    }

    /**
     * Why [candidate] is not one more baseline response: the reasons, empty when it fits.
     * [lengthSlack] widens the accepted body length for a known harmless difference.
     */
    fun diff(baseline: Baseline, candidate: ProbeResult, lengthSlack: Int = 0): List<String> {
        val reasons = ArrayList<String>(2)
        val status = baseline.status
        if (status != null && candidate.status != status) reasons += "status $status -> ${candidate.status}"
        baseline.headerReasons(candidate, reasons)
        val tolerance = baseline.lengthTolerance + lengthSlack
        val length = candidate.body.length
        if (length < baseline.minLength - tolerance || length > baseline.maxLength + tolerance) {
            reasons += "body length $length outside baseline ${baseline.minLength}..${baseline.maxLength}"
        } else if (reasons.isEmpty() && baseline.samples.none { similarity(it.body, candidate.body) >= baseline.similarityThreshold }) {
            reasons += "body differs from every baseline sample"
        }
        return reasons
    }

    /**
     * Why [candidate] differs from [control], a response to the same request without the input
     * under test, judged with the noise bounds learned in [baseline]; empty when it does not.
     */
    fun diff(baseline: Baseline, control: ProbeResult, candidate: ProbeResult, lengthSlack: Int = 0): List<String> {
        val reasons = ArrayList<String>(2)
        if (baseline.status != null && control.status != candidate.status) {
            reasons += "status ${control.status} -> ${candidate.status}"
        }
        baseline.headerReasons(control, candidate, reasons)
        val tolerance = baseline.lengthTolerance + lengthSlack
        if (abs(candidate.body.length - control.body.length) > tolerance) {
            reasons += "body length ${control.body.length} -> ${candidate.body.length}"
        } else if (reasons.isEmpty() && similarity(control.body, candidate.body) < baseline.similarityThreshold) {
            reasons += "body content changed"
        }
        return reasons
    }

    private fun similarity(a: String, b: String): Double =
        if (a == b) 100.0 else TextSimilarity.dice(a.take(MAX_SIMILARITY_CHARS), b.take(MAX_SIMILARITY_CHARS))

    private fun comparable(name: String, value: String?): String? =
        if (name == "set-cookie") shapeOf(name, value) else value?.trim()

    /** What stays the same about a header whose value changes on every response. */
    private fun shapeOf(name: String, value: String?): String? = when {
        value == null -> null
        name == "set-cookie" -> value.lineSequence()
            .map { it.substringBefore('=').trim() }
            .filter { it.isNotEmpty() }
            .sorted()
            .joinToString(",")
        else -> "present"
    }

    private fun headerReason(name: String, before: String?, after: String?): String = when {
        before == null -> "header $name appeared"
        after == null -> "header $name disappeared"
        else -> "header $name changed"
    }
}
