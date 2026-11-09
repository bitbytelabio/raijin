package io.bitbytelab.raijin.core

/** One observed HTTP response, reduced to what matters for behavior-diff comparison. */
data class ProbeResult(val status: Int, val body: String)

/**
 * Behavior-diff oracle: flags a candidate as "interesting" when it measurably changes server
 * behavior compared to a baseline, without requiring the candidate's value to be reflected
 * verbatim in the response — the gap plain reflection-probing (see [io.bitbytelab.raijin.bridge.ReconBridge.paramMine])
 * leaves open, since a parameter can influence control flow (auth checks, cache keys, feature
 * flags) without ever echoing its value back.
 */
object BehavioralDiff {
    fun changed(
        baseline: ProbeResult,
        candidate: ProbeResult,
        similarityThreshold: Double = 98.0,
        noiseThresholdBytes: Int = 0,
    ): Boolean {
        if (baseline.status != candidate.status) return true
        if (TextSimilarity.dice(baseline.body, candidate.body) < similarityThreshold) return true
        if (noiseThresholdBytes > 0 && kotlin.math.abs(baseline.body.length - candidate.body.length) > noiseThresholdBytes) return true
        return false
    }
}
