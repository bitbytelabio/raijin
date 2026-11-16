package io.bitbytelab.raijin.injection

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** How sure a finding is, in Burp's terms. */
enum class Confidence(val id: String) {
    /** The response holds proof only the vulnerability explains: file contents, a computed value, command output. */
    CERTAIN("certain"),

    /** Behaviour reproduced under controls: a repeated delay, a repeated TRUE/FALSE divergence, a verified markup escape. */
    FIRM("firm"),

    /** A precondition was shown, not the impact. */
    TENTATIVE("tentative"),
}

/**
 * One confirmed observation. [payload] is the value that goes at `FUZZ`; [evidence] holds how it
 * was written on the wire and the baseline next to the probe, so the result can be re-checked.
 */
data class Finding(
    val cls: InjectionClass,
    val technique: String,
    val severity: String,
    val confidence: Confidence,
    val detail: String,
    val payload: String,
    val evidence: JsonObject,
) {
    fun toJson(): JsonObject = buildJsonObject {
        put("class", cls.id)
        put("technique", technique)
        put("severity", severity)
        put("confidence", confidence.id)
        put("detail", detail)
        put("payload", payload)
        put("evidence", evidence)
    }
}
