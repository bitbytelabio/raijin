package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.core.asBooleanSafe
import io.bitbytelab.raijin.core.asBoundedInt
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.safety.ScopeGate
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put

/**
 * Batch broken-access-control / IDOR testing: replays each request under every
 * identity and flags where a lower-privilege or unauthenticated identity gets a
 * response matching a higher-privilege one. Scales auth_diff (single request)
 * across many endpoints in one call, reusing AnalysisBridge.authDiff (which is
 * scope-gated, applies each identity through AuthIdentityApplier and judges the
 * responses with the AuthDiffVerdict logic).
 */
class AccessControlBridge(api: MontoyaApi) {

    private val analysis = AnalysisBridge(api)

    /**
     * @param deniedRegex optional: a response whose body matches it is treated as denied whatever
     *   its status, for every request of the sweep.
     */
    fun sweep(requests: List<JsonObject>, identities: List<JsonObject>, deniedRegex: String? = null): JsonObject {
        if (requests.isEmpty() || identities.size < 2) {
            return buildJsonObject {
                put("error", "Provide 'requests' (>=1) and 'identities' (>=2, e.g. an authed identity plus a 'none' identity).")
            }
        }
        deniedRegex?.let { pattern ->
            SafeRegex.validate(pattern, ignoreCase = true)?.let { err ->
                return buildJsonObject { put("error", "Invalid denied_regex: $err") }
            }
        }
        // The identities are the same for every request, so a set that cannot work is refused once.
        AuthIdentityApplier.indistinguishableError(identities.map { AuthIdentityApplier.parse(it) })?.let { err ->
            return buildJsonObject { put("error", err) }
        }

        val results = requests.mapIndexed { idx, r -> sweepOne(idx, r, identities, deniedRegex) }

        val flagged = results.count { entry ->
            (entry["findings"] as? JsonArray)?.any { f ->
                val sev = ((f as? JsonObject)?.get("severity") as? JsonPrimitive)?.contentOrNull
                sev == "critical" || sev == "high"
            } == true
        }

        // The batch scope convention: refused items counted, warned ones too, an error when all were refused.
        val skipped = results.count { (it["out_of_scope"] as? JsonPrimitive)?.booleanOrNull == true }
        val sentOutOfScope = results.count { it[ScopeGate.WARNING] != null }
        return buildJsonObject {
            if (skipped > 0 && skipped == results.size) {
                put("error", "Not sent: all $skipped requests are outside Burp's target scope (mcp_scope_mode=enforce).")
            }
            if (skipped > 0) put(ScopeGate.SKIPPED, skipped)
            if (sentOutOfScope > 0) put(ScopeGate.SENT, sentOutOfScope)
            put("requests_tested", requests.size)
            put("identities", identities.size)
            put("requests_with_broken_access_control", flagged)
            put("results", buildJsonArray { results.forEach { add(it) } })
            put("note", "Each request is replayed under every identity; 'findings' per request flag where a lower-privilege/unauth identity gets a response matching a higher-privilege one (broken access control / IDOR).")
        }
    }

    private fun sweepOne(idx: Int, r: JsonObject, identities: List<JsonObject>, deniedRegex: String?): JsonObject {
        fun failed(message: String) = buildJsonObject { put("request_index", idx); put("error", message) }

        val raw = text(r, "raw_request") ?: text(r, "request")
        val host = text(r, "host")
        if (raw == null || host == null) return failed("each request needs 'raw_request' and 'host'")
        val port = r["port"].asBoundedInt("port", 1, 65535).getOrElse { return failed(it.message ?: "Invalid port") } ?: 443
        val tls = r["use_tls"].asBooleanSafe() ?: r["tls"].asBooleanSafe() ?: (port == 443)

        val diff = analysis.authDiff(raw, host, port, tls, identities, null, deniedRegex)
        return buildJsonObject {
            put("request_index", idx)
            put("target", "${if (tls) "https" else "http"}://$host:$port")
            for (key in PASSED_THROUGH) diff[key]?.let { put(key, it) }
        }
    }

    private fun text(o: JsonObject, key: String): String? = (o[key] as? JsonPrimitive)?.contentOrNull

    private companion object {
        /** Keys of an auth_diff result that a sweep entry repeats. */
        val PASSED_THROUGH = listOf("error", "out_of_scope", "scope_warning", "findings", "responses", "notes", "errors")
    }
}
