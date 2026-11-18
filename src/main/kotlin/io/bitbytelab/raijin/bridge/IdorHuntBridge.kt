package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import io.bitbytelab.raijin.bridge.AnalysisBridge.Companion.normalizeCrlfMessage
import io.bitbytelab.raijin.core.BodyText
import io.bitbytelab.raijin.core.TextSimilarity
import io.bitbytelab.raijin.safety.BoundedHttp
import io.bitbytelab.raijin.safety.ScopeGate
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put

/**
 * The `idor_hunt` engine's live layer. Orchestrates the pure [IdorHunt] logic
 * against real HTTP:
 *
 *  1. **Identity diff** (reused, id held constant) — delegates to the vetted,
 *     scope-gated [AnalysisBridge.authDiff] for vertical / unauthenticated
 *     access-control coverage.
 *  2. **Canary matrix** (the flagship, id varied) — for every (reader, owner)
 *     pair it swaps the object id to the owner's resource, replays under the
 *     reader's identity, and asserts the owner's canary appears in the reader's
 *     response (a CONFIRMED horizontal IDOR), filtering own-data-reflection FPs.
 *  3. **Transform enumeration** (opt-in) — replays the §2 id-transformation set
 *     (neighbours, encodings, type-juggling) under the primary identity. Each
 *     response is placed against that identity's own view, the server's answer
 *     for an id that does not exist and the other identities' own views, and a
 *     cross-user read is confirmed by another identity's canary
 *     ([IdorHunt.assessTransform]); a bare 2xx is not reported.
 *
 * Every send goes through the same [ScopeGate] and [BoundedHttp] the rest of the
 * extension uses, so `mcp_scope_mode=enforce` gates it and no send can hang, and
 * every identity is applied by [AuthIdentityApplier].
 */
class IdorHuntBridge(private val api: MontoyaApi) {

    private val scopeGate = ScopeGate(api)
    private val analysis = AnalysisBridge(api)

    /** One identity of a hunt: how it authenticates, the object it owns, a string only in its own data. */
    private class Party(val identity: AuthIdentityApplier.Identity, val objectId: String?, val canary: String?) {
        val name: String get() = identity.name
    }

    /** Outcome of one replay: [status] is 0, with an [error], when nothing came back. */
    private class Sent(val status: Int, val body: String, val error: String? = null) {
        val served: Boolean get() = status in 200..299
    }

    /**
     * @param idName narrows the reference to one parameter: a query / form / cookie / header name,
     *   a JSON path or key, or the 0-based index of a path segment.
     */
    fun hunt(
        request: String,
        host: String,
        port: Int,
        useTls: Boolean,
        identities: List<JsonObject>,
        idLocation: String?,
        idValue: String?,
        transforms: Boolean,
        enumerate: Int,
        idName: String? = null
    ): JsonObject {
        if (request.isBlank()) return err("Empty request: provide a raw HTTP request that identity A makes to A's own object.")
        if (identities.size < 2) return err("Provide 'identities' (>=2): e.g. two low-priv peers A and B, each with 'object_id' (a resource they own) and 'canary' (a string only in their own data). A 'none'/'unauth' identity is also useful.")

        // An identity without a name gets a positional one, so two of them are still told apart.
        val named = identities.mapIndexed { i, identity ->
            if (str(identity, "name") != null) identity else JsonObject(identity + ("name" to JsonPrimitive("identity_${i + 1}")))
        }
        val parties = named.map { Party(AuthIdentityApplier.parse(it), str(it, "object_id"), str(it, "canary")) }
        AuthIdentityApplier.indistinguishableError(parties.map { it.identity })?.let { return err(it) }
        val identityHeaders = AuthIdentityApplier.identityHeaders(parties.map { it.identity })

        val url = (if (useTls) "https" else "http") + "://$host:$port/"
        val base = normalizeCrlfMessage(request)
        val scope = scopeGate.checkRequest(host, port, useTls, base)
        if (scope.blocked) return scope.denyJson()
        return scope.annotate(huntChecked(base, url, host, port, useTls, request, named, parties, identityHeaders, idLocation, idValue, idName, transforms, enumerate))
    }

    private fun huntChecked(
        base: String,
        url: String,
        host: String,
        port: Int,
        useTls: Boolean,
        request: String,
        named: List<JsonObject>,
        parties: List<Party>,
        identityHeaders: Set<String>,
        idLocation: String?,
        idValue: String?,
        idName: String?,
        transforms: Boolean,
        enumerate: Int,
    ): JsonObject {
        // 1. Locate the object reference to swap.
        val ref = IdorHunt.resolveRef(base, idLocation, idValue, idName, parties.mapNotNull { it.objectId })
        if (ref == null && (idValue != null || idName != null)) {
            val pin = listOfNotNull(
                idValue?.let { "id_value '$it'" },
                idName?.let { "id_name '$it'" },
                idLocation?.let { "id_location '$it'" }
            ).joinToString(", ")
            return err("No object reference matches $pin: the value must stand alone as a path segment, a query/form/cookie/header value or a JSON value of the request, or begin a path segment before a character that is not a letter or digit (42 of /users/42-alice). Nothing was sent.")
        }

        return try {
            val service = HttpService.httpService(host, port, useTls)
            fun send(raw: String, party: Party): Sent = sendAs(raw, service, party.identity, identityHeaders)

            // 2. Identity-only diff (vertical / unauth; object id held constant) — reuse the audited engine.
            val identityDiff = analysis.authDiff(request, host, port, useTls, named, null)

            // 3. Canary matrix (horizontal object-id swap).
            val owners = parties.filter { it.objectId != null }
            val probes = mutableListOf<IdorHunt.CanaryProbe>()
            val replays = buildJsonArray {
                if (ref != null) {
                    for (reader in parties) {
                        for (owner in owners) {
                            if (reader.name.equals(owner.name, true)) continue
                            val ownerId = owner.objectId ?: continue
                            val sent = send(IdorHunt.applySwap(base, ref, ownerId), reader)
                            probes.add(
                                IdorHunt.CanaryProbe(
                                    reader = reader.name, owner = owner.name, targetId = ownerId,
                                    status = sent.status, body = sent.body,
                                    ownerCanary = owner.canary, readerCanary = reader.canary
                                )
                            )
                            add(buildJsonObject {
                                put("reader", reader.name); put("owner", owner.name)
                                put("target_id", ownerId); put("status", sent.status)
                                put("body_length", sent.body.length)
                                put("owner_canary_present", IdorHunt.containsCanary(sent.body, owner.canary))
                                put("body_preview", preview(sent.body))
                                sent.error?.let { put("error", it) }
                            })
                        }
                    }
                }
            }
            val canaryFindings = IdorHunt.assessCanary(probes)

            // 4. Optional transform / neighbour enumeration under the primary identity.
            val transformFindings = mutableListOf<IdorHunt.Finding>()
            var transformBaseline: JsonObject? = null
            val transformProbes = if (ref != null && (transforms || enumerate > 0)) {
                val reader = parties.first()
                val cls = IdorHunt.classify(ref.value)
                val count = minOf(MAX_TRANSFORMS, if (enumerate > 0) enumerate else MAX_TRANSFORMS)

                // What the transformed ids are measured against: the reader's own object, the
                // server's answer for an id that cannot exist, and the other identities' own views.
                // A login page or a denial served with 200 is no own view either.
                val own = send(base, reader)
                val ownBody = if (own.served && !AuthDenialHeuristic.looksDenied(own.body)) own.body else null
                val missRequest = IdorHunt.applySwap(base, ref, IdorHunt.missProbeValue(ref.value, cls))
                val miss = if (missRequest != base) send(missRequest, reader) else null
                val missBody = if (miss != null && miss.served && miss.body.isNotBlank() &&
                    (ownBody == null || TextSimilarity.dice(miss.body, ownBody) < IdorHunt.MISS_SIMILARITY)
                ) miss.body else null
                val others = parties.filter { !it.name.equals(reader.name, true) }.mapIndexed { i, other ->
                    val ownId = other.objectId
                    val view = if (ownId != null && i < MAX_REFERENCE_VIEWS) {
                        send(IdorHunt.applySwap(base, ref, ownId), other).takeIf { it.served }?.body
                    } else {
                        null
                    }
                    IdorHunt.OtherIdentity(other.name, other.canary, view)
                }
                val baseline = IdorHunt.TransformBaseline(ownBody, missBody, reader.canary, others)
                transformBaseline = buildJsonObject {
                    put("reader", reader.name)
                    put("own_status", own.status)
                    put("own_view", ownBody != null)
                    if (ownBody == null) {
                        put(
                            "own_view_note",
                            "The unmodified request did not give '${reader.name}' its own object (status ${own.status}" +
                                (if (own.served) ", a login page or denial message" else "") +
                                "), so transformed ids are not compared by similarity: only a canary can grade them above info."
                        )
                    }
                    miss?.let { put("unknown_id_status", it.status) }
                    put("unknown_id_fingerprinted", missBody != null)
                    put("identities_with_own_view", buildJsonArray { others.filter { it.ownView != null }.forEach { add(it.name) } })
                }

                val unverified = mutableListOf<String>()
                val rows = buildJsonArray {
                    for ((value, technique) in IdorHunt.mutations(ref.value, cls, count)) {
                        val swapped = IdorHunt.applySwap(base, ref, value)
                        if (swapped == base) continue
                        val sent = send(swapped, reader)
                        val verdict = IdorHunt.assessTransform(
                            reader.name, technique, value, sent.status, sent.body, baseline, TextSimilarity::dice
                        )
                        when {
                            verdict.id == "unverified_object" -> unverified += value
                            verdict.severity != "none" && verdict.severity != "info" ->
                                transformFindings.add(IdorHunt.Finding(verdict.severity, verdict.id, verdict.detail))
                        }
                        add(buildJsonObject {
                            put("technique", technique); put("value", value)
                            put("status", sent.status); put("body_length", sent.body.length)
                            put("verdict", verdict.id)
                            put("candidate", verdict.candidate)
                            verdict.similarityToOwn?.let { put("similarity_to_own", it) }
                            verdict.matchedIdentity?.let { put("matched_identity", it) }
                            sent.error?.let { put("error", it) }
                        })
                    }
                }
                if (unverified.isNotEmpty()) {
                    transformFindings.add(
                        IdorHunt.Finding(
                            "medium", "unverified_object",
                            "${unverified.size} transformed id(s) returned an object that is neither '${reader.name}'s own view nor a not-found answer (${unverified.take(10).joinToString(", ") { "'$it'" }}) — candidates: no canary shows whose data it is. Inspect them, or give the identities canaries."
                        )
                    )
                }
                rows
            } else {
                JsonArray(emptyList())
            }

            buildJsonObject {
                put("target", url)
                put("object_ref", ref?.let {
                    buildJsonObject {
                        put("location", it.location); put("name", it.name)
                        if (it.index >= 0) put("index", it.index)
                        put("value", it.value); put("format", it.format.name)
                        put("classification", IdorHunt.classify(it.value).note)
                    }
                } ?: JsonNull)
                put("identities_tested", named.size)
                put("owners_with_object_id", owners.size)
                put("top_severity", IdorHunt.topSeverity(canaryFindings + transformFindings))
                put("horizontal_findings", findingsJson(canaryFindings))
                put("horizontal_replays", replays)
                put("transform_findings", findingsJson(transformFindings))
                put("transform_probes", transformProbes)
                transformBaseline?.let { put("transform_baseline", it) }
                put("identity_diff", identityDiff)
                put(
                    "note",
                    if (ref == null) {
                        "No object reference was detected in the request, so no id was swapped: pass id_value (and id_location / id_name) to pin it. identity_diff is the vertical/unauth check with the id held constant."
                    } else {
                        "horizontal_findings come from swapping the object id across identities and asserting the owner's canary (CONFIRMED cross-user read); transform_findings grade the id mutations against the primary identity's own view and the other identities' canaries; identity_diff is the vertical/unauth check with the id held constant. Supply each identity's own 'object_id' + 'canary' to reach confirmed-grade precision."
                    }
                )
            }
        } catch (e: Exception) {
            err("IDOR hunt failed: ${AnalysisBridge.describeException(e)}")
        }
    }

    /** Sends [rawRequest] as [identity] (same application as auth_diff), bounded. */
    private fun sendAs(
        rawRequest: String,
        service: HttpService,
        identity: AuthIdentityApplier.Identity,
        identityHeaders: Set<String>
    ): Sent = try {
        val applied = AuthIdentityApplier.apply(rawRequest, identity, identityHeaders)
        val httpRequest = HttpRequest.httpRequest(service, BurpByteArray.byteArray(*AuthIdentityApplier.wireBytes(applied.request)))
        val response = BoundedHttp.sendInternal(api, httpRequest)?.response()
        if (response == null) {
            Sent(0, "", "no response (timeout or connection error)")
        } else {
            Sent(response.statusCode().toInt(), response.bodyToString() ?: "")
        }
    } catch (e: Exception) {
        Sent(0, "", AnalysisBridge.describeException(e))
    }

    private fun findingsJson(findings: List<IdorHunt.Finding>): JsonArray = buildJsonArray {
        findings.forEach { f ->
            add(buildJsonObject { put("severity", f.severity); put("id", f.id); put("detail", f.detail) })
        }
    }

    private fun preview(body: String): String = BodyText.render(body, PREVIEW_CHARS, label = "response body").text

    private fun str(o: JsonObject, key: String): String? = (o[key] as? JsonPrimitive)?.contentOrNull

    private fun err(msg: String): JsonObject = buildJsonObject { put("error", msg) }

    companion object {
        /** Hard ceiling on transform replays so an opt-in enumeration can't turn into a flood. */
        const val MAX_TRANSFORMS = 25

        /** Other identities whose own view of their own object is fetched as a transform reference. */
        private const val MAX_REFERENCE_VIEWS = 5

        private const val PREVIEW_CHARS = 300
    }
}
