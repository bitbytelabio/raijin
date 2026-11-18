package io.bitbytelab.raijin.jwt

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWECryptoParts
import com.nimbusds.jose.JWEDecrypter
import com.nimbusds.jose.JWEEncrypter
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSignerOption
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.AESDecrypter
import com.nimbusds.jose.crypto.AESEncrypter
import com.nimbusds.jose.crypto.DirectDecrypter
import com.nimbusds.jose.crypto.DirectEncrypter
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.PasswordBasedDecrypter
import com.nimbusds.jose.crypto.PasswordBasedEncrypter
import com.nimbusds.jose.crypto.RSADecrypter
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.crypto.X25519Decrypter
import com.nimbusds.jose.crypto.X25519Encrypter
import com.nimbusds.jose.crypto.impl.AAD
import com.nimbusds.jose.crypto.impl.CriticalHeaderParamsDeferral
import com.nimbusds.jose.crypto.impl.ECDHCryptoProvider
import com.nimbusds.jose.crypto.opts.AllowWeakRSAKey
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.OctetSequenceKey
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.Base64URL
import org.bouncycastle.crypto.agreement.X448Agreement
import org.bouncycastle.crypto.generators.X448KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters
import org.bouncycastle.crypto.params.X448KeyGenerationParameters
import org.bouncycastle.crypto.params.X448PrivateKeyParameters
import org.bouncycastle.crypto.params.X448PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.signers.Ed448Signer
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.putJsonArray

/**
 * JWS and JWE operations on keys from [JwtKeyRing]. Nimbus does the cryptography.
 * BouncyCastle is registered for ES256K (secp256k1), which the JDK provider does not ship.
 *
 * Signing and verifying work on the token's own segments ([Jwt.Raw]), not on a parsed claims set.
 * Nimbus' `JWTClaimsSet` rejects an `exp` that is a string or an `aud` that is a number and
 * re-serialises everything else, while a token under test has to keep what its issuer wrote.
 */
object JwtJose {
    private const val PBES_SALT_BYTES = 16
    private const val PBES_ITERATIONS = 1000

    /**
     * Highest PBES2 iteration count (`p2c`) [decryptPassword] accepts. Nimbus 9.x ran PBKDF2 over
     * whatever count the header named before checking anything (CVE-2023-52428); Nimbus 10 caps it
     * too, but with a JOSEException, and this check keeps the refusal ahead of any key derivation.
     */
    private const val MAX_PBES2_COUNT = 1_000_000

    /** JWS `alg` values the signing modes take. */
    val JWS_ALGS: List<String> = listOf(
        "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
        "ES256", "ES256K", "ES384", "ES512", "EdDSA",
    )

    /** JWE key management `alg` values [encrypt] takes. */
    val JWE_ALGS: List<String> = listOf(
        "RSA-OAEP-256", "RSA-OAEP-384", "RSA-OAEP-512", "RSA-OAEP", "RSA1_5",
        "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW",
        "A128KW", "A192KW", "A256KW", "A128GCMKW", "A192GCMKW", "A256GCMKW", "dir",
        "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW",
    )

    /** JWE content encryption `enc` values [encrypt] takes. */
    val JWE_ENCS: List<String> = listOf(
        "A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
        "A128CBC+HS256", "A256CBC+HS512", "XC20P",
    )

    /** Header parameters that tell a verifier where the signing key is. A forged token should carry only its own. */
    private val KEY_REFERENCES = setOf("jwk", "jku", "x5u", "x5c", "x5t", "x5t#S256")

    init {
        JwtKeyRing.bcProvider()
    }

    /**
     * Signs [token] with [jwk]. The header keeps what it had and gets `alg` and `kid` (the key's
     * id). The payload keeps its bytes unless [overrides] names claims.
     */
    fun sign(token: String, jwk: JWK, alg: String?, overrides: JsonObject?): String =
        signed(token, jwk, alg, overrides)

    /** True when [jwk] verifies [token] under the algorithm the token's own header names. */
    fun verify(token: String, jwk: JWK): Boolean = check(token, jwk).valid

    /** What [check] found. [reason] says why a token did not verify. */
    data class Verification(val valid: Boolean, val reason: String? = null)

    /**
     * Verifies the signature over the token's segments as sent. The header's `alg` decides the
     * algorithm and has to belong to the key: an Ed25519 key verifies `EdDSA` only, an RSA key
     * never an `HS256` token, and `none` nothing, whatever the signature bytes are. A header that
     * repeats `alg` with different values names no algorithm.
     */
    fun check(token: String, jwk: JWK): Verification {
        val raw = Jwt.split(token) ?: return Verification(false, "Not a decodable JWS")
        val alg = singleAlg(raw) ?: return Verification(false, "The header does not name one alg as a string")
        val accepted = algsFor(jwk)
        if (accepted.isEmpty()) return Verification(false, cannotSign(jwk).message)
        if (alg !in accepted) {
            return Verification(false, "alg $alg does not belong to this ${keyLabel(jwk)} key, which verifies ${accepted.joinToString(", ")}")
        }
        val signature = try {
            Jwt.b64UrlDecode(raw.signature)
        } catch (_: IllegalArgumentException) {
            return Verification(false, "The signature is not base64url")
        }
        if (signature.isEmpty()) return Verification(false, "The token carries no signature")
        val input = raw.signingInput.toByteArray(Charsets.US_ASCII)
        val matches = try {
            when (jwk) {
                is OctetSequenceKey -> MessageDigest.isEqual(Jwt.hmacBytes(input, jwk.toByteArray(), alg), signature)
                is RSAKey -> RSASSAVerifier(jwk.toRSAPublicKey())
                    .verify(JWSHeader(JWSAlgorithm.parse(alg)), input, Base64URL.encode(signature))
                is ECKey -> {
                    val verifier = ECDSAVerifier(jwk.toECPublicKey())
                    if (alg == JWSAlgorithm.ES256K.name) verifier.jcaContext.provider = JwtKeyRing.bcProvider()
                    verifier.verify(JWSHeader(JWSAlgorithm.parse(alg)), input, Base64URL.encode(signature))
                }
                is OctetKeyPair -> edVerify(jwk.curve, jwk.decodedX, input, signature)
                else -> false
            }
        } catch (e: Exception) {
            return Verification(false, "Could not verify: ${e.message ?: e.javaClass.simpleName}")
        }
        return if (matches) Verification(true) else Verification(false, "The signature does not match this key")
    }

    /** Signs like [sign] and puts the public half of [jwk] in the `jwk` header, in place of any other key reference. */
    fun embedJwk(token: String, jwk: JWK, alg: String?, overrides: JsonObject?): String {
        val public = jwk.toPublicJWK()
            ?: throw IllegalArgumentException("embed_jwk needs an asymmetric key")
        val embedded = mapOf("jwk" to Json.parseToJsonElement(public.toJSONString()))
        return signed(token, jwk, alg, overrides, embedded, KEY_REFERENCES - "jwk")
    }

    /**
     * HMAC with an empty secret. JCA rejects a zero-length key, and HMAC defines that
     * secret as the hash block filled with zeros, which [Jwt.hmac] can compute.
     */
    fun emptyHmac(token: String, alg: String?, overrides: JsonObject?): String {
        val algorithm = (alg ?: "HS256").uppercase()
        val block = when (algorithm) {
            "HS256" -> ByteArray(64)
            "HS384", "HS512" -> ByteArray(128)
            else -> throw IllegalArgumentException("empty_hmac requires HS256, HS384, or HS512")
        }
        val (headerB64, payloadB64) = rewrittenParts(token, algorithm, overrides)
        val sig = Jwt.hmac("$headerB64.$payloadB64", block, algorithm)
            ?: throw IllegalArgumentException("Could not compute $algorithm")
        return "$headerB64.$payloadB64.$sig"
    }

    /** ES256, ES384, or ES512 token whose ECDSA signature is two ASN.1 integers of value zero. */
    fun psychic(token: String, alg: String?, overrides: JsonObject?): String {
        val algorithm = (alg ?: "ES256").uppercase()
        if (algorithm != "ES256" && algorithm != "ES384" && algorithm != "ES512") {
            throw IllegalArgumentException("psychic requires ES256, ES384, or ES512")
        }
        val (headerB64, payloadB64) = rewrittenParts(token, algorithm, overrides)
        val signature = byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00)
        return "$headerB64.$payloadB64.${Jwt.b64UrlEncode(signature)}"
    }

    /**
     * [psychic] in the JWS form (RFC 7518 3.4): r || s as fixed-size big-endian integers, all zero
     * (64, 96 or 132 bytes). A JOSE library reads this form, a raw DER verifier the other one.
     */
    fun psychicRawRs(token: String, alg: String?, overrides: JsonObject?): String {
        val algorithm = (alg ?: "ES256").uppercase()
        val size = when (algorithm) {
            "ES256" -> 64
            "ES384" -> 96
            "ES512" -> 132
            else -> throw IllegalArgumentException("psychic requires ES256, ES384, or ES512")
        }
        val (headerB64, payloadB64) = rewrittenParts(token, algorithm, overrides)
        return "$headerB64.$payloadB64.${Jwt.b64UrlEncode(ByteArray(size))}"
    }

    /**
     * Writes [url] into the `jku` or `x5u` header and leaves the signature bytes unchanged: enough
     * to see whether the target fetches the URL. [headerUrlSigned] makes a token that verifies.
     */
    fun headerUrl(token: String, headerName: String?, url: String, overrides: JsonObject?): String {
        val name = urlHeader(headerName)
        val raw = Jwt.split(token) ?: throw IllegalArgumentException("Not a decodable JWT")
        val header = Jwt.headerSegment(raw, mapOf(name to JsonPrimitive(url)))
        return "$header.${Jwt.payloadSegment(raw, overrides)}.${raw.signature}"
    }

    /**
     * A token signed for a `jku` / `x5u` test, and the [document] that has to be served at [url]
     * for its signature to verify.
     */
    class HostedKey(
        val token: String,
        val header: String,
        val url: String,
        val contentType: String,
        val document: String,
    )

    /**
     * The whole `jku` / `x5u` key substitution in one step: [token] signed with [jwk], its header
     * pointing at [url] (any other key reference removed), and the document that URL has to serve —
     * a JWK set holding exactly the public half of [jwk] for `jku`, the key's self-signed
     * certificate as a PEM chain for `x5u`.
     */
    fun headerUrlSigned(
        token: String,
        jwk: JWK,
        headerName: String?,
        url: String,
        alg: String?,
        overrides: JsonObject?,
    ): HostedKey {
        val name = urlHeader(headerName)
        val public = jwk.toPublicJWK()
            ?: throw IllegalArgumentException("header_url needs an asymmetric key: a $name document cannot hold a shared secret")
        val signed = signed(token, jwk, alg, overrides, mapOf(name to JsonPrimitive(url)), KEY_REFERENCES - name)
        if (name == "x5u") {
            return HostedKey(signed, name, url, "application/pem-certificate-chain", selfSignedCertificatePem(jwk))
        }
        val jwks = buildJsonObject {
            putJsonArray("keys") { add(Json.parseToJsonElement(public.toJSONString())) }
        }
        return HostedKey(signed, name, url, "application/json", jwks.toString())
    }

    fun encrypt(plaintext: String, jwk: JWK, alg: String?, enc: String?): String {
        val jweAlg = JWEAlgorithm.parse(alg?.let { canonical(it, JWE_ALGS) } ?: defaultJweAlg(jwk))
        val method = EncryptionMethod.parse(enc?.let { canonical(it, JWE_ENCS) } ?: "A256GCM")
        val header = JWEHeader.Builder(jweAlg, method).keyID(jwk.keyID).build()
        val obj = JWEObject(header, Payload(plaintext))
        obj.encrypt(encrypter(jwk, jweAlg))
        return obj.serialize()
    }

    fun encryptPassword(plaintext: String, password: String, alg: String?, enc: String?): String {
        val jweAlg = JWEAlgorithm.parse(alg?.let { canonical(it, JWE_ALGS) } ?: JWEAlgorithm.PBES2_HS256_A128KW.name)
        val method = EncryptionMethod.parse(enc?.let { canonical(it, JWE_ENCS) } ?: "A256GCM")
        val header = JWEHeader.Builder(jweAlg, method).build()
        val obj = JWEObject(header, Payload(plaintext))
        obj.encrypt(PasswordBasedEncrypter(password.toByteArray(Charsets.UTF_8), PBES_SALT_BYTES, PBES_ITERATIONS))
        return obj.serialize()
    }

    fun decrypt(token: String, jwk: JWK): String {
        val obj = JWEObject.parse(token)
        obj.decrypt(decrypter(jwk, obj.header))
        return obj.payload.toString()
    }

    fun decryptPassword(token: String, password: String): String {
        val obj = JWEObject.parse(token)
        val count = obj.header.pbeS2Count
        require(count <= MAX_PBES2_COUNT) {
            "The token asks for $count PBES2 iterations (p2c); more than $MAX_PBES2_COUNT is refused " +
                "before deriving a key (CVE-2023-52428)"
        }
        obj.decrypt(PasswordBasedDecrypter(password.toByteArray(Charsets.UTF_8)))
        return obj.payload.toString()
    }

    /** The public key in the token's `jwk` header, or null when it has none. */
    fun embeddedPublicJwk(token: String): JWK? {
        val raw = Jwt.split(token) ?: throw IllegalArgumentException("Not a decodable JWS")
        val embedded = raw.header["jwk"] as? JsonObject ?: return null
        return JWK.parse(embedded.toString())
    }

    /**
     * [token] signed with [jwk]. The header keeps what it had, gets `alg`, `kid` and [header], and
     * loses the members in [drop]; it is edited as text ([Jwt.headerSegment]), so an unusual header
     * survives. The payload is the token's own segment unless [overrides] names claims.
     */
    private fun signed(
        token: String,
        jwk: JWK,
        alg: String?,
        overrides: JsonObject?,
        header: Map<String, JsonElement> = emptyMap(),
        drop: Set<String> = emptySet(),
    ): String {
        val raw = Jwt.split(token) ?: throw IllegalArgumentException("Not a decodable JWS")
        val algorithm = signAlgorithm(jwk, alg)
        val changes = LinkedHashMap<String, JsonElement>()
        changes["alg"] = JsonPrimitive(algorithm.name)
        jwk.keyID?.let { changes["kid"] = JsonPrimitive(it) }
        changes.putAll(header)
        val signingInput = "${Jwt.headerSegment(raw, changes, drop)}.${Jwt.payloadSegment(raw, overrides)}"
        return "$signingInput.${signature(jwk, algorithm, signingInput)}"
    }

    /** The requested algorithm, else the key's own when it is a signature algorithm, else the default for its type. */
    private fun signAlgorithm(jwk: JWK, requested: String?): JWSAlgorithm = JWSAlgorithm.parse(
        requested?.let { canonical(it, JWS_ALGS) }
            ?: jwk.algorithm?.name?.takeIf { it in JWS_ALGS }
            ?: defaultSignAlg(jwk)
    )

    /** Signs [signingInput], the `header.payload` text exactly as it goes on the wire. */
    private fun signature(jwk: JWK, algorithm: JWSAlgorithm, signingInput: String): String {
        val accepted = algsFor(jwk)
        if (accepted.isEmpty()) throw cannotSign(jwk)
        if (algorithm.name !in accepted) {
            throw IllegalArgumentException(
                "alg ${algorithm.name} does not belong to this ${keyLabel(jwk)} key, which signs ${accepted.joinToString(", ")}"
            )
        }
        if (!jwk.isPrivate) throw IllegalArgumentException("Key cannot sign (public only)")
        val input = signingInput.toByteArray(Charsets.US_ASCII)
        return when (jwk) {
            // Not Nimbus' MACSigner: it refuses secrets under 256 bits, and a short secret is a test case here.
            is OctetSequenceKey -> Jwt.hmac(signingInput, jwk.toByteArray(), algorithm.name)
                ?: throw IllegalArgumentException("Could not compute ${algorithm.name}")
            // Same for RSA keys under 2048 bits, which the default signer refuses.
            is RSAKey -> RSASSASigner(jwk.toPrivateKey(), setOf<JWSSignerOption>(AllowWeakRSAKey.getInstance()))
                .sign(JWSHeader(algorithm), input).toString()
            is ECKey -> {
                val signer = ECDSASigner(jwk)
                if (algorithm == JWSAlgorithm.ES256K) signer.jcaContext.provider = JwtKeyRing.bcProvider()
                signer.sign(JWSHeader(algorithm), input).toString()
            }
            // BouncyCastle EdDSA. Nimbus' Ed25519 signer needs Tink and has no Ed448.
            is OctetKeyPair -> Jwt.b64UrlEncode(edSign(jwk.curve, jwk.decodedD, input))
            else -> throw IllegalArgumentException("Key type ${jwk.keyType} cannot sign")
        }
    }

    /**
     * The header's `alg` when it is one string. A header that repeats `alg` with different values
     * has none: which copy a parser reads is exactly what a forged token plays on.
     */
    private fun singleAlg(raw: Jwt.Raw): String? {
        val copies = RawJson.members(raw.headerText).orEmpty().filter { it.name == "alg" }
            .map { raw.headerText.substring(it.valueStart, it.valueEnd) }
        if (copies.distinct().size > 1) return null
        return (raw.header["alg"] as? JsonPrimitive)?.takeIf { it.isString }?.content
    }

    /** The JWS algorithms [jwk] signs and verifies. Empty for a key that does neither. */
    private fun algsFor(jwk: JWK): List<String> = when (jwk) {
        is OctetSequenceKey -> listOf("HS256", "HS384", "HS512")
        is RSAKey -> listOf("RS256", "RS384", "RS512", "PS256", "PS384", "PS512")
        is ECKey -> listOf(ecAlg(jwk.curve))
        is OctetKeyPair -> if (jwk.curve.isEdwards()) listOf("EdDSA") else emptyList()
        else -> emptyList()
    }

    private fun keyLabel(jwk: JWK): String = when (jwk) {
        is ECKey -> "EC ${jwk.curve?.name}"
        is OctetKeyPair -> "OKP ${jwk.curve?.name}"
        else -> jwk.keyType?.value ?: "unknown"
    }

    private fun cannotSign(jwk: JWK): IllegalArgumentException = IllegalArgumentException(
        if (jwk is OctetKeyPair) {
            "An ${keyLabel(jwk)} key agrees on encryption keys (mode=encrypt, mode=decrypt with ECDH-ES); it cannot sign or verify"
        } else {
            "Key type ${jwk.keyType} cannot sign"
        }
    )

    /** [name] in the spelling of [known] when only its case differs (`rs256` -> `RS256`, `DIR` -> `dir`). */
    private fun canonical(name: String, known: List<String>): String =
        known.firstOrNull { it.equals(name.trim(), ignoreCase = true) } ?: name.trim()

    private fun urlHeader(headerName: String?): String {
        val name = (headerName ?: "jku").trim().lowercase()
        if (name != "jku" && name != "x5u") {
            throw IllegalArgumentException("header must be jku or x5u")
        }
        return name
    }

    private fun edSign(curve: Curve, seed: ByteArray, input: ByteArray): ByteArray = when (curve) {
        Curve.Ed25519 -> {
            val signer = Ed25519Signer()
            signer.init(true, Ed25519PrivateKeyParameters(seed, 0))
            signer.update(input, 0, input.size)
            signer.generateSignature()
        }
        Curve.Ed448 -> {
            val signer = Ed448Signer(ByteArray(0))
            signer.init(true, Ed448PrivateKeyParameters(seed, 0))
            signer.update(input, 0, input.size)
            signer.generateSignature()
        }
        else -> throw IllegalArgumentException("Curve ${curve.name} cannot sign")
    }

    private fun edVerify(curve: Curve, x: ByteArray, input: ByteArray, sig: ByteArray): Boolean = when (curve) {
        Curve.Ed25519 -> {
            val signer = Ed25519Signer()
            signer.init(false, Ed25519PublicKeyParameters(x, 0))
            signer.update(input, 0, input.size)
            signer.verifySignature(sig)
        }
        Curve.Ed448 -> {
            val signer = Ed448Signer(ByteArray(0))
            signer.init(false, Ed448PublicKeyParameters(x, 0))
            signer.update(input, 0, input.size)
            signer.verifySignature(sig)
        }
        else -> false
    }

    private fun Curve.isEdwards(): Boolean = this == Curve.Ed25519 || this == Curve.Ed448

    private fun x25519Available(): Boolean = try {
        Class.forName("com.google.crypto.tink.subtle.X25519")
        true
    } catch (_: ClassNotFoundException) {
        false
    }

    private fun encrypter(jwk: JWK, alg: JWEAlgorithm): JWEEncrypter {
        val public = if (jwk is OctetSequenceKey) jwk else (jwk.toPublicJWK() ?: jwk)
        return when (public) {
            is RSAKey -> RSAEncrypter(public)
            is ECKey -> ECDHEncrypter(public)
            is OctetKeyPair -> when (public.curve) {
                Curve.X25519 -> {
                    if (!x25519Available()) {
                        throw IllegalArgumentException("X25519 encryption is not available in this build")
                    }
                    X25519Encrypter(public)
                }
                Curve.X448 -> X448Encrypter(public)
                else -> throw IllegalArgumentException("Curve ${public.curve.name} cannot encrypt")
            }
            is OctetSequenceKey -> if (alg == JWEAlgorithm.DIR) DirectEncrypter(public) else AESEncrypter(public)
            else -> throw IllegalArgumentException("Key type ${jwk.keyType} cannot encrypt")
        }
    }

    private fun decrypter(jwk: JWK, header: JWEHeader): JWEDecrypter = when (jwk) {
        is RSAKey -> RSADecrypter(jwk)
        is ECKey -> ECDHDecrypter(jwk)
        is OctetKeyPair -> when (jwk.curve) {
            Curve.X25519 -> {
                if (!x25519Available()) {
                    throw IllegalArgumentException("X25519 decryption is not available in this build")
                }
                X25519Decrypter(jwk)
            }
            Curve.X448 -> X448Decrypter(jwk)
            else -> throw IllegalArgumentException("Curve ${jwk.curve.name} cannot decrypt")
        }
        is OctetSequenceKey -> if (header.algorithm == JWEAlgorithm.DIR) DirectDecrypter(jwk) else AESDecrypter(jwk)
        else -> throw IllegalArgumentException("Key type ${jwk.keyType} cannot decrypt")
    }

    private fun rewrittenParts(token: String, alg: String, overrides: JsonObject?): Pair<String, String> {
        val raw = Jwt.split(token) ?: throw IllegalArgumentException("Not a decodable JWT")
        return Jwt.headerSegment(raw, mapOf("alg" to JsonPrimitive(alg))) to Jwt.payloadSegment(raw, overrides)
    }

    private fun defaultSignAlg(jwk: JWK): String = when (jwk) {
        is RSAKey -> "RS256"
        is ECKey -> ecAlg(jwk.curve)
        is OctetKeyPair -> if (jwk.curve.isEdwards()) "EdDSA" else throw cannotSign(jwk)
        is OctetSequenceKey -> when (jwk.keyValue.decode().size) {
            48 -> "HS384"
            64 -> "HS512"
            else -> "HS256"
        }
        else -> throw IllegalArgumentException("Key type ${jwk.keyType} cannot sign")
    }

    private fun ecAlg(curve: Curve?): String = when (curve) {
        Curve.P_384 -> "ES384"
        Curve.P_521 -> "ES512"
        Curve.SECP256K1 -> "ES256K"
        else -> "ES256"
    }

    private fun defaultJweAlg(jwk: JWK): String = when (jwk) {
        is RSAKey -> "RSA-OAEP-256"
        is ECKey, is OctetKeyPair -> "ECDH-ES"
        is OctetSequenceKey -> "dir"
        else -> throw IllegalArgumentException("Key type ${jwk.keyType} cannot encrypt")
    }

    private fun x448SharedSecret(publicBytes: ByteArray, privateBytes: ByteArray): SecretKey {
        if (publicBytes.size != X448PrivateKeyParameters.KEY_SIZE || privateBytes.size != X448PrivateKeyParameters.KEY_SIZE) {
            throw JOSEException("Invalid X448 key length (expected ${X448PrivateKeyParameters.KEY_SIZE} bytes)")
        }
        val agreement = X448Agreement()
        agreement.init(X448PrivateKeyParameters(privateBytes, 0))
        val secret = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(X448PublicKeyParameters(publicBytes, 0), secret, 0)
        if (secret.all { it == 0.toByte() }) {
            throw JOSEException("X448 shared secret is all-zero (low-order public key)")
        }
        return SecretKeySpec(secret, "AES")
    }

    private class X448Encrypter(private val publicKey: OctetKeyPair) :
        ECDHCryptoProvider(publicKey.curve, null), JWEEncrypter {
        init {
            if (publicKey.curve != Curve.X448) throw JOSEException("X448Encrypter requires crv=X448")
            if (publicKey.isPrivate) throw JOSEException("X448Encrypter requires a public key")
        }

        override fun supportedEllipticCurves(): Set<Curve> = setOf(Curve.X448)

        override fun encrypt(header: JWEHeader, clearText: ByteArray, aad: ByteArray): JWECryptoParts {
            val gen = X448KeyPairGenerator()
            gen.init(X448KeyGenerationParameters(SecureRandom()))
            val pair = gen.generateKeyPair()
            val ephPubBytes = (pair.public as X448PublicKeyParameters).encoded
            val ephPrivBytes = (pair.private as X448PrivateKeyParameters).encoded
            val ephPublicKey = OctetKeyPair.Builder(Curve.X448, Base64URL.encode(ephPubBytes)).build()
            val updatedHeader = JWEHeader.Builder(header).ephemeralPublicKey(ephPublicKey).build()
            val z = x448SharedSecret(publicKey.decodedX, ephPrivBytes)
            // JWEObject computed aad over the header before epk was added; authenticate the header that
            // goes on the wire, as Nimbus's own ECDH and X25519 encrypters do.
            val updatedAad = if (aad.contentEquals(AAD.compute(header))) AAD.compute(updatedHeader) else aad
            return encryptWithZ(updatedHeader, z, clearText, updatedAad)
        }
    }

    private class X448Decrypter(private val privateKey: OctetKeyPair) :
        ECDHCryptoProvider(privateKey.curve, null), JWEDecrypter {
        private val critPolicy = CriticalHeaderParamsDeferral()

        init {
            if (privateKey.curve != Curve.X448) throw JOSEException("X448Decrypter requires crv=X448")
            if (!privateKey.isPrivate) throw JOSEException("X448Decrypter requires a private key")
        }

        override fun supportedEllipticCurves(): Set<Curve> = setOf(Curve.X448)

        override fun decrypt(
            header: JWEHeader,
            encryptedKey: Base64URL?,
            iv: Base64URL?,
            cipherText: Base64URL?,
            authTag: Base64URL?,
            aad: ByteArray,
        ): ByteArray {
            critPolicy.ensureHeaderPasses(header)
            val epk = header.ephemeralPublicKey as? OctetKeyPair
                ?: throw JOSEException("Missing ephemeral public key epk JWE header parameter")
            if (epk.curve != Curve.X448) {
                throw JOSEException("Curve of ephemeral public key does not match curve of private key")
            }
            val z = x448SharedSecret(epk.decodedX, privateKey.decodedD)
            return decryptWithZ(
                header, aad, z, encryptedKey, iv, cipherText, authTag, JWEObject.MAX_DECOMPRESSED_PLAIN_TEXT_LENGTH,
            )
        }
    }
}
