package io.bitbytelab.raijin.jwt

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEDecrypter
import com.nimbusds.jose.JWEEncrypter
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.AESDecrypter
import com.nimbusds.jose.crypto.AESEncrypter
import com.nimbusds.jose.crypto.DirectDecrypter
import com.nimbusds.jose.crypto.DirectEncrypter
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.PasswordBasedDecrypter
import com.nimbusds.jose.crypto.PasswordBasedEncrypter
import com.nimbusds.jose.crypto.RSADecrypter
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.crypto.X25519Decrypter
import com.nimbusds.jose.crypto.X25519Encrypter
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory
import com.nimbusds.jose.jca.JCAAware
import com.nimbusds.jose.jca.JCAContext
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.OctetSequenceKey
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.signers.Ed448Signer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

/**
 * JWS and JWE operations on keys from [JwtKeyRing]. Nimbus does the cryptography.
 * BouncyCastle is registered for ES256K (secp256k1), which the JDK provider does not ship.
 */
object JwtJose {
    private const val PBES_SALT_BYTES = 16
    private const val PBES_ITERATIONS = 1000

    init {
        JwtKeyRing.bcProvider()
    }

    fun sign(token: String, jwk: JWK, alg: String?, overrides: JsonObject?): String {
        val parsed = parseSigned(token)
        val algorithm = JWSAlgorithm.parse(alg ?: jwk.algorithm?.name ?: defaultSignAlg(jwk))
        val header = jwsHeader(parsed.header, algorithm, jwk.keyID, null)
        val payload = payload(parsed, overrides)
        if (jwk is OctetKeyPair && jwk.curve.isEdwards()) return signEd(header, payload.toString(), jwk)
        val jws = SignedJWT(header, JWTClaimsSet.parse(payload.toString()))
        jws.sign(signer(signingKey(jwk), algorithm))
        return jws.serialize()
    }

    fun verify(token: String, jwk: JWK): Boolean {
        if (jwk is OctetKeyPair && jwk.curve.isEdwards()) return verifyEd(token, jwk)
        val parsed = parseSigned(token)
        val factory = DefaultJWSVerifierFactory()
        if (parsed.header.algorithm == JWSAlgorithm.ES256K) {
            factory.jcaContext.provider = JwtKeyRing.bcProvider()
        }
        val verifier = factory.createJWSVerifier(parsed.header, javaPublicKey(jwk))
        return parsed.verify(verifier)
    }

    fun embedJwk(token: String, jwk: JWK, alg: String?, overrides: JsonObject?): String {
        val public = jwk.toPublicJWK()
            ?: throw IllegalArgumentException("embed_jwk needs an asymmetric key")
        val parsed = parseSigned(token)
        val algorithm = JWSAlgorithm.parse(alg ?: jwk.algorithm?.name ?: defaultSignAlg(jwk))
        val header = jwsHeader(parsed.header, algorithm, jwk.keyID, public)
        val payload = payload(parsed, overrides)
        if (jwk is OctetKeyPair && jwk.curve.isEdwards()) return signEd(header, payload.toString(), jwk)
        val jws = SignedJWT(header, JWTClaimsSet.parse(payload.toString()))
        jws.sign(signer(signingKey(jwk), algorithm))
        return jws.serialize()
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

    /** Writes [url] into the `jku` or `x5u` header and leaves the signature bytes unchanged. */
    fun headerUrl(token: String, headerName: String?, url: String, overrides: JsonObject?): String {
        val name = (headerName ?: "jku").lowercase()
        if (name != "jku" && name != "x5u") {
            throw IllegalArgumentException("header must be jku or x5u")
        }
        val parts = Jwt.decode(token) ?: throw IllegalArgumentException("Not a decodable JWT")
        val header = JsonObject(parts.header + mapOf(name to JsonPrimitive(url)))
        val payload = if (overrides != null) JsonObject(parts.payload + overrides) else parts.payload
        return "${Jwt.b64UrlEncode(header.toString())}.${Jwt.b64UrlEncode(payload.toString())}.${parts.signature}"
    }

    fun encrypt(plaintext: String, jwk: JWK, alg: String?, enc: String?): String {
        val jweAlg = JWEAlgorithm.parse(alg ?: defaultJweAlg(jwk))
        val method = EncryptionMethod.parse(enc ?: "A256GCM")
        val header = JWEHeader.Builder(jweAlg, method).keyID(jwk.keyID).build()
        val obj = JWEObject(header, Payload(plaintext))
        obj.encrypt(encrypter(jwk, jweAlg))
        return obj.serialize()
    }

    fun encryptPassword(plaintext: String, password: String, alg: String?, enc: String?): String {
        val jweAlg = JWEAlgorithm.parse(alg ?: JWEAlgorithm.PBES2_HS256_A128KW.name)
        val method = EncryptionMethod.parse(enc ?: "A256GCM")
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
        obj.decrypt(PasswordBasedDecrypter(password.toByteArray(Charsets.UTF_8)))
        return obj.payload.toString()
    }

    fun embeddedPublicJwk(token: String): JWK? {
        val parsed = parseSigned(token)
        return parsed.header.jwk
    }

    private fun parseSigned(token: String): SignedJWT = try {
        SignedJWT.parse(token)
    } catch (e: Exception) {
        throw IllegalArgumentException("Not a decodable JWS: ${e.message}")
    }

    private fun payload(parsed: SignedJWT, overrides: JsonObject?): JsonObject {
        val current = Json.parseToJsonElement(parsed.payload.toString()).jsonObject
        return if (overrides != null) JsonObject(current + overrides) else current
    }

    /** BouncyCastle EdDSA. Nimbus's Ed25519 signer loads Tink, which this project does not ship. */
    private fun signEd(header: JWSHeader, payloadJson: String, jwk: OctetKeyPair): String {
        val seed = jwk.d?.decode() ?: throw IllegalArgumentException("Key cannot sign (public only)")
        val headerPart = header.toBase64URL().toString()
        val payloadPart = Base64URL.encode(payloadJson.toByteArray(Charsets.UTF_8)).toString()
        val input = "$headerPart.$payloadPart".toByteArray(Charsets.US_ASCII)
        val sig = edSign(jwk.curve, seed, input)
        return "$headerPart.$payloadPart.${Base64URL.encode(sig)}"
    }

    private fun verifyEd(token: String, jwk: OctetKeyPair): Boolean {
        val parts = token.split('.')
        if (parts.size != 3) return false
        val input = "${parts[0]}.${parts[1]}".toByteArray(Charsets.US_ASCII)
        val sig = Base64URL(parts[2]).decode()
        val x = (jwk.toPublicJWK() ?: jwk).decodedX
        return edVerify(jwk.curve, x, input, sig)
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

    private fun jwsHeader(source: JWSHeader?, algorithm: JWSAlgorithm, kid: String?, embedded: JWK?): JWSHeader {
        val builder = JWSHeader.Builder(algorithm).type(source?.type ?: JOSEObjectType.JWT)
        val id = kid ?: source?.keyID
        if (id != null) builder.keyID(id)
        source?.contentType?.let { builder.contentType(it) }
        if (embedded != null) builder.jwk(embedded)
        return builder.build()
    }

    private fun signer(jwk: JWK, algorithm: JWSAlgorithm): com.nimbusds.jose.JWSSigner {
        val factory = DefaultJWSSignerFactory()
        if (algorithm == JWSAlgorithm.ES256K) factory.jcaContext.provider = JwtKeyRing.bcProvider()
        val created = factory.createJWSSigner(jwk, algorithm)
        if (algorithm == JWSAlgorithm.ES256K && created is JCAAware<*>) {
            @Suppress("UNCHECKED_CAST")
            (created as JCAAware<JCAContext>).jcaContext.provider = JwtKeyRing.bcProvider()
        }
        return created
    }

    private fun javaPublicKey(jwk: JWK): java.security.Key {
        val public = jwk.toPublicJWK() ?: jwk
        return when (public) {
            is RSAKey -> public.toPublicKey()
            is ECKey -> public.toECPublicKey()
            is OctetKeyPair -> public.toPublicKey()
            is OctetSequenceKey -> public.toSecretKey()
            else -> throw IllegalArgumentException("Unsupported key type ${jwk.keyType}")
        }
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
            else -> throw IllegalArgumentException("Curve ${jwk.curve.name} cannot decrypt")
        }
        is OctetSequenceKey -> if (header.algorithm == JWEAlgorithm.DIR) DirectDecrypter(jwk) else AESDecrypter(jwk)
        else -> throw IllegalArgumentException("Key type ${jwk.keyType} cannot decrypt")
    }

    private fun rewrittenParts(token: String, alg: String, overrides: JsonObject?): Pair<String, String> {
        val parts = Jwt.decode(token) ?: throw IllegalArgumentException("Not a decodable JWT")
        val header = JsonObject(parts.header + mapOf("alg" to JsonPrimitive(alg)))
        val payload = if (overrides != null) JsonObject(parts.payload + overrides) else parts.payload
        return Jwt.b64UrlEncode(header.toString()) to Jwt.b64UrlEncode(payload.toString())
    }

    private fun signingKey(jwk: JWK): JWK {
        if (!jwk.isPrivate && jwk !is OctetSequenceKey) {
            throw IllegalArgumentException("Key cannot sign (public only)")
        }
        return jwk
    }

    private fun defaultSignAlg(jwk: JWK): String = when (jwk) {
        is RSAKey -> "RS256"
        is ECKey -> when (jwk.curve) {
            Curve.P_384 -> "ES384"
            Curve.P_521 -> "ES512"
            Curve.SECP256K1 -> "ES256K"
            else -> "ES256"
        }
        is OctetKeyPair -> when (jwk.curve) {
            Curve.Ed25519, Curve.Ed448 -> "EdDSA"
            else -> throw IllegalArgumentException("Curve ${jwk.curve.name} cannot sign")
        }
        is OctetSequenceKey -> when (jwk.keyValue.decode().size) {
            48 -> "HS384"
            64 -> "HS512"
            else -> "HS256"
        }
        else -> throw IllegalArgumentException("Key type ${jwk.keyType} cannot sign")
    }

    private fun defaultJweAlg(jwk: JWK): String = when (jwk) {
        is RSAKey -> "RSA-OAEP-256"
        is ECKey, is OctetKeyPair -> "ECDH-ES"
        is OctetSequenceKey -> "dir"
        else -> throw IllegalArgumentException("Key type ${jwk.keyType} cannot encrypt")
    }
}
