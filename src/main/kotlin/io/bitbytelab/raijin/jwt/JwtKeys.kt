package io.bitbytelab.raijin.jwt

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.util.Base64URL
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.Ed448KeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X448KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.Ed448KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.params.X448KeyGenerationParameters
import org.bouncycastle.crypto.params.X448PrivateKeyParameters
import org.bouncycastle.crypto.params.X448PublicKeyParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import java.security.SecureRandom
import java.security.Security
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.io.StringWriter

/**
 * In-memory JWK ring. Private material stays in [snapshot] and in
 * [JwtKey.export] only when private export is requested.
 */
class JwtKeyRing {
    private val keys = ConcurrentHashMap<String, JwtKey>()

    fun generate(kty: String, size: Int?, crv: String?, alg: String?, id: String?): JwtKey {
        val kind = kty.trim().lowercase()
        val key = when (kind) {
            "rsa" -> {
                val bits = size ?: 2048
                if (bits < 512 || bits % 8 != 0) {
                    throw IllegalArgumentException("RSA size must be a multiple of 8 and at least 512")
                }
                val kid = freshId(id, "rsa")
                val gen = RSAKeyGenerator(bits).keyID(kid)
                if (alg != null) gen.algorithm(com.nimbusds.jose.JWSAlgorithm.parse(alg))
                jose(kid, gen.generate())
            }
            "ec" -> {
                val curve = curveOf(crv ?: "P-256")
                if (curve == Curve.Ed25519 || curve == Curve.Ed448 || curve == Curve.X25519 || curve == Curve.X448) {
                    throw IllegalArgumentException("Curve ${curve.name} is an OKP key, not EC")
                }
                val kid = freshId(id, "ec")
                if (curve == Curve.SECP256K1) {
                    jose(kid, secp256k1(kid, alg))
                } else {
                    val gen = ECKeyGenerator(curve).keyID(kid)
                    if (alg != null) gen.algorithm(com.nimbusds.jose.JWSAlgorithm.parse(alg))
                    jose(kid, gen.generate())
                }
            }
            "okp" -> {
                val curve = curveOf(crv ?: "Ed25519")
                if (curve != Curve.Ed25519 && curve != Curve.Ed448 && curve != Curve.X25519 && curve != Curve.X448) {
                    throw IllegalArgumentException("Curve ${curve.name} is not an OKP curve")
                }
                val kid = freshId(id, "okp")
                jose(kid, okp(curve, kid, alg))
            }
            "oct" -> {
                val bits = size ?: 256
                if (bits < 128 || bits % 8 != 0) {
                    throw IllegalArgumentException("oct size must be a multiple of 8 and at least 128")
                }
                val kid = freshId(id, "oct")
                val gen = OctetSequenceKeyGenerator(bits).keyID(kid)
                if (alg != null) gen.algorithm(com.nimbusds.jose.JWSAlgorithm.parse(alg))
                jose(kid, gen.generate())
            }
            "password" -> {
                val kid = freshId(id, "password")
                val bytes = ByteArray(24).also { SecureRandom().nextBytes(it) }
                val secret = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
                JwtKey.Password(kid, secret, alg)
            }
            else -> throw IllegalArgumentException("Unknown kty '$kty'. Use RSA, EC, OKP, oct, or password")
        }
        keys[key.id] = key
        return key
    }

    /** Imports a PEM document, one JWK, or a JWK set. Returns the stored keys. */
    fun import(pem: String?, jwkJson: String?, password: String?): List<JwtKey> {
        val stored = when {
            !password.isNullOrBlank() && pem.isNullOrBlank() && jwkJson.isNullOrBlank() ->
                listOf(JwtKey.Password(freshId(null, "password"), password, null))
            !pem.isNullOrBlank() -> pemToJwks(pem).map { storeParsed(it) }
            !jwkJson.isNullOrBlank() -> parseJwkText(jwkJson).map { storeParsed(it) }
            else -> throw IllegalArgumentException("import requires pem, jwk, or password")
        }
        stored.forEach { keys[it.id] = it }
        return stored
    }

    fun list(): List<JwtKey> = keys.values.sortedBy { it.id }

    fun get(id: String): JwtKey =
        keys[id] ?: throw IllegalArgumentException("Unknown key_id '$id'")

    fun delete(id: String): Boolean = keys.remove(id) != null

    fun snapshot(): String {
        val arr = buildJsonArray {
            keys.values.sortedBy { it.id }.forEach { key ->
                add(buildJsonObject {
                    put("id", key.id)
                    put("material", key.persist())
                })
            }
        }
        return buildJsonObject {
            put("v", 1)
            put("keys", arr)
        }.toString()
    }

    fun restore(json: String) {
        val root = Json.parseToJsonElement(json).jsonObject
        val arr = root["keys"] as? JsonArray ?: return
        for (el in arr) {
            val obj = el as? JsonObject ?: continue
            val id = obj["id"]?.jsonPrimitive?.contentOrNull ?: continue
            val material = obj["material"]?.jsonPrimitive?.contentOrNull ?: continue
            val key = try {
                decodeMaterial(id, material)
            } catch (_: Exception) {
                continue
            }
            keys[key.id] = key
        }
    }

    private fun storeParsed(jwk: JWK): JwtKey {
        val kid = jwk.keyID?.takeIf { it.isNotBlank() } ?: freshId(null, jwk.keyType?.value ?: "key")
        val withKid = if (jwk.keyID == kid) jwk else {
            JWK.parse(buildJsonObject {
                val parsed = Json.parseToJsonElement(jwk.toJSONString()).jsonObject
                parsed.forEach { (k, v) -> put(k, v) }
                put("kid", kid)
            }.toString())
        }
        if (keys.containsKey(kid)) throw IllegalArgumentException("key_id '$kid' already exists")
        val stored = jose(kid, withKid)
        keys[stored.id] = stored
        return stored
    }

    private fun freshId(requested: String?, prefix: String): String {
        val base = requested?.trim()?.takeIf { it.isNotEmpty() }
        if (base != null && !keys.containsKey(base)) return base
        if (base != null) throw IllegalArgumentException("key_id '$base' already exists")
        var n = keys.size + 1
        var id = "$prefix-$n"
        while (keys.containsKey(id)) {
            n += 1
            id = "$prefix-$n"
        }
        return id
    }

    companion object {
        /** Nimbus generates OKP keys via Tink. These curves come from BouncyCastle instead. */
        private fun okp(curve: Curve, kid: String, alg: String?): OctetKeyPair {
            val (x, d) = when (curve) {
                Curve.Ed25519 -> {
                    val gen = Ed25519KeyPairGenerator()
                    gen.init(Ed25519KeyGenerationParameters(SecureRandom()))
                    val pair = gen.generateKeyPair()
                    (pair.public as Ed25519PublicKeyParameters).encoded to
                        (pair.private as Ed25519PrivateKeyParameters).encoded
                }
                Curve.Ed448 -> {
                    val gen = Ed448KeyPairGenerator()
                    gen.init(Ed448KeyGenerationParameters(SecureRandom()))
                    val pair = gen.generateKeyPair()
                    (pair.public as Ed448PublicKeyParameters).encoded to
                        (pair.private as Ed448PrivateKeyParameters).encoded
                }
                Curve.X25519 -> {
                    val gen = X25519KeyPairGenerator()
                    gen.init(X25519KeyGenerationParameters(SecureRandom()))
                    val pair = gen.generateKeyPair()
                    (pair.public as X25519PublicKeyParameters).encoded to
                        (pair.private as X25519PrivateKeyParameters).encoded
                }
                Curve.X448 -> {
                    val gen = X448KeyPairGenerator()
                    gen.init(X448KeyGenerationParameters(SecureRandom()))
                    val pair = gen.generateKeyPair()
                    (pair.public as X448PublicKeyParameters).encoded to
                        (pair.private as X448PrivateKeyParameters).encoded
                }
                else -> throw IllegalArgumentException("Curve ${curve.name} is not an OKP curve")
            }
            val builder = OctetKeyPair.Builder(curve, Base64URL.encode(x)).d(Base64URL.encode(d)).keyID(kid)
            if (alg != null) builder.algorithm(com.nimbusds.jose.Algorithm.parse(alg))
            return builder.build()
        }

        private fun secp256k1(kid: String, alg: String?): ECKey {
            val generator = java.security.KeyPairGenerator.getInstance("EC", bcProvider())
            generator.initialize(ECGenParameterSpec("secp256k1"), SecureRandom())
            val pair = generator.generateKeyPair()
            val builder = ECKey.Builder(Curve.SECP256K1, pair.public as ECPublicKey)
                .privateKey(pair.private as ECPrivateKey)
                .keyID(kid)
            if (alg != null) builder.algorithm(com.nimbusds.jose.JWSAlgorithm.parse(alg))
            return builder.build()
        }

        fun bcProvider(): java.security.Provider {
            val name = BouncyCastleProvider.PROVIDER_NAME
            return Security.getProvider(name) ?: BouncyCastleProvider().also { Security.addProvider(it) }
        }

        fun curveOf(crv: String): Curve = when (crv.trim().uppercase().replace("_", "-")) {
            "P-256", "P256", "SECP256R1" -> Curve.P_256
            "P-384", "P384", "SECP384R1" -> Curve.P_384
            "P-521", "P521", "SECP521R1" -> Curve.P_521
            "SECP256K1", "P-256K", "ES256K" -> Curve.SECP256K1
            "ED25519" -> Curve.Ed25519
            "ED448" -> Curve.Ed448
            "X25519" -> Curve.X25519
            "X448" -> Curve.X448
            else -> throw IllegalArgumentException("Unknown curve '$crv'")
        }
    }
}

sealed class JwtKey {
    abstract val id: String
    abstract val kty: String
    abstract val alg: String?
    abstract val publicOnly: Boolean
    abstract val crv: String?

    /** JSON stored in the extension key ring. Includes private material. */
    abstract fun persist(): String

    abstract fun publicJwk(): JsonObject?

    fun summary(): JsonObject = buildJsonObject {
        put("key_id", id)
        put("kty", kty)
        put("public_only", publicOnly)
        alg?.let { put("alg", it) }
        crv?.let { put("crv", it) }
    }

    data class Jose(override val id: String, val jwk: JWK) : JwtKey() {
        override val kty: String get() = jwk.keyType?.value ?: "oct"
        override val alg: String? get() = jwk.algorithm?.name
        override val publicOnly: Boolean get() = !jwk.isPrivate
        override val crv: String? get() = when (jwk) {
            is ECKey -> jwk.curve?.name
            is OctetKeyPair -> jwk.curve?.name
            else -> null
        }

        override fun persist(): String = jwk.toJSONString()

        override fun publicJwk(): JsonObject? {
            val pub = jwk.toPublicJWK() ?: return null
            return Json.parseToJsonElement(pub.toJSONString()).jsonObject
        }

        fun exportJwk(includePrivate: Boolean): JsonObject {
            if (includePrivate) return Json.parseToJsonElement(jwk.toJSONString()).jsonObject
            return publicJwk()
                ?: throw IllegalArgumentException("Key '$id' has no public form. Pass include_private=true to export it")
        }

        fun exportPem(includePrivate: Boolean): String {
            val obj: Any = when {
                includePrivate && jwk.isPrivate -> when (jwk) {
                    is RSAKey -> jwk.toPrivateKey()
                    is ECKey -> jwk.toECPrivateKey()
                    is OctetKeyPair -> jwk.toPrivateKey()
                    else -> throw IllegalArgumentException("Key '$id' cannot be exported as PEM")
                }
                else -> when (val pub = jwk.toPublicJWK()) {
                    is RSAKey -> pub.toPublicKey()
                    is ECKey -> pub.toECPublicKey()
                    is OctetKeyPair -> pub.toPublicKey()
                    null -> throw IllegalArgumentException("Key '$id' has no public PEM. Pass include_private=true")
                    else -> throw IllegalArgumentException("Key '$id' cannot be exported as PEM")
                }
            }
            val sw = StringWriter()
            JcaPEMWriter(sw).use { it.writeObject(obj) }
            return sw.toString()
        }
    }

    data class Password(override val id: String, val password: String, override val alg: String?) : JwtKey() {
        override val kty: String get() = "password"
        override val publicOnly: Boolean get() = false
        override val crv: String? get() = null

        override fun persist(): String = buildJsonObject {
            put("kty", "password")
            put("k", password)
            alg?.let { put("alg", it) }
        }.toString()

        override fun publicJwk(): JsonObject? = null

        fun exportPrivate(): JsonObject = buildJsonObject {
            put("kty", "password")
            put("k", password)
            alg?.let { put("alg", it) }
        }
    }
}

private fun jose(id: String, jwk: JWK): JwtKey.Jose = JwtKey.Jose(id, jwk)

private fun decodeMaterial(id: String, material: String): JwtKey {
    val el = Json.parseToJsonElement(material)
    val obj = el as? JsonObject
    if (obj != null && obj["kty"]?.jsonPrimitive?.contentOrNull == "password") {
        val secret = obj["k"]?.jsonPrimitive?.contentOrNull
            ?: throw IllegalArgumentException("password key is missing k")
        return JwtKey.Password(id, secret, obj["alg"]?.jsonPrimitive?.contentOrNull)
    }
    return JwtKey.Jose(id, JWK.parse(material))
}

private fun parseJwkText(text: String): List<JWK> {
    val trimmed = text.trim()
    val el = Json.parseToJsonElement(trimmed)
    if (el is JsonObject && el["keys"] is JsonArray) {
        return JWKSet.parse(trimmed).keys
    }
    return listOf(JWK.parse(trimmed))
}

private fun pemToJwks(pem: String): List<JWK> {
    val parsed = JWK.parseFromPEMEncodedObjects(pem.trim())
    return listOf(parsed)
}
