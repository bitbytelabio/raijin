package io.bitbytelab.raijin.jwt

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.OctetSequenceKey
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.util.Base64URL
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERUTF8String
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
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
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.StringWriter
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Security
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import java.util.Date
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * JWK ring. Private material stays in [snapshot] and in
 * [JwtKey.Jose.exportJwk] only when private export is requested.
 *
 * Reads never wait. Writers take [writeLock] one at a time and hand the whole ring to [store]
 * before they release it, so stores happen in the order the ring changed and each one holds a
 * complete ring: two tools writing at once cannot leave the store without one of their keys.
 *
 * @param store receives [snapshot] after every change (the extension's persistent data), or null
 *   for a ring that lives in memory only.
 */
class JwtKeyRing(private val store: ((String) -> Unit)? = null) {
    private val keys = ConcurrentHashMap<String, JwtKey>()
    private val writeLock = ReentrantLock()

    /**
     * Ids promised to a generation that is still running. Key material is generated outside
     * [writeLock] (RSA can take seconds), and the id must stay taken meanwhile. Guarded by [writeLock].
     */
    private val reserved = HashSet<String>()

    /** Why the last [persist] failed, or null when the store holds the ring as it is now. */
    @Volatile
    var storeError: String? = null
        private set

    fun generate(kty: String, size: Int?, crv: String?, alg: String?, id: String?): JwtKey {
        val kind = kty.trim().lowercase()
        val kid = reserve(id, kind)
        try {
            val key = create(kind, kid, size, crv, alg)
            commit { keys[kid] = key }
            return key
        } finally {
            writeLock.withLock { reserved.remove(kid) }
        }
    }

    /** Imports a PEM document, one JWK, or a JWK set. Returns the stored keys; stores all of them or none. */
    fun import(pem: String?, jwkJson: String?, password: String?): List<JwtKey> {
        val parsed = when {
            !pem.isNullOrBlank() -> pemToJwks(pem)
            !jwkJson.isNullOrBlank() -> parseJwkText(jwkJson)
            !password.isNullOrBlank() -> return commit {
                val key = JwtKey.Password(nextId("password"), password, null)
                keys[key.id] = key
                listOf(key)
            }
            else -> throw IllegalArgumentException("import requires pem, jwk, or password")
        }
        return commit { withIds(parsed).onEach { keys[it.id] = it } }
    }

    fun list(): List<JwtKey> = keys.values.sortedBy { it.id }

    fun get(id: String): JwtKey =
        keys[id] ?: throw IllegalArgumentException("Unknown key_id '$id'")

    fun delete(id: String): Boolean = writeLock.withLock {
        val removed = keys.remove(id) != null
        if (removed) persist()
        removed
    }

    fun snapshot(): String = writeLock.withLock {
        val arr = buildJsonArray {
            keys.values.sortedBy { it.id }.forEach { key ->
                add(buildJsonObject {
                    put("id", key.id)
                    put("material", key.persist())
                })
            }
        }
        buildJsonObject {
            put("v", 1)
            put("keys", arr)
        }.toString()
    }

    fun restore(json: String) {
        val root = Json.parseToJsonElement(json).jsonObject
        val arr = root["keys"] as? JsonArray ?: return
        writeLock.withLock {
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
    }

    /**
     * Hands the whole ring to the store. Every change calls this before it lets go of the ring,
     * which is what keeps the stored ring whole when two changes race. Returns false, and sets
     * [storeError], when the store throws: the keys then stay usable in memory.
     */
    fun persist(): Boolean {
        val sink = store ?: return true
        return writeLock.withLock {
            try {
                sink(snapshot())
                storeError = null
                true
            } catch (e: Exception) {
                storeError = e.message ?: e.javaClass.simpleName
                false
            }
        }
    }

    /** Applies [change] and stores the ring as one step. */
    private inline fun <T> commit(change: () -> T): T = writeLock.withLock {
        val result = change()
        persist()
        result
    }

    private fun reserve(requested: String?, prefix: String): String = writeLock.withLock {
        val wanted = requested?.trim()?.takeIf { it.isNotEmpty() }
        if (wanted != null && taken(wanted)) throw IllegalArgumentException("key_id '$wanted' already exists")
        val id = wanted ?: nextId(prefix)
        reserved.add(id)
        id
    }

    private fun taken(id: String): Boolean = keys.containsKey(id) || id in reserved

    /** The next free `prefix-N` id. Call under [writeLock]; [pending] holds ids of a batch not stored yet. */
    private fun nextId(prefix: String, pending: Set<String> = emptySet()): String {
        var n = keys.size + pending.size + 1
        while (taken("$prefix-$n") || "$prefix-$n" in pending) n += 1
        return "$prefix-$n"
    }

    /**
     * Gives each imported JWK its ring id: its own `kid`, or a fresh one. Fails before anything is
     * stored when an id is taken, so an import never lands half-way. Call under [writeLock].
     */
    private fun withIds(parsed: List<JWK>): List<JwtKey.Jose> {
        val batch = LinkedHashMap<String, JwtKey.Jose>()
        for (jwk in parsed) {
            val own = jwk.keyID?.takeIf { it.isNotBlank() }
            if (own != null && (taken(own) || own in batch)) throw IllegalArgumentException("key_id '$own' already exists")
            val kid = own ?: nextId(jwk.keyType?.value ?: "key", batch.keys)
            val withKid = if (own != null) jwk else {
                JWK.parse(buildJsonObject {
                    val json = Json.parseToJsonElement(jwk.toJSONString()).jsonObject
                    json.forEach { (k, v) -> put(k, v) }
                    put("kid", kid)
                }.toString())
            }
            batch[kid] = jose(kid, withKid)
        }
        return batch.values.toList()
    }

    /** Builds the key material for [kid]. Runs outside [writeLock]. */
    private fun create(kind: String, kid: String, size: Int?, crv: String?, alg: String?): JwtKey = when (kind) {
        "rsa" -> {
            val bits = size ?: 2048
            if (bits < 512 || bits % 8 != 0) {
                throw IllegalArgumentException("RSA size must be a multiple of 8 and at least 512")
            }
            // Nimbus refuses to generate under 2048 bits unless asked; a weak key is a test case here.
            val gen = RSAKeyGenerator(bits, true).keyID(kid)
            if (alg != null) gen.algorithm(com.nimbusds.jose.JWSAlgorithm.parse(alg))
            jose(kid, gen.generate())
        }
        "ec" -> {
            val curve = curveOf(crv ?: "P-256")
            if (curve.isOkp()) {
                throw IllegalArgumentException("Curve ${curve.name} is an OKP key, not EC")
            }
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
            if (!curve.isOkp()) {
                throw IllegalArgumentException("Curve ${curve.name} is not an OKP curve")
            }
            jose(kid, okp(curve, kid, alg))
        }
        "oct" -> {
            val bits = size ?: 256
            if (bits < 128 || bits % 8 != 0) {
                throw IllegalArgumentException("oct size must be a multiple of 8 and at least 128")
            }
            val gen = OctetSequenceKeyGenerator(bits).keyID(kid)
            if (alg != null) gen.algorithm(com.nimbusds.jose.JWSAlgorithm.parse(alg))
            jose(kid, gen.generate())
        }
        "password" -> {
            val bytes = ByteArray(24).also { SecureRandom().nextBytes(it) }
            val secret = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
            JwtKey.Password(kid, secret, alg)
        }
        else -> throw IllegalArgumentException("Unknown kty '$kind'. Use ${KTYS.joinToString(", ")}")
    }

    companion object {
        /** `kty` values [generate] accepts (matched without regard to case). */
        val KTYS: List<String> = listOf("RSA", "EC", "OKP", "oct", "password")

        /** Curve names [curveOf] accepts, in their JWK spelling. */
        val CURVES: List<String> = listOf("P-256", "P-384", "P-521", "secp256k1", "Ed25519", "Ed448", "X25519", "X448")

        /** Smallest and largest `size` in bits [generate] can use (128-bit oct up to the JDK's RSA limit). */
        const val MIN_SIZE_BITS = 128
        const val MAX_SIZE_BITS = 16384

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
            else -> throw IllegalArgumentException("Unknown curve '$crv'. Use ${CURVES.joinToString(", ")}")
        }
    }
}

sealed class JwtKey {
    abstract val id: String
    abstract val kty: String
    abstract val alg: String?
    abstract val publicOnly: Boolean
    abstract val crv: String?

    /**
     * The `jwt_attack` modes this key can serve. Reported with every key, so nobody has to find out
     * by trial that an X448 key encrypts but cannot sign.
     */
    abstract val modes: List<String>

    /** JSON stored in the extension key ring. Includes private material. */
    abstract fun persist(): String

    abstract fun publicJwk(): JsonObject?

    fun summary(): JsonObject = buildJsonObject {
        put("key_id", id)
        put("kty", kty)
        put("public_only", publicOnly)
        alg?.let { put("alg", it) }
        crv?.let { put("crv", it) }
        putJsonArray("modes") { modes.forEach { add(it) } }
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

        override val modes: List<String>
            get() {
                val signs = when (jwk) {
                    is RSAKey, is ECKey, is OctetSequenceKey -> true
                    is OctetKeyPair -> jwk.curve == Curve.Ed25519 || jwk.curve == Curve.Ed448
                    else -> false
                }
                val encrypts = when (jwk) {
                    is RSAKey, is OctetSequenceKey -> true
                    is ECKey -> jwk.curve != Curve.SECP256K1
                    is OctetKeyPair -> jwk.curve == Curve.X25519 || jwk.curve == Curve.X448
                    else -> false
                }
                val asymmetric = jwk !is OctetSequenceKey
                val private = jwk.isPrivate
                return buildList {
                    if (signs && private) add("sign_key")
                    if (signs) add("verify")
                    if (signs && private && asymmetric) {
                        add("embed_jwk")
                        add("header_url")
                    }
                    if (asymmetric) add("alg_confusion")
                    if (encrypts) add("encrypt")
                    if (encrypts && private) add("decrypt")
                }
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
                    is OctetKeyPair -> okpPrivateInfo(jwk)
                    else -> throw IllegalArgumentException("Key '$id' cannot be exported as PEM")
                }
                else -> publicPemObject(jwk)
                    ?: throw IllegalArgumentException("Key '$id' has no public PEM. Pass include_private=true")
            }
            return pem(obj)
        }
    }

    data class Password(override val id: String, val password: String, override val alg: String?) : JwtKey() {
        override val kty: String get() = "password"
        override val publicOnly: Boolean get() = false
        override val crv: String? get() = null
        override val modes: List<String> get() = listOf("encrypt", "decrypt")

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

private fun Curve.isOkp(): Boolean =
    this == Curve.Ed25519 || this == Curve.Ed448 || this == Curve.X25519 || this == Curve.X448

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

/**
 * Converts standalone JWK or JWK-set JSON text to a public-key PEM document — the form
 * `jwt_attack`'s `alg_confusion` mode needs for `public_key` (it treats that parameter as
 * literal HMAC-secret bytes, so it needs byte-exact PEM text, not JSON). A JWK set uses its
 * first entry. This lets a caller pass a server's JWKS entry directly instead of first
 * importing it into the key ring and exporting it as PEM by hand.
 */
fun jwkTextToPem(jwkJson: String): String {
    val jwk = parseJwkText(jwkJson).firstOrNull()
        ?: throw IllegalArgumentException("No JWK found in the supplied JSON")
    val obj = publicPemObject(jwk)
        ?: throw IllegalArgumentException("JWK has no exportable public key (kty=${jwk.keyType?.value})")
    return pem(obj)
}

private fun pemToJwks(pem: String): List<JWK> {
    val parsed = JWK.parseFromPEMEncodedObjects(pem.trim())
    return listOf(parsed)
}

/** PEM text with LF line ends on every platform: a PEM used as an HMAC secret has to match byte for byte. */
private fun pem(obj: Any): String {
    val sw = StringWriter()
    JcaPEMWriter(sw).use { it.writeObject(obj) }
    return sw.toString().replace("\r\n", "\n")
}

/** What [pem] writes as the public key of [jwk], or null when the key has no public half. */
private fun publicPemObject(jwk: JWK): Any? = when (val public = jwk.toPublicJWK()) {
    is RSAKey -> public.toPublicKey()
    is ECKey -> public.toECPublicKey()
    is OctetKeyPair -> okpPublicInfo(public)
    else -> null
}

/** RFC 8410 algorithm identifier of an OKP curve. */
private fun okpAlgorithm(curve: Curve): AlgorithmIdentifier = AlgorithmIdentifier(
    ASN1ObjectIdentifier(
        when (curve) {
            Curve.X25519 -> "1.3.101.110"
            Curve.X448 -> "1.3.101.111"
            Curve.Ed25519 -> "1.3.101.112"
            Curve.Ed448 -> "1.3.101.113"
            else -> throw IllegalArgumentException("Curve ${curve.name} is not an OKP curve")
        }
    )
)

/**
 * Nimbus (10.10 included) cannot turn an OKP key into a JCA key ("Export to java.security.PublicKey not
 * supported"), so the PEM forms of Ed25519, Ed448, X25519 and X448 keys are built from the raw
 * key bytes.
 */
private fun okpPublicInfo(jwk: OctetKeyPair): SubjectPublicKeyInfo =
    SubjectPublicKeyInfo(okpAlgorithm(jwk.curve), jwk.decodedX)

private fun okpPrivateInfo(jwk: OctetKeyPair): PrivateKeyInfo =
    PrivateKeyInfo(okpAlgorithm(jwk.curve), DEROctetString(jwk.decodedD))

private const val DAY_MILLIS = 24L * 60 * 60 * 1000

/**
 * A self-signed X.509 certificate for [jwk] as PEM: the one-certificate chain an `x5u` URL has to
 * serve (RFC 7515 section 4.1.5). BouncyCastle signs it, so every ring key that can sign gets one
 * the same way.
 */
internal fun selfSignedCertificatePem(jwk: JWK): String {
    if (!jwk.isPrivate) throw IllegalArgumentException("Key cannot sign (public only)")
    val provider = JwtKeyRing.bcProvider()
    val publicInfo: SubjectPublicKeyInfo
    val privateKey: PrivateKey
    val signatureAlgorithm: String
    when (jwk) {
        is RSAKey -> {
            publicInfo = SubjectPublicKeyInfo.getInstance(jwk.toRSAPublicKey().encoded)
            privateKey = jwk.toPrivateKey()
            signatureAlgorithm = "SHA256withRSA"
        }
        is ECKey -> {
            publicInfo = SubjectPublicKeyInfo.getInstance(jwk.toECPublicKey().encoded)
            privateKey = jwk.toECPrivateKey()
            signatureAlgorithm = when (jwk.curve) {
                Curve.P_384 -> "SHA384withECDSA"
                Curve.P_521 -> "SHA512withECDSA"
                else -> "SHA256withECDSA"
            }
        }
        is OctetKeyPair -> {
            if (jwk.curve != Curve.Ed25519 && jwk.curve != Curve.Ed448) {
                throw IllegalArgumentException("Curve ${jwk.curve.name} cannot sign a certificate")
            }
            publicInfo = okpPublicInfo(jwk)
            privateKey = KeyFactory.getInstance(jwk.curve.name, provider)
                .generatePrivate(PKCS8EncodedKeySpec(okpPrivateInfo(jwk).encoded))
            signatureAlgorithm = jwk.curve.name
        }
        else -> throw IllegalArgumentException("A certificate needs an RSA, EC, Ed25519 or Ed448 key")
    }
    val name = X500NameBuilder(BCStyle.INSTANCE)
        .addRDN(BCStyle.CN, DERUTF8String(jwk.keyID?.takeIf { it.isNotEmpty() } ?: "jwt"))
        .build()
    val now = System.currentTimeMillis()
    val certificate = X509v3CertificateBuilder(
        name,
        BigInteger(63, SecureRandom()).add(BigInteger.ONE),
        Date(now - DAY_MILLIS),
        Date(now + 365 * DAY_MILLIS),
        name,
        publicInfo,
    ).build(JcaContentSignerBuilder(signatureAlgorithm).setProvider(provider).build(privateKey))
    return pem(certificate)
}
