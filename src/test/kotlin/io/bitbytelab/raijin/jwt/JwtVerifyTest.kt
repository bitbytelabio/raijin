package io.bitbytelab.raijin.jwt

import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.OctetSequenceKey
import io.bitbytelab.raijin.bridge.JwtBridge
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.signers.Ed448Signer
import java.security.Signature
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A signature only counts under the algorithm the token's header names, and that algorithm has to
 * belong to the key. Each forged token here carries a signature that is cryptographically valid
 * over its own header and payload, so the header check is the only thing between it and "valid".
 */
class JwtVerifyTest {
    private val claims = """{"sub":"administrator"}"""

    /** A token over [headerJson] whose signature is whatever [sign] makes of the signing input. */
    private fun forged(headerJson: String, sign: (ByteArray) -> ByteArray): String {
        val input = "${Jwt.b64UrlEncode(headerJson)}.${Jwt.b64UrlEncode(claims)}"
        return "$input.${Jwt.b64UrlEncode(sign(input.toByteArray(Charsets.US_ASCII)))}"
    }

    private fun ed25519(d: ByteArray): (ByteArray) -> ByteArray = { input ->
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(d, 0))
        signer.update(input, 0, input.size)
        signer.generateSignature()
    }

    private fun ed448(d: ByteArray): (ByteArray) -> ByteArray = { input ->
        val signer = Ed448Signer(ByteArray(0))
        signer.init(true, Ed448PrivateKeyParameters(d, 0))
        signer.update(input, 0, input.size)
        signer.generateSignature()
    }

    /** Headers that name anything but one `EdDSA`. */
    private val notEdDsa = listOf(
        """{"alg":"none"}""",
        """{"alg":"None","typ":"JWT"}""",
        """{"alg":"HS256","typ":"JWT"}""",
        """{"alg":"RS256"}""",
        """{"alg":"ES256"}""",
        """{"alg":"eddsa"}""",
        """{"alg":"EDDSA"}""",
        """{"alg":"Ed25519"}""",
        """{"typ":"JWT"}""",
        """{"alg":null}""",
        """{"alg":["EdDSA"]}""",
        """{"alg":{"name":"EdDSA"}}""",
        """{"alg":"EdDSA","alg":"none"}""",
        """{"alg":"none","alg":"EdDSA"}""",
    )

    private fun assertOnlyEdDsaVerifies(key: OctetKeyPair, sign: (ByteArray) -> ByteArray) {
        val publicKey = key.toPublicJWK()
        // Control: these signatures do verify as soon as the header names EdDSA.
        for (header in listOf("""{"alg":"EdDSA"}""", """{"typ":"JWT","alg":"EdDSA","kid":7}""", """{"alg":"EdDSA","alg":"EdDSA"}""")) {
            assertTrue(JwtJose.verify(forged(header, sign), key), header)
            assertTrue(JwtJose.verify(forged(header, sign), publicKey), header)
            assertNull(JwtJose.check(forged(header, sign), key).reason, header)
        }
        for (header in notEdDsa) {
            val token = forged(header, sign)
            assertFalse(JwtJose.verify(token, key), header)
            assertFalse(JwtJose.verify(token, publicKey), header)
            assertNotNull(JwtJose.check(token, key).reason, header)
        }
    }

    @Test
    fun `an Ed25519 key rejects a valid Ed25519 signature under any header but EdDSA`() {
        val key = (JwtKeyRing().generate("OKP", null, "Ed25519", null, null) as JwtKey.Jose).jwk as OctetKeyPair
        assertOnlyEdDsaVerifies(key, ed25519(key.decodedD))
    }

    @Test
    fun `an Ed448 key rejects a valid Ed448 signature under any header but EdDSA`() {
        val key = (JwtKeyRing().generate("OKP", null, "Ed448", null, null) as JwtKey.Jose).jwk as OctetKeyPair
        assertOnlyEdDsaVerifies(key, ed448(key.decodedD))
    }

    @Test
    fun `an Ed25519 signature does not verify against another curve's key`() {
        val ring = JwtKeyRing()
        val ed25519Key = (ring.generate("OKP", null, "Ed25519", null, null) as JwtKey.Jose).jwk as OctetKeyPair
        val ed448Key = (ring.generate("OKP", null, "Ed448", null, null) as JwtKey.Jose).jwk
        val x25519Key = (ring.generate("OKP", null, "X25519", null, null) as JwtKey.Jose).jwk
        val token = forged("""{"alg":"EdDSA"}""", ed25519(ed25519Key.decodedD))

        assertTrue(JwtJose.verify(token, ed25519Key))
        assertFalse(JwtJose.verify(token, ed448Key))
        assertFalse(JwtJose.verify(token, x25519Key))
        assertTrue("cannot sign or verify" in JwtJose.check(token, x25519Key).reason!!)
    }

    @Test
    fun `an HMAC token made from the RSA public key does not verify against that RSA key`() {
        val rsa = JwtKeyRing().generate("RSA", 2048, null, null, null) as JwtKey.Jose
        val original = JwtJose.sign(forged("""{"alg":"none"}""") { ByteArray(0) }, rsa.jwk, "RS256", null)
        assertTrue(JwtJose.verify(original, rsa.jwk))

        val pem = rsa.exportPem(includePrivate = false)
        val confused = Jwt.resign(original, pem, "HS256")!!
        assertFalse(JwtJose.verify(confused, rsa.jwk))
        assertTrue("HS256" in JwtJose.check(confused, rsa.jwk).reason!!)

        // The token is a sound HS256 token under the PEM bytes: only the key's type stands in its way.
        val pemAsSecret = OctetSequenceKey.Builder(pem.toByteArray()).build()
        assertTrue(JwtJose.verify(confused, pemAsSecret))
        // And the real RS256 token is no HMAC token for that secret.
        assertFalse(JwtJose.verify(original, pemAsSecret))
    }

    @Test
    fun `an EC key verifies only the algorithm of its curve`() {
        val ring = JwtKeyRing()
        val key = (ring.generate("EC", null, "P-256", null, null) as JwtKey.Jose).jwk as ECKey
        val es256: (ByteArray) -> ByteArray = { input ->
            val signer = Signature.getInstance("SHA256withECDSAinP1363Format")
            signer.initSign(key.toECPrivateKey())
            signer.update(input)
            signer.sign()
        }
        assertTrue(JwtJose.verify(forged("""{"alg":"ES256"}""", es256), key))
        for (alg in listOf("ES384", "ES512", "ES256K", "RS256", "PS256", "HS256", "EdDSA", "none", "es256")) {
            val token = forged("""{"alg":"$alg"}""", es256)
            assertFalse(JwtJose.verify(token, key), alg)
            assertTrue(alg in JwtJose.check(token, key).reason!!, alg)
        }

        val other = (ring.generate("EC", null, "P-256", null, null) as JwtKey.Jose).jwk
        val token = forged("""{"alg":"ES256"}""", es256)
        assertFalse(JwtJose.verify(token, other))
        assertEquals("The signature does not match this key", JwtJose.check(token, other).reason)
    }

    @Test
    fun `a secret key verifies HMAC tokens only`() {
        val key = (JwtKeyRing().generate("oct", 256, null, null, null) as JwtKey.Jose).jwk as OctetSequenceKey
        val hs256: (ByteArray) -> ByteArray = { input -> Jwt.hmacBytes(input, key.toByteArray(), "HS256")!! }

        assertTrue(JwtJose.verify(forged("""{"alg":"HS256"}""", hs256), key))
        for (alg in listOf("RS256", "ES256", "EdDSA", "none", "hs256", "HS384")) {
            assertFalse(JwtJose.verify(forged("""{"alg":"$alg"}""", hs256), key), alg)
        }
    }

    @Test
    fun `tokens without a usable signature do not verify`() {
        val key = (JwtKeyRing().generate("OKP", null, "Ed25519", null, null) as JwtKey.Jose).jwk
        val signed = forged("""{"alg":"EdDSA"}""", ed25519((key as OctetKeyPair).decodedD))
        val (header, payload, signature) = signed.split('.')

        assertFalse(JwtJose.verify("$header.$payload.", key))
        assertFalse(JwtJose.verify("$header.$payload", key))
        assertFalse(JwtJose.verify("$header.$payload.***", key))
        assertFalse(JwtJose.verify("$header.$payload.$signature.extra", key))
        assertFalse(JwtJose.verify("not a token", key))
        assertFalse(JwtJose.verify("$header.${Jwt.b64UrlEncode("""{"sub":"someone else"}""")}.$signature", key))
        assertTrue(JwtJose.verify(" $signed\n", key))
    }

    @Test
    fun `short secrets and small RSA keys sign and verify`() {
        val ring = JwtKeyRing()
        val base = forged("""{"alg":"none","typ":"JWT"}""") { ByteArray(0) }

        // "secret" as a JWK: six bytes, far below what Nimbus' own HMAC signer accepts.
        val shortSecret = ring.import(null, """{"kty":"oct","k":"c2VjcmV0"}""", null).single() as JwtKey.Jose
        val signed = JwtJose.sign(base, shortSecret.jwk, null, null)
        assertEquals("HS256", Jwt.split(signed)!!.alg)
        assertTrue(JwtJose.verify(signed, shortSecret.jwk))
        assertEquals("secret", Jwt.crack(signed, listOf("nope", "secret")))

        val oct128 = ring.generate("oct", 128, null, null, null) as JwtKey.Jose
        assertTrue(JwtJose.verify(JwtJose.sign(base, oct128.jwk, "HS512", null), oct128.jwk))

        val rsa1024 = ring.generate("RSA", 1024, null, null, null) as JwtKey.Jose
        for (alg in listOf("RS256", "PS256")) {
            assertTrue(JwtJose.verify(JwtJose.sign(base, rsa1024.jwk, alg, null), rsa1024.jwk), alg)
        }
    }

    @Test
    fun `a key refuses to sign under an algorithm that is not its own`() {
        val ring = JwtKeyRing()
        val base = forged("""{"alg":"none"}""") { ByteArray(0) }
        val ec = (ring.generate("EC", null, "P-256", null, null) as JwtKey.Jose).jwk
        val ed = (ring.generate("OKP", null, "Ed25519", null, null) as JwtKey.Jose).jwk
        val oct = (ring.generate("oct", 256, null, null, null) as JwtKey.Jose).jwk

        for ((key, alg) in listOf(ec to "ES384", ec to "RS256", ed to "ES256", oct to "RS256", ec to "HS256")) {
            val failure = runCatching { JwtJose.sign(base, key, alg, null) }.exceptionOrNull()
            assertTrue(failure is IllegalArgumentException, "${key.keyType} with $alg: $failure")
            assertTrue(alg in failure.message!!, failure.message)
        }
        // Case alone is no reason to refuse.
        assertEquals("ES256", Jwt.split(JwtJose.sign(base, ec, "es256", null))!!.alg)
        assertEquals("EdDSA", Jwt.split(JwtJose.sign(base, ed, "eddsa", null))!!.alg)
    }

    @Test
    fun `verify says why each ring key does not match`() {
        val bridge = JwtBridge()
        bridge.keys(action = "generate", kty = "OKP", crv = "Ed25519", keyId = "ed")
        bridge.keys(action = "generate", kty = "EC", crv = "P-256", keyId = "ec")
        bridge.keys(action = "generate", kty = "OKP", crv = "X25519", keyId = "x")
        val exported = bridge.keys(action = "export", keyId = "ed", includePrivate = true)
        val d = Jwt.b64UrlDecode(exported["jwk"]!!.jsonObject["d"]!!.jsonPrimitive.content)

        fun rows(result: JsonObject): Map<String, JsonObject> =
            result["matches"]!!.jsonArray.associate { it.jsonObject["key_id"]!!.jsonPrimitive.content to it.jsonObject }

        val unsigned = bridge.attack(forged("""{"alg":"none"}""", ed25519(d)), "verify", null, null, null, null, null)
        assertEquals(false, unsigned["valid"]!!.jsonPrimitive.boolean)
        assertEquals(setOf("ed", "ec", "x"), rows(unsigned).keys)
        rows(unsigned).values.forEach { row ->
            assertEquals(false, row["valid"]!!.jsonPrimitive.boolean)
            assertTrue(row["reason"]!!.jsonPrimitive.content.isNotBlank())
        }
        assertTrue("none" in rows(unsigned).getValue("ed")["reason"]!!.jsonPrimitive.content)

        val real = bridge.attack(forged("""{"alg":"EdDSA"}""", ed25519(d)), "verify", null, null, null, null, null)
        assertEquals(true, real["valid"]!!.jsonPrimitive.boolean)
        assertEquals(true, rows(real).getValue("ed")["valid"]!!.jsonPrimitive.boolean)
        assertNull(rows(real).getValue("ed")["reason"])
        assertEquals(false, rows(real).getValue("ec")["valid"]!!.jsonPrimitive.boolean)

        val one = bridge.attack(forged("""{"alg":"EdDSA"}""", ed25519(d)), "verify", null, null, null, null, null, keyId = "ec")
        assertEquals(false, one["valid"]!!.jsonPrimitive.boolean)
        assertEquals(setOf("ec"), rows(one).keys)
    }
}
