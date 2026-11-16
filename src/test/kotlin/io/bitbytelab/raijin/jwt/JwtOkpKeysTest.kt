package io.bitbytelab.raijin.jwt

import com.nimbusds.jose.jwk.OctetKeyPair
import io.bitbytelab.raijin.bridge.JwtBridge
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.security.KeyFactory
import java.security.interfaces.EdECPrivateKey
import java.security.interfaces.XECPrivateKey
import java.security.spec.NamedParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Every operation the ring offers on an OKP key either works or says plainly why it cannot: an
 * X448 or X25519 key encrypts and decrypts, an Ed25519 or Ed448 key signs, and all four export.
 */
class JwtOkpKeysTest {
    private val token =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
            ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" +
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

    private fun der(pem: String): ByteArray =
        Base64.getMimeDecoder().decode(pem.lineSequence().filterNot { it.startsWith("-----") }.joinToString(""))

    private fun run(bridge: JwtBridge, input: String, mode: String, keyId: String?, alg: String? = null, enc: String? = null, url: String? = null): JsonObject =
        bridge.attack(input, mode, null, null, null, null, alg, keyId = keyId, enc = enc, url = url)

    @Test
    fun `an X448 key encrypts and decrypts with every ECDH-ES variant`() {
        val key = (JwtKeyRing().generate("OKP", null, "X448", null, null) as JwtKey.Jose).jwk
        val plaintext = "{\"role\":\"admin\"}"
        val algs = listOf(null, "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW")
        val encs = listOf(null, "A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512")
        for (alg in algs) for (enc in encs) {
            val jwe = JwtJose.encrypt(plaintext, key, alg, enc)
            assertEquals(5, jwe.split('.').size, "$alg / $enc")
            assertEquals(plaintext, JwtJose.decrypt(jwe, key), "$alg / $enc")
        }
    }

    @Test
    fun `X448 encryption needs only the public key and decryption the matching private one`() {
        val ring = JwtKeyRing()
        val key = (ring.generate("OKP", null, "X448", null, null) as JwtKey.Jose).jwk as OctetKeyPair
        val other = (ring.generate("OKP", null, "X448", null, null) as JwtKey.Jose).jwk
        val public = key.toPublicJWK()

        val jwe = JwtJose.encrypt("for one reader", public, "ECDH-ES+A256KW", "A256GCM")
        assertEquals("for one reader", JwtJose.decrypt(jwe, key))
        assertFailsWith<Exception> { JwtJose.decrypt(jwe, public) }
        assertFailsWith<Exception> { JwtJose.decrypt(jwe, other) }
    }

    @Test
    fun `the ring says what an X448 key can do and refuses the rest in plain words`() {
        val bridge = JwtBridge()
        val generated = bridge.keys(action = "generate", kty = "OKP", crv = "X448", keyId = "x")
        assertNull(generated["error"])
        assertEquals("X448", generated["crv"]!!.jsonPrimitive.content)
        val modes = listOf("alg_confusion", "encrypt", "decrypt")
        assertEquals(modes, generated["modes"]!!.jsonArray.map { it.jsonPrimitive.content })
        val listed = bridge.keys(action = "list")["keys"]!!.jsonArray.single().jsonObject
        assertEquals(modes, listed["modes"]!!.jsonArray.map { it.jsonPrimitive.content })

        // What it offers works, through the same calls the tool makes.
        val jwe = run(bridge, "{\"role\":\"admin\"}", "encrypt", "x")["token"]!!.jsonPrimitive.content
        assertEquals("{\"role\":\"admin\"}", run(bridge, jwe, "decrypt", "x")["plaintext"]!!.jsonPrimitive.content)
        val wrapped = run(bridge, "wrapped", "encrypt", "x", alg = "ecdh-es+a128kw", enc = "A128CBC-HS256")["token"]!!.jsonPrimitive.content
        assertEquals("wrapped", run(bridge, wrapped, "decrypt", "x")["plaintext"]!!.jsonPrimitive.content)
        val pem = bridge.keys(action = "export", keyId = "x", format = "pem")["pem"]!!.jsonPrimitive.content
        assertEquals(Jwt.resign(token, pem, "HS256"), run(bridge, token, "alg_confusion", "x")["token"]!!.jsonPrimitive.content)

        // What it cannot do names the reason instead of a library's internal message.
        for (mode in listOf("sign_key", "embed_jwk", "header_url")) {
            val refused = run(bridge, token, mode, "x", url = "https://a.example/jwks.json")
            assertTrue("cannot sign" in refused["error"]!!.jsonPrimitive.content, "$mode: $refused")
        }
        val explicit = run(bridge, token, "sign_key", "x", alg = "EdDSA")
        assertTrue("cannot sign" in explicit["error"]!!.jsonPrimitive.content, explicit.toString())
        val verified = run(bridge, token, "verify", "x")
        assertEquals(false, verified["valid"]!!.jsonPrimitive.boolean)
        val reason = verified["matches"]!!.jsonArray.single().jsonObject["reason"]!!.jsonPrimitive.content
        assertTrue("cannot sign or verify" in reason, reason)
    }

    @Test
    fun `key modes follow what each key type can do`() {
        val ring = JwtKeyRing()
        val signing = listOf("sign_key", "verify", "embed_jwk", "header_url", "alg_confusion")
        assertEquals(signing, ring.generate("OKP", null, "Ed25519", null, null).modes)
        assertEquals(signing, ring.generate("OKP", null, "Ed448", null, null).modes)
        assertEquals(listOf("alg_confusion", "encrypt", "decrypt"), ring.generate("OKP", null, "X25519", null, null).modes)
        assertEquals(signing + listOf("encrypt", "decrypt"), ring.generate("EC", null, "P-256", null, null).modes)
        assertEquals(signing, ring.generate("EC", null, "secp256k1", null, null).modes)
        assertEquals(listOf("sign_key", "verify", "encrypt", "decrypt"), ring.generate("oct", 256, null, null, null).modes)
        assertEquals(listOf("encrypt", "decrypt"), ring.generate("password", null, null, null, null).modes)

        // A public key verifies and encrypts; it does not sign or decrypt.
        val ec = ring.generate("EC", null, "P-384", null, null) as JwtKey.Jose
        val publicOnly = JwtKeyRing().import(null, ec.exportJwk(includePrivate = false).toString(), null).single()
        assertEquals(listOf("verify", "alg_confusion", "encrypt"), publicOnly.modes)
    }

    @Test
    fun `OKP keys export as PEM the JDK reads back`() {
        val bridge = JwtBridge()
        for (crv in listOf("X448", "X25519", "Ed25519", "Ed448")) {
            bridge.keys(action = "generate", kty = "OKP", crv = crv, keyId = crv)
            val jwk = bridge.keys(action = "export", keyId = crv, includePrivate = true)["jwk"]!!.jsonObject
            val x = Jwt.b64UrlDecode(jwk["x"]!!.jsonPrimitive.content)
            val d = Jwt.b64UrlDecode(jwk["d"]!!.jsonPrimitive.content)
            val jdkAlgorithm = if (crv.startsWith("X")) "XDH" else "EdDSA"

            val publicPem = bridge.keys(action = "export", keyId = crv, format = "pem")["pem"]!!.jsonPrimitive.content
            assertTrue(publicPem.startsWith("-----BEGIN PUBLIC KEY-----\n"), publicPem)
            val publicDer = der(publicPem)
            KeyFactory.getInstance(jdkAlgorithm).generatePublic(X509EncodedKeySpec(publicDer))
            assertContentEquals(x, publicDer.copyOfRange(publicDer.size - x.size, publicDer.size), crv)

            val privatePem = bridge.keys(action = "export", keyId = crv, format = "pem", includePrivate = true)["pem"]!!
                .jsonPrimitive.content
            assertTrue(privatePem.startsWith("-----BEGIN PRIVATE KEY-----\n"), privatePem)
            val privateKey = KeyFactory.getInstance(jdkAlgorithm).generatePrivate(PKCS8EncodedKeySpec(der(privatePem)))
            val (curve, raw) = when (privateKey) {
                is XECPrivateKey -> (privateKey.params as NamedParameterSpec).name to privateKey.scalar.get()
                is EdECPrivateKey -> privateKey.params.name to privateKey.bytes.get()
                else -> error("unexpected key class ${privateKey.javaClass}")
            }
            assertEquals(crv, curve)
            assertContentEquals(d, raw, crv)
        }
    }

    @Test
    fun `a key's stored encryption alg is not taken for its signing alg`() {
        val ring = JwtKeyRing()
        val encryptionKey = ring.generate("RSA", 2048, null, "RSA-OAEP-256", null) as JwtKey.Jose
        val signed = JwtJose.sign(token, encryptionKey.jwk, null, null)
        assertEquals("RS256", Jwt.split(signed)!!.alg)
        assertTrue(JwtJose.verify(signed, encryptionKey.jwk))

        val pssKey = ring.generate("RSA", 2048, null, "PS384", null) as JwtKey.Jose
        assertEquals("PS384", Jwt.split(JwtJose.sign(token, pssKey.jwk, null, null))!!.alg)
    }
}
