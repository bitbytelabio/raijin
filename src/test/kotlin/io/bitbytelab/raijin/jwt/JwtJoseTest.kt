package io.bitbytelab.raijin.jwt

import io.bitbytelab.raijin.bridge.JwtBridge
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class JwtJoseTest {
    private val token =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
            ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" +
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

    @Test
    fun `RSA sign then verify`() {
        val ring = JwtKeyRing()
        val key = ring.generate("RSA", 2048, null, null, null) as JwtKey.Jose
        val signed = JwtJose.sign(token, key.jwk, "RS256", null)
        assertEquals("RS256", Jwt.decode(signed)!!.alg)
        assertTrue(JwtJose.verify(signed, key.jwk))
    }

    @Test
    fun `P-256 sign then verify`() {
        val ring = JwtKeyRing()
        val key = ring.generate("EC", null, "P-256", null, null) as JwtKey.Jose
        val signed = JwtJose.sign(token, key.jwk, null, buildJsonObject { put("sub", "admin") })
        assertEquals("ES256", Jwt.decode(signed)!!.alg)
        assertEquals("admin", Jwt.decode(signed)!!.payload["sub"]?.jsonPrimitive?.content)
        assertTrue(JwtJose.verify(signed, key.jwk))
    }

    @Test
    fun `Ed25519 sign then verify`() {
        val ring = JwtKeyRing()
        val key = ring.generate("OKP", null, "Ed25519", null, null) as JwtKey.Jose
        val signed = JwtJose.sign(token, key.jwk, "EdDSA", null)
        assertEquals("EdDSA", Jwt.decode(signed)!!.alg)
        assertTrue(JwtJose.verify(signed, key.jwk))
    }

    @Test
    fun `X25519 encrypt then decrypt`() {
        val ring = JwtKeyRing()
        val key = ring.generate("OKP", null, "X25519", null, null) as JwtKey.Jose
        val encrypted = JwtJose.encrypt("hello x", key.jwk, "ECDH-ES", "A256GCM")
        assertEquals("hello x", JwtJose.decrypt(encrypted, key.jwk))
    }

    @Test
    fun `RSA-OAEP-256 and A256GCM round-trip`() {
        val ring = JwtKeyRing()
        val key = ring.generate("RSA", 2048, null, null, null) as JwtKey.Jose
        val encrypted = JwtJose.encrypt("hello jwt", key.jwk, "RSA-OAEP-256", "A256GCM")
        assertEquals(5, encrypted.split('.').size)
        assertEquals("hello jwt", JwtJose.decrypt(encrypted, key.jwk))
    }

    @Test
    fun `PEM and JWK round-trip`() {
        val ring = JwtKeyRing()
        val key = ring.generate("RSA", 2048, null, null, "pem-1") as JwtKey.Jose
        val pem = key.exportPem(includePrivate = true)
        val jwk = key.exportJwk(includePrivate = true).toString()
        assertTrue(pem.contains("PRIVATE KEY"))
        ring.delete("pem-1")

        val fromPem = ring.import(pem, null, null).single() as JwtKey.Jose
        val signed = JwtJose.sign(token, fromPem.jwk, "RS256", null)
        assertTrue(JwtJose.verify(signed, fromPem.jwk))

        ring.delete(fromPem.id)
        val fromJwk = ring.import(null, jwk, null).single() as JwtKey.Jose
        assertTrue(JwtJose.verify(signed, fromJwk.jwk))
    }

    @Test
    fun `embed_jwk puts the public key in the header and verifies`() {
        val ring = JwtKeyRing()
        val key = ring.generate("EC", null, "P-256", null, null) as JwtKey.Jose
        val signed = JwtJose.embedJwk(token, key.jwk, null, null)
        val embedded = JwtJose.embeddedPublicJwk(signed)
        assertNotNull(embedded)
        val header = Jwt.decode(signed)!!.header["jwk"]!!.jsonObject
        assertEquals("EC", header["kty"]?.jsonPrimitive?.content)
        assertFalse(header.containsKey("d"))
        assertTrue(JwtJose.verify(signed, embedded))
    }

    @Test
    fun `empty_hmac matches an all-zero HMAC block and psychic is the zero ECDSA signature`() {
        val empty = JwtJose.emptyHmac(token, "HS256", null)
        val parts = Jwt.decode(empty)!!
        assertEquals("HS256", parts.alg)
        val expected = Jwt.hmac(parts.signingInput, ByteArray(64), "HS256")
        assertEquals(expected, parts.signature)

        val psychic = JwtJose.psychic(token, "ES256", null)
        val decoded = Jwt.decode(psychic)!!
        assertEquals("ES256", decoded.alg)
        assertEquals(
            byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00).toList(),
            Jwt.b64UrlDecode(decoded.signature).toList()
        )
    }

    @Test
    fun `list and default export omit private material`() {
        val saved = mutableListOf<String>()
        val bridge = JwtBridge(load = { null }, save = { saved += it })
        val generated = bridge.keys(action = "generate", kty = "EC", crv = "P-256")
        val id = generated["key_id"]!!.jsonPrimitive.content
        assertTrue(generated["public_jwk"]!!.jsonObject.containsKey("x"))
        assertFalse(generated["public_jwk"]!!.jsonObject.containsKey("d"))

        val listed = bridge.keys(action = "list")
        val row = listed["keys"]!!.jsonArray.first().jsonObject
        assertEquals(id, row["key_id"]?.jsonPrimitive?.content)
        assertFalse(row.containsKey("d"))

        val exported = bridge.keys(action = "export", keyId = id)
        assertFalse(exported["jwk"]!!.jsonObject.containsKey("d"))
        val privateExport = bridge.keys(action = "export", keyId = id, includePrivate = true)
        assertTrue(privateExport["jwk"]!!.jsonObject.containsKey("d"))
        assertTrue(saved.isNotEmpty())

        val restored = JwtBridge(load = { saved.last() }, save = null)
        val again = restored.keys(action = "list")
        assertEquals(id, again["keys"]!!.jsonArray.first().jsonObject["key_id"]?.jsonPrimitive?.content)
    }

    @Test
    fun `forge_none output is unchanged`() {
        val forged = Jwt.forgeNone(token)
        assertTrue(forged.all { it.endsWith(".") })
        assertNull(Jwt.decode("not a jwt"))
    }
}
