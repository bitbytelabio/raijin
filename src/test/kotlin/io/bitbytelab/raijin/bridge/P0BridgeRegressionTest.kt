package io.bitbytelab.raijin.bridge

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.bitbytelab.raijin.jwt.JwtJose
import io.bitbytelab.raijin.jwt.JwtKey
import io.bitbytelab.raijin.jwt.JwtKeyRing
import io.bitbytelab.raijin.safety.RequestHygiene
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonPrimitive
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class P0BridgeRegressionTest {

    @Test
    fun `FindingsBridge rejects NaN and non-finite CVSS scores and synchronizes add and remove`() {
        val state = StateManager()
        val bridge = FindingsBridge(state)

        val nanRes = bridge.add("xss", "high", "https://ex.com/a", "q", "reflected", "ev", cvssScore = "NaN")
        assertTrue(nanRes["error"] != null, nanRes.toString())

        val infRes = bridge.add("xss", "high", "https://ex.com/a", "q", "reflected", "ev", cvssScore = "Infinity")
        assertTrue(infRes["error"] != null, infRes.toString())

        val pool = Executors.newFixedThreadPool(4)
        val latch = CountDownLatch(20)
        repeat(20) { i ->
            pool.submit {
                try {
                    bridge.add("sqli", "high", "https://ex.com/item?id=$i", "id", "dup check", "ev")
                    bridge.add("sqli", "high", "https://ex.com/item?id=$i", "id", "dup check", "ev")
                } finally {
                    latch.countDown()
                }
            }
        }
        latch.await()
        pool.shutdownNow()
        assertEquals(20, state.findings.size)
    }

    @Test
    fun `UtilitiesBridge decodeSmartPure sets fully_decoded accurately at cap`() {
        var encoded = "secret"
        repeat(25) {
            encoded = Base64.getEncoder().encodeToString(encoded.toByteArray(Charsets.UTF_8))
        }
        val exactAtCap = UtilitiesBridge.decodeSmartPure(encoded, maxDepth = 25)
        assertEquals(true, exactAtCap["fully_decoded"]?.jsonPrimitive?.boolean)

        val oneMore = Base64.getEncoder().encodeToString(encoded.toByteArray(Charsets.UTF_8))
        val hitCap = UtilitiesBridge.decodeSmartPure(oneMore, maxDepth = 25)
        assertEquals(false, hitCap["fully_decoded"]?.jsonPrimitive?.boolean)
    }

    @Test
    fun `RequestHygiene normalizeCrlf preserves LF and escaped n inside body and fixContentLength respects smuggling`() {
        val reqWithEscapedBody = "POST /api HTTP/1.1\nHost: x.com\nContent-Type: application/json\n\n{\"msg\":\"line1\\nline2\"}"
        val normalized = RequestHygiene.normalizeCrlf(reqWithEscapedBody)
        assertTrue(normalized.startsWith("POST /api HTTP/1.1\r\nHost: x.com\r\nContent-Type: application/json\r\n\r\n"))
        assertTrue(normalized.endsWith("{\"msg\":\"line1\\nline2\"}"))

        // Desync CL.TE request must NOT have Content-Length rewritten
        val clTe = "POST / HTTP/1.1\r\nHost: x.com\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n\r\n"
        assertEquals(clTe, RequestHygiene.fixContentLength(clTe).request)

        // Duplicate CL.CL must NOT be rewritten
        val clCl = "POST / HTTP/1.1\r\nHost: x.com\r\nContent-Length: 4\r\nContent-Length: 100\r\n\r\nabcd"
        assertEquals(clCl, RequestHygiene.fixContentLength(clCl).request)

        // Normal request updates mismatched Content-Length
        val normal = "POST / HTTP/1.1\r\nHost: x.com\r\nContent-Length: 1\r\n\r\n{\"a\":\"hello\"}"
        val fixed = RequestHygiene.fixContentLength(normal, utf8Body = true)
        assertEquals(13, fixed.rewrittenTo)
        assertTrue(fixed.request.contains("Content-Length: 13\r\n"))
    }

    @Test
    fun `AuthDiffVerdict does not mark shared 403 or redirect to login as unauth_accessible`() {
        val all403 = listOf(
            AuthDiffVerdict.LevelResult("high", 403, "forbidden"),
            AuthDiffVerdict.LevelResult("low", 403, "forbidden"),
            AuthDiffVerdict.LevelResult("anonymous", 403, "forbidden")
        )
        val findings403 = AuthDiffVerdict.assess(all403, similarity = { _, _ -> 100.0 }, url = "https://ex.com/admin")
        assertTrue(findings403.none { it.id == "unauth_accessible" }, findings403.toString())
        val ident403 = findings403.firstOrNull { it.id == "all_identical_non_success" }
        assertNotNull(ident403, findings403.toString())
        assertEquals("info", ident403.severity)

        val high302Login = listOf(
            AuthDiffVerdict.LevelResult("high", 302, "", location = "https://ex.com/login"),
            AuthDiffVerdict.LevelResult("anonymous", 302, "", location = "/auth/signin")
        )
        val findings302 = AuthDiffVerdict.assess(high302Login, similarity = { _, _ -> 100.0 }, url = "https://ex.com/dashboard")
        assertTrue(findings302.none { it.id == "unauth_accessible" }, findings302.toString())
        val ident302 = findings302.firstOrNull { it.id == "all_identical_non_success" }
        assertNotNull(ident302, findings302.toString())
        assertEquals("info", ident302.severity)
    }

    @Test
    fun `InjectionBridge preparePayloadRequest escapes JSON strings and URL request line while updating Content-Length`() {
        val jsonReq = "POST /api/login HTTP/1.1\r\nHost: ex.com\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n{\"user\":\"FUZZ\"}"
        val injectedJson = InjectionBridge.preparePayloadRequest(jsonReq, "' OR \"1\"=\"1")
        assertTrue(injectedJson.contains("""{"user":"' OR \"1\"=\"1"}"""), injectedJson)
        assertTrue(injectedJson.contains("Content-Length: 25\r\n"), injectedJson)

        val getReq = "GET /search?q=FUZZ HTTP/1.1\r\nHost: ex.com\r\n\r\n"
        val injectedGet = InjectionBridge.preparePayloadRequest(getReq, "a b&c#1")
        assertTrue(injectedGet.startsWith("GET /search?q=a%20b%26c%231 HTTP/1.1\r\n"), injectedGet)
    }

    @Test
    fun `JwtJose verify rejects non-EdDSA token on Ed25519 key and X448 encrypt-decrypt round-trips`() {
        val ring = JwtKeyRing()
        val edKey = (ring.generate(kty = "OKP", size = null, crv = "Ed25519", alg = "EdDSA", id = "ed-1") as JwtKey.Jose).jwk
        val hsJwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.HS256).keyID("ed-1").build(),
            JWTClaimsSet.Builder().subject("admin").build()
        )
        hsJwt.sign(MACSigner(ByteArray(32) { 1 }))
        assertFalse(JwtJose.verify(hsJwt.serialize(), edKey))

        val x448Key = (ring.generate(kty = "OKP", size = null, crv = "X448", alg = "ECDH-ES", id = "x448-1") as JwtKey.Jose).jwk
        val encrypted = JwtJose.encrypt("{\"role\":\"admin\"}", x448Key, "ECDH-ES", "A256GCM")
        val decrypted = JwtJose.decrypt(encrypted, x448Key)
        assertEquals("{\"role\":\"admin\"}", decrypted)
    }

    @Test
    fun `SafeRegex validate replace and single-pass find handle edge cases safely`() {
        assertNotNull(SafeRegex.validate("[unclosed"))
        assertNull(SafeRegex.validate("token=[a-z0-9]+"))

        val replaced = SafeRegex.replace(pattern = "world", input = "hello world", replacement = "\$10 \$foo")
        assertEquals("hello world", replaced)

        val match = SafeRegex.find("(abc)-(\\d+)", "prefix abc-42 suffix")
        assertNotNull(match)
        assertEquals("abc", match.groupValues[1])
        assertEquals("42", match.groupValues[2])
    }
}
