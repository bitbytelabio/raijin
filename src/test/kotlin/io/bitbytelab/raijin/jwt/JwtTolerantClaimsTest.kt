package io.bitbytelab.raijin.jwt

import io.bitbytelab.raijin.bridge.JwtBridge
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Tokens under test rarely look like the RFC: claims repeat, `exp` is a string, the payload is an
 * array or not JSON at all. Every signing mode has to hand such a payload back byte for byte, and
 * change only the claims it was asked to change.
 */
class JwtTolerantClaimsTest {
    private val header = """{"alg":"HS256","typ":"JWT"}"""

    /** A repeated `exp` (one copy a string), a mixed-type `aud`, a float `iat`, odd spacing, escaped slashes. */
    private val oddClaims =
        """{"sub":"u", "exp":"1700000000","exp":1700000001 ,"aud":[1,{"x":null}],"iat":1.5e9,"iss":"https:\/\/issuer\/a"}"""

    private val payloads: Map<String, ByteArray> = linkedMapOf(
        "odd claims" to oddClaims.toByteArray(),
        "claims a strict claims parser rejects" to
            """{"exp":"soon","aud":5,"iat":[1],"sub":{"a":1},"iss":7,"nbf":true}""".toByteArray(),
        "array" to "[1,2,3]".toByteArray(),
        "string" to "\"just a string\"".toByteArray(),
        "plain text" to "not json at all".toByteArray(),
        "binary" to byteArrayOf(0x00, 0xff.toByte(), 0xfe.toByte(), 0x7b),
        "empty" to ByteArray(0),
    )

    private val ring = JwtKeyRing()
    private val ec = (ring.generate("EC", null, "P-256", null, "ec-1") as JwtKey.Jose).jwk
    private val ed = (ring.generate("OKP", null, "Ed25519", null, "ed-1") as JwtKey.Jose).jwk
    private val oct = (ring.generate("oct", 256, null, null, "oct-1") as JwtKey.Jose).jwk

    /** An HS256 token over exactly these header and payload bytes. */
    private fun token(headerJson: String, payload: ByteArray, secret: String = "secret"): String {
        val input = "${Jwt.b64UrlEncode(headerJson)}.${Jwt.b64UrlEncode(payload)}"
        return "$input.${Jwt.hmac(input, secret.toByteArray(), "HS256")}"
    }

    private fun payloadOf(token: String): String = token.split('.')[1]

    private fun text(segment: String): String = String(Jwt.b64UrlDecode(segment), Charsets.UTF_8)

    @Test
    fun `every signing mode keeps an odd payload byte for byte`() {
        for ((name, payload) in payloads) {
            val original = token(header, payload)
            val segment = Jwt.b64UrlEncode(payload)

            val hmac = Jwt.resign(original, "newsecret", "HS512")!!
            assertEquals(segment, payloadOf(hmac), name)
            assertEquals("newsecret", Jwt.crack(hmac, listOf("x", "newsecret")), name)

            for (key in listOf(ec, ed, oct)) {
                val signed = JwtJose.sign(original, key, null, null)
                assertEquals(segment, payloadOf(signed), "$name, ${key.keyType} key")
                assertTrue(JwtJose.verify(signed, key), "$name, ${key.keyType} key")
            }
            assertEquals(segment, payloadOf(JwtJose.embedJwk(original, ec, null, null)), name)
            assertEquals(segment, payloadOf(JwtJose.emptyHmac(original, null, null)), name)
            assertEquals(segment, payloadOf(JwtJose.psychic(original, null, null)), name)
            assertEquals(segment, payloadOf(JwtJose.headerUrl(original, "jku", "https://a.example/k", null)), name)
            val hosted = JwtJose.headerUrlSigned(original, ec, "jku", "https://a.example/k", null, null)
            assertEquals(segment, payloadOf(hosted.token), name)
            Jwt.forgeNone(original).forEach { assertEquals(segment, payloadOf(it), name) }
        }
    }

    @Test
    fun `overrides are written into the payload text in place`() {
        val original = token(header, oddClaims.toByteArray())
        val overrides = buildJsonObject { put("exp", 5); put("role", "admin") }
        // Both copies of exp get the value, role goes last, and nothing else moves.
        val expected =
            """{"sub":"u", "exp":5,"exp":5 ,"aud":[1,{"x":null}],"iat":1.5e9,"iss":"https:\/\/issuer\/a","role":"admin"}"""

        val signed = JwtJose.sign(original, ec, null, overrides)
        assertEquals(expected, text(payloadOf(signed)))
        assertTrue(JwtJose.verify(signed, ec))

        val hmac = Jwt.resign(original, "s", "HS256", overrides)!!
        assertEquals(expected, text(payloadOf(hmac)))
        Jwt.forgeNone(original, overrides).forEach { assertEquals(expected, text(payloadOf(it))) }
        assertEquals(expected, text(payloadOf(JwtJose.psychic(original, null, overrides))))
    }

    @Test
    fun `overrides need a JSON object payload and say so`() {
        val overrides = buildJsonObject { put("sub", "admin") }
        for (name in listOf("array", "string", "plain text", "binary", "empty")) {
            val payload = payloads.getValue(name)
            val original = token(header, payload)
            assertFailsWith<IllegalArgumentException>(name) { JwtJose.sign(original, ec, null, overrides) }
            assertFailsWith<IllegalArgumentException>(name) { Jwt.resign(original, "s", "HS256", overrides) }
            assertFailsWith<IllegalArgumentException>(name) { Jwt.forgeNone(original, overrides) }
            // No claim to write: the payload is signed as it is.
            val untouched = JwtJose.sign(original, ec, null, JsonObject(emptyMap()))
            assertEquals(Jwt.b64UrlEncode(payload), payloadOf(untouched), name)
        }

        val refused = JwtBridge().attack(token(header, "[1,2,3]".toByteArray()), "sign", "s", null, null, overrides, null)
        assertTrue(refused["error"]!!.jsonPrimitive.content.contains("payload_overrides"), refused.toString())
    }

    @Test
    fun `signing keeps the header and only sets alg and kid`() {
        val oddHeader = """{"typ":"JWT", "alg":"HS256","kid":7,"x":{"y":[1]},"crit":["x"]}"""
        val original = token(oddHeader, oddClaims.toByteArray())

        val signed = JwtJose.sign(original, ec, null, null)
        assertEquals(
            """{"typ":"JWT", "alg":"ES256","kid":"ec-1","x":{"y":[1]},"crit":["x"]}""",
            text(signed.split('.')[0])
        )
        assertTrue(JwtJose.verify(signed, ec))

        val hmac = Jwt.resign(original, "s", "HS512")!!
        assertEquals("""{"typ":"JWT", "alg":"HS512","kid":7,"x":{"y":[1]},"crit":["x"]}""", text(hmac.split('.')[0]))
    }

    @Test
    fun `segments that are padded base64 are signed as they were sent`() {
        val padded = Base64.getUrlEncoder()
        val headerSegment = padded.encodeToString("""{"alg":"HS256","t":10}""".toByteArray())
        val payloadSegment = padded.encodeToString("""{"sub":"u"}""".toByteArray())
        assertTrue(headerSegment.endsWith("=") && payloadSegment.endsWith("="))
        val signingInput = "$headerSegment.$payloadSegment"
        val original = "$signingInput.${Jwt.hmac(signingInput, "s".toByteArray(), "HS256")}"

        // Same alg, same secret, no overrides: nothing in the signing input changes.
        assertEquals(original, Jwt.resign(original, "s", "HS256"))
        // A ring key changes the header. The payload segment still is the one that was sent.
        val signed = JwtJose.sign(original, ec, null, null)
        assertEquals(payloadSegment, payloadOf(signed))
        assertTrue(JwtJose.verify(signed, ec))
    }

    @Test
    fun `an unsigned token can be signed with a ring key`() {
        val unsigned = Jwt.forgeNone(token(header, oddClaims.toByteArray())).first()
        val signed = JwtJose.sign(unsigned, ed, null, null)
        assertEquals("EdDSA", Jwt.split(signed)!!.alg)
        assertEquals(payloadOf(unsigned), payloadOf(signed))
        assertTrue(JwtJose.verify(signed, ed))
    }

    @Test
    fun `crack works whatever the payload holds`() {
        for ((name, payload) in payloads) {
            assertEquals("letmein", Jwt.crack(token(header, payload, "letmein"), listOf("nope", "letmein")), name)
        }
        val bridge = JwtBridge()
        val cracked = bridge.attack(token(header, "[1,2,3]".toByteArray(), "letmein"), "crack", null, null, null, null, null)
        assertEquals(true, cracked["cracked"]!!.jsonPrimitive.boolean)
        assertEquals("letmein", cracked["secret"]!!.jsonPrimitive.content)

        // Nothing to crack on a token that is not HMAC-signed, and that is an error, not "no match".
        val asymmetric = JwtJose.sign(token(header, oddClaims.toByteArray()), ec, null, null)
        val refused = bridge.attack(asymmetric, "crack", null, null, null, null, null)
        assertTrue(refused["error"]!!.jsonPrimitive.content.contains("ES256"), refused.toString())
    }

    @Test
    fun `analyze reads odd claims instead of failing on them`() {
        fun ids(payload: String, headerJson: String = header): List<String> =
            Jwt.analyze(token(headerJson, payload.toByteArray())).map { it.id }

        // The copy of exp a last-wins parser reads is a number in the past.
        assertEquals(listOf("alg_hmac", "duplicate_claims", "expired"), ids(oddClaims))
        assertEquals(listOf("alg_hmac", "exp_malformed", "expired"), ids("""{"exp":"1700000000"}"""))
        assertEquals(listOf("alg_hmac", "exp_malformed"), ids("""{"exp":[1700000000]}"""))
        assertEquals(listOf("alg_hmac", "exp_malformed"), ids("""{"exp":true}"""))
        assertEquals(listOf("alg_hmac", "expired"), ids("""{"exp":1.7e9}"""))
        assertEquals(listOf("alg_hmac"), ids("""{"exp":4102444800}"""))
        assertEquals(listOf("alg_hmac", "no_exp"), ids("""{"exp":null}"""))
        assertEquals(listOf("alg_hmac", "payload_not_object"), ids("[1,2,3]"))
        assertEquals(listOf("alg_hmac", "payload_not_object"), ids("not json"))
        // An alg that is not text names no algorithm, and is no reason to fail either.
        assertEquals(listOf("kid_present", "no_exp"), ids("{}", """{"alg":["HS256"],"kid":{"a":1}}"""))
        assertEquals(
            listOf("alg_hmac", "duplicate_header", "no_exp"),
            ids("{}", """{"alg":"none","alg":"HS256"}""")
        )
    }

    @Test
    fun `analyze shows what the payload really holds`() {
        val bridge = JwtBridge()
        fun analyze(payload: ByteArray, headerJson: String = header): JsonObject =
            bridge.attack(token(headerJson, payload), "analyze", null, null, null, null, null)

        val odd = analyze(oddClaims.toByteArray())
        assertNull(odd["error"])
        assertEquals("HS256", odd["alg"]!!.jsonPrimitive.content)
        assertEquals("1700000001", odd["payload"]!!.jsonObject["exp"]!!.jsonPrimitive.content)
        assertEquals(oddClaims, odd["payload_raw"]!!.jsonPrimitive.content)

        // A plain token needs no raw copy: the parsed view already says everything.
        val plain = analyze("""{"sub":"u"}""".toByteArray())
        assertNull(plain["payload_raw"])
        assertNull(plain["header_raw"])

        assertTrue(analyze("[1,2,3]".toByteArray())["payload"] is JsonArray)
        assertEquals("not json at all", analyze("not json at all".toByteArray())["payload"]!!.jsonPrimitive.content)
        val binary = analyze(payloads.getValue("binary"))
        assertNull(binary["payload"])
        assertEquals(4, binary["payload_bytes"]!!.jsonPrimitive.int)

        // A nested token is one bare word to a lenient JSON parser. It is text, and the result stays valid JSON.
        val nested = token(header, """{"sub":"inner"}""".toByteArray())
        val outer = analyze(nested.toByteArray())
        assertEquals(nested, outer["payload"]!!.jsonPrimitive.content)
        assertTrue(outer["payload"]!!.jsonPrimitive.isString)

        // Bare words inside the claims are quoted in the view and shown as sent in payload_raw.
        val sloppy = analyze("""{"admin":True,"n":NaN,"ok":true}""".toByteArray())
        assertEquals(sloppy, Json.parseToJsonElement(sloppy.toString()))
        assertTrue(sloppy["payload"]!!.jsonObject["admin"]!!.jsonPrimitive.isString)
        assertFalse(sloppy["payload"]!!.jsonObject["ok"]!!.jsonPrimitive.isString)
        assertEquals("""{"admin":True,"n":NaN,"ok":true}""", sloppy["payload_raw"]!!.jsonPrimitive.content)

        val repeatedAlg = """{"alg":"none","alg":"HS256"}"""
        assertEquals(repeatedAlg, analyze("{}".toByteArray(), repeatedAlg)["header_raw"]!!.jsonPrimitive.content)
    }
}
