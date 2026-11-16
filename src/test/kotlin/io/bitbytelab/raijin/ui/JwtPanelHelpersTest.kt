package io.bitbytelab.raijin.ui

import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class JwtPanelHelpersTest {

    @Test
    fun `blank overrides mean none`() {
        assertEquals(OverridesInput.Empty, parseOverrides(null))
        assertEquals(OverridesInput.Empty, parseOverrides("   "))
    }

    @Test
    fun `a JSON object is accepted`() {
        val parsed = assertIs<OverridesInput.Ok>(parseOverrides(""" {"sub":"admin","admin":true} """))
        assertEquals(JsonPrimitive("admin"), parsed.claims["sub"])
    }

    @Test
    fun `malformed JSON is reported instead of silently ignored`() {
        val parsed = assertIs<OverridesInput.Invalid>(parseOverrides("""{"sub":"admin""""))
        assertTrue(parsed.message.startsWith("payload_overrides is not valid JSON"), parsed.message)
        assertTrue('\n' !in parsed.message)
    }

    @Test
    fun `valid JSON that is not an object names what it got`() {
        assertTrue(assertIs<OverridesInput.Invalid>(parseOverrides("""["sub"]""")).message.endsWith("not an array"))
        assertTrue(assertIs<OverridesInput.Invalid>(parseOverrides("\"admin\"")).message.endsWith("not a string"))
        assertTrue(assertIs<OverridesInput.Invalid>(parseOverrides("42")).message.endsWith("not a number or boolean"))
        assertTrue(assertIs<OverridesInput.Invalid>(parseOverrides("null")).message.endsWith("not null"))
    }

    @Test
    fun `copy finds the token, every forge_none variant, and a nested decrypted token`() {
        assertEquals(listOf("a.b.c"), copyableTokens(buildJsonObject { put("token", "a.b.c") }))
        val variants = buildJsonObject {
            put("variants", buildJsonArray { add("h1.p."); add("h2.p.") })
            put("note", "send each")
        }
        assertEquals(listOf("h1.p.", "h2.p."), copyableTokens(variants))
        assertEquals(listOf("x.y.z"), copyableTokens(buildJsonObject { put("plaintext", "x.y.z") }))
        assertEquals(listOf("a.b.c.d.e"), copyableTokens(buildJsonObject { put("plaintext", " a.b.c.d.e ") }))
    }

    @Test
    fun `nothing to copy from errors or plain text`() {
        assertEquals(emptyList(), copyableTokens(buildJsonObject { put("error", "bad") }))
        assertEquals(emptyList(), copyableTokens(buildJsonObject { put("plaintext", "hello world. again.") }))
        assertEquals(emptyList(), copyableTokens(buildJsonObject { put("cracked", false) }))
    }

    @Test
    fun `ring ids come from the list result in order`() {
        val listed = buildJsonObject {
            put("keys", buildJsonArray {
                add(buildJsonObject { put("key_id", "rsa-1"); put("kty", "RSA") })
                add(buildJsonObject { put("kty", "EC") })
                add(buildJsonObject { put("key_id", "pw") })
            })
        }
        assertEquals(listOf("rsa-1", "pw"), ringKeyIds(listed))
        assertEquals(emptyList(), ringKeyIds(buildJsonObject { put("error", "x") }))
    }

    @Test
    fun `key modes come from the list result by key id`() {
        val listed = buildJsonObject {
            put("keys", buildJsonArray {
                add(buildJsonObject {
                    put("key_id", "rsa-1")
                    put("modes", buildJsonArray { add("sign_key"); add("header_url"); add("encrypt") })
                })
                add(buildJsonObject { put("key_id", "old") })
                add(buildJsonObject { put("modes", buildJsonArray { add("verify") }) })
            })
        }
        assertEquals(mapOf("rsa-1" to listOf("sign_key", "header_url", "encrypt"), "old" to emptyList()), ringKeyModes(listed))
    }

    @Test
    fun `a key that cannot run a mode blocks it and says what it can do`() {
        val modes = mapOf("x448" to listOf("encrypt", "decrypt"), "hmac" to listOf("sign_key", "verify"), "none" to emptyList())
        assertEquals(null, keyModeBlocker("encrypt", "x448", modes, keyOptional = false))
        assertEquals("Key 'x448' cannot run sign_key (it supports: encrypt, decrypt)", keyModeBlocker("sign_key", "x448", modes, keyOptional = false))
        assertEquals("Key 'hmac' cannot run header_url (it supports: sign_key, verify)", keyModeBlocker("header_url", "hmac", modes, keyOptional = true))
        assertEquals("Key 'none' cannot run decrypt (it supports: no jwt_attack mode)", keyModeBlocker("decrypt", "none", modes, keyOptional = false))
    }

    @Test
    fun `no key passes only where the mode works without one, and an unlisted key is left to the bridge`() {
        assertEquals(null, keyModeBlocker("header_url", "", emptyMap(), keyOptional = true))
        assertEquals(null, keyModeBlocker("alg_confusion", null, emptyMap(), keyOptional = true))
        assertEquals("Pick a key ring id first", keyModeBlocker("embed_jwk", " ", emptyMap(), keyOptional = false))
        assertEquals(null, keyModeBlocker("embed_jwk", "added-elsewhere", mapOf("other" to listOf("verify")), keyOptional = false))
    }

    @Test
    fun `a signed header_url result carries the document to host`() {
        val jwks = """{"keys":[{"kty":"RSA","e":"AQAB","n":"abc"}]}"""
        val result = buildJsonObject {
            put("token", "h.p.s")
            put("host", buildJsonObject {
                put("url", "https://attacker.example/jwks.json")
                put("content_type", "application/json")
                put("body", jwks)
            })
        }
        assertEquals(HostedDocument("https://attacker.example/jwks.json", "application/json", jwks), hostedDocument(result))
        val pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
        val x5u = buildJsonObject { put("host", buildJsonObject { put("url", "u"); put("body", pem) }) }
        assertEquals(HostedDocument("u", "", pem), hostedDocument(x5u))
    }

    @Test
    fun `results without a host document show none`() {
        assertEquals(null, hostedDocument(buildJsonObject { put("token", "h.p.s"); put("note", "unsigned") }))
        assertEquals(null, hostedDocument(buildJsonObject { put("host", buildJsonObject { put("url", "u") }) }))
        assertEquals(null, hostedDocument(buildJsonObject { put("host", "not an object") }))
    }
}
