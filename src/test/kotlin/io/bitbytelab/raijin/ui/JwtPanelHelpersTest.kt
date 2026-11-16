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
}
