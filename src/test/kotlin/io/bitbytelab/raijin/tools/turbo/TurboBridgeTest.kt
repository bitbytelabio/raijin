package io.bitbytelab.raijin.tools.turbo

import io.bitbytelab.raijin.bridge.TurboBridge
import io.bitbytelab.raijin.turbo.TurboSettings
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class TurboBridgeTest {

    @Test fun `handler result maps convert to JSON`() {
        val json = TurboBridge.toJson(
            mapOf(
                "status" to "completed",
                "count" to 3,
                "ratio" to 0.5,
                "ok" to true,
                "missing" to null,
                "ids" to listOf(1, 2),
                "nested" to mapOf("k" to "v"),
            )
        )
        val o = json.jsonObject
        assertEquals("completed", o["status"]!!.jsonPrimitive.content)
        assertEquals(3, o["count"]!!.jsonPrimitive.int)
        assertEquals(true, o["ok"]!!.jsonPrimitive.content.toBoolean())
        assertIs<JsonNull>(o["missing"])
        assertEquals(listOf(1, 2), o["ids"]!!.jsonArray.map { it.jsonPrimitive.int })
        assertEquals("v", o["nested"]!!.jsonObject["k"]!!.jsonPrimitive.content)
    }

    @Test fun `output round-trips through the JSON parser`() {
        val text = TurboBridge.toJson(mapOf("a" to listOf(mapOf("b" to "c\n\"quoted\"")))).toString()
        val parsed = Json.parseToJsonElement(text)
        assertIs<JsonObject>(parsed)
        assertIs<JsonArray>(parsed.jsonObject["a"])
    }

    @Test fun `running scripts from MCP is off by default`() {
        // Outside Burp no settings panel is registered, so every setting reports its default.
        assertFalse(TurboSettings.allowMcpRuns)
        assertFalse(TurboBridge().runsAllowed())
        assertTrue(TurboBridge.RUNS_DISABLED_MESSAGE.contains("Allow MCP clients to run Turbo scripts"))
    }
}
