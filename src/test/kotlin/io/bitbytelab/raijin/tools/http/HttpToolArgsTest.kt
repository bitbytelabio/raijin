package io.bitbytelab.raijin.tools.http

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.add
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class HttpToolArgsTest {

    private fun args(json: String) = ToolArgs(Json.parseToJsonElement(json).jsonObject)

    @Test
    fun `out-of-range numbers are clamped with a note instead of rejected`() {
        val a = args("""{"count": 5000, "max_responses": 0, "rate": -3.5, "inside": 7}""")
        assertEquals(1000, a.clampedInt("count", 1..1000))
        assertEquals(1, a.clampedInt("max_responses", 1..1000))
        assertEquals(0.0, a.clampedDouble("rate", 0.0..100.0))
        assertEquals(7, a.clampedInt("inside", 1..10))
        assertNull(a.clampedInt("absent", 1..10))
        assertEquals(3, a.notes.size, a.notes.toString())
        assertTrue(a.notes[0].contains("'count' = 5000") && a.notes[0].contains("1000 was used"), a.notes[0])
        assertTrue(a.notes[2].contains("'rate' = -3.5") && a.notes[2].contains("0 was used"), a.notes[2])
    }

    @Test
    fun `timeout_ms 0 means no hard timeout, negative reads as 0 and too large is capped`() {
        val a = args("""{"zero": 0, "negative": -1, "huge": 9000000, "normal": 1500}""")
        assertEquals(0, a.timeoutMs("zero", 25_000))
        assertEquals(0, a.timeoutMs("negative", 25_000))
        assertEquals(ToolArgs.MAX_TIMEOUT_MS, a.timeoutMs("huge", 25_000))
        assertEquals(1500, a.timeoutMs("normal", 25_000))
        assertEquals(25_000, a.timeoutMs("absent", 25_000))
        assertEquals(2, a.notes.size, a.notes.toString())
    }

    @Test
    fun `malformed values and strict ranges are errors`() {
        val a = args("""{"port": 70000, "count": "many", "mode": "burst", "flag": "yes", "obj": {}}""")
        assertTrue("1 and 65535" in assertFailsWith<IllegalArgumentException> { a.int("port", 1..65535) }.message!!)
        assertTrue("must be an integer" in assertFailsWith<IllegalArgumentException> { a.clampedInt("count", 1..10) }.message!!)
        assertTrue("concat, single_write" in assertFailsWith<IllegalArgumentException> { a.enum("mode", listOf("concat", "single_write")) }.message!!)
        assertTrue("true or false" in assertFailsWith<IllegalArgumentException> { a.bool("flag") }.message!!)
        assertTrue("must be a string" in assertFailsWith<IllegalArgumentException> { a.string("obj") }.message!!)
    }

    @Test
    fun `enum values come back in their canonical spelling and TLS follows the aliases`() {
        assertEquals("HTTP_2", args("""{"m": " http_2 "}""").enum("m", listOf("AUTO", "HTTP_2")))
        assertNull(args("""{"m": " "}""").enum("m", listOf("AUTO")))
        assertEquals(true, args("""{}""").tls(443))
        assertEquals(false, args("""{}""").tls(80))
        assertEquals(true, args("""{"https": "true"}""").tls(80))
        assertEquals(false, args("""{"use_tls": false, "tls": true}""").tls(443))
    }

    @Test
    fun `notes are appended to the result's own notes`() {
        val a = args("""{"count": 0}""")
        a.clampedInt("count", 1..10)
        val result: JsonObject = buildJsonObject {
            put("ok", true)
            putJsonArray("notes") { add("from the bridge") }
        }
        val merged = a.withNotes(result)
        assertEquals(listOf("from the bridge", a.notes.single()), merged.getValue("notes").jsonArray.map { it.jsonPrimitive.content })
        val untouched: JsonElement = ToolArgs(emptyMap()).withNotes(result)
        assertEquals(result, untouched)
    }
}
