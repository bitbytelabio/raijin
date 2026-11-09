package io.bitbytelab.raijin.core

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Regression tests for the MCP Activity double-escaping bug: [ToolCallTracker] previously
 * built its per-argument summary by calling `.toString()` on each [kotlinx.serialization.json.JsonElement]
 * (which for a string primitive already returns *quoted* JSON text) and storing that text as a
 * **new** string value — so the outer object's own serialization re-escaped the embedded quotes
 * and backslashes, corrupting `"start"` into `"\"start\""` and doubling every `\r\n` into
 * `\\r\\n` in the Activity tab, the persisted history file, and the web dashboard alike.
 * [truncateJsonForSummary] keeps a string primitive's actual content, not its re-quoted form, so
 * the result stays single-encoded no matter how many times it's embedded.
 */
class JsonTruncateTest {

    @Test
    fun `a short string primitive round-trips to the same content, not its quoted form`() {
        val result = truncateJsonForSummary(JsonPrimitive("start"), 200)
        assertEquals(JsonPrimitive("start"), result)
        // The literal bug: the old code produced the 7-char string "\"start\"" here instead.
        assertEquals("start", (result as JsonPrimitive).content)
    }

    @Test
    fun `embedding the result in an outer object does not double-escape quotes`() {
        val outer = buildJsonObject { put("action", truncateJsonForSummary(JsonPrimitive("start"), 200)) }
        // Must be the normal, single-encoded shape — not "action":"\"start\"".
        assertEquals("""{"action":"start"}""", outer.toString())
    }

    @Test
    fun `a string containing real CRLF is not double-escaped when embedded`() {
        val value = JsonPrimitive("GET / HTTP/1.1\r\nHost: x")
        val outer = buildJsonObject { put("base_request", truncateJsonForSummary(value, 200)) }
        val serialized = outer.toString()
        // Single JSON escaping of the embedded \r\n — never the doubled \\r\\n the bug produced.
        assertTrue("\\r\\n" in serialized, serialized)
        assertTrue("\\\\r\\\\n" !in serialized, serialized)
    }

    @Test
    fun `a long string primitive is truncated by its actual content length`() {
        val long = "x".repeat(300)
        val result = truncateJsonForSummary(JsonPrimitive(long), 200) as JsonPrimitive
        assertEquals(201, result.content.length) // 200 chars + the truncation marker char
        assertTrue(result.content.startsWith("x".repeat(200)))
    }

    @Test
    fun `a short string under the limit is returned unchanged`() {
        val result = truncateJsonForSummary(JsonPrimitive("short"), 200) as JsonPrimitive
        assertEquals("short", result.content)
    }

    @Test
    fun `non-string primitives pass through untouched`() {
        assertEquals(JsonPrimitive(42), truncateJsonForSummary(JsonPrimitive(42), 5))
        assertEquals(JsonPrimitive(true), truncateJsonForSummary(JsonPrimitive(true), 5))
        assertEquals(JsonNull, truncateJsonForSummary(JsonNull, 5))
    }

    @Test
    fun `a small nested object is kept as real structure, not stringified`() {
        val nested = buildJsonObject { put("x", 1); put("y", "two") }
        val result = truncateJsonForSummary(nested, 200)
        assertEquals(nested, result)
        assertTrue(result is JsonObject)
    }

    @Test
    fun `a huge nested object is collapsed to a labeled truncated string, not silently cut mid-JSON`() {
        val big = buildJsonArray { repeat(100) { add(JsonPrimitive("x".repeat(20))) } }
        val serializedLen = big.toString().length
        val result = truncateJsonForSummary(big, 50) as JsonPrimitive
        val content = result.content
        assertTrue(content.startsWith("["), content) // the array's own serialized form, truncated — not silently dropped
        assertTrue("truncated $serializedLen chars" in content, content)
    }

    @Test
    fun `a nested object under the limit is kept as structure even when it contains an array`() {
        val small = buildJsonObject { put("items", JsonArray(listOf(JsonPrimitive("a"), JsonPrimitive("b")))) }
        assertEquals(small, truncateJsonForSummary(small, 200))
    }
}
