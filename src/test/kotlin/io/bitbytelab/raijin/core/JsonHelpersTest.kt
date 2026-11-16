package io.bitbytelab.raijin.core

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class JsonHelpersTest {

    @Test
    fun `asIntSafe accepts numbers and numeric strings only`() {
        assertEquals(42, JsonPrimitive(42).asIntSafe())
        assertEquals(-7, JsonPrimitive("-7").asIntSafe())
        assertNull(JsonPrimitive(1.5).asIntSafe())
        assertNull(JsonPrimitive("abc").asIntSafe())
        assertNull(JsonPrimitive(Long.MAX_VALUE).asIntSafe())
        assertNull(JsonNull.asIntSafe())
        assertNull(null.asIntSafe())
        assertNull(buildJsonObject { put("a", 1) }.asIntSafe())
    }

    @Test
    fun `asBooleanSafe accepts booleans and true or false strings`() {
        assertEquals(true, JsonPrimitive(true).asBooleanSafe())
        assertEquals(false, JsonPrimitive("FALSE").asBooleanSafe())
        assertEquals(true, JsonPrimitive(" True ").asBooleanSafe())
        assertNull(JsonPrimitive("yes").asBooleanSafe())
        assertNull(JsonPrimitive(1).asBooleanSafe())
        assertNull(JsonNull.asBooleanSafe())
        assertNull(null.asBooleanSafe())
    }

    @Test
    fun `asBoundedInt returns null when absent and an error when invalid or out of range`() {
        assertNull(null.asBoundedInt("port", 1, 65535).getOrThrow())
        assertNull(JsonNull.asBoundedInt("port", 1, 65535).getOrThrow())
        assertEquals(443, JsonPrimitive(443).asBoundedInt("port", 1, 65535).getOrThrow())
        assertEquals(8080, JsonPrimitive("8080").asBoundedInt("port", 1, 65535).getOrThrow())

        val high = JsonPrimitive(70000).asBoundedInt("port", 1, 65535).exceptionOrNull()?.message.orEmpty()
        assertTrue("'port'" in high && "between 1 and 65535" in high && "70000" in high, high)
        val text = JsonPrimitive("x").asBoundedInt("port", 1, 65535).exceptionOrNull()?.message.orEmpty()
        assertTrue("must be an integer" in text, text)
    }

    /** An argument as a client sends it, parsed from JSON text, so the literal's own spelling is kept. */
    private fun arg(json: String) = Json.parseToJsonElement("""{"v":$json}""").jsonObject.getValue("v")

    @Test
    fun `integral numbers are accepted however they are written`() {
        assertEquals(50, arg("50.0").asIntSafe())
        assertEquals(50, JsonPrimitive(50.0).asIntSafe())
        assertEquals(50, arg("\"50.0\"").asIntSafe())
        assertEquals(100, arg("1e2").asIntSafe())
        assertEquals(0, arg("-0.0").asIntSafe())
        assertEquals(42, arg("\" 42 \"").asIntSafe())
        assertEquals(Int.MAX_VALUE, arg("2147483647.0").asIntSafe())
        assertEquals(50, arg("50.0").asBoundedInt("max_depth", 1, 100).getOrThrow())
    }

    @Test
    fun `integer reads are exact, never rounded`() {
        assertNull(arg("50.5").asIntSafe())
        assertNull(arg("100000000000000001e-17").asLongSafe(), "1.00000000000000001 is not 1")
        assertNull(arg("\"1e-\"").asLongSafe(), "a malformed exponent is not a number")
        assertEquals(9007199254740993L, arg("9007199254740993e0").asLongSafe())
        assertEquals(2147483648L, arg("2147483648.0").asLongSafe())
        assertNull(arg("2147483648.0").asIntSafe())
        assertNull(arg("1e400").asLongSafe())
        assertNull(arg("1E+2147483647").asLongSafe())
        assertNull(arg("1E-2147483647").asLongSafe())
        assertNull(arg("\"NaN\"").asLongSafe())
    }

    @Test
    fun `asClampedInt moves out-of-range values to the nearest bound and reports it`() {
        assertNull(null.asClampedInt("max_results", 0, 10_000).getOrThrow())
        assertEquals(ClampedInt(50, clamped = false), arg("50.0").asClampedInt("max_results", 0, 10_000).getOrThrow())
        assertEquals(ClampedInt(10_000, clamped = true), arg("50000").asClampedInt("max_results", 0, 10_000).getOrThrow())
        assertEquals(ClampedInt(10_000, clamped = true), arg("1e30").asClampedInt("max_results", 0, 10_000).getOrThrow())
        assertEquals(ClampedInt(0, clamped = true), arg("-1").asClampedInt("max_results", 0, 10_000).getOrThrow())
        val fraction = arg("1.5").asClampedInt("max_results", 0, 10_000).exceptionOrNull()?.message.orEmpty()
        assertTrue("'max_results'" in fraction && "must be an integer" in fraction, fraction)

        val result = buildJsonObject { put("returned", 3) }
        assertEquals(result, result.withClampReport("max_results", ClampedInt(3, clamped = false)))
        assertEquals(result, result.withClampReport("max_results", null))
        assertEquals(
            JsonObject(result + ("max_results_clamped_to" to JsonPrimitive(10_000))),
            result.withClampReport("max_results", ClampedInt(10_000, clamped = true)),
        )
    }

    @Test
    fun `asStringList accepts arrays, JSON array strings and single values`() {
        assertEquals(listOf("a", "b"), buildJsonArray { add("a"); add("b") }.asStringList())
        assertEquals(listOf("a", "b"), JsonPrimitive("[\"a\",\"b\"]").asStringList())
        assertEquals(listOf("solo"), JsonPrimitive("solo").asStringList())
        assertNull(null.asStringList())
    }

    @Test
    fun `asJsonObjectSafe parses stringified objects and rejects other text`() {
        assertEquals(buildJsonObject { put("k", "v") }, JsonPrimitive("{\"k\":\"v\"}").asJsonObjectSafe())
        assertNull(JsonPrimitive("not json").asJsonObjectSafe())
        assertNull(JsonPrimitive("{broken").asJsonObjectSafe())
    }
}
