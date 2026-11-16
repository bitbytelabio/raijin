package io.bitbytelab.raijin.core

import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.add
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
