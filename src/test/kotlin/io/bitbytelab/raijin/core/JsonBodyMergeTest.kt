package io.bitbytelab.raijin.core

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals

class JsonBodyMergeTest {

    @Test
    fun `an empty body becomes a fresh object with just the new key`() {
        val result = JsonBodyMerge.mergeKey("", "candidate", "zZmarker")
        val obj = Json.parseToJsonElement(result).jsonObject
        assertEquals(1, obj.size)
        assertEquals("zZmarker", obj["candidate"]?.jsonPrimitive?.content)
    }

    @Test
    fun `a non-JSON body is replaced with a fresh object rather than left untouched`() {
        // This is the actual bug: recon(action=param_mine, inject_in=json_body) builds its base
        // request from a bare URL (no body at all), so the body text here is "" — every
        // candidate must still get its own request, not the same untouched empty body repeated.
        val result = JsonBodyMerge.mergeKey("not json at all", "q", "1")
        val obj = Json.parseToJsonElement(result).jsonObject
        assertEquals("1", obj["q"]?.jsonPrimitive?.content)
    }

    @Test
    fun `an existing JSON object body is preserved and the new key is added`() {
        val result = JsonBodyMerge.mergeKey("""{"existing":"value"}""", "candidate", "zZmarker")
        val obj = Json.parseToJsonElement(result).jsonObject
        assertEquals("value", obj["existing"]?.jsonPrimitive?.content)
        assertEquals("zZmarker", obj["candidate"]?.jsonPrimitive?.content)
    }

    @Test
    fun `adding the same key twice overwrites rather than duplicates`() {
        val once = JsonBodyMerge.mergeKey("""{"q":"old"}""", "q", "new")
        val obj = Json.parseToJsonElement(once).jsonObject
        assertEquals(1, obj.size)
        assertEquals("new", obj["q"]?.jsonPrimitive?.content)
    }

    @Test
    fun `a JSON array body is treated as not-an-object and replaced with a fresh object`() {
        val result = JsonBodyMerge.mergeKey("""["a","b"]""", "q", "1")
        val obj = Json.parseToJsonElement(result).jsonObject
        assertEquals(1, obj.size)
        assertEquals("1", obj["q"]?.jsonPrimitive?.content)
    }
}
