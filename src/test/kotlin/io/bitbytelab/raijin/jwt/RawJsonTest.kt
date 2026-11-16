package io.bitbytelab.raijin.jwt

import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class RawJsonTest {

    @Test
    fun `members are located with their exact value text`() {
        val text = """ { "a" : 1.50 , "b":"x,}\"y" ,"c":{"d":[1,{"e":"]"}]},"a":null } """
        val members = RawJson.members(text)!!
        assertEquals(listOf("a", "b", "c", "a"), members.map { it.name })
        assertEquals(
            listOf("1.50", "\"x,}\\\"y\"", "{\"d\":[1,{\"e\":\"]\"}]}", "null"),
            members.map { text.substring(it.valueStart, it.valueEnd) }
        )
        assertEquals("\"b\"", text.substring(members[1].start, members[1].start + 3))
    }

    @Test
    fun `an empty object has no members`() {
        assertEquals(0, RawJson.members("{}")!!.size)
        assertEquals(0, RawJson.members(" { } ")!!.size)
    }

    @Test
    fun `text that is not one JSON object has no member list`() {
        val notObjects = listOf(
            "", "[1]", "\"s\"", "7", "{", "{\"a\":1", "{\"a\":1} x", "{\"a\"}", "{\"a\":}", "{\"a\":1,}",
            "{a:1}", "{\"a\":\"unterminated}", "{\"a\":[1,2}",
        )
        for (text in notObjects) {
            assertNull(RawJson.members(text), text)
            assertNull(RawJson.set(text, mapOf("a" to JsonPrimitive(1))), text)
            assertNull(RawJson.remove(text, setOf("a")), text)
        }
    }

    @Test
    fun `values no strict parser accepts are still located`() {
        val text = """{"a":NaN,"b":0x10,"c":+1,"d":tru}"""
        val members = RawJson.members(text)!!
        assertEquals(listOf("NaN", "0x10", "+1", "tru"), members.map { text.substring(it.valueStart, it.valueEnd) })
    }

    @Test
    fun `set replaces every copy in place and appends new names`() {
        val text = """{"sub":"u", "exp":"1","exp":2 ,"n":1.0}"""
        val changed = RawJson.set(
            text,
            mapOf("exp" to JsonPrimitive(9), "role" to JsonPrimitive("admin"), "sub" to JsonPrimitive("root"))
        )
        assertEquals("""{"sub":"root", "exp":9,"exp":9 ,"n":1.0,"role":"admin"}""", changed)
    }

    @Test
    fun `set leaves everything it does not name byte for byte`() {
        val text = """{"a":{"x": [1, 2]},"b":NaN,"c":"p\/q", "d" : 1e3}"""
        assertEquals(
            """{"a":{"x": [1, 2]},"b":NaN,"c":"z", "d" : 1e3}""",
            RawJson.set(text, mapOf("c" to JsonPrimitive("z")))
        )
        assertEquals(text, RawJson.set(text, emptyMap()))
    }

    @Test
    fun `set writes objects, null and strings that need escaping`() {
        val changes = mapOf(
            "a" to buildJsonObject { put("k", "v") },
            "b" to JsonNull,
            "quo\"te" to JsonPrimitive("line\nbreak"),
        )
        assertEquals("""{"a":{"k":"v"},"b":null,"quo\"te":"line\nbreak" }""", RawJson.set("{ }", changes))
    }

    @Test
    fun `an escaped member name is matched by the name it spells`() {
        val text = """{"\u0065xp":1,"e\u0078p":2}"""
        assertEquals(listOf("exp", "exp"), RawJson.members(text)!!.map { it.name })
        assertEquals("""{"\u0065xp":7,"e\u0078p":7}""", RawJson.set(text, mapOf("exp" to JsonPrimitive(7))))
    }

    @Test
    fun `remove takes members out and keeps the rest and its separators`() {
        val text = """{ "a":1 , "b":2 ,"c":3 }"""
        assertEquals("""{ "a":1 , "c":3 }""", RawJson.remove(text, setOf("b")))
        assertEquals("""{ "a":1 , "b":2 }""", RawJson.remove(text, setOf("c")))
        assertEquals("""{ "b":2 ,"c":3 }""", RawJson.remove(text, setOf("a")))
        assertEquals("""{ "b":2 }""", RawJson.remove(text, setOf("a", "c")))
        assertEquals("{  }", RawJson.remove(text, setOf("a", "b", "c")))
        assertEquals(text, RawJson.remove(text, setOf("zz")))
        assertEquals("""{"x":0}""", RawJson.remove("""{"k":1,"x":0,"k":2}""", setOf("k")))
    }

    @Test
    fun `repeated names are reported once each in first-seen order`() {
        assertEquals(listOf("a", "b"), RawJson.repeated("""{"a":1,"b":2,"a":3,"b":4,"c":5,"a":6}"""))
        assertTrue(RawJson.repeated("""{"a":1,"b":2}""").isEmpty())
        assertTrue(RawJson.repeated("[1]").isEmpty())
    }
}
