package io.bitbytelab.raijin.bridge

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/** [JsonLeafSpans] finds each scalar of a JSON text together with the exact characters it occupies. */
class JsonLeafSpansTest {

    @Test
    fun `leaves carry their path, key, decoded value and exact source span`() {
        val json = "{ \"user\": {\"id\": 5, \"name\": \"a\\\"b\"}, \"ids\": [7, \"8\"], \"ok\": true, \"none\": null }"
        val leaves = assertNotNull(JsonLeafSpans.scan(json))

        assertEquals(listOf("user.id", "user.name", "ids[0]", "ids[1]", "ok", "none"), leaves.map { it.path })
        assertEquals(listOf("id", "name", "ids", "ids", "ok", "none"), leaves.map { it.key })
        assertEquals(listOf("5", "a\"b", "7", "8", "true", "null"), leaves.map { it.value })
        assertEquals(listOf(false, true, false, true, false, false), leaves.map { it.quoted })
        // Each span is the token exactly as written, quotes and escapes included.
        assertEquals(
            listOf("5", "\"a\\\"b\"", "7", "\"8\"", "true", "null"),
            leaves.map { json.substring(it.start, it.end) }
        )
    }

    @Test
    fun `nested arrays and root arrays are addressed by index`() {
        val leaves = assertNotNull(JsonLeafSpans.scan("[{\"id\":1},[2,3]]"))
        assertEquals(listOf("[0].id", "[1][0]", "[1][1]"), leaves.map { it.path })
        assertEquals(listOf("1", "2", "3"), leaves.map { it.value })
    }

    @Test
    fun `string escapes are decoded`() {
        val leaf = assertNotNull(JsonLeafSpans.scan("\"\\u0041\\n\\t\\/\\\\\\b\\f\\r\"")).single()
        assertEquals("A\n\t/\\\b\u000C\r", leaf.value)
        assertEquals("", leaf.path)
    }

    @Test
    fun `numbers of every JSON form are bare leaves`() {
        val leaves = assertNotNull(JsonLeafSpans.scan("[0, -1, 12.50, 1e9, -2.5E-3]"))
        assertEquals(listOf("0", "-1", "12.50", "1e9", "-2.5E-3"), leaves.map { it.value })
        assertEquals(listOf(false, false, false, false, false), leaves.map { it.quoted })
    }

    @Test
    fun `empty containers have no leaves`() {
        val leaves = assertNotNull(JsonLeafSpans.scan(" { \"a\": {}, \"b\": [] } "))
        assertEquals(0, leaves.size)
    }

    @Test
    fun `text that is not one well-formed JSON value is rejected`() {
        val malformed = listOf(
            "", "   ", "{\"a\":}", "{\"a\":1,}", "{'a':1}", "{\"a\":1} x", "[1 2]", "{\"a\":\"unterminated",
            "{\"a\":01}", "tru", "{\"a\" 1}", "[1,]", "{\"a\":\"bad \\x escape\"}", "{\"a\":\"\\u12g4\"}", "{a:1}"
        )
        malformed.forEach { assertNull(JsonLeafSpans.scan(it), it) }
    }

    @Test
    fun `nesting deeper than the limit is rejected instead of overflowing the stack`() {
        assertNotNull(JsonLeafSpans.scan("[".repeat(100) + "1" + "]".repeat(100)))
        assertNull(JsonLeafSpans.scan("[".repeat(5000) + "1" + "]".repeat(5000)))
    }

    @Test
    fun `render keeps the type of the value it replaces`() {
        val leaves = assertNotNull(JsonLeafSpans.scan("{\"s\":\"9\",\"n\":9}"))
        val string = leaves[0]
        val number = leaves[1]

        assertEquals("\"9002\"", JsonLeafSpans.render(string, "9002"))
        assertEquals("9002", JsonLeafSpans.render(number, "9002"))
        // A number cannot hold text: it becomes a string.
        assertEquals("\"9 \"", JsonLeafSpans.render(number, "9 "))
        assertEquals("\"a\\\"b\\\\c\"", JsonLeafSpans.render(string, "a\"b\\c"))
        // A JSON array replaces the scalar as an array (type juggling); a look-alike is just text.
        assertEquals("[\"9\"]", JsonLeafSpans.render(string, "[\"9\"]"))
        assertEquals("[\"9\"]", JsonLeafSpans.render(number, "[\"9\"]"))
        assertEquals("\"[not json\"", JsonLeafSpans.render(string, "[not json"))
    }
}
