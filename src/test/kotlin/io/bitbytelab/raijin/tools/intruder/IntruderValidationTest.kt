package io.bitbytelab.raijin.tools.intruder

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for [IntruderValidation], the pure position-pair and regex validators used by
 * the Intruder tool handlers. No live Montoya API is required.
 *
 * BUG #16: malformed `[start, end]` position pairs must be rejected with a clean, consistent
 *          [IllegalArgumentException] — both too-few (previously a leaked
 *          IndexOutOfBoundsException) and too-many (previously silently truncated) elements.
 * BUG #33: an invalid `regex_replace` pattern must be rejected eagerly at registration time.
 */
class IntruderValidationTest {

    private fun arr(vararg ints: Int): JsonArray = buildJsonArray {
        for (i in ints) add(JsonPrimitive(i))
    }

    // ---- BUG #16: position pair arity ----

    @Test
    fun `valid two-element pair parses to start and end`() {
        val pair = IntruderValidation.parsePositionArray(arr(3, 7))
        assertEquals(3, pair.first)
        assertEquals(7, pair.second)
    }

    @Test
    fun `equal start and end is accepted (zero-width point)`() {
        val pair = IntruderValidation.parsePositionArray(arr(5, 5))
        assertEquals(5 to 5, pair)
    }

    @Test
    fun `too few elements is rejected with descriptive arity message`() {
        val e = assertFailsWith<IllegalArgumentException> {
            IntruderValidation.parsePositionArray(arr(3))
        }
        val msg = e.message ?: ""
        assertEquals("each position must be a [start,end] pair (got 1 element(s))", msg)
        // No leaked JDK bounds text.
        assertNull(Regex("(?i)index").find(msg)?.value)
    }

    @Test
    fun `empty array is rejected with descriptive arity message`() {
        val e = assertFailsWith<IllegalArgumentException> {
            IntruderValidation.parsePositionArray(arr())
        }
        assertEquals("each position must be a [start,end] pair (got 0 element(s))", e.message)
    }

    @Test
    fun `too many elements is rejected the same way as too few (not truncated)`() {
        val e = assertFailsWith<IllegalArgumentException> {
            IntruderValidation.parsePositionArray(arr(1, 2, 3))
        }
        assertEquals("each position must be a [start,end] pair (got 3 element(s))", e.message)
    }

    @Test
    fun `non-integer start is rejected cleanly`() {
        val bad = buildJsonArray { add(JsonPrimitive("x")); add(JsonPrimitive(5)) }
        val e = assertFailsWith<IllegalArgumentException> {
            IntruderValidation.parsePositionArray(bad)
        }
        assertEquals("position start must be an integer", e.message)
    }

    @Test
    fun `end before start is rejected`() {
        val e = assertFailsWith<IllegalArgumentException> {
            IntruderValidation.parsePositionArray(arr(9, 2))
        }
        assertEquals("position end (2) must be >= start (9)", e.message)
    }

    // ---- BUG #33: regex_replace eager validation ----

    @Test
    fun `valid regex pattern passes validation with no error`() {
        assertNull(IntruderValidation.regexError(mapOf("regex_pattern" to "[a-z]+")))
    }

    @Test
    fun `invalid regex pattern is rejected at registration time`() {
        val err = IntruderValidation.regexError(mapOf("regex_pattern" to "[unterminated"))
        assertNotNull(err, "an uncompilable pattern must be rejected")
        val text = err["error"]?.jsonPrimitive?.content ?: ""
        assertEquals(true, text.startsWith("Invalid regex_pattern:"))
    }

    @Test
    fun `missing regex pattern is rejected`() {
        val err = IntruderValidation.regexError(emptyMap())
        assertNotNull(err)
        assertEquals(
            "regex_replace requires a non-empty regex_pattern",
            err["error"]?.jsonPrimitive?.content
        )
    }

    @Test
    fun `blank regex pattern is rejected`() {
        val err = IntruderValidation.regexError(mapOf("regex_pattern" to ""))
        assertNotNull(err)
        assertEquals(
            "regex_replace requires a non-empty regex_pattern",
            err["error"]?.jsonPrimitive?.content
        )
    }

    @Test
    fun `a replacement that names a group the pattern lacks is rejected at registration time`() {
        // Java only reads the replacement once a payload matches, so these used to surface mid-run.
        fun error(pattern: String, replacement: String) =
            IntruderValidation.regexError(mapOf("regex_pattern" to pattern, "regex_replacement" to replacement))
                ?.get("error")?.jsonPrimitive?.content

        assertNull(error("(a)(b)", "$2$1"))
        assertNull(error("(?<user>\\w+)@", "\${user} at "))
        assertNull(error("a", "costs \\$5"))
        assertTrue(error("a", "$1")!!.startsWith("Invalid regex_replacement:"))
        assertTrue(error("(a)", "\${user}")!!.contains("user"))
        assertTrue(error("a", "trailing \\")!!.startsWith("Invalid regex_replacement:"))
        assertTrue(error("a", "100$")!!.startsWith("Invalid regex_replacement:"))
    }

    // ---- numeric bounds ----

    @Test
    fun `a position cannot start before the request does`() {
        val e = assertFailsWith<IllegalArgumentException> { IntruderValidation.parsePositionArray(arr(-1, 4)) }
        assertEquals("position start (-1) must be >= 0", e.message)
    }

    @Test
    fun `the object form of a position follows the same rules as the array form`() {
        assertEquals(3 to 7, IntruderValidation.parsePositionObject(buildJsonObject { put("start", 3); put("end", 7) }))
        assertEquals(3 to 7, IntruderValidation.parsePositionObject(buildJsonObject { put("0", 3); put("1", 7) }))
        assertEquals(
            "position end (2) must be >= start (9)",
            assertFailsWith<IllegalArgumentException> {
                IntruderValidation.parsePositionObject(buildJsonObject { put("start", 9); put("end", 2) })
            }.message
        )
        assertEquals(
            "Position missing 'end' field",
            assertFailsWith<IllegalArgumentException> {
                IntruderValidation.parsePositionObject(buildJsonObject { put("start", 9) })
            }.message
        )
    }

    @Test
    fun `port must be a TCP port`() {
        assertEquals(8443, IntruderValidation.port(JsonPrimitive(8443)))
        assertEquals(443, IntruderValidation.port(JsonPrimitive("443")), "a numeric string is accepted")
        for (bad in listOf(JsonPrimitive(0), JsonPrimitive(65536), JsonPrimitive(-1))) {
            assertEquals(
                "Parameter 'port' must be between 1 and 65535",
                assertFailsWith<IllegalArgumentException> { IntruderValidation.port(bad) }.message
            )
        }
        assertEquals(
            "Parameter 'port' must be an integer",
            assertFailsWith<IllegalArgumentException> { IntruderValidation.port(JsonPrimitive("https")) }.message
        )
        for (missing in listOf(null, JsonNull)) {
            assertEquals(
                "Missing required parameter: port",
                assertFailsWith<IllegalArgumentException> { IntruderValidation.port(missing) }.message
            )
        }
    }
}
