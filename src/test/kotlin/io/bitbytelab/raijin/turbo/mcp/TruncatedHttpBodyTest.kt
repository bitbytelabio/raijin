package io.bitbytelab.raijin.turbo.mcp

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class TruncatedHttpBodyTest {

    private fun lines(count: Int, separator: String = "\n") = (1..count).joinToString(separator) { "line$it" }

    @Test
    fun `keeps the first limit lines when the body has more`() {
        val body = TruncatedHttpBody(lines(500), limit = 100)

        assertEquals(lines(100), body.content)
        assertTrue(body.truncated)
        assertEquals(500, body.totalLines)
        assertEquals(lines(500).length, body.totalLength)
    }

    @Test
    fun `cuts CRLF bodies on the line boundary without a dangling CR`() {
        val body = TruncatedHttpBody(lines(5, "\r\n"), limit = 2)

        assertEquals("line1\r\nline2", body.content)
        assertTrue(body.truncated)
        assertEquals(5, body.totalLines)
    }

    @Test
    fun `a long single line is one line and is not cut`() {
        val body = TruncatedHttpBody("A".repeat(5000), limit = 100)

        assertEquals("A".repeat(5000), body.content)
        assertFalse(body.truncated)
        assertEquals(1, body.totalLines)
    }

    @Test
    fun `returns full body when it has fewer lines than limit`() {
        val body = TruncatedHttpBody("short", limit = 100)

        assertEquals("short", body.content)
        assertFalse(body.truncated)
        assertEquals(5, body.totalLength)
    }

    @Test
    fun `returns full body when limit is zero`() {
        val body = TruncatedHttpBody(lines(500), limit = 0)

        assertEquals(lines(500), body.content)
        assertFalse(body.truncated)
    }

    @Test
    fun `exactly limit lines with a trailing newline is not truncated`() {
        val text = lines(3) + "\n"
        val body = TruncatedHttpBody(text, limit = 3)

        assertEquals(text, body.content)
        assertFalse(body.truncated)
        assertEquals(3, body.totalLines)
    }

    @Test
    fun `toResponseFields returns content, flag, and both totals`() {
        val fields = TruncatedHttpBody(lines(200), limit = 50).toResponseFields()

        assertEquals(lines(50), fields["response_body"])
        assertEquals(true, fields["response_body_truncated"])
        assertEquals(lines(200).length, fields["response_body_total_length"])
        assertEquals(200, fields["response_body_total_lines"])
    }

    @Test
    fun `handles empty body`() {
        val body = TruncatedHttpBody("", limit = 100)

        assertEquals("", body.content)
        assertFalse(body.truncated)
        assertEquals(0, body.totalLength)
        assertEquals(0, body.totalLines)
    }
}
