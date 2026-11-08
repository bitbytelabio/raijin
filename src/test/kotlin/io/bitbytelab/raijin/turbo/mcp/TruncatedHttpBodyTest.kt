package io.bitbytelab.raijin.turbo.mcp

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class TruncatedHttpBodyTest {

    @Test
    fun `truncates body when longer than limit`() {
        val body = TruncatedHttpBody("A".repeat(500), limit = 100)

        assertEquals("A".repeat(100), body.content)
        assertTrue(body.truncated)
        assertEquals(500, body.totalLength)
    }

    @Test
    fun `returns full body when shorter than limit`() {
        val body = TruncatedHttpBody("short", limit = 100)

        assertEquals("short", body.content)
        assertFalse(body.truncated)
        assertEquals(5, body.totalLength)
    }

    @Test
    fun `returns full body when limit is zero`() {
        val body = TruncatedHttpBody("A".repeat(500), limit = 0)

        assertEquals("A".repeat(500), body.content)
        assertFalse(body.truncated)
        assertEquals(500, body.totalLength)
    }

    @Test
    fun `toResponseFields returns all three fields`() {
        val body = TruncatedHttpBody("A".repeat(200), limit = 50)
        val fields = body.toResponseFields()

        assertEquals("A".repeat(50), fields["response_body"])
        assertEquals(true, fields["response_body_truncated"])
        assertEquals(200, fields["response_body_total_length"])
    }

    @Test
    fun `handles empty body`() {
        val body = TruncatedHttpBody("", limit = 100)

        assertEquals("", body.content)
        assertFalse(body.truncated)
        assertEquals(0, body.totalLength)
    }

    @Test
    fun `handles exact limit match`() {
        val body = TruncatedHttpBody("A".repeat(100), limit = 100)

        assertEquals("A".repeat(100), body.content)
        assertFalse(body.truncated)
        assertEquals(100, body.totalLength)
    }
}
