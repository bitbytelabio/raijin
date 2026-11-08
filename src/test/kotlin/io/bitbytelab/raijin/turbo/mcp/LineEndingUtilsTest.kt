package io.bitbytelab.raijin.turbo.mcp

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class LineEndingUtilsTest {

    @Test
    fun `hasMixedLineEndings returns true for mixed LF and CRLF`() {
        assertTrue(hasMixedLineEndings("line1\nline2\r\nline3"))
        assertTrue(hasMixedLineEndings("def foo():\n    pass\r\n"))
        assertTrue(hasMixedLineEndings("\r\nfirst\nsecond"))
    }

    @Test
    fun `hasMixedLineEndings returns false for uniform LF`() {
        assertFalse(hasMixedLineEndings("line1\nline2\nline3"))
        assertFalse(hasMixedLineEndings("single\n"))
    }

    @Test
    fun `hasMixedLineEndings returns false for uniform CRLF`() {
        assertFalse(hasMixedLineEndings("line1\r\nline2\r\nline3"))
        assertFalse(hasMixedLineEndings("single\r\n"))
    }

    @Test
    fun `hasMixedLineEndings returns false for no line endings`() {
        assertFalse(hasMixedLineEndings("single line no ending"))
        assertFalse(hasMixedLineEndings(""))
    }

    @Test
    fun `normalizeScriptLineEndings normalizes mixed to CRLF`() {
        val input = "line1\nline2\r\nline3\n"
        val result = normalizeScriptLineEndings(input)

        assertEquals("line1\r\nline2\r\nline3\r\n", result.script)
        assertNotNull(result.warning)
        assertTrue(result.warning!!.contains("mixed line endings"))
    }

    @Test
    fun `normalizeScriptLineEndings preserves uniform LF when not mixed`() {
        val input = "line1\nline2\nline3"
        val result = normalizeScriptLineEndings(input)

        assertEquals(input, result.script)
        assertNull(result.warning)
    }

    @Test
    fun `normalizeScriptLineEndings preserves uniform CRLF`() {
        val input = "line1\r\nline2\r\nline3"
        val result = normalizeScriptLineEndings(input)

        assertEquals(input, result.script)
        assertNull(result.warning)
    }

    @Test
    fun `normalizeScriptLineEndings skips normalization when disabled`() {
        val input = "line1\nline2\r\nline3"
        val result = normalizeScriptLineEndings(input, normalize = false)

        assertEquals(input, result.script)
        assertNull(result.warning)
    }

    @Test
    fun `normalizeScriptLineEndings warning mentions how to disable`() {
        val input = "mixed\nlines\r\nhere"
        val result = normalizeScriptLineEndings(input)

        assertNotNull(result.warning)
        assertTrue(result.warning!!.contains("normalize_line_endings"))
    }
}
