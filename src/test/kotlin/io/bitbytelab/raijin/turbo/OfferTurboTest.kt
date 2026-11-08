package io.bitbytelab.raijin.turbo

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class OfferTurboTest {

    @Test
    fun `extractScriptFromNotes returns script when marker present`() {
        val notes = "my comment\nReqs: 5\n\n--- Script ---\ndef queueRequests(target, wordlists):\n    pass"
        assertEquals("def queueRequests(target, wordlists):\n    pass", extractScriptFromNotes(notes))
    }

    @Test
    fun `extractScriptFromNotes returns null when marker absent`() {
        val notes = "just a comment with no script section"
        assertNull(extractScriptFromNotes(notes))
    }

    @Test
    fun `extractScriptFromNotes returns null for null input`() {
        assertNull(extractScriptFromNotes(null))
    }

    @Test
    fun `extractScriptFromNotes returns null for empty input`() {
        assertNull(extractScriptFromNotes(""))
    }

    @Test
    fun `extractScriptFromNotes returns null for blank input`() {
        assertNull(extractScriptFromNotes("   \n  \t  "))
    }

    @Test
    fun `extractScriptFromNotes returns null when content after marker is blank`() {
        val notes = "comment\n\n--- Script ---\n   \n  "
        assertNull(extractScriptFromNotes(notes))
    }

    @Test
    fun `extractScriptFromNotes uses last marker when multiple present`() {
        val notes = "user wrote --- Script --- in their comment\n\n--- Script ---\nactual_script()"
        assertEquals("actual_script()", extractScriptFromNotes(notes))
    }

    @Test
    fun `extractScriptFromNotes trims trailing whitespace`() {
        val notes = "comment\n\n--- Script ---\nscript_body()\n\n\n"
        assertEquals("script_body()", extractScriptFromNotes(notes))
    }
}
