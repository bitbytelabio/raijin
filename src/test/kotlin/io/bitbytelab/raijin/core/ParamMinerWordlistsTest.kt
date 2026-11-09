package io.bitbytelab.raijin.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ParamMinerWordlistsTest {

    @Test
    fun `explicit candidates are used as-is regardless of wordlistName`() {
        val resolved = ParamMinerWordlists.resolve(listOf("a", "b"), "does-not-matter")
        assertTrue(resolved is ParamMinerWordlists.Resolved.Ok)
        assertEquals(listOf("a", "b"), resolved.candidates)
    }

    @Test
    fun `an unknown wordlist name is an error, not a silent empty scan`() {
        // Exactly the reported bug shape: a typo like "param-miner-param" (missing the trailing
        // 's') must not resolve to an empty candidate list that looks like a clean scan.
        val resolved = ParamMinerWordlists.resolve(null, "param-miner-param")
        assertTrue(resolved is ParamMinerWordlists.Resolved.Error)
        assertTrue(resolved.message.contains("Unknown wordlist"))
    }

    @Test
    fun `the default bundled wordlist resolves to a non-empty candidate list`() {
        val resolved = ParamMinerWordlists.resolve(null, ParamMinerWordlists.DEFAULT)
        assertTrue(resolved is ParamMinerWordlists.Resolved.Ok)
        assertTrue(resolved.candidates.isNotEmpty())
    }

    @Test
    fun `the header wordlist also resolves to a non-empty candidate list`() {
        val resolved = ParamMinerWordlists.resolve(null, "param-miner-headers")
        assertTrue(resolved is ParamMinerWordlists.Resolved.Ok)
        assertTrue(resolved.candidates.isNotEmpty())
    }
}
