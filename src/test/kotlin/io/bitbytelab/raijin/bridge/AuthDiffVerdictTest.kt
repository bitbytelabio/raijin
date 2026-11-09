package io.bitbytelab.raijin.bridge

import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.assertFalse

class AuthDiffVerdictTest {

    // exact-match similarity for deterministic tests (0 or 100)
    private val sim = { a: String, b: String -> if (a == b) 100.0 else 0.0 }
    private fun lr(name: String, status: Int, body: String) = AuthDiffVerdict.LevelResult(name, status, body)

    @Test
    fun `flags all-identical responses as critical broken access control`() {
        val f = AuthDiffVerdict.assess(listOf(lr("admin", 200, "data"), lr("user", 200, "data"), lr("none", 200, "data")), sim)
        assertTrue(f.any { it.id == "all_identical" && it.severity == "critical" })
    }

    @Test
    fun `flags an unauth level that returns the same protected body as an authed level`() {
        val f = AuthDiffVerdict.assess(
            listOf(lr("admin", 200, "secret"), lr("user", 403, "denied"), lr("none", 200, "secret")), sim
        )
        assertTrue(f.any { it.id == "unauth_reads_protected" && it.severity == "critical" })
    }

    @Test
    fun `flags an unauth-accessible endpoint even when the body differs`() {
        val f = AuthDiffVerdict.assess(listOf(lr("admin", 200, "secret"), lr("none", 200, "public-page")), sim)
        assertTrue(f.any { it.id == "unauth_accessible" && it.severity == "high" })
        assertFalse(f.any { it.id == "unauth_reads_protected" })
    }

    @Test
    fun `proper enforcement (authed 200, unauth 401) yields no critical or high finding`() {
        val f = AuthDiffVerdict.assess(listOf(lr("admin", 200, "secret"), lr("none", 401, "denied")), sim)
        assertFalse(f.any { it.severity == "critical" || it.severity == "high" })
    }

    @Test
    fun `flags two different authenticated identities sharing protected content even when a third level differs`() {
        // The documented Autorize setup: a "captured" browsing session, a lower-privilege
        // identity, and "none". If low_priv sees the SAME content as the real session while none
        // is correctly blocked, overall status is not uniform (captured/low_priv=200, none=403),
        // so the all-identical branch never fires — but captured vs low_priv must still be flagged.
        val f = AuthDiffVerdict.assess(
            listOf(lr("captured", 200, "secret"), lr("low_priv", 200, "secret"), lr("none", 403, "denied")), sim
        )
        assertTrue(f.any { it.id == "cross_identity_match" && it.severity == "critical" })
        // none was properly blocked (403, not a 2xx/3xx) — must not also be flagged as accessible.
        assertFalse(f.any { it.id == "unauth_accessible" })
    }

    @Test
    fun `a matched unauth level is not also reported as unauth_accessible`() {
        val f = AuthDiffVerdict.assess(
            listOf(lr("admin", 200, "secret"), lr("user", 403, "denied"), lr("none", 200, "secret")), sim
        )
        assertTrue(f.any { it.id == "unauth_reads_protected" })
        assertFalse(f.any { it.id == "unauth_accessible" })
    }

    // Graduated similarity (not just exact-match) so the threshold overrides below are meaningful.
    private val gradedSim = { a: String, b: String ->
        if (a == b) 100.0 else if (a.take(3) == b.take(3)) 80.0 else 0.0
    }

    @Test
    fun `a lower unauthMatchThreshold flags a looser body match that the default would miss`() {
        val results = listOf(lr("admin", 200, "secretXYZ"), lr("none", 200, "secretABC"))
        val default = AuthDiffVerdict.assess(results, gradedSim)
        assertFalse(default.any { it.id == "unauth_reads_protected" })

        val loosened = AuthDiffVerdict.assess(results, gradedSim, unauthMatchThreshold = 75.0)
        assertTrue(loosened.any { it.id == "unauth_reads_protected" })
    }

    @Test
    fun `a lower allSimilarThreshold downgrades a near-identical response to all_identical`() {
        val results = listOf(lr("admin", 200, "dataXYZ"), lr("user", 200, "dataABC"), lr("none", 200, "dataQRS"))
        val default = AuthDiffVerdict.assess(results, gradedSim)
        assertFalse(default.any { it.id == "all_identical" })

        val loosened = AuthDiffVerdict.assess(results, gradedSim, allSimilarThreshold = 75.0)
        assertTrue(loosened.any { it.id == "all_identical" })
    }
}
