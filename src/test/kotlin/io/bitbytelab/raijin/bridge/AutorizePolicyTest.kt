package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.state.AutorizeRule
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The pure decisions of the live Autorize tap: what it replays, as whom, and what it keeps. */
class AutorizePolicyTest {

    private fun rule(methods: Set<String>? = null, includeMutating: Boolean = false) =
        AutorizeRule("arule-1", listOf(buildJsonObject { put("name", "none") }), methods = methods, includeMutating = includeMutating)

    /** Bodies match only when equal, so each verdict below is about status and wording alone. */
    private val exact: (String, String) -> Double = { a, b -> if (a == b) 100.0 else 0.0 }

    private fun level(name: String, status: Int, body: String, contentType: String = "application/json") =
        AuthDiffVerdict.LevelResult(name, status, body, contentType)

    private val data = "{\"orders\":[{\"id\":1,\"owner\":\"admin@shop.test\"}]}"

    @Test
    fun `state-changing methods are skipped unless the rule opts in, and a methods filter comes first`() {
        assertNull(AutorizePolicy.methodSkip(rule(), "GET"))
        for (method in listOf("POST", "put", "Delete", "PATCH")) {
            assertEquals(AutorizePolicy.SKIPPED_MUTATING, AutorizePolicy.methodSkip(rule(), method), method)
        }
        assertEquals(AutorizePolicy.SKIPPED_MUTATING, AutorizePolicy.methodSkip(rule(methods = setOf("POST")), "POST"), "naming it is not opting in")
        assertEquals(AutorizePolicy.FILTERED, AutorizePolicy.methodSkip(rule(methods = setOf("GET")), "POST"))
        assertNull(AutorizePolicy.methodSkip(rule(includeMutating = true), "DELETE"))
        assertNull(AutorizePolicy.methodSkip(rule(), "OPTIONS"))

        assertEquals(listOf("DELETE", "POST"), AutorizePolicy.unreplayedMethods(setOf("GET", "post", "DELETE"), includeMutating = false))
        assertEquals(emptyList(), AutorizePolicy.unreplayedMethods(setOf("POST"), includeMutating = true))
        assertEquals(emptyList(), AutorizePolicy.unreplayedMethods(null, includeMutating = false))
    }

    @Test
    fun `an original is replayed only when it was authenticated and found something`() {
        assertEquals(AutorizePolicy.SKIPPED_NOT_FOUND, AutorizePolicy.originalSkip(404, listOf("Cookie"), emptySet()))
        assertEquals(AutorizePolicy.SKIPPED_UNAUTHENTICATED, AutorizePolicy.originalSkip(401, listOf("Cookie"), emptySet()))
        assertEquals(AutorizePolicy.SKIPPED_UNAUTHENTICATED, AutorizePolicy.originalSkip(200, listOf("Host", "Accept"), emptySet()))
        assertNull(AutorizePolicy.originalSkip(200, listOf("Host", "authorization"), emptySet()))
        assertNull(AutorizePolicy.originalSkip(403, listOf("X-Api-Key"), emptySet()))
        assertNull(AutorizePolicy.originalSkip(302, listOf("Cookie"), emptySet()))
        // A header the rule's identities authenticate with counts as a credential too.
        assertNull(AutorizePolicy.originalSkip(200, listOf("X-Tenant-Key"), setOf("x-tenant-key")))
        assertTrue(AutorizePolicy.carriesCredentials(listOf(" Cookie "), emptySet()))
        assertFalse(AutorizePolicy.carriesCredentials(listOf("X-Csrf-Token"), emptySet()), "a CSRF token alone is no session")
    }

    @Test
    fun `identities that would send the captured request as it is are left out`() {
        val raw = "GET /a HTTP/1.1\r\nHost: shop.test\r\nCookie: s=admin\r\n\r\n"
        val identities = listOf(
            buildJsonObject { put("name", "same"); put("header_name", "cookie"); put("header_value", " s=admin") },
            buildJsonObject { put("name", "admin") },
            buildJsonObject { put("name", "none") },
            buildJsonObject { put("name", "low"); put("header_name", "Cookie"); put("header_value", "s=low") },
        ).map { AuthIdentityApplier.parse(it) }

        val replays = AutorizePolicy.replays(raw, identities)
        assertEquals(listOf("none", "low"), replays.map { it.identity.name })
        assertFalse("Cookie" in replays[0].applied.request)
        assertTrue("Cookie: s=low" in replays[1].applied.request)
        assertFalse("s=admin" in replays[1].applied.request, "the captured session is replaced, not sent alongside")
    }

    @Test
    fun `a critical or high verdict is kept and recorded`() {
        val judgement = assertNotNull(
            AutorizePolicy.judge(listOf(level("captured", 200, data), level("low", 200, data), level("none", 401, "{}")), "https://shop.test/api/orders", 90.0, exact)
        )
        assertFalse(judgement.softDenial)
        assertEquals(listOf("cross_identity_match"), judgement.actionable.map { it.id })
        assertEquals(judgement.actionable, judgement.findings)
    }

    @Test
    fun `a verdict with nothing worth keeping is dropped`() {
        val refused = listOf(level("captured", 200, data), level("low", 403, "{\"error\":\"forbidden\"}"), level("none", 401, "{}"))
        assertNull(AutorizePolicy.judge(refused, "https://shop.test/api/orders", 90.0, exact))
    }

    @Test
    fun `a soft denial is kept, with what status and similarity alone would say`() {
        val levels = listOf(level("captured", 200, data), level("none", 200, "{\"error\":\"unauthorized\"}"))
        val judgement = assertNotNull(AutorizePolicy.judge(levels, "https://shop.test/api/orders", 90.0, exact))
        assertTrue(judgement.softDenial)
        assertTrue(judgement.actionable.isEmpty(), "a soft denial is not recorded as a finding")
        assertEquals(listOf("unauth_soft_denial", AutorizePolicy.STATUS_ONLY_ID), judgement.findings.map { it.id })
        assertTrue("[high] unauth_accessible" in judgement.findings.last().detail, judgement.findings.last().detail)
    }

    @Test
    fun `denial wording that hides nothing is not kept`() {
        // On status alone this static asset would only be informational, so the denial wording changed nothing.
        val levels = listOf(level("captured", 200, "body{}", "text/css"), level("none", 200, "{\"error\":\"unauthorized\"}", "text/css"))
        assertNull(AutorizePolicy.judge(levels, "https://shop.test/app.css", 90.0, exact))
    }
}
