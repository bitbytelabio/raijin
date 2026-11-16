package io.bitbytelab.raijin.webprobe

import io.bitbytelab.raijin.webprobe.CorsAnalysis.OriginTest
import io.bitbytelab.raijin.webprobe.CorsAnalysis.Preflight
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CorsAnalysisTest {

    @Test
    fun `reflected origin with credentials is critical`() {
        val v = CorsAnalysis.assess("https://evil.example", "https://evil.example", "true")
        assertEquals("critical", v?.severity)
        assertEquals("reflected_origin_with_creds", v?.id)
    }

    @Test
    fun `reflected origin without credentials is high`() {
        val v = CorsAnalysis.assess("https://evil.example", "https://evil.example", null)
        assertEquals("high", v?.severity)
        assertEquals("reflected_origin", v?.id)
    }

    @Test
    fun `null origin allowed is high`() {
        val v = CorsAnalysis.assess("null", "null", "true")
        assertEquals("high", v?.severity)
        assertEquals("null_origin_allowed", v?.id)
    }

    @Test
    fun `wildcard without credentials is low`() {
        assertEquals("low", CorsAnalysis.assess("https://evil.example", "*", null)?.severity)
    }

    @Test
    fun `non-reflected site-specific ACAO is not a finding`() {
        assertNull(CorsAnalysis.assess("https://evil.example", "https://trusted.example", "true"))
    }

    @Test
    fun `absent ACAO is not a finding`() {
        assertNull(CorsAnalysis.assess("https://evil.example", null, null))
    }

    @Test
    fun `ACAO and ACAC are compared trimmed and without regard to case`() {
        val v = CorsAnalysis.assess("https://Evil.Example", "  https://evil.example ", " TRUE ")
        assertEquals("reflected_origin_with_creds", v?.id)
        assertEquals("null_origin_allowed", CorsAnalysis.assess("null", " Null", null)?.id)
        assertEquals("wildcard_with_creds", CorsAnalysis.assess("https://evil.example", " * ", "True")?.id)
        // Two values in one header are no value a browser accepts.
        assertNull(CorsAnalysis.assess("https://evil.example", "https://evil.example, https://other.example", "true"))
    }

    // --- origins built from the target ------------------------------------------------------

    @Test
    fun `origins for a named host cover the common allowlist mistakes`() {
        assertEquals(
            listOf(
                OriginTest(CorsAnalysis.ARBITRARY, "https://raijin-cors-probe.example"),
                OriginTest(CorsAnalysis.NULL, "null"),
                OriginTest(CorsAnalysis.TARGET_AS_PREFIX, "https://app.example.com.raijin-cors-probe.example"),
                OriginTest(CorsAnalysis.TARGET_AS_SUFFIX, "https://raijin-cors-probeexample.com"),
                OriginTest(CorsAnalysis.UNESCAPED_DOT, "https://appxexample.com"),
                OriginTest(CorsAnalysis.UNDERSCORE, "https://app.example.com_.raijin-cors-probe.example"),
                OriginTest(CorsAnalysis.SUBDOMAIN, "https://raijin-cors-probe.app.example.com"),
                OriginTest(CorsAnalysis.HTTP_DOWNGRADE, "http://app.example.com"),
            ),
            CorsAnalysis.origins("https://App.Example.com/api/me?x=1"),
        )
    }

    @Test
    fun `a two-label host has no dot to leave unescaped, an http target nothing to downgrade`() {
        val origins = CorsAnalysis.origins("http://example.com:8080/")
        assertEquals(
            listOf(
                CorsAnalysis.ARBITRARY to "https://raijin-cors-probe.example",
                CorsAnalysis.NULL to "null",
                CorsAnalysis.TARGET_AS_PREFIX to "http://example.com.raijin-cors-probe.example",
                CorsAnalysis.TARGET_AS_SUFFIX to "http://raijin-cors-probeexample.com",
                CorsAnalysis.UNDERSCORE to "http://example.com_.raijin-cors-probe.example",
                CorsAnalysis.SUBDOMAIN to "http://raijin-cors-probe.example.com",
            ),
            origins.map { it.kind to it.origin },
        )
    }

    @Test
    fun `the look-alike domain is built from what someone could register`() {
        assertEquals("example.com", CorsAnalysis.registrable("a.b.example.com"))
        assertEquals("example.co.uk", CorsAnalysis.registrable("shop.example.co.uk"))
        assertEquals("example.com", CorsAnalysis.registrable("example.com"))
        val origins = CorsAnalysis.origins("https://shop.example.co.uk/").associate { it.kind to it.origin }
        assertEquals("https://raijin-cors-probeexample.co.uk", origins[CorsAnalysis.TARGET_AS_SUFFIX])
        assertEquals("https://shopxexample.co.uk", origins[CorsAnalysis.UNESCAPED_DOT])
    }

    @Test
    fun `an address or a single-label host gets only the origins that make sense for it`() {
        assertEquals(
            listOf(CorsAnalysis.ARBITRARY, CorsAnalysis.NULL, CorsAnalysis.TARGET_AS_PREFIX, CorsAnalysis.HTTP_DOWNGRADE),
            CorsAnalysis.origins("https://10.0.0.5/admin").map { it.kind },
        )
        assertEquals(
            listOf(CorsAnalysis.ARBITRARY, CorsAnalysis.NULL, CorsAnalysis.TARGET_AS_PREFIX),
            CorsAnalysis.origins("http://localhost:3000/").map { it.kind },
        )
        assertEquals(listOf(CorsAnalysis.ARBITRARY, CorsAnalysis.NULL), CorsAnalysis.origins("not a url").map { it.kind })
    }

    // --- verdicts per crafted origin --------------------------------------------------------

    @Test
    fun `an origin anyone can register is as bad as reflecting every origin`() {
        for (kind in listOf(CorsAnalysis.TARGET_AS_PREFIX, CorsAnalysis.TARGET_AS_SUFFIX, CorsAnalysis.UNESCAPED_DOT, CorsAnalysis.UNDERSCORE)) {
            val test = OriginTest(kind, "https://crafted.example")
            val withCreds = assertNotNull(CorsAnalysis.assess(test, "https://crafted.example", "true"), kind)
            assertEquals("critical", withCreds.severity, kind)
            assertEquals("allowlist_bypass_$kind", withCreds.id)
            assertTrue("https://crafted.example" in withCreds.detail)
            assertEquals("high", CorsAnalysis.assess(test, "https://crafted.example", null)?.severity, kind)
            assertNull(CorsAnalysis.assess(test, "https://app.example.com", "true"), "$kind: the server answered with its own origin")
        }
    }

    @Test
    fun `a trusted subdomain or http origin needs a further foothold and rates lower`() {
        val subdomain = OriginTest(CorsAnalysis.SUBDOMAIN, "https://raijin-cors-probe.app.example.com")
        assertEquals("any_subdomain_trusted", CorsAnalysis.assess(subdomain, subdomain.origin, "true")?.id)
        assertEquals("medium", CorsAnalysis.assess(subdomain, subdomain.origin, "true")?.severity)
        assertEquals("low", CorsAnalysis.assess(subdomain, subdomain.origin, null)?.severity)

        val http = OriginTest(CorsAnalysis.HTTP_DOWNGRADE, "http://app.example.com")
        assertEquals("http_origin_trusted", CorsAnalysis.assess(http, "http://app.example.com", "true")?.id)
        assertEquals("medium", CorsAnalysis.assess(http, "http://app.example.com", "true")?.severity)
        assertEquals("low", CorsAnalysis.assess(http, "http://app.example.com", "false")?.severity)

        // A wildcard is a wildcard whichever origin was sent.
        assertEquals("wildcard", CorsAnalysis.assess(subdomain, "*", null)?.id)
    }

    // --- Vary and preflight -----------------------------------------------------------------

    @Test
    fun `Vary is read as a list`() {
        assertTrue(CorsAnalysis.variesOnOrigin("Origin"))
        assertTrue(CorsAnalysis.variesOnOrigin("Accept-Encoding, origin"))
        assertTrue(CorsAnalysis.variesOnOrigin("Accept-Encoding\nOrigin"))
        assertTrue(CorsAnalysis.variesOnOrigin("*"))
        assertFalse(CorsAnalysis.variesOnOrigin("Accept-Encoding"))
        assertFalse(CorsAnalysis.variesOnOrigin("X-Origin-Hint"))
        assertFalse(CorsAnalysis.variesOnOrigin(null))
    }

    @Test
    fun `an ACAO that follows the Origin without Vary Origin is flagged`() {
        val test = OriginTest(CorsAnalysis.ARBITRARY, "https://raijin-cors-probe.example")
        val missing = assertNotNull(CorsAnalysis.missingVary(test, "https://raijin-cors-probe.example", "Accept-Encoding"))
        assertEquals("missing_vary_origin", missing.id)
        assertEquals("low", missing.severity)
        assertNotNull(CorsAnalysis.missingVary(test, " HTTPS://raijin-cors-probe.example ", null))

        assertNull(CorsAnalysis.missingVary(test, "https://raijin-cors-probe.example", "Origin, Accept-Encoding"))
        assertNull(CorsAnalysis.missingVary(test, "*", null), "a fixed value needs no Vary")
        assertNull(CorsAnalysis.missingVary(test, "https://app.example.com", null))
        assertNull(CorsAnalysis.missingVary(test, null, null))
    }

    @Test
    fun `a preflight that approves the origin and an unsafe method or custom header is a finding`() {
        val test = OriginTest(CorsAnalysis.ARBITRARY, "https://raijin-cors-probe.example")
        val verdict = assertNotNull(
            CorsAnalysis.assessPreflight(test, Preflight(204, test.origin, "true", "GET, PUT, DELETE", "Authorization, X-Raijin-Probe"))
        )
        assertEquals("critical", verdict.severity)
        assertEquals("preflight_reflected_origin_with_creds", verdict.id)
        assertTrue("method PUT and header x-raijin-probe" in verdict.detail, verdict.detail)

        val methodOnly = assertNotNull(CorsAnalysis.assessPreflight(test, Preflight(200, test.origin, null, "PUT", null)))
        assertEquals("preflight_reflected_origin", methodOnly.id)
        assertEquals("high", methodOnly.severity)
        assertTrue("method PUT" in methodOnly.detail && "header" !in methodOnly.detail.substringBefore(" for this origin"))

        assertEquals("preflight_wildcard", CorsAnalysis.assessPreflight(test, Preflight(204, "*", null, "*", null))?.id)
    }

    @Test
    fun `a preflight a browser would not act on is not a finding`() {
        val test = OriginTest(CorsAnalysis.ARBITRARY, "https://raijin-cors-probe.example")
        // Origin approved, but neither the method nor the header asked for.
        assertNull(CorsAnalysis.assessPreflight(test, Preflight(200, test.origin, "true", "GET, POST", "Content-Type")))
        // Approved in the headers of an error response.
        assertNull(CorsAnalysis.assessPreflight(test, Preflight(403, test.origin, "true", "PUT", "x-raijin-probe")))
        // Another origin approved.
        assertNull(CorsAnalysis.assessPreflight(test, Preflight(204, "https://app.example.com", "true", "PUT", "x-raijin-probe")))
        assertNull(CorsAnalysis.assessPreflight(test, Preflight(204, null, null, null, null)))
    }
}
