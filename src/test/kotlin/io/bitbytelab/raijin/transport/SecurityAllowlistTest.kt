package io.bitbytelab.raijin.transport

import io.ktor.http.parametersOf
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The Host-header + CORS-origin allowlist is the anti-DNS-rebinding control. When the bind host
 * becomes configurable it must be built from the explicit allowed-host list (not hardcoded
 * loopback), for every (host x port) pair. This pins that pure construction.
 */
class SecurityAllowlistTest {

    @Test fun `builds host and origin allowlists for each host x port`() {
        val (hosts, origins) = SecurityConfig.buildAllowlists(listOf("127.0.0.1", "localhost"), listOf(9876))
        assertEquals(setOf("127.0.0.1:9876", "localhost:9876"), hosts)
        assertEquals(setOf("http://127.0.0.1:9876", "http://localhost:9876"), origins)
    }

    @Test fun `dedupes repeated hosts`() {
        val (hosts, _) = SecurityConfig.buildAllowlists(listOf("127.0.0.1", "127.0.0.1"), listOf(9876))
        assertEquals(setOf("127.0.0.1:9876"), hosts)
    }

    @Test fun `covers every port for a concrete bind host`() {
        val (hosts, origins) = SecurityConfig.buildAllowlists(listOf("192.168.1.50"), listOf(9876, 9877))
        assertEquals(setOf("192.168.1.50:9876", "192.168.1.50:9877"), hosts)
        assertEquals(setOf("http://192.168.1.50:9876", "http://192.168.1.50:9877"), origins)
    }

    // ---- IPv6 / case normalization -------------------------------------------

    @Test fun `IPv6 hosts are bracketed in RFC 5952 form`() {
        assertEquals("[::1]", SecurityConfig.formatHostForAuthority("0:0:0:0:0:0:0:1"))
        assertEquals("[fe80::1]", SecurityConfig.formatHostForAuthority("FE80:0:0:0:0:0:0:1%en0"))
        val (hosts, _) = SecurityConfig.buildAllowlists(listOf("fe80:0:0:0:1c2b:3cff:fe4d:5e6f"), listOf(9876))
        assertEquals(setOf("[fe80::1c2b:3cff:fe4d:5e6f]:9876"), hosts, "a NetworkHosts address must match the compressed form clients send")
    }

    @Test fun `Host and Origin values normalize like the allowlists`() {
        assertEquals("[::1]:9876", SecurityConfig.normalizeAuthority("[0:0:0:0:0:0:0:1]:9876"))
        assertEquals("localhost:9876", SecurityConfig.normalizeAuthority(" LocalHost:9876 "))
        assertEquals("http://[::1]:9876", SecurityConfig.normalizeOrigin("HTTP://[0::1]:9876"))
        assertEquals("https://burp.internal", SecurityConfig.normalizeOrigin("https://Burp.Internal/"))
    }

    // ---- extra allowed hosts -------------------------------------------------

    @Test fun `extra host entries parse names, ports, IPv6 and pasted URLs`() {
        assertEquals("burp-vm.tailnet.ts.net" to null, SecurityConfig.parseHostEntry(" Burp-VM.tailnet.ts.net "))
        assertEquals("burp.internal" to 8443, SecurityConfig.parseHostEntry("burp.internal:8443"))
        assertEquals("[fd7a::5]" to 9876, SecurityConfig.parseHostEntry("[FD7A:0::5]:9876"))
        assertEquals("[fd7a::5]" to null, SecurityConfig.parseHostEntry("fd7a::5"))
        assertEquals("burp.example.com" to null, SecurityConfig.parseHostEntry("https://burp.example.com/dashboard"))
        for (bad in listOf("", "*.ts.net", "burp.internal:0", "burp.internal:abc", "[fd7a::5", "bad host", "-bad-")) {
            assertNull(SecurityConfig.parseHostEntry(bad), bad)
        }
        assertEquals(listOf("*.ts.net"), SecurityConfig.invalidHostEntries(listOf("burp.internal", "*.ts.net")))
    }

    @Test fun `a bare extra host is allowed with and without a listener port, an explicit port only as given`() {
        val (hosts, origins) = SecurityConfig.extraHostAllowlists(listOf("burp.internal", "proxy.lan:8443"), listOf(9876, 9877))
        assertEquals(
            setOf("burp.internal", "burp.internal:9876", "burp.internal:9877", "proxy.lan:8443"),
            hosts
        )
        assertTrue("https://burp.internal" in origins)
        assertTrue("http://burp.internal:9877" in origins)
        assertTrue("https://proxy.lan:8443" in origins)
        assertFalse("https://proxy.lan" in origins)
    }

    // ---- bearer token helpers -------------------------------------------------

    @Test fun `bearer tokens are read only from the Bearer scheme`() {
        assertEquals("abc", SecurityConfig.bearerToken("Bearer abc"))
        assertEquals("abc", SecurityConfig.bearerToken("bEaReR   abc "))
        assertNull(SecurityConfig.bearerToken("Basic abc"))
        assertNull(SecurityConfig.bearerToken("Bearer"))
        assertNull(SecurityConfig.bearerToken("Bearer    "))
        assertNull(SecurityConfig.bearerToken(null))
    }

    @Test fun `token comparison matches exactly and never matches an empty token`() {
        assertTrue(SecurityConfig.tokenMatches("tok", "tok"))
        assertFalse(SecurityConfig.tokenMatches("tok", "tok2"))
        assertFalse(SecurityConfig.tokenMatches("TOK", "tok"))
        assertFalse(SecurityConfig.tokenMatches("", ""))
        assertFalse(SecurityConfig.tokenMatches(null, "tok"))
        assertFalse(SecurityConfig.tokenMatches("tok", null))
    }

    @Test fun `the auth cookie carries a token digest, never the token`() {
        val v = SecurityConfig.authCookieValue("my-token")
        assertFalse(v.contains("my-token"))
        assertEquals(v, SecurityConfig.authCookieValue("my-token"))
        assertFalse(v == SecurityConfig.authCookieValue("my-token2"))
        assertTrue(v.all { it.isLetterOrDigit() || it == '-' || it == '_' }, "cookie-safe characters only: $v")
    }

    @Test fun `the post-login redirect drops the token and cannot leave the server`() {
        assertEquals("/", SecurityConfig.withoutTokenParam("/", parametersOf("token", "t")))
        assertEquals("/api?a=1&b=x+y", SecurityConfig.withoutTokenParam("/api", parametersOf("a" to listOf("1"), "token" to listOf("t"), "b" to listOf("x y"))))
        assertEquals("/evil.example/x", SecurityConfig.withoutTokenParam("//evil.example/x", parametersOf("token", "t")))
    }
}
