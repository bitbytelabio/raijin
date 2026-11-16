package io.bitbytelab.raijin.ui

import io.bitbytelab.raijin.core.RebindOutcome
import io.bitbytelab.raijin.safety.ScopeMode
import io.bitbytelab.raijin.transport.BindHostPolicy
import io.bitbytelab.raijin.transport.BindHostPolicy.Kind
import io.bitbytelab.raijin.transport.RemoteAccess
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ServerSettingsTest {

    @Test
    fun `scope mode is stored lower-case and reads back as the same mode`() {
        assertEquals(listOf("off", "warn", "enforce"), ScopeMode.entries.map(ServerSettings::scopeModeValue))
        for (mode in ScopeMode.entries) {
            assertEquals(mode, ScopeMode.fromString(ServerSettings.scopeModeValue(mode)))
        }
    }

    @Test
    fun `literal hosts classify without DNS exactly like BindHostPolicy`() {
        val literals = listOf(
            "127.0.0.1", "127.8.9.10", "::1", "[::1]", "localhost", "0.0.0.0", "::",
            "192.168.56.101", "10.0.2.15", "100.101.102.103", "fd7a:115c:a1e0::1", "", "  ", "a b",
        )
        for (host in literals) {
            assertEquals(BindHostPolicy.classify(host), ServerSettings.quickKind(host), "host '$host'")
        }
        // A name with a colon that is no IPv6 literal can never be bound.
        assertEquals(Kind.INVALID, ServerSettings.quickKind("zz:1"))
        assertEquals(Kind.INVALID, ServerSettings.quickKind("fd7a::zz"))
    }

    @Test
    fun `host names are left to the off-EDT classification`() {
        assertNull(ServerSettings.quickKind("burp-vm.tailnet.ts.net"))
        assertNull(ServerSettings.quickKind("010.0.0.1"))
        assertNull(ServerSettings.quickKind("300.1.1.1"))
    }

    @Test
    fun `the token is forced on for every non-loopback bind`() {
        assertTrue(ServerSettings.authForced(Kind.WILDCARD))
        assertTrue(ServerSettings.authForced(Kind.OTHER))
        assertFalse(ServerSettings.authForced(Kind.LOOPBACK))
        assertFalse(ServerSettings.authForced(Kind.INVALID))
        assertFalse(ServerSettings.authForced(null))
    }

    @Test
    fun `auth requirement follows the property, then the checkbox, on loopback`() {
        val none: (String) -> String? = { null }
        assertFalse(ServerSettings.authRequired(Kind.LOOPBACK, requireAuthChoice = false, sysProp = none))
        assertTrue(ServerSettings.authRequired(Kind.LOOPBACK, requireAuthChoice = true, sysProp = none))
        assertTrue(ServerSettings.authRequired(Kind.OTHER, requireAuthChoice = false, sysProp = none))

        val propertyOff: (String) -> String? = { if (it == RemoteAccess.PROP_REQUIRE_AUTH) "false" else null }
        assertFalse(ServerSettings.authRequired(Kind.LOOPBACK, requireAuthChoice = true, sysProp = propertyOff))
        assertTrue(ServerSettings.authRequired(Kind.WILDCARD, requireAuthChoice = false, sysProp = propertyOff))
    }

    @Test
    fun `overridden settings mirror RemoteAccess's property ladder`() {
        val props = mapOf(
            RemoteAccess.PROP_REQUIRE_AUTH to "maybe",
            RemoteAccess.PROP_AUTH_TOKEN to "",
            RemoteAccess.PROP_ALLOWED_IPS to "10.0.0.0/8",
        )
        assertEquals(
            setOf(RemoteAccess.PREF_AUTH_TOKEN, RemoteAccess.PREF_ALLOWED_IPS),
            ServerSettings.overriddenPrefs(props::get),
        )
        assertEquals(
            setOf(RemoteAccess.PREF_REQUIRE_AUTH),
            ServerSettings.overriddenPrefs(mapOf(RemoteAccess.PROP_REQUIRE_AUTH to " TRUE ".lowercase())::get),
        )
    }

    @Test
    fun `bind suggestions list this machine's reachable addresses, IPv4 first`() {
        // As NetworkHosts reports them: Java prints IPv6 in full and strips the zone id.
        val local = listOf(
            "127.0.0.1", "fe80:0:0:0:1c2d:3e4f:5a6b:7c8d", "fd7a:115c:a1e0::5", "192.168.56.101", "0:0:0:0:0:0:0:1",
            "169.254.10.1", "10.0.2.15", "192.168.56.101",
        )
        assertEquals(
            listOf("0.0.0.0", "127.0.0.1", "192.168.56.101", "10.0.2.15", "fd7a:115c:a1e0::5"),
            ServerSettings.bindHostSuggestions("0.0.0.0", local),
        )
        assertEquals("192.168.56.101", ServerSettings.bindHostSuggestions(" 192.168.56.101 ", emptyList()).first())
    }

    @Test
    fun `client hosts depend on what the listeners are bound to`() {
        val local = listOf("127.0.0.1", "10.0.2.15", "192.168.56.101", "fe80::2")
        val extra = listOf("burp-vm.tailnet.ts.net")
        assertEquals(listOf("127.0.0.1"), ServerSettings.clientHosts("127.0.0.1", Kind.LOOPBACK, local, extra))
        assertEquals(
            listOf("192.168.56.101", "burp-vm.tailnet.ts.net"),
            ServerSettings.clientHosts("192.168.56.101", Kind.OTHER, local, extra),
        )
        assertEquals(
            listOf("10.0.2.15", "192.168.56.101", "burp-vm.tailnet.ts.net", "127.0.0.1"),
            ServerSettings.clientHosts("0.0.0.0", Kind.WILDCARD, local, extra),
        )
        assertEquals(listOf("fd7a::1"), ServerSettings.clientHosts("[fd7a::1]", null, local, extra))
    }

    @Test
    fun `allowed IPs accept addresses and CIDR ranges and reject everything else`() {
        val valid = listOf("192.168.56.1", "10.0.2.2/32", "100.64.0.0/10", "0.0.0.0/0", "::1", "[::1]", "fd7a:115c:a1e0::/48", "[fd7a::]/64")
        assertEquals(emptyList(), ServerSettings.invalidIpEntries(valid))
        val invalid = listOf("192.168.56", "1.2.3.4/33", "::1/129", "example.com", "10.0.0.0/x", "256.1.1.1", "010.0.0.1")
        assertEquals(invalid, ServerSettings.invalidIpEntries(invalid))
    }

    @Test
    fun `allowed hosts reject URLs, paths, credentials and ports`() {
        val entries = listOf("burp-vm.tailnet.ts.net", "burp.internal", "[::1]", "http://burp.internal", "burp/x", "user@burp", "burp.internal:9876")
        assertEquals(
            listOf("http://burp.internal", "burp/x", "user@burp", "burp.internal:9876"),
            ServerSettings.invalidHostEntries(entries),
        )
    }

    @Test
    fun `the form compares settings, not formatting`() {
        fun form(host: String, token: String, ips: String, hosts: String) = ServerSettings.RemoteForm.of(
            bindHost = host, allowRemoteBind = false, requireAuth = true, token = token, allowedIps = ips, allowedHosts = hosts,
        )
        val saved = form("127.0.0.1", "tok", "10.0.0.1, 10.0.0.2", "")
        assertEquals(saved, form(" 127.0.0.1 ", " tok ", "10.0.0.1 10.0.0.2", " "))
        assertNotEquals(saved, form("127.0.0.1", "other", "10.0.0.1, 10.0.0.2", ""))
    }

    @Test
    fun `the token is masked down to its last four characters`() {
        assertEquals("••••••••wxyz", ServerSettings.mask("abcdefghijklmnopqrstuvwxyz"))
        assertEquals("•••", ServerSettings.mask("abc"))
    }

    @Test
    fun `effective status flags an exposed listener without token or allowlist`() {
        val exposedNoToken = ServerSettings.effectiveStatus(RemoteAccess.Config(), exposed = true)
        assertEquals(ServerSettings.Tone.ERROR, exposedNoToken.tone)

        val withToken = RemoteAccess.Config(authRequired = true, token = "abcdefghijkl")
        val exposedAnySource = ServerSettings.effectiveStatus(withToken, exposed = true)
        assertEquals(ServerSettings.Tone.WARN, exposedAnySource.tone)
        assertTrue("ijkl" in exposedAnySource.text)
        assertFalse("abcdefgh" in exposedAnySource.text)

        val restricted = ServerSettings.effectiveStatus(withToken.copy(allowedIps = listOf("192.168.56.1")), exposed = true)
        assertEquals(ServerSettings.Tone.OK, restricted.tone)
        assertTrue("192.168.56.1" in restricted.text)

        assertEquals(ServerSettings.Tone.MUTED, ServerSettings.effectiveStatus(RemoteAccess.Config(), exposed = false).tone)
        assertEquals(ServerSettings.Tone.OK, ServerSettings.effectiveStatus(withToken, exposed = false).tone)
    }

    @Test
    fun `rebind report says whether the token protects an exposed listener`() {
        val exposed = RebindOutcome("192.168.56.101", exposed = true, downgraded = false, boundOk = true, message = null)
        val protectedMsg = ServerSettings.rebindMessage(exposed, RemoteAccess.Config(authRequired = true, token = "t"))
        assertTrue("Authorization: Bearer" in protectedMsg)
        assertTrue("No source-IP allowlist" in protectedMsg)

        val openMsg = ServerSettings.rebindMessage(exposed, RemoteAccess.Config())
        assertTrue("No bearer token is enforced" in openMsg)

        val failed = RebindOutcome("127.0.0.1", exposed = false, downgraded = true, boundOk = false, message = "invalid bind host")
        val failedMsg = ServerSettings.rebindMessage(failed, RemoteAccess.Config())
        assertTrue("did NOT come up" in failedMsg)
        assertTrue("invalid bind host" in failedMsg)
    }

    @Test
    fun `exposure warning names the allowlist when one is set`() {
        assertTrue("No Allowed IPs" in ServerSettings.exposureWarning("0.0.0.0", emptyList()))
        assertTrue("192.168.56.1" in ServerSettings.exposureWarning("0.0.0.0", listOf("192.168.56.1")))
    }
}
