package io.bitbytelab.raijin.transport

import burp.api.montoya.persistence.Preferences
import java.lang.reflect.Proxy
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Resolution of the remote-access settings from preferences and `-D` properties, and their install. */
class RemoteAccessTest {

    private class FakePrefs {
        val strings = mutableMapOf<String, String>()
        val booleans = mutableMapOf<String, Boolean>()

        val prefs: Preferences = Proxy.newProxyInstance(
            Preferences::class.java.classLoader,
            arrayOf(Preferences::class.java)
        ) { proxy, method, args ->
            when (method.name) {
                "getString" -> strings[args!![0] as String]
                "setString" -> { strings[args!![0] as String] = args[1] as String; null }
                "getBoolean" -> booleans[args!![0] as String]
                "setBoolean" -> { booleans[args!![0] as String] = args[1] as Boolean; null }
                "hashCode" -> System.identityHashCode(proxy)
                "equals" -> proxy === args?.firstOrNull()
                "toString" -> "FakePrefs"
                else -> null
            }
        } as Preferences
    }

    private val noProps: (String) -> String? = { null }

    @AfterTest fun reset() {
        RemoteAccess.applyFromPreferences(FakePrefs().prefs, exposed = false, sysProp = noProps)
    }

    @Test fun `loopback without the opt-in needs no token and stores nothing`() {
        val p = FakePrefs()
        val r = RemoteAccess.applyFromPreferences(p.prefs, exposed = false, sysProp = noProps)
        assertFalse(r.config.authRequired)
        assertNull(r.config.token)
        assertFalse(r.generatedToken)
        assertTrue(p.strings.isEmpty())
        assertEquals(r.config, RemoteAccess.current)
        assertFalse(RemoteAccess.exposed)
    }

    @Test fun `an exposed bind turns auth on and saves a generated token once`() {
        val p = FakePrefs()
        val first = RemoteAccess.applyFromPreferences(p.prefs, exposed = true, sysProp = noProps)
        assertTrue(first.config.authRequired)
        assertTrue(first.generatedToken)
        val token = assertNotNull(first.config.token)
        assertTrue(token.length >= 43, "256-bit token expected: $token")
        assertEquals(token, p.strings[RemoteAccess.PREF_AUTH_TOKEN])
        assertEquals(first.config, RemoteAccess.current)
        assertTrue(RemoteAccess.exposed)

        val again = RemoteAccess.applyFromPreferences(p.prefs, exposed = true, sysProp = noProps)
        assertFalse(again.generatedToken, "the saved token is reused across reloads")
        assertEquals(token, again.config.token)
    }

    @Test fun `require-auth opt-in applies on loopback`() {
        val p = FakePrefs().apply { booleans[RemoteAccess.PREF_REQUIRE_AUTH] = true; strings[RemoteAccess.PREF_AUTH_TOKEN] = "pref-token" }
        val r = RemoteAccess.applyFromPreferences(p.prefs, exposed = false, sysProp = noProps)
        assertTrue(r.config.authRequired)
        assertEquals("pref-token", r.config.token)
        assertFalse(r.generatedToken)
    }

    @Test fun `system properties win over preferences but cannot turn auth off when exposed`() {
        val p = FakePrefs().apply {
            strings[RemoteAccess.PREF_AUTH_TOKEN] = "pref-token"
            strings[RemoteAccess.PREF_ALLOWED_IPS] = "10.0.0.1"
        }
        val props = mapOf(
            RemoteAccess.PROP_REQUIRE_AUTH to "false",
            RemoteAccess.PROP_AUTH_TOKEN to "  prop-token ",
            RemoteAccess.PROP_ALLOWED_IPS to "192.168.56.1, 100.64.0.0/10",
            RemoteAccess.PROP_ALLOWED_HOSTS to "burp-vm.tailnet.ts.net"
        )
        val r = RemoteAccess.applyFromPreferences(p.prefs, exposed = true, sysProp = { props[it] })
        assertTrue(r.config.authRequired)
        assertEquals("prop-token", r.config.token)
        assertFalse(r.generatedToken)
        assertEquals("pref-token", p.strings[RemoteAccess.PREF_AUTH_TOKEN], "a -D token is never written to the preferences")
        assertEquals(listOf("192.168.56.1", "100.64.0.0/10"), r.config.allowedIps)
        assertEquals(listOf("burp-vm.tailnet.ts.net"), r.config.allowedHosts)
    }

    @Test fun `reapply keeps the recorded exposure`() {
        val p = FakePrefs()
        RemoteAccess.applyFromPreferences(p.prefs, exposed = true, sysProp = noProps)
        p.strings[RemoteAccess.PREF_ALLOWED_IPS] = "192.168.56.1"
        val r = RemoteAccess.reapply(p.prefs)
        assertTrue(r.config.authRequired)
        assertEquals(listOf("192.168.56.1"), RemoteAccess.current.allowedIps)
    }

    @Test fun `list settings split on commas, whitespace and semicolons`() {
        assertEquals(listOf("a", "b", "c"), RemoteAccess.parseList(" a, b;c\n a "))
        assertTrue(RemoteAccess.parseList(null).isEmpty())
    }

    @Test fun `warnings flag an exposed bind without a source allowlist and unusable entries, never the token`() {
        val secret = "SECRET-TOKEN-123"
        val exposedOpen = RemoteAccess.warnings(RemoteAccess.Config(authRequired = true, token = secret), exposed = true)
        assertEquals(1, exposedOpen.size)
        assertTrue(exposedOpen.single().contains(RemoteAccess.PREF_ALLOWED_IPS))

        val bad = RemoteAccess.warnings(
            RemoteAccess.Config(authRequired = true, token = secret, allowedIps = listOf("10.0.0.1", "tailnet"), allowedHosts = listOf("*.ts.net")),
            exposed = true
        )
        assertEquals(2, bad.size, bad.toString())
        assertTrue(bad.any { "tailnet" in it } && bad.any { "*.ts.net" in it })
        assertTrue((exposedOpen + bad).none { secret in it })

        assertTrue(RemoteAccess.warnings(RemoteAccess.Config(), exposed = false).isEmpty())
    }
}
