package io.bitbytelab.raijin.transport

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The source IP / CIDR allowlist: literal-only parsing (no DNS), containment, loopback always allowed. */
class SourceAddressPolicyTest {

    private fun ranges(vararg entries: String) = entries.map { assertNotNull(SourceAddressPolicy.parseRange(it), it) }

    @Test fun `parses IPv4, IPv6, brackets, zone ids and mapped addresses`() {
        assertEquals(4, SourceAddressPolicy.parseAddress("192.168.56.1")?.address?.size)
        assertEquals(16, SourceAddressPolicy.parseAddress("fd7a:115c:a1e0::1")?.address?.size)
        assertEquals(16, SourceAddressPolicy.parseAddress("[::1]")?.address?.size)
        assertEquals(16, SourceAddressPolicy.parseAddress("fe80::1%en0")?.address?.size)
        // IPv4-mapped IPv6 comes back as IPv4, so IPv4 ranges match it.
        assertEquals("10.0.2.2", SourceAddressPolicy.parseAddress("::ffff:10.0.2.2")?.hostAddress)
    }

    @Test fun `rejects names and malformed literals without resolving them`() {
        for (bad in listOf("localhost", "burp.internal", "256.1.1.1", "1.2.3", "g::1", "", " ", "1.2.3.4.5", "::zz")) {
            assertNull(SourceAddressPolicy.parseAddress(bad), bad)
        }
    }

    @Test fun `parses ranges and rejects out-of-range prefixes`() {
        assertNotNull(SourceAddressPolicy.parseRange("100.64.0.0/10"))
        assertNotNull(SourceAddressPolicy.parseRange("0.0.0.0/0"))
        assertNotNull(SourceAddressPolicy.parseRange("fd7a:115c:a1e0::/48"))
        assertNotNull(SourceAddressPolicy.parseRange("::/0"))
        for (bad in listOf("10.0.0.0/33", "10.0.0.0/-1", "10.0.0.0/x", "::/129", "tailnet/10", "10.0.0.0/")) {
            assertNull(SourceAddressPolicy.parseRange(bad), bad)
        }
        assertEquals(listOf("tailnet", "10.0.0.0/33"), SourceAddressPolicy.invalidEntries(listOf("10.0.0.1", "tailnet", "10.0.0.0/33")))
    }

    @Test fun `CIDR containment respects partial-byte prefixes`() {
        val cgnat = ranges("100.64.0.0/10")
        assertTrue(SourceAddressPolicy.isAllowed("100.64.0.0", cgnat))
        assertTrue(SourceAddressPolicy.isAllowed("100.127.255.255", cgnat))
        assertFalse(SourceAddressPolicy.isAllowed("100.63.255.255", cgnat))
        assertFalse(SourceAddressPolicy.isAllowed("100.128.0.0", cgnat))

        val v6 = ranges("fd7a:115c:a1e0::/48")
        assertTrue(SourceAddressPolicy.isAllowed("fd7a:115c:a1e0:ffff::9", v6))
        assertFalse(SourceAddressPolicy.isAllowed("fd7a:115c:a1e1::9", v6))
        assertFalse(SourceAddressPolicy.isAllowed("100.64.0.1", v6), "an IPv4 peer never matches an IPv6 range")
    }

    @Test fun `a single address matches only itself`() {
        val host = ranges("192.168.56.1")
        assertTrue(SourceAddressPolicy.isAllowed("192.168.56.1", host))
        assertTrue(SourceAddressPolicy.isAllowed("::ffff:192.168.56.1", host))
        assertFalse(SourceAddressPolicy.isAllowed("192.168.56.10", host))
    }

    @Test fun `no allowlist allows every source, an active one refuses non-literals`() {
        assertTrue(SourceAddressPolicy.isAllowed("203.0.113.9", null))
        assertTrue(SourceAddressPolicy.isAllowed("unknown", null))
        val list = ranges("10.0.2.2")
        assertFalse(SourceAddressPolicy.isAllowed("unknown", list))
        assertFalse(SourceAddressPolicy.isAllowed("", list))
        // Entries that were all invalid still leave the allowlist active: only loopback gets in.
        assertFalse(SourceAddressPolicy.isAllowed("203.0.113.9", emptyList()))
        assertTrue(SourceAddressPolicy.isAllowed("127.0.0.1", emptyList()))
    }

    @Test fun `loopback always passes an active allowlist`() {
        val list = ranges("10.0.2.2")
        for (peer in listOf("127.0.0.1", "127.8.9.10", "::1", "0:0:0:0:0:0:0:1", "localhost")) {
            assertTrue(SourceAddressPolicy.isAllowed(peer, list), peer)
        }
    }

    @Test fun `formats IPv6 per RFC 5952`() {
        fun fmt(s: String) = SourceAddressPolicy.formatIpv6(SourceAddressPolicy.parseAddress(s)!!.address)
        assertEquals("::1", fmt("0:0:0:0:0:0:0:1"))
        assertEquals("::", fmt("0:0:0:0:0:0:0:0"))
        assertEquals("fe80::1c2b:3cff:fe4d:5e6f", fmt("FE80:0:0:0:1C2B:3CFF:FE4D:5E6F"))
        assertEquals("2001:db8::1", fmt("2001:0db8:0000:0000:0000:0000:0000:0001"))
        assertEquals("1:0:1::1:0:0", fmt("1:0:1:0:0:1:0:0"), "first of equally long zero runs")
        assertEquals("1:0:2:3:4:5:6:7", fmt("1:0:2:3:4:5:6:7"), "a single zero group is not compressed")
        assertEquals("1::", fmt("1:0:0:0:0:0:0:0"))
    }
}
