package io.bitbytelab.raijin.bridge

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The host, URL and header conditions that traffic rules and proxy rules share. */
class RuleMatcherTest {

    @Test
    fun `headers are searched as Name colon value lines joined by CRLF, ignoring case`() {
        val headers = listOf(fakeHeader("Host", "app.test"), fakeHeader("X-Api-Key", "k1"))
        assertTrue(RuleMatcher.headers("\\AHost: app\\.test\\r\\nX-Api-Key: k1\\z", headers), "nothing after the last line")
        assertTrue(RuleMatcher.headers("x-api-key: K1", headers))
        assertTrue(RuleMatcher.headers("\\A\\z", emptyList()))
    }

    @Test
    fun `a URL is searched ignoring case, and a URL or host Burp could not give never matches`() {
        assertTrue(RuleMatcher.url("/API/", "https://app.test/api/users"))
        assertFalse(RuleMatcher.url("/admin", "https://app.test/api/users"))
        assertFalse(RuleMatcher.url(".*", null))
        assertTrue(RuleMatcher.host("*.app.test", "API.app.test"))
        assertFalse(RuleMatcher.host("*", null))
    }
}
