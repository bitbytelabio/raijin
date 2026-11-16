package io.bitbytelab.raijin.webprobe

import io.bitbytelab.raijin.webprobe.CacheSignals.State
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CacheSignalsTest {

    private fun classify(vararg headers: Pair<String, String>) = CacheSignals.classify(mapOf(*headers))

    private fun state(vararg headers: Pair<String, String>) = classify(*headers).state

    @Test
    fun `Cloudflare's cache status is read word by word`() {
        assertEquals(State.HIT, state("cf-cache-status" to "HIT"))
        assertEquals(State.HIT, state("cf-cache-status" to "REVALIDATED"))
        assertEquals(State.HIT, state("cf-cache-status" to "STALE"))
        assertEquals(State.MISS, state("cf-cache-status" to "MISS"))
        assertEquals(State.MISS, state("cf-cache-status" to "EXPIRED"))
        assertEquals(State.UNCACHEABLE, state("cf-cache-status" to "DYNAMIC"))
        assertEquals(State.UNCACHEABLE, state("cf-cache-status" to "BYPASS"))
        assertEquals("cloudflare", classify("cf-cache-status" to "HIT").vendor)
        assertEquals(listOf("cf-cache-status: HIT"), classify("cf-cache-status" to "HIT").evidence)
    }

    @Test
    fun `X-Cache is read in its many dialects`() {
        assertEquals(State.HIT, state("x-cache" to "HIT"))
        assertEquals(State.MISS, state("x-cache" to "MISS"))
        assertEquals(State.HIT, state("x-cache" to "Hit from cloudfront"))
        assertEquals(State.MISS, state("x-cache" to "Miss from cloudfront"))
        assertEquals(State.HIT, state("x-cache" to "RefreshHit from cloudfront"))
        assertEquals(State.UNKNOWN, state("x-cache" to "Error from cloudfront"))
        assertEquals(State.HIT, state("x-cache" to "TCP_HIT from a23-1-2-3.deploy.akamaitechnologies.com (AkamaiGHost/9.5)"))
        assertEquals(State.MISS, state("x-cache" to "TCP_REFRESH_MISS"))
        assertEquals(State.UNCACHEABLE, state("x-cache" to "CONFIG_NOCACHE"))
        assertEquals(State.UNCACHEABLE, state("x-cache" to "PRIVATE_NOSTORE"))
    }

    @Test
    fun `with several cache tiers the one nearest the client decides`() {
        // Fastly: shield missed, edge hit.
        assertEquals(State.HIT, state("x-cache" to "MISS, HIT"))
        assertEquals(State.MISS, state("x-cache" to "HIT, MISS"))
        assertEquals(State.HIT, state("x-cache" to "MISS", "x-cache-hits" to "0, 3", "cf-cache-status" to "HIT"))
    }

    @Test
    fun `other caches announce themselves in their own headers`() {
        assertEquals(State.HIT, state("x-cache-status" to "HIT"))
        assertEquals(State.UNCACHEABLE, state("x-cache-status" to "BYPASS"))
        assertEquals(State.HIT, state("x-vercel-cache" to "HIT"))
        assertEquals(State.MISS, state("x-drupal-cache" to "MISS"))
        assertEquals(State.HIT, state("x-litespeed-cache" to "hit"))
        assertEquals(State.HIT, state("cache-status" to "ExampleCache; hit; ttl=120"))
        assertEquals(State.MISS, state("cache-status" to "ExampleCache; fwd=uri-miss; stored"))
        assertEquals(State.UNCACHEABLE, state("cache-status" to "ExampleCache; fwd=bypass"))
        assertEquals(State.MISS, state("x-rack-cache" to "miss, store"))
        assertEquals(State.HIT, state("x-rack-cache" to "fresh"))
        assertEquals(State.HIT, state("server-timing" to "cdn-cache; desc=HIT, edge; dur=1"))
        assertEquals(State.MISS, state("server-timing" to "cdn-cache-miss, cdn-pop;desc=\"LHR50\""))
    }

    @Test
    fun `hit counters, Varnish ids and Age decide when no status word does`() {
        assertEquals(State.HIT, state("x-cache-hits" to "2"))
        assertEquals(State.MISS, state("x-cache-hits" to "0"))
        assertEquals(State.HIT, state("x-cache-hits" to "0, 1"))
        assertEquals(State.HIT, state("x-varnish" to "32770 32768"))
        assertEquals(State.MISS, state("x-varnish" to "32770"))
        assertEquals(State.HIT, state("age" to "37"))
        assertEquals(State.UNKNOWN, state("age" to "0"))
        assertEquals(37, classify("age" to "37").age)
        // A status word outranks the weaker signs.
        assertEquals(State.MISS, state("x-cache" to "MISS", "age" to "37"))
    }

    @Test
    fun `no cache header means unknown, not miss`() {
        val observed = classify("content-type" to "text/html", "server" to "nginx")
        assertEquals(State.UNKNOWN, observed.state)
        assertTrue(observed.evidence.isEmpty())
        assertNull(observed.vendor)
        assertNull(observed.age)
        assertNull(observed.storable)
    }

    @Test
    fun `Cache-Control says whether a shared cache may store the response`() {
        assertEquals(true, classify("cache-control" to "public, max-age=3600").storable)
        assertEquals(true, classify("cache-control" to "s-maxage=60").storable)
        assertEquals(false, classify("cache-control" to "no-store").storable)
        assertEquals(false, classify("cache-control" to "private, max-age=600").storable)
        assertNull(classify("cache-control" to "max-age=0").storable)
        assertNull(classify("cache-control" to "no-cache").storable)
    }

    @Test
    fun `the CDN is recognised from its own headers`() {
        assertEquals("cloudflare", classify("cf-ray" to "8a1b2c3d4e5f-LHR").vendor)
        assertEquals("cloudfront", classify("x-amz-cf-id" to "abc", "x-cache" to "Miss from cloudfront").vendor)
        assertEquals("cloudfront", classify("via" to "1.1 abc.cloudfront.net (CloudFront)").vendor)
        assertEquals("akamai", classify("x-cache" to "TCP_MISS from a1.deploy.akamaitechnologies.com").vendor)
        assertEquals("fastly", classify("x-served-by" to "cache-lhr1234-LHR", "x-cache-hits" to "0", "x-cache" to "MISS").vendor)
        assertEquals("azure", classify("x-azure-ref" to "0abc").vendor)
        assertEquals("vercel", classify("x-vercel-cache" to "MISS").vendor)
        assertEquals("netlify", classify("x-nf-request-id" to "01H").vendor)
        assertEquals("varnish", classify("via" to "1.1 varnish (Varnish/6.0)", "x-varnish" to "1 2").vendor)
        assertEquals("nginx", classify("x-cache-status" to "MISS").vendor)
    }
}
