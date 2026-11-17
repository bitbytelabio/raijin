package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.sitemap.SiteMap
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonPrimitive
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Regression tests for BUG #9: sitemap_add_request corrupted UTF-8 request bodies/paths to
 * Latin-1 when constructing an HttpRequest from a Kotlin String via Montoya's lossy String
 * overload. The fix encodes the request to bytes with UTF-8 and uses the ByteArray overload.
 *
 * These exercise the pure charset core ([SitemapBridge.encodeRequestBytes]). The Montoya
 * ByteArray wrapper ([SitemapBridge.requestToByteArray]) is not covered here: it calls the
 * Montoya ByteArray factory, which requires a live Burp runtime (ObjectFactoryLocator.FACTORY
 * is null in a plain unit-test JVM) and cannot be exercised outside Burp.
 */
class SitemapBridgeTest {

    @Test
    fun `encodeRequestBytes preserves multibyte codepoints as UTF-8`() {
        // "café" plus a snowman and a CJK char — all non-Latin-1-representable multibyte cases.
        val body = "café ☃ 日本語"
        val request = "POST /søk HTTP/1.1\r\nHost: x\r\n\r\n$body"

        val actual = SitemapBridge.encodeRequestBytes(request)
        val expected = request.toByteArray(Charsets.UTF_8)

        assertContentEquals(expected, actual, "request must be encoded as UTF-8")
    }

    @Test
    fun `encodeRequestBytes does not narrow to Latin-1`() {
        // A single snowman is 3 bytes in UTF-8 but would be a lossy '?' (or single byte) under
        // ISO-8859-1. Proving the byte count rules out the old Latin-1 narrowing.
        val request = "GET /☃ HTTP/1.1\r\n\r\n"

        val utf8 = SitemapBridge.encodeRequestBytes(request)
        val latin1 = request.toByteArray(Charsets.ISO_8859_1)

        assertTrue(utf8.size > latin1.size, "UTF-8 encoding must widen the multibyte codepoint")
        assertContentEquals(request.toByteArray(Charsets.UTF_8), utf8)
    }

    @Test
    fun `encodeRequestBytes keeps Content-Length byte-accurate for unicode body`() {
        val body = "naïve—payload"
        val expectedLen = body.toByteArray(Charsets.UTF_8).size
        val request = "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: $expectedLen\r\n\r\n$body"

        val bytes = SitemapBridge.encodeRequestBytes(request)
        // The trailing body bytes of the encoded request must equal the UTF-8 body bytes, so a
        // client-declared Content-Length computed from UTF-8 stays accurate on the wire.
        val bodyBytes = body.toByteArray(Charsets.UTF_8)
        val tail = bytes.copyOfRange(bytes.size - bodyBytes.size, bytes.size)
        assertContentEquals(bodyBytes, tail)
    }

    @Test
    fun `plain ASCII request is unchanged`() {
        val request = "GET /health HTTP/1.1\r\nHost: x\r\n\r\n"
        assertContentEquals(
            request.toByteArray(Charsets.UTF_8),
            SitemapBridge.encodeRequestBytes(request)
        )
    }
}

/** [SitemapBridge.query] filtering against proxy stubs of the Montoya site map. */
class SitemapBridgeQueryTest {

    private inline fun <reified T> stub(crossinline answer: (String) -> Any?): T =
        Proxy.newProxyInstance(T::class.java.classLoader, arrayOf(T::class.java)) { _, m, _ -> answer(m.name) } as T

    private fun bridge(): SitemapBridge {
        val request = stub<HttpRequest> { name ->
            when (name) {
                "url" -> "https://t.test/a"
                "method" -> "GET"
                "toString" -> "GET /a HTTP/1.1\r\nHost: t.test\r\nX-Secret: token123\r\n\r\n"
                else -> null
            }
        }
        val entry = stub<HttpRequestResponse> { name ->
            when (name) {
                "request" -> request
                "hasResponse" -> false
                else -> null
            }
        }
        val siteMap = stub<SiteMap> { name -> if (name == "requestResponses") listOf(entry) else null }
        return SitemapBridge(stub<MontoyaApi> { name -> if (name == "siteMap") siteMap else null })
    }

    private fun matched(searchIn: String?, pattern: String) = bridge().query(
        urlPrefix = null, searchPattern = pattern, maxResults = 10,
        includeRequest = false, includeResponse = false, searchIn = searchIn,
    )["matched"]?.jsonPrimitive?.int

    @Test
    fun `search_pattern matches the URL by default and the request only when asked`() {
        assertEquals(1, matched(null, "t\\.test/a"))
        assertEquals(0, matched(null, "token123"))
        assertEquals(1, matched("request", "token123"))
        assertEquals(1, matched("all", "token123"))
    }

    @Test
    fun `invalid regexes are reported as errors instead of thrown`() {
        val bad = bridge().query(
            urlPrefix = null, searchPattern = "(", maxResults = 10,
            includeRequest = false, includeResponse = false,
        )
        assertTrue(bad["error"]?.jsonPrimitive?.content?.startsWith("Invalid search_pattern regex") == true, bad.toString())
        val badExclude = bridge().query(
            urlPrefix = null, searchPattern = null, maxResults = 10,
            includeRequest = false, includeResponse = false, excludePattern = "[",
        )
        assertTrue(badExclude["error"]?.jsonPrimitive?.content?.startsWith("Invalid exclude_pattern regex") == true)
    }

    @Test
    fun `parseSeverity accepts info alias and rejects unknown severities`() {
        assertEquals(
            burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.INFORMATION,
            SitemapBridge.parseSeverity("info"),
        )
        assertEquals(
            burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.INFORMATION,
            SitemapBridge.parseSeverity(" INFO "),
        )
        assertEquals(
            burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.HIGH,
            SitemapBridge.parseSeverity("high"),
        )
        val err = kotlin.test.assertFailsWith<IllegalArgumentException> {
            SitemapBridge.parseSeverity("critical")
        }
        assertTrue("info" in err.message.orEmpty(), err.message)
    }
}
