package io.bitbytelab.raijin.recon

import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ProbeHttpTest {

    private val base = ProbeRequest("GET", "/a?x=1", listOf("Host" to "t.example", "User-Agent" to "ua"))

    @Test
    fun `a request renders as HTTP 1 text with its headers as given`() {
        assertEquals("GET /a?x=1 HTTP/1.1\r\nHost: t.example\r\nUser-Agent: ua\r\n\r\n", base.render())
    }

    @Test
    fun `Content-Length is counted for a body and left alone when the request declares its framing`() {
        val post = base.copy(method = "POST")
        assertTrue(post.withBody("a=1").render().endsWith("User-Agent: ua\r\nContent-Length: 3\r\n\r\na=1"))
        assertTrue(post.render().contains("\r\nContent-Length: 0\r\n\r\n"), "a POST without a body still says so")
        assertTrue("Content-Length" !in base.render(), "a GET without a body has no Content-Length")

        val declared = post.withBody("abc").withHeader("Content-Length", "99")
        assertEquals(1, Regex("Content-Length").findAll(declared.render()).count())
        assertTrue(declared.render().contains("Content-Length: 99\r\n"))
        assertTrue("Content-Length" !in post.withBody("abc").withHeader("Transfer-Encoding", "chunked").render())
    }

    @Test
    fun `Content-Length counts bytes in the charset the request is sent with`() {
        val post = base.copy(method = "POST")
        // U+00E9 goes out as one Latin-1 byte; a character beyond U+00FF makes the whole message UTF-8.
        assertTrue(post.withBody("\u00e9").render().contains("Content-Length: 1\r\n"))
        assertTrue(post.withBody("\u20ac").render().contains("Content-Length: 3\r\n"))
        assertTrue(post.withBody("\u00e9\u20ac").render().contains("Content-Length: 5\r\n"))
    }

    @Test
    fun `replacing the body drops a Content-Length written for the old one`() {
        val request = base.copy(method = "POST").withHeader("Content-Length", "3").withBody("longer body")
        assertNull(request.header("content-length"))
        assertTrue(request.render().contains("Content-Length: 11\r\n"))
    }

    @Test
    fun `setting a header replaces every header of that name, whatever its case`() {
        val request = ProbeRequest("GET", "/", listOf("A" to "1", "b" to "2", "a" to "3"))
        assertEquals(listOf("a" to "9", "b" to "2"), request.withHeader("a", "9").headers)
        assertEquals(listOf("A" to "1", "b" to "2", "a" to "3", "C" to "4"), request.withHeader("C", "4").headers)
        assertEquals("1", request.header("a"))
        assertEquals(listOf("b" to "2"), request.withoutHeader("A").headers)
        assertEquals(listOf("A" to "x", "b" to "y"), request.withHeaders(listOf("A" to "x", "B" to "ignored", "b" to "y")).headers)
    }

    @Test
    fun `query pairs are appended, the path is replaced without touching the query`() {
        assertEquals("/a?x=1&y=2", base.withQuery("y=2").target)
        assertEquals("/p?y=2", base.copy(target = "/p").withQuery("y=2").target)
        assertEquals(base, base.withQuery(""))
        assertEquals("/b/c.css?x=1", base.withPath("/b/c.css").target)
        assertEquals("/b", base.copy(target = "/a").withPath("/b").target)
        assertEquals("/a", base.path)
        assertEquals("x=1", base.query)
        assertNull(base.copy(target = "/a").query)
    }

    @Test
    fun `cookies are added after the ones already there`() {
        assertEquals("a=1", base.withCookies("a=1").header("Cookie"))
        assertEquals("s=1; a=1", base.withHeader("Cookie", "s=1;").withCookies("a=1").header("Cookie"))
        assertEquals(base, base.withCookies(""))
    }

    @Test
    fun `an absolute URL is split without rewriting its path or query`() {
        val parts = UrlParts.parse("https://App.Example.com:8443/a/b;x%00?q=1&r=%2F#frag")!!
        assertEquals("https", parts.scheme)
        assertEquals("app.example.com", parts.host)
        assertEquals(8443, parts.port)
        assertEquals("/a/b;x%00", parts.path)
        assertEquals("q=1&r=%2F", parts.query)
        assertEquals("https://app.example.com:8443", parts.origin)
        assertEquals("/a/", parts.directory)
        assertTrue(parts.secure)

        val bare = UrlParts.parse("http://h")!!
        assertEquals("/", bare.path)
        assertNull(bare.query)
        assertNull(bare.port)
        assertEquals("http://h", bare.origin)

        assertEquals("h", UrlParts.parse("https://user:secret@h/x")!!.host)
        val v6 = UrlParts.parse("http://[::1]:8080/")!!
        assertEquals("[::1]", v6.host)
        assertEquals(8080, v6.port)
        assertEquals("[::1]", UrlParts.parse("http://[::1]/")!!.host)
    }

    @Test
    fun `what is not an http URL does not parse`() {
        assertNull(UrlParts.parse("ftp://h/x"))
        assertNull(UrlParts.parse("not a url"))
        assertNull(UrlParts.parse("https://h:port/"))
        assertNull(UrlParts.parse("https:///path"))
    }

    @Test
    fun `pair parts keep everything but what would break the pair apart`() {
        assertEquals("a%20b%26c%3Dd%23e%2Bf%3Bg", ProbeText.encodePairPart("a b&c=d#e+f;g"))
        assertEquals("%C3%A9", ProbeText.encodePairPart("\u00e9"))
        assertEquals("%0D%0A", ProbeText.encodePairPart("\r\n"))
        // Already encoded, or odd on purpose: left as typed.
        assertEquals("%41[0]'\"<x>", ProbeText.encodePairPart("%41[0]'\"<x>"))
        assertEquals("plain_name-1.x", ProbeText.encodePairPart("plain_name-1.x"))
        assertEquals("a=1&b%20c=2", ProbeText.pairs(listOf("a" to "1", "b c" to "2"), "&"))
        assertEquals("", ProbeText.pairs(emptyList(), "&"))
    }

    @Test
    fun `tokens are lower-case, start with a letter and follow the random source`() {
        val token = ProbeText.token(Random(3), 12)
        assertEquals(12, token.length)
        assertTrue(token[0].isLetter() && token.all { it.isLowerCase() || it.isDigit() }, token)
        assertEquals(token, ProbeText.token(Random(3), 12))
    }
}
