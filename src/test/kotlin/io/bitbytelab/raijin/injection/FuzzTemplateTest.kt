package io.bitbytelab.raijin.injection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class FuzzTemplateTest {

    private fun get(target: String, vararg headers: String): String =
        "GET $target HTTP/1.1\r\nHost: t\r\n" + headers.joinToString("") { "$it\r\n" } + "\r\n"

    private fun post(contentType: String?, body: String): String =
        "POST /api HTTP/1.1\r\nHost: t\r\n" + (contentType?.let { "Content-Type: $it\r\n" } ?: "") +
            "Content-Length: ${body.length}\r\n\r\n$body"

    private fun contexts(request: String): List<FuzzContext> = FuzzTemplate.parse(request).contexts

    private fun render(request: String, payload: String, encoding: PayloadEncoding = PayloadEncoding.AUTO): String =
        FuzzTemplate.parse(request).render(payload, encoding)

    private fun requestLine(request: String): String = request.substringBefore("\r\n")

    private fun body(request: String): String = request.substringAfter("\r\n\r\n")

    private fun contentLength(request: String): Int =
        Regex("Content-Length: (\\d+)").find(request)!!.groupValues[1].toInt()

    // ---------------------------------------------------------------
    // Context detection
    // ---------------------------------------------------------------

    @Test
    fun `markers are classified by where they sit`() {
        assertEquals(listOf(FuzzContext.URL_QUERY), contexts(get("/search?q=FUZZ")))
        assertEquals(listOf(FuzzContext.URL_PATH), contexts(get("/files/FUZZ")))
        assertEquals(listOf(FuzzContext.COOKIE), contexts(get("/", "Cookie: TrackingId=FUZZ")))
        assertEquals(listOf(FuzzContext.HEADER), contexts(get("/", "X-Forwarded-For: FUZZ")))
        assertEquals(listOf(FuzzContext.FORM), contexts(post("application/x-www-form-urlencoded", "a=1&b=FUZZ")))
        assertEquals(listOf(FuzzContext.JSON_STRING), contexts(post("application/json; charset=utf-8", "{\"a\":\"FUZZ\"}")))
        assertEquals(listOf(FuzzContext.JSON_VALUE), contexts(post("application/json", "{\"a\":FUZZ}")))
        assertEquals(listOf(FuzzContext.XML), contexts(post("text/xml", "<a><b>FUZZ</b></a>")))
        assertEquals(listOf(FuzzContext.RAW), contexts(post("multipart/form-data; boundary=x", "--x\r\n\r\nFUZZ\r\n--x--")))
        assertEquals(listOf(FuzzContext.RAW), contexts("FUZZ / HTTP/1.1\r\nHost: t\r\n\r\n"))
    }

    @Test
    fun `a body without a useful content type is classified by its shape`() {
        assertEquals(listOf(FuzzContext.JSON_STRING), contexts(post(null, "{\"a\":\"FUZZ\"}")))
        assertEquals(listOf(FuzzContext.JSON_STRING), contexts(post("text/plain", "{\"a\":\"FUZZ\"}")))
        assertEquals(listOf(FuzzContext.FORM), contexts(post(null, "a=FUZZ&b=2")))
        assertEquals(listOf(FuzzContext.XML), contexts(post(null, "<a>FUZZ</a>")))
        assertEquals(listOf(FuzzContext.RAW), contexts(post(null, "FUZZ")))
        assertEquals(listOf(FuzzContext.RAW), contexts(post(null, "some text FUZZ here")))
    }

    @Test
    fun `a request without the marker has no contexts`() {
        val template = FuzzTemplate.parse(get("/search?q=1"))
        assertFalse(template.hasMarker)
        assertTrue(template.contexts.isEmpty())
    }

    // ---------------------------------------------------------------
    // Encoding per context
    // ---------------------------------------------------------------

    @Test
    fun `a query payload cannot break the request line`() {
        val request = get("/search?q=FUZZ")
        assertEquals("GET /search?q=a%20b%26c%231 HTTP/1.1", requestLine(render(request, "a b&c#1")))
        assertEquals("GET /search?q='%20OR%20%221%22%3D%221 HTTP/1.1", requestLine(render(request, "' OR \"1\"=\"1")))
        assertEquals("GET /search?q=%7B%7B7*7%7D%7D HTTP/1.1", requestLine(render(request, "{{7*7}}")))
        assertEquals("GET /search?q=1%0D%0AX-A:%201 HTTP/1.1", requestLine(render(request, "1\r\nX-A: 1")))
        assertEquals("GET /search?q=a%2Bb%3Bc HTTP/1.1", requestLine(render(request, "a+b;c")))
    }

    @Test
    fun `percent sequences a payload already has are kept and a stray percent is encoded`() {
        val request = get("/search?q=FUZZ")
        assertEquals("GET /search?q=..%2f..%2fetc%2fpasswd HTTP/1.1", requestLine(render(request, "..%2f..%2fetc%2fpasswd")))
        assertEquals("GET /search?q=x%0d%0aY:%201 HTTP/1.1", requestLine(render(request, "x%0d%0aY: 1")))
        assertEquals("GET /search?q=100%25 HTTP/1.1", requestLine(render(request, "100%")))
        assertEquals("GET /search?q=%25zz%25a HTTP/1.1", requestLine(render(request, "%zz%a")))
    }

    @Test
    fun `non-ASCII characters are percent-encoded as UTF-8 in a URL`() {
        val request = get("/search?q=FUZZ")
        assertEquals("GET /search?q=%C3%A9 HTTP/1.1", requestLine(render(request, "\u00e9")))
        assertEquals("GET /search?q=%F0%9F%98%80 HTTP/1.1", requestLine(render(request, "\uD83D\uDE00")))
    }

    @Test
    fun `a path payload keeps path delimiters and encodes what ends the path`() {
        val request = get("/files/FUZZ")
        assertEquals("GET /files/../../etc/passwd HTTP/1.1", requestLine(render(request, "../../etc/passwd")))
        assertEquals("GET /files/a%20b%3Fc%23d HTTP/1.1", requestLine(render(request, "a b?c#d")))
        assertEquals("GET /files/a&b=c;d+e HTTP/1.1", requestLine(render(request, "a&b=c;d+e")))
    }

    @Test
    fun `a form payload is encoded and Content-Length follows`() {
        val rendered = render(post("application/x-www-form-urlencoded", "a=1&b=FUZZ"), "x y&z=1")
        assertEquals("a=1&b=x%20y%26z%3D1", body(rendered))
        assertEquals(19, contentLength(rendered))
    }

    @Test
    fun `a JSON string payload is escaped and Content-Length follows`() {
        val rendered = render(post("application/json", "{\"user\":\"FUZZ\"}"), "' OR \"1\"=\"1")
        assertEquals("{\"user\":\"' OR \\\"1\\\"=\\\"1\"}", body(rendered))
        assertEquals(25, contentLength(rendered))

        val control = render(post("application/json", "{\"user\":\"FUZZ\"}"), "a\\b\r\n\tc\u0001")
        assertEquals("{\"user\":\"a\\\\b\\r\\n\\tc\\u0001\"}", body(control))
    }

    @Test
    fun `a bare JSON value stays valid JSON`() {
        val request = post("application/json", "{\"id\":FUZZ}")
        assertEquals("{\"id\":1}", body(render(request, "1")))
        assertEquals("{\"id\":-2.5e3}", body(render(request, "-2.5e3")))
        assertEquals("{\"id\":true}", body(render(request, "true")))
        assertEquals("{\"id\":{\"\$gt\":\"\"}}", body(render(request, "{\"\$gt\":\"\"}")))
        assertEquals("{\"id\":\"1 AND 1=1\"}", body(render(request, "1 AND 1=1")))
        assertEquals("{\"id\":\"1'\\\"\"}", body(render(request, "1'\"")))
        assertEquals("{\"id\":\"{broken\"}", body(render(request, "{broken")))
    }

    @Test
    fun `an XML payload is escaped`() {
        val rendered = render(post("application/xml", "<a><b>FUZZ</b></a>"), "<x>&'\"")
        assertEquals("<a><b>&lt;x&gt;&amp;&apos;&quot;</b></a>", body(rendered))
        assertEquals(body(rendered).length, contentLength(rendered))
    }

    @Test
    fun `a header payload stays on its line and a cookie payload in its pair`() {
        val cookie = render(get("/", "Cookie: TrackingId=FUZZ; theme=dark"), "x';SELECT 1-- -\r\nX-A: 1")
        assertTrue("Cookie: TrackingId=x'%3BSELECT 1-- -%0D%0AX-A: 1; theme=dark\r\n" in cookie, cookie)

        val header = render(get("/", "X-Forwarded-For: FUZZ"), "1;2\r\nX-A: 1")
        assertTrue("X-Forwarded-For: 1;2%0D%0AX-A: 1\r\n" in header, header)
    }

    @Test
    fun `each marker is encoded for its own position`() {
        val request = "POST /api?x=FUZZ HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\nContent-Length: 12\r\n\r\n{\"a\":\"FUZZ\"}"
        val template = FuzzTemplate.parse(request)
        assertEquals(listOf(FuzzContext.URL_QUERY, FuzzContext.JSON_STRING), template.contexts)
        val rendered = template.render("a \"b\"")
        assertEquals("POST /api?x=a%20%22b%22 HTTP/1.1", requestLine(rendered))
        assertEquals("{\"a\":\"a \\\"b\\\"\"}", body(rendered))
        assertEquals("a%20%22b%22", template.encoded("a \"b\""))
    }

    // ---------------------------------------------------------------
    // Explicit encoding
    // ---------------------------------------------------------------

    @Test
    fun `raw sends the payload byte for byte`() {
        val rendered = render(get("/search?q=FUZZ"), "a b\r\nX: 1", PayloadEncoding.RAW)
        assertTrue(rendered.startsWith("GET /search?q=a b\r\nX: 1 HTTP/1.1\r\n"), rendered)
        assertEquals("{\"a\":\"x\"y\"}", body(render(post("application/json", "{\"a\":\"FUZZ\"}"), "x\"y", PayloadEncoding.RAW)))
    }

    @Test
    fun `url, json and xml force one encoder whatever the position`() {
        val json = post("application/json", "{\"a\":\"FUZZ\"}")
        assertEquals("{\"a\":\"a%20b%22\"}", body(render(json, "a b\"", PayloadEncoding.URL)))
        assertEquals("{\"a\":\"&lt;b&gt;\"}", body(render(json, "<b>", PayloadEncoding.XML)))
        assertEquals("GET /search?q=a\\\"b HTTP/1.1", requestLine(render(get("/search?q=FUZZ"), "a\"b", PayloadEncoding.JSON)))
    }

    @Test
    fun `encoding ids resolve case-insensitively and unknown ones do not`() {
        assertEquals(PayloadEncoding.AUTO, PayloadEncoding.fromId("auto"))
        assertEquals(PayloadEncoding.RAW, PayloadEncoding.fromId(" RAW "))
        assertNull(PayloadEncoding.fromId("base64"))
        assertNull(PayloadEncoding.fromId(null))
        assertEquals(listOf("auto", "raw", "url", "json", "xml"), PayloadEncoding.ids)
    }

    // ---------------------------------------------------------------
    // Content-Length
    // ---------------------------------------------------------------

    @Test
    fun `Content-Length is counted in the charset the request is sent in`() {
        val request = post("application/json", "{\"a\":\"FUZZ\"}")
        // U+00E9 fits one byte, so the request stays ISO-8859-1.
        assertEquals(9, contentLength(render(request, "\u00e9")))
        // U+20AC does not, so the whole request goes out as UTF-8 (three bytes for the character).
        assertEquals(11, contentLength(render(request, "\u20ac")))
    }

    @Test
    fun `a deliberate Transfer-Encoding request keeps its Content-Length`() {
        val request = "POST /api HTTP/1.1\r\nHost: t\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\na=FUZZ"
        assertEquals(3, contentLength(render(request, "a much longer payload")))
    }

    // ---------------------------------------------------------------
    // Structural rewrites
    // ---------------------------------------------------------------

    @Test
    fun `operator pairs replace a query or form parameter`() {
        val operators = listOf("\$gt" to "", "\$lt" to "~ ~")
        val query = FuzzTemplate.parse(get("/users?role=x&user=FUZZ&page=2")).renderKeyOperators(operators)
        assertEquals("GET /users?role=x&user%5B\$gt%5D=&user%5B\$lt%5D=~%20~&page=2 HTTP/1.1", requestLine(query!!))

        val form = FuzzTemplate.parse(post("application/x-www-form-urlencoded", "next=/a?b&user=FUZZ")).renderKeyOperators(operators)
        assertEquals("next=/a?b&user%5B\$gt%5D=&user%5B\$lt%5D=~%20~", body(form!!))
        assertEquals(body(form).length, contentLength(form))
    }

    @Test
    fun `operator pairs need a named parameter value`() {
        val operators = listOf("\$gt" to "")
        assertNull(FuzzTemplate.parse(get("/users/FUZZ")).renderKeyOperators(operators))
        assertNull(FuzzTemplate.parse(get("/users?FUZZ=1")).renderKeyOperators(operators))
        assertNull(FuzzTemplate.parse(post("application/json", "{\"user\":\"FUZZ\"}")).renderKeyOperators(operators))
        assertNull(FuzzTemplate.parse(get("/users?user=FUZZ")).renderKeyOperators(emptyList()))
    }

    @Test
    fun `a JSON value is replaced whole, quotes included`() {
        val operator = "{\"\$gt\":\"\"}"
        assertEquals(
            "{\"user\":{\"\$gt\":\"\"},\"n\":1}",
            body(FuzzTemplate.parse(post("application/json", "{\"user\":\"FUZZ\",\"n\":1}")).renderJsonValue(operator)!!)
        )
        assertEquals("{\"id\":{\"\$gt\":\"\"}}", body(FuzzTemplate.parse(post("application/json", "{\"id\":FUZZ}")).renderJsonValue(operator)!!))
        assertNull(FuzzTemplate.parse(post("application/json", "{\"user\":\"xFUZZ\"}")).renderJsonValue(operator))
        assertNull(FuzzTemplate.parse(get("/users?user=FUZZ")).renderJsonValue(operator))
    }

    @Test
    fun `an entity probe adds a DOCTYPE to the XML body and a raw reference at the marker`() {
        val xml = "<?xml version=\"1.0\"?><stock><id>FUZZ</id></stock>"
        val rendered = FuzzTemplate.parse(post("application/xml", xml))
            .renderXmlEntity("<!ENTITY x SYSTEM \"file:///etc/passwd\">", "&x;")
        assertEquals(
            "<?xml version=\"1.0\"?><!DOCTYPE stock [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><stock><id>&x;</id></stock>",
            body(rendered!!)
        )
        assertEquals(body(rendered).length, contentLength(rendered))
    }

    @Test
    fun `an entity probe does not apply without a root element, with a DOCTYPE or outside XML`() {
        val declarations = "<!ENTITY x \"y\">"
        assertNull(FuzzTemplate.parse(post("application/xml", "FUZZ")).renderXmlEntity(declarations, "&x;"))
        assertNull(
            FuzzTemplate.parse(post("application/xml", "<!DOCTYPE a [<!ENTITY q \"1\">]><a>FUZZ</a>")).renderXmlEntity(declarations, "&x;")
        )
        assertNull(FuzzTemplate.parse(get("/search?q=FUZZ")).renderXmlEntity(declarations, "&x;"))
        assertTrue(FuzzTemplate.parse(post("application/xml", "FUZZ")).inXmlBody)
        assertFalse(FuzzTemplate.parse(get("/search?q=FUZZ")).inXmlBody)
    }
}
