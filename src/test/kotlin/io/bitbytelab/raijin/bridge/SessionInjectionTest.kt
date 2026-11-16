package io.bitbytelab.raijin.bridge

import burp.api.montoya.http.message.params.HttpParameter
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import io.bitbytelab.raijin.state.SessionRule
import java.lang.reflect.Proxy
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import burp.api.montoya.core.ByteArray as BurpByteArray

/** A [T] whose calls go to [handler] (method name, arguments); a call it does not expect fails the test. */
private inline fun <reified T : Any> fake(noinline handler: (String, Array<out Any?>) -> Any?): T =
    Proxy.newProxyInstance(T::class.java.classLoader, arrayOf(T::class.java)) { proxy, method, args ->
        when (method.name) {
            "toString" -> "fake ${T::class.simpleName}"
            "hashCode" -> System.identityHashCode(proxy)
            "equals" -> proxy === args?.firstOrNull()
            else -> handler(method.name, args ?: emptyArray<Any?>())
        }
    } as T

private fun bytes(data: ByteArray): BurpByteArray = fake { m, _ ->
    when (m) {
        "getBytes" -> data.copyOf()
        "length" -> data.size
        else -> error("ByteArray.$m")
    }
}

private fun parameter(name: String, value: String, type: HttpParameterType): HttpParameter = fake { m, _ ->
    when (m) {
        "name" -> name
        "value" -> value
        "type" -> type
        else -> error("HttpParameter.$m")
    }
}

/** A request with a request target, headers (cookies in one `Cookie` header) and a body; `withBody` keeps Content-Length right as Burp does. */
@Suppress("ArrayInDataClass") // equality is never used: copy() is the point
private data class Message(val path: String, val headers: List<Pair<String, String>>, val body: ByteArray) {
    fun header(name: String) = headers.firstOrNull { it.first.equals(name, ignoreCase = true) }?.second
    fun cookies(): Map<String, String> = header("Cookie")?.split(';')?.map { it.trim() }?.filter { '=' in it }
        ?.associate { it.substringBefore('=') to it.substringAfter('=') }.orEmpty()
    fun form(): Map<String, String> = String(body, Charsets.ISO_8859_1).split('&').filter { '=' in it }
        .associate { it.substringBefore('=') to it.substringAfter('=') }
    fun withHeader(name: String, value: String?) =
        copy(headers = headers.filterNot { it.first.equals(name, ignoreCase = true) } + listOfNotNull(value?.let { name to it }))
}

private fun request(path: String = "/", headers: List<Pair<String, String>> = emptyList(), body: String = ""): HttpRequest =
    request(Message(path, headers, body.toByteArray(Charsets.UTF_8)))

private fun request(m: Message): HttpRequest = fake { name, a ->
    fun parameters(): Array<HttpParameter> = (a[0] as? Array<*>)?.map { it as HttpParameter }?.toTypedArray()
        ?: (a[0] as List<*>).map { it as HttpParameter }.toTypedArray()
    when (name) {
        "path" -> m.path
        "withPath" -> request(m.copy(path = a[0] as String))
        "headerValue" -> m.header(a[0] as String)
        "hasHeader" -> m.header(a[0] as String) != null
        "withUpdatedHeader", "withAddedHeader" -> request(m.withHeader(a[0] as String, a[1] as String))
        "body" -> bytes(m.body)
        "withBody" -> {
            val body = (a[0] as BurpByteArray).bytes
            request(m.copy(body = body).withHeader("Content-Length", body.size.toString()))
        }
        "hasParameter" -> when (a[1]) {
            HttpParameterType.COOKIE -> (a[0] as String) in m.cookies()
            HttpParameterType.BODY -> (a[0] as String) in m.form()
            else -> false
        }
        "parameterValue" -> if (a[1] == HttpParameterType.COOKIE) m.cookies()[a[0] as String] else m.form()[a[0] as String]
        "withUpdatedParameters", "withAddedParameters" -> {
            var updated = m
            for (p in parameters()) {
                updated = if (p.type() == HttpParameterType.COOKIE) {
                    val jar = updated.cookies().toMutableMap().also { it[p.name()] = p.value() }
                    updated.withHeader("Cookie", jar.entries.joinToString("; ") { "${it.key}=${it.value}" })
                } else {
                    val form = updated.form().toMutableMap().also { it[p.name()] = p.value() }
                    updated.copy(body = form.entries.joinToString("&") { "${it.key}=${it.value}" }.toByteArray(Charsets.ISO_8859_1))
                }
            }
            request(updated)
        }
        "toByteArray" -> bytes(m.body)
        else -> error("HttpRequest.$name")
    }
}

private fun HttpRequest.bodyBytes(): ByteArray = body().bytes

private val factory: MontoyaObjectFactory = fake { m, a ->
    when (m) {
        "byteArray" -> bytes(a[0] as ByteArray)
        "cookieParameter" -> parameter(a[0] as String, a[1] as String, HttpParameterType.COOKIE)
        "bodyParameter" -> parameter(a[0] as String, a[1] as String, HttpParameterType.BODY)
        else -> error("MontoyaObjectFactory.$m")
    }
}

class SessionInjectionTest {

    private var previousFactory: MontoyaObjectFactory? = null

    @BeforeTest
    fun installFactory() {
        previousFactory = ObjectFactoryLocator.FACTORY
        ObjectFactoryLocator.FACTORY = factory
    }

    @AfterTest
    fun restoreFactory() {
        ObjectFactoryLocator.FACTORY = previousFactory
    }

    private fun rule(injectInto: String, injectName: String, template: String = "{value}", ifMissing: Boolean = true) = SessionRule(
        ruleName = "r", scope = "all", scopePattern = null, extractFrom = "body", extractHeaderName = null,
        extractRegex = "(.+)", injectInto = injectInto, injectName = injectName, injectValueTemplate = template,
        injectIfMissing = ifMissing,
    )

    // --- query string ---

    @Test
    fun `upsertQuery replaces the first parameter of that name and keeps everything else`() {
        assertEquals("/api?a=1&token=new&b=2", SessionInjection.upsertQuery("/api?a=1&token=old&b=2", "token", "new", true))
        assertEquals("/api?token=new&token=2", SessionInjection.upsertQuery("/api?token=1&token=2", "token", "new", false))
        assertEquals("/p?a=1&&b=2&token=v", SessionInjection.upsertQuery("/p?a=1&&b=2", "token", "v", true))
        assertEquals("/p?a=1&token=v#frag", SessionInjection.upsertQuery("/p?a=1#frag", "token", "v", true))
        assertEquals("/p?Token=1&token=v", SessionInjection.upsertQuery("/p?Token=1", "token", "v", true))
        assertNull(SessionInjection.upsertQuery("/api?token=same", "token", "same", true))
    }

    @Test
    fun `upsertQuery adds a missing parameter only when allowed`() {
        assertEquals("/api?token=v", SessionInjection.upsertQuery("/api", "token", "v", true))
        assertEquals("/api?token=v", SessionInjection.upsertQuery("/api?", "token", "v", true))
        assertEquals("/api?a=1&token=v", SessionInjection.upsertQuery("/api?a=1", "token", "v", true))
        assertNull(SessionInjection.upsertQuery("/api?a=1", "token", "v", false))
        assertTrue(SessionInjection.queryHas("/api?a=1&token=", "token"))
        assertFalse(SessionInjection.queryHas("/api?a=1#token=2", "token"))
    }

    // --- JSON body ---

    @Test
    fun `a JSON target must name exactly one value`() {
        assertNull(SessionInjection.validateJsonTarget("$.auth.token"))
        assertNull(SessionInjection.validateJsonTarget("token"))
        assertNull(SessionInjection.validateJsonTarget("$.items[0].id"))
        assertTrue("whole document" in SessionInjection.validateJsonTarget("$")!!)
        assertTrue("exactly one value" in SessionInjection.validateJsonTarget("$..token")!!)
        assertTrue("exactly one value" in SessionInjection.validateJsonTarget("$.items[*].id")!!)
        assertNotNull(SessionInjection.validateJsonTarget("$.a["))
    }

    @Test
    fun `an existing value is replaced in place, every other character kept`() {
        val body = "{ \"user\" : {\"name\":\"bob\",  \"token\" : \"old\"},\n  \"path\":\"a\\/b\", \"n\": 1 }"
        assertEquals(body.replace("\"old\"", "\"new\""), SessionInjection.upsertJson(body, "$.user.token", "new", false))
        assertEquals("[{\"t\":\"new\"}]", SessionInjection.upsertJson("[{\"t\":\"old\"}]", "[0].t", "new", false))
        assertEquals("{\"t\":\"a\\\"b\\\\c\\n\"}", SessionInjection.upsertJson("{\"t\":\"old\"}", "t", "a\"b\\c\n", false))
        assertNull(SessionInjection.upsertJson("{\"t\":\"same\"}", "t", "same", true))
        assertEquals("{\"t\":\"same\"}", SessionInjection.replaceJsonLeaf("{\"t\":\"same\"}", "t", "same"))
    }

    @Test
    fun `numbers and booleans stay unquoted when the new value is one too`() {
        assertEquals("{\"id\":42,\"t\":\"old\"}", SessionInjection.upsertJson("{\"id\":1,\"t\":\"old\"}", "$.id", "42", false))
        assertEquals("{\"id\":\"abc\"}", SessionInjection.upsertJson("{\"id\":1}", "$.id", "abc", false))
        assertEquals("{\"t\":\"42\"}", SessionInjection.upsertJson("{\"t\":\"old\"}", "$.t", "42", false))
        assertEquals("{\"f\":true}", SessionInjection.upsertJson("{\"f\":false}", "$.f", "true", false))
        assertEquals("{\"v\":7}", SessionInjection.upsertJson("{\"v\":null}", "$.v", "7", false))
    }

    @Test
    fun `a missing member is added only when allowed and an array is never extended`() {
        assertEquals("{\"a\":1,\"auth\":{\"token\":\"v\"}}", SessionInjection.upsertJson("{\"a\":1}", "$.auth.token", "v", true))
        assertNull(SessionInjection.upsertJson("{\"a\":1}", "$.auth.token", "v", false))
        assertNull(SessionInjection.upsertJson("{\"items\":[1]}", "$.items[3]", "v", true))
        assertNull(SessionInjection.upsertJson("{\"a\":\"text\"}", "$.a.b", "v", true))
        assertEquals("{\"items\":[{\"t\":\"new\"}]}", SessionInjection.upsertJson("{\"items\": [ {\"t\": \"old\"} ]}", "$.items[-1].t", "new", false))
        assertNull(SessionInjection.upsertJson("not json", "$.a", "v", true))
        assertNull(SessionInjection.upsertJson("", "$.a", "v", true))
        assertNull(SessionInjection.upsertJson("{\"a\":1}", "$..a", "v", true))
    }

    // --- Montoya requests ---

    @Test
    fun `header injection updates an existing header and adds one only when allowed`() {
        val withAuth = request(headers = listOf("Authorization" to "Bearer old"))
        val bare = request()
        assertEquals("Bearer t", SessionInjection.inject(rule("header", "Authorization", "Bearer {value}"), withAuth, "t").headerValue("Authorization"))
        assertEquals("Bearer t", SessionInjection.inject(rule("header", "Authorization", "Bearer {value}"), bare, "t").headerValue("Authorization"))
        assertSame(bare, SessionInjection.inject(rule("header", "Authorization", "Bearer {value}", ifMissing = false), bare, "t"))
        assertEquals("Bearer t", SessionInjection.inject(rule("header", "Authorization", "Bearer {value}", ifMissing = false), withAuth, "t").headerValue("Authorization"))
        // A value from the target never splits a header.
        assertSame(withAuth, SessionInjection.inject(rule("header", "Authorization"), withAuth, "x\r\nInjected: 1"))
    }

    @Test
    fun `cookie injection updates the cookie and never adds one when not allowed`() {
        val jar = request(headers = listOf("Cookie" to "session=old; theme=dark"))
        assertEquals("session=new; theme=dark", SessionInjection.inject(rule("cookie", "session"), jar, "new").headerValue("Cookie"))
        assertEquals("theme=dark; csrf=c", SessionInjection.inject(rule("cookie", "csrf"), request(headers = listOf("Cookie" to "theme=dark")), "c").headerValue("Cookie"))
        assertSame(jar, SessionInjection.inject(rule("cookie", "csrf", ifMissing = false), jar, "c"))
        assertSame(jar, SessionInjection.inject(rule("cookie", "session"), jar, "old"))
        assertSame(jar, SessionInjection.inject(rule("cookie", "session"), jar, "a\nb"))
    }

    @Test
    fun `query injection writes the rendered value into the request target`() {
        val sent = SessionInjection.inject(rule("query", "token", "{value|url}"), request("/api?a=1&token=old"), "a b/c")
        assertEquals("/api?a=1&token=a%20b%2Fc", sent.path())
        val untouched = request("/api?a=1")
        assertSame(untouched, SessionInjection.inject(rule("query", "token", ifMissing = false), untouched, "v"))
        assertSame(untouched, SessionInjection.inject(rule("query", "a"), untouched, "x\r\ny"))
    }

    @Test
    fun `JSON injection keeps the other bytes of the body and Content-Length right`() {
        val body = "{\"name\": \"Zoë\",\n \"auth\": {\"token\": \"old\", \"n\": 1}}"
        val original = request(headers = listOf("Content-Type" to "application/json", "Content-Length" to body.toByteArray().size.toString()), body = body)

        val sent = SessionInjection.inject(rule("json", "$.auth.token"), original, "é1")
        val expected = body.replace("\"old\"", "\"é1\"").toByteArray(Charsets.UTF_8)
        assertContentEquals(expected, sent.bodyBytes())
        assertEquals(expected.size.toString(), sent.headerValue("Content-Length"))

        val number = SessionInjection.inject(rule("json", "auth.n"), original, "5")
        assertContentEquals(body.replace("\"n\": 1", "\"n\": 5").toByteArray(Charsets.UTF_8), number.bodyBytes())

        val added = SessionInjection.inject(rule("json", "$.csrf"), original, "c")
        assertEquals("{\"name\":\"Zoë\",\"auth\":{\"token\":\"old\",\"n\":1},\"csrf\":\"c\"}", String(added.bodyBytes(), Charsets.UTF_8))
        assertSame(original, SessionInjection.inject(rule("json", "$.csrf", ifMissing = false), original, "c"))
        assertSame(original, SessionInjection.inject(rule("json", "$.auth.token"), original, "old"))

        val form = request(body = "a=1")
        assertSame(form, SessionInjection.inject(rule("json", "$.a"), form, "v"))
    }

    @Test
    fun `carries tells whether the request holds the rule's place`() {
        val r = request(
            "/api?token=1",
            listOf("X-Api-Key" to "k", "Cookie" to "session=s"),
            "{\"auth\":{\"token\":\"t\"}}",
        )
        assertTrue(SessionInjection.carries(rule("header", "x-api-key"), r))
        assertTrue(SessionInjection.carries(rule("cookie", "session"), r))
        assertTrue(SessionInjection.carries(rule("query", "token"), r))
        assertTrue(SessionInjection.carries(rule("json", "$.auth.token"), r))
        assertFalse(SessionInjection.carries(rule("header", "Authorization"), r))
        assertFalse(SessionInjection.carries(rule("cookie", "csrf"), r))
        assertFalse(SessionInjection.carries(rule("json", "$.auth.other"), r))
    }
}
