package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.state.ProxyRule
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * What a proxy rule's `modify` action does to a message, against the immutable fake messages of
 * [FakeHttpMessages][fakeRequest], which update and remove only the first header written exactly
 * as named.
 */
class ProxyRuleEditsTest {

    private fun request(msg: FakeMessage) = fakeRequest(msg)

    private fun requestRule(
        addHeader: String? = null,
        removeHeader: String? = null,
        replaceHeader: Map<String, String>? = null,
        setHeader: Map<String, String>? = null,
        method: String? = null,
        path: String? = null,
        pathRegex: String? = null,
        bodyRegex: String? = null,
        bodyReplacement: String? = null,
    ) = ProxyRule(
        ruleId = "r", type = "request", action = "modify", modifyAddHeader = addHeader, modifyRemoveHeader = removeHeader,
        modifyReplaceHeader = replaceHeader, modifySetHeader = setHeader, modifyMethod = method, modifyPath = path,
        modifyPathRegex = pathRegex, modifyBodyRegex = bodyRegex, modifyBodyReplacement = bodyReplacement,
    )

    @Test
    fun `a request rule rewrites the method and the whole path`() {
        val out = ProxyRuleEdits.applyTo(requestRule(method = "PUT", path = "/admin/users?debug=1"), request(FakeMessage(path = "/users")))
        assertEquals("PUT", out.method())
        assertEquals("/admin/users?debug=1", out.path())
    }

    @Test
    fun `a path regex replaces each match, with group references`() {
        val rule = requestRule(path = "/v2/$1", pathRegex = "^/v1/(.*)")
        assertEquals("/v2/orders?id=7", ProxyRuleEdits.applyTo(rule, request(FakeMessage(path = "/v1/orders?id=7"))).path())

        // No match: the request is passed on as it is.
        val untouched = request(FakeMessage(path = "/health"))
        assertSame(untouched, ProxyRuleEdits.applyTo(rule, untouched))
        assertNull(ProxyRuleEdits.rewrittenPath(rule, "/health"))
        assertEquals("/api", ProxyRuleEdits.rewrittenPath(requestRule(path = "", pathRegex = "/debug"), "/api/debug"))
    }

    @Test
    fun `setting a header replaces every occurrence of it, whatever its case, instead of sending it twice`() {
        val rule = requestRule(setHeader = mapOf("Authorization" to "Bearer new"))

        val single = ProxyRuleEdits.applyTo(rule, request(FakeMessage(headers = listOf("Host" to "a.test", "authorization" to "Bearer old"))))
        assertEquals(listOf("Host" to "a.test", "authorization" to "Bearer new"), single.headerPairs(), "updated in place")

        val doubled = request(FakeMessage(headers = listOf("Authorization" to "a", "Host" to "a.test", "AUTHORIZATION" to "b")))
        assertEquals(listOf("Host" to "a.test", "Authorization" to "Bearer new"), ProxyRuleEdits.applyTo(rule, doubled).headerPairs())

        val absent = ProxyRuleEdits.applyTo(rule, request(FakeMessage(headers = listOf("Host" to "a.test"))))
        assertEquals(listOf("Host" to "a.test", "Authorization" to "Bearer new"), absent.headerPairs())
    }

    @Test
    fun `replacing a header only touches headers the message has`() {
        val rule = requestRule(replaceHeader = mapOf("cookie" to "session=low"))
        assertEquals(
            listOf("Cookie" to "session=low"),
            ProxyRuleEdits.applyTo(rule, request(FakeMessage(headers = listOf("Cookie" to "session=admin")))).headerPairs(),
        )
        assertEquals(emptyList(), ProxyRuleEdits.applyTo(rule, request(FakeMessage())).headerPairs())
    }

    @Test
    fun `removing a header removes every occurrence, and runs before an add of the same name`() {
        val msg = FakeMessage(headers = listOf("X-Forwarded-For" to "1.1.1.1", "Host" to "a.test", "x-forwarded-for" to "2.2.2.2"))
        assertEquals(listOf("Host" to "a.test"), ProxyRuleEdits.applyTo(requestRule(removeHeader = "X-Forwarded-For:"), request(msg)).headerPairs())

        val swapped = ProxyRuleEdits.applyTo(requestRule(removeHeader = "X-Forwarded-For", addHeader = "X-Forwarded-For: 127.0.0.1"), request(msg))
        assertEquals(listOf("Host" to "a.test", "X-Forwarded-For" to "127.0.0.1"), swapped.headerPairs())
    }

    @Test
    fun `an added header is written as given, CR LF and spacing included`() {
        val injected = ProxyRuleEdits.applyTo(requestRule(addHeader = "X-A: 1\r\nX-B: 2"), request(FakeMessage()))
        assertEquals(listOf("X-A" to "1\r\nX-B: 2"), injected.headerPairs())

        val obfuscated = ProxyRuleEdits.applyTo(requestRule(addHeader = "Transfer-Encoding : chunked\r\n"), request(FakeMessage()))
        assertEquals(listOf("Transfer-Encoding " to "chunked"), obfuscated.headerPairs())
    }

    @Test
    fun `header lines split at the first colon and keep the name as written`() {
        assertEquals("X-A" to "1\r\nX-B: 2", ProxyRuleEdits.parseHeaderLine("X-A: 1\r\nX-B: 2"))
        assertEquals(" X-Obf\t" to "v", ProxyRuleEdits.parseHeaderLine(" X-Obf\t:  v"))
        assertEquals("X" to "", ProxyRuleEdits.parseHeaderLine("X:"))
        assertNull(ProxyRuleEdits.parseHeaderLine("no colon"))
        assertNull(ProxyRuleEdits.parseHeaderLine(": value"))
        assertEquals("Cookie", ProxyRuleEdits.headerName("  Cookie: "))
    }

    @Test
    fun `the body regex only rewrites the body when it matches`() {
        val rule = requestRule(bodyRegex = "role=\\w+", bodyReplacement = "role=admin")
        assertEquals("a=1&role=admin", ProxyRuleEdits.applyTo(rule, request(FakeMessage(body = "a=1&role=user"))).bodyToString())
        val untouched = request(FakeMessage(body = "nothing here"))
        assertSame(untouched, ProxyRuleEdits.applyTo(rule, untouched))
    }

    @Test
    fun `a response rule rewrites the status code and sets headers`() {
        val rule = ProxyRule(
            ruleId = "r", type = "response", action = "modify", modifyStatus = 200,
            modifySetHeader = mapOf("Access-Control-Allow-Origin" to "*"), modifyRemoveHeader = "Location",
        )
        val out = ProxyRuleEdits.applyTo(rule, fakeResponse(FakeMessage(status = 302, headers = listOf("Location" to "/login"))))
        assertEquals(200, out.statusCode().toInt())
        assertEquals(listOf("Access-Control-Allow-Origin" to "*"), out.headerPairs())
    }

    @Test
    fun `modify needs something to do`() {
        assertFalse(ProxyRuleEdits.modifies(ProxyRule(ruleId = "r", type = "request", action = "modify")))
        assertTrue(ProxyRuleEdits.modifies(requestRule(method = "POST")))
        assertTrue(ProxyRuleEdits.modifies(ProxyRule(ruleId = "r", type = "response", action = "modify", modifyStatus = 500)))
        assertTrue(ProxyRuleEdits.modifies(requestRule(setHeader = mapOf("X" to "1"))))
    }
}
