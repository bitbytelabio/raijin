package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.ToolSource
import burp.api.montoya.core.ToolType
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.params.HttpParameter
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import burp.api.montoya.scope.Scope
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.safety.BoundedHttp
import io.bitbytelab.raijin.state.SessionRule
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.state.TrafficRule
import java.lang.reflect.Proxy
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

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

private fun header(name: String, value: String): HttpHeader = fake { m, _ ->
    when (m) {
        "name" -> name
        "value" -> value
        else -> error("HttpHeader.$m")
    }
}

private fun toolSource(tool: ToolType): ToolSource = fake { m, a ->
    when (m) {
        "toolType" -> tool
        "isFromTool" -> (a[0] as Array<*>).contains(tool)
        else -> error("ToolSource.$m")
    }
}

private val annotations: Annotations = fake { m, _ -> error("Annotations.$m") }

private fun named(name: Any?) = { field: Pair<String, String> -> field.first.equals(name as String, ignoreCase = true) }

/** Cookies held in the request's single `Cookie` header, which is how the fake models cookie parameters. */
private fun cookies(headers: List<Pair<String, String>>): Map<String, String> =
    headers.firstOrNull(named("Cookie"))?.second
        ?.split(';')?.map { it.trim() }?.filter { '=' in it }
        ?.associate { it.substringBefore('=') to it.substringAfter('=') }
        .orEmpty()

/** An outgoing request from [tool] with [headers]; every `with*` returns a modified copy. */
private fun request(headers: List<Pair<String, String>>, tool: ToolType, id: Int = 1): HttpRequestToBeSent = fake { m, a ->
    fun copy(h: List<Pair<String, String>>) = request(h, tool, id)
    when (m) {
        "toolSource" -> toolSource(tool)
        "messageId" -> id
        "annotations" -> annotations
        "url" -> "https://target.example/api"
        "httpService" -> fake<HttpService> { sm, _ -> if (sm == "host") "target.example" else error("HttpService.$sm") }
        "headers" -> headers.map { (n, v) -> header(n, v) }
        "hasHeader" -> a.size == 1 && a[0] is String && headers.any(named(a[0]))
        "headerValue" -> headers.firstOrNull(named(a[0]))?.second
        "withRemovedHeader" -> copy(headers.filterNot(named(a[0])))
        "withAddedHeader" -> copy(headers + (a[0] as String to a[1] as String))
        "withUpdatedHeader", "withHeader" -> copy(headers.filterNot(named(a[0])) + (a[0] as String to a[1] as String))
        "hasParameter" -> a[1] == HttpParameterType.COOKIE && (a[0] as String) in cookies(headers)
        "withAddedParameters", "withUpdatedParameters" -> {
            val jar = cookies(headers).toMutableMap()
            (a[0] as Array<*>).map { it as HttpParameter }.forEach { jar[it.name()] = it.value() }
            copy(headers.filterNot(named("Cookie")) + ("Cookie" to jar.entries.joinToString("; ") { "${it.key}=${it.value}" }))
        }
        else -> error("HttpRequest.$m")
    }
}

private fun response(headers: List<Pair<String, String>>, tool: ToolType, id: Int): HttpResponseReceived = fake { m, a ->
    when (m) {
        "messageId" -> id
        "toolSource" -> toolSource(tool)
        "annotations" -> annotations
        "initiatingRequest" -> request(emptyList(), tool, id)
        "headers" -> headers.map { (n, v) -> header(n, v) }
        "headerValue" -> headers.firstOrNull(named(a[0]))?.second
        "bodyToString" -> ""
        "withAddedHeader" -> response(headers + (a[0] as String to a[1] as String), tool, id)
        else -> error("HttpResponse.$m")
    }
}

/** What Burp's object factory does for the calls the global handler makes. */
private val factory: MontoyaObjectFactory = fake { m, a ->
    when (m) {
        "requestResult" -> {
            check(a.size <= 2) { "drop/spoof is not expected here" }
            val sent = a[0] as HttpRequest
            fake<RequestToBeSentAction> { am, _ -> if (am == "request") sent else error("RequestToBeSentAction.$am") }
        }
        "responseResult" -> {
            val received = a[0] as HttpResponse
            fake<ResponseReceivedAction> { am, _ -> if (am == "response") received else error("ResponseReceivedAction.$am") }
        }
        "cookieParameter" -> fake<HttpParameter> { pm, _ ->
            when (pm) {
                "name" -> a[0]
                "value" -> a[1]
                "type" -> HttpParameterType.COOKIE
                else -> error("HttpParameter.$pm")
            }
        }
        else -> error("MontoyaObjectFactory.$m")
    }
}

private val api: MontoyaApi = fake { m, _ ->
    if (m == "scope") fake<Scope> { sm, _ -> if (sm == "isInScope") true else error("Scope.$sm") } else error("MontoyaApi.$m")
}

class HttpBridgeTest {

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

    /** The operator's global auth rule (no tool filter) and a session rule holding a token to inject. */
    private fun operatorState() = StateManager().apply {
        trafficRules.add(TrafficRule(ruleId = "auth", direction = "request", modifyAddHeader = "Authorization: Bearer operator"))
        sessionRules.add(
            SessionRule(
                ruleName = "session", scope = "all", scopePattern = null,
                extractFrom = "header", extractHeaderName = "X-Session", extractRegex = "(.+)",
                injectInto = "cookie", injectName = "session", injectValueTemplate = "{value}",
                lastExtractedValue = "operator-session"
            )
        )
    }

    private val marker = BoundedHttp.INTERNAL_BYPASS_HEADER to "1"

    // --- global handler: internal probes ---

    @Test
    fun `an internal unauthenticated probe leaves without injected credentials or the marker`() {
        val handler = HttpBridge(api, EventBus(), operatorState()).createGlobalHttpHandler()
        val sent = handler.handleHttpRequestToBeSent(request(listOf("Host" to "target.example", marker), ToolType.EXTENSIONS)).request()
        assertFalse(sent.hasHeader("Authorization"))
        assertFalse(sent.hasHeader("Cookie"))
        assertFalse(sent.hasHeader(BoundedHttp.INTERNAL_BYPASS_HEADER))
        assertEquals("target.example", sent.headerValue("Host"))
    }

    @Test
    fun `ordinary extension traffic still gets traffic and session rules`() {
        val handler = HttpBridge(api, EventBus(), operatorState()).createGlobalHttpHandler()
        val sent = handler.handleHttpRequestToBeSent(request(listOf("Host" to "target.example"), ToolType.EXTENSIONS)).request()
        assertEquals("Bearer operator", sent.headerValue("Authorization"))
        assertEquals("session=operator-session", sent.headerValue("Cookie"))
    }

    @Test
    fun `a traffic rule whose tool filter names EXTENSIONS still applies to internal probes`() {
        val state = operatorState().apply {
            trafficRules.add(TrafficRule(ruleId = "tag", direction = "request", modifyAddHeader = "X-Probe: 1", toolFilter = setOf("EXTENSIONS")))
        }
        val handler = HttpBridge(api, EventBus(), state).createGlobalHttpHandler()
        val sent = handler.handleHttpRequestToBeSent(request(listOf(marker), ToolType.EXTENSIONS)).request()
        assertEquals("1", sent.headerValue("X-Probe"))
        assertFalse(sent.hasHeader("Authorization"))
        assertFalse(sent.hasHeader("Cookie"))
    }

    @Test
    fun `an internal probe's response skips response rules and session extraction`() {
        val state = operatorState().apply {
            trafficRules.add(TrafficRule(ruleId = "seen", direction = "response", modifyAddHeader = "X-Seen: 1"))
        }
        val handler = HttpBridge(api, EventBus(), state).createGlobalHttpHandler()
        handler.handleHttpRequestToBeSent(request(listOf(marker), ToolType.EXTENSIONS, id = 42))
        val probeResponse = handler.handleHttpResponseReceived(response(listOf("X-Session" to "anonymous"), ToolType.EXTENSIONS, id = 42)).response()
        assertNull(probeResponse.headerValue("X-Seen"))
        assertEquals("operator-session", state.sessionRules.single().lastExtractedValue)

        val normalResponse = handler.handleHttpResponseReceived(response(listOf("X-Session" to "fresh"), ToolType.PROXY, id = 43)).response()
        assertEquals("1", normalResponse.headerValue("X-Seen"))
        assertEquals("fresh", state.sessionRules.single().lastExtractedValue)
    }

    @Test
    fun `the marker never reaches the wire but only exempts extension traffic`() {
        val handler = HttpBridge(api, EventBus(), operatorState()).createGlobalHttpHandler()
        val sent = handler.handleHttpRequestToBeSent(request(listOf(marker), ToolType.REPEATER)).request()
        assertFalse(sent.hasHeader(BoundedHttp.INTERNAL_BYPASS_HEADER))
        assertEquals("Bearer operator", sent.headerValue("Authorization"))
    }

    @Test
    fun `trafficRuleAppliesTo exempts internal probes from rules that do not name EXTENSIONS`() {
        val unfiltered = TrafficRule(ruleId = "a", direction = "request")
        val extensions = unfiltered.copy(toolFilter = setOf("extensions"))
        val scanner = unfiltered.copy(toolFilter = setOf("SCANNER"))
        assertTrue(HttpBridge.trafficRuleAppliesTo(unfiltered, "PROXY", internalProbe = false))
        assertFalse(HttpBridge.trafficRuleAppliesTo(unfiltered, "EXTENSIONS", internalProbe = true))
        assertTrue(HttpBridge.trafficRuleAppliesTo(extensions, "EXTENSIONS", internalProbe = true))
        assertFalse(HttpBridge.trafficRuleAppliesTo(scanner, "EXTENSIONS", internalProbe = true))
        assertTrue(HttpBridge.trafficRuleAppliesTo(scanner, "SCANNER", internalProbe = false))
        assertFalse(HttpBridge.trafficRuleAppliesTo(scanner, null, internalProbe = false))
    }

    // --- Host header parsing ---

    @Test
    fun `parseHostHeader reads host and port including IPv6 literals`() {
        assertEquals("::1" to 8443, HttpBridge.parseHostHeader("GET / HTTP/1.1\r\nHost: [::1]:8443\r\nX-Port: 9999\r\n\r\n"))
        assertEquals("::1" to null, HttpBridge.parseHostHeader("GET / HTTP/1.1\r\nHost: [::1]\r\n\r\n"))
        assertEquals("fe80::1" to null, HttpBridge.parseHostHeader("GET / HTTP/1.1\r\nHost: fe80::1\r\n\r\n"))
        assertEquals("example.com" to 8080, HttpBridge.parseHostHeader("GET / HTTP/1.1\nhost: example.com:8080\n\n"))
        assertEquals("example.com" to null, HttpBridge.parseHostHeader("GET / HTTP/1.1\r\nHost: example.com:99999\r\n\r\n"))
        assertEquals("a.example" to null, HttpBridge.parseHostHeader("GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example:1\r\n\r\n"))
    }

    @Test
    fun `parseHostHeader never crosses a line break or reads the body`() {
        // An empty Host must not borrow the next line's "name:port".
        assertNull(HttpBridge.parseHostHeader("GET / HTTP/1.1\r\nHost:\r\nfoo:8080\r\n\r\n"))
        // A Host header inside a smuggled request in the body is not the target.
        assertNull(HttpBridge.parseHostHeader("POST / HTTP/1.1\r\nContent-Length: 40\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal:81\r\n\r\n"))
        // An absolute-form request line is not a Host header.
        assertNull(HttpBridge.parseHostHeader("GET http://other:81/ HTTP/1.1\r\n\r\n"))
    }

    // --- structured request construction ---

    @Test
    fun `constructRawHttpRequest counts Content-Length in the charset the request is sent with`() {
        val latin1 = HttpBridge.constructRawHttpRequest("https://h/p?q=1", "POST", emptyMap(), "é", "h", 443, true)
        assertEquals("POST /p?q=1 HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\n\r\né", latin1)
        // A wide char in a header sends the whole request as UTF-8, so "é" in the body is 2 bytes.
        val wide = HttpBridge.constructRawHttpRequest("https://h/", "POST", mapOf("X-Name" to "日本"), "é", "h", 443, true)
        assertTrue(wide.contains("Content-Length: 2\r\n"), wide)
        // Caller-supplied framing is never second-guessed.
        val declared = HttpBridge.constructRawHttpRequest("https://h/", "POST", mapOf("Content-Length" to "99"), "abc", "h", 443, true)
        assertEquals("POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 99\r\n\r\nabc", declared)
    }

    @Test
    fun `constructRawHttpRequest brackets an IPv6 host in the Host header`() {
        assertTrue(HttpBridge.constructRawHttpRequest("http://x/", "GET", emptyMap(), null, "::1", 8080, false).contains("\r\nHost: [::1]:8080\r\n"))
        assertTrue(HttpBridge.constructRawHttpRequest("https://[::1]/", "GET", emptyMap(), null, "[::1]", 443, true).contains("\r\nHost: [::1]\r\n"))
    }
}
