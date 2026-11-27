package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.ToolSource
import burp.api.montoya.core.ToolType
import burp.api.montoya.http.Http
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
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonPrimitive

/**
 * A [T] whose calls go to [handler] (method name, arguments); a call it does not expect fails the
 * test.
 */
private inline fun <reified T : Any> fake(noinline handler: (String, Array<out Any?>) -> Any?): T =
    Proxy.newProxyInstance(T::class.java.classLoader, arrayOf(T::class.java)) { proxy, method, args
        ->
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

private fun named(name: Any?) = { field: Pair<String, String> ->
    field.first.equals(name as String, ignoreCase = true)
}

/**
 * Cookies held in the request's single `Cookie` header, which is how the fake models cookie
 * parameters.
 */
private fun cookies(headers: List<Pair<String, String>>): Map<String, String> =
    headers
        .firstOrNull(named("Cookie"))
        ?.second
        ?.split(';')
        ?.map { it.trim() }
        ?.filter { '=' in it }
        ?.associate { it.substringBefore('=') to it.substringAfter('=') }
        .orEmpty()

/** An outgoing request from [tool] with [headers]; every `with*` returns a modified copy. */
private fun request(
    headers: List<Pair<String, String>>,
    tool: ToolType,
    id: Int = 1,
): HttpRequestToBeSent = fake { m, a ->
    fun copy(h: List<Pair<String, String>>) = request(h, tool, id)
    when (m) {
        "toolSource" -> toolSource(tool)
        "messageId" -> id
        "annotations" -> annotations
        "url" -> "https://target.example/api"
        "httpService" ->
            fake<HttpService> { sm, _ ->
                if (sm == "host") "target.example" else error("HttpService.$sm")
            }
        "headers" -> headers.map { (n, v) -> header(n, v) }
        "hasHeader" -> a.size == 1 && a[0] is String && headers.any(named(a[0]))
        "headerValue" -> headers.firstOrNull(named(a[0]))?.second
        "withRemovedHeader" -> copy(headers.filterNot(named(a[0])))
        "withAddedHeader" -> copy(headers + (a[0] as String to a[1] as String))
        "withUpdatedHeader",
        "withHeader" -> copy(headers.filterNot(named(a[0])) + (a[0] as String to a[1] as String))
        "hasParameter" -> a[1] == HttpParameterType.COOKIE && (a[0] as String) in cookies(headers)
        "withAddedParameters",
        "withUpdatedParameters" -> {
            val jar = cookies(headers).toMutableMap()
            (a[0] as Array<*>).map { it as HttpParameter }.forEach { jar[it.name()] = it.value() }
            copy(
                headers.filterNot(named("Cookie")) +
                    ("Cookie" to jar.entries.joinToString("; ") { "${it.key}=${it.value}" }),
            )
        }
        else -> error("HttpRequest.$m")
    }
}

private fun response(
    headers: List<Pair<String, String>>,
    tool: ToolType,
    id: Int,
): HttpResponseReceived = fake { m, a ->
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
            fake<RequestToBeSentAction> { am, _ ->
                if (am == "request") sent else error("RequestToBeSentAction.$am")
            }
        }
        "responseResult" -> {
            val received = a[0] as HttpResponse
            fake<ResponseReceivedAction> { am, _ ->
                if (am == "response") received else error("ResponseReceivedAction.$am")
            }
        }
        "cookieParameter" ->
            fake<HttpParameter> { pm, _ ->
                when (pm) {
                    "name" -> a[0]
                    "value" -> a[1]
                    "type" -> HttpParameterType.COOKIE
                    else -> error("HttpParameter.$pm")
                }
            }
        // http_send_raw_bytes builds its request from a service and bytes.
        "httpService" -> fake<HttpService> { sm, _ -> error("HttpService.$sm") }
        "byteArray" -> fake<burp.api.montoya.core.ByteArray> { bm, _ -> error("ByteArray.$bm") }
        "httpRequest" -> fake<HttpRequest> { rm, _ -> error("HttpRequest.$rm") }
        else -> error("MontoyaObjectFactory.$m")
    }
}

private val api: MontoyaApi = fake { m, _ ->
    if (m == "scope") fake<Scope> { sm, _ -> if (sm == "isInScope") true else error("Scope.$sm") }
    else error("MontoyaApi.$m")
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

    /**
     * The operator's global auth rule (no tool filter) and a session rule holding a token to
     * inject.
     */
    private fun operatorState() =
        StateManager().apply {
            trafficRules.add(
                TrafficRule(
                    ruleId = "auth",
                    direction = "request",
                    modifyAddHeader = "Authorization: Bearer operator",
                ),
            )
            sessionRules.add(
                SessionRule(
                    ruleName = "session",
                    scope = "all",
                    scopePattern = null,
                    extractFrom = "header",
                    extractHeaderName = "X-Session",
                    extractRegex = "(.+)",
                    injectInto = "cookie",
                    injectName = "session",
                    injectValueTemplate = "{value}",
                    lastExtractedValue = "operator-session",
                ),
            )
        }

    private val marker = BoundedHttp.INTERNAL_BYPASS_HEADER to "1"

    // --- global handler: internal probes ---

    @Test
    fun `an internal unauthenticated probe leaves without injected credentials or the marker`() {
        val handler = HttpBridge(api, EventBus(), operatorState()).createGlobalHttpHandler()
        val sent =
            handler
                .handleHttpRequestToBeSent(
                    request(listOf("Host" to "target.example", marker), ToolType.EXTENSIONS),
                )
                .request()
        assertFalse(sent.hasHeader("Authorization"))
        assertFalse(sent.hasHeader("Cookie"))
        assertFalse(sent.hasHeader(BoundedHttp.INTERNAL_BYPASS_HEADER))
        assertEquals("target.example", sent.headerValue("Host"))
    }

    @Test
    fun `ordinary extension traffic still gets traffic and session rules`() {
        val handler = HttpBridge(api, EventBus(), operatorState()).createGlobalHttpHandler()
        val sent =
            handler
                .handleHttpRequestToBeSent(
                    request(listOf("Host" to "target.example"), ToolType.EXTENSIONS),
                )
                .request()
        assertEquals("Bearer operator", sent.headerValue("Authorization"))
        assertEquals("session=operator-session", sent.headerValue("Cookie"))
    }

    @Test
    fun `a traffic rule whose tool filter names EXTENSIONS still applies to internal probes`() {
        val state =
            operatorState().apply {
                trafficRules.add(
                    TrafficRule(
                        ruleId = "tag",
                        direction = "request",
                        modifyAddHeader = "X-Probe: 1",
                        toolFilter = setOf("EXTENSIONS"),
                    ),
                )
            }
        val handler = HttpBridge(api, EventBus(), state).createGlobalHttpHandler()
        val sent =
            handler
                .handleHttpRequestToBeSent(request(listOf(marker), ToolType.EXTENSIONS))
                .request()
        assertEquals("1", sent.headerValue("X-Probe"))
        assertFalse(sent.hasHeader("Authorization"))
        assertFalse(sent.hasHeader("Cookie"))
    }

    @Test
    fun `an internal probe's response skips response rules and session extraction`() {
        val state =
            operatorState().apply {
                trafficRules.add(
                    TrafficRule(
                        ruleId = "seen",
                        direction = "response",
                        modifyAddHeader = "X-Seen: 1",
                    ),
                )
            }
        val handler = HttpBridge(api, EventBus(), state).createGlobalHttpHandler()
        handler.handleHttpRequestToBeSent(request(listOf(marker), ToolType.EXTENSIONS, id = 42))
        val probeResponse =
            handler
                .handleHttpResponseReceived(
                    response(listOf("X-Session" to "anonymous"), ToolType.EXTENSIONS, id = 42),
                )
                .response()
        assertNull(probeResponse.headerValue("X-Seen"))
        assertEquals("operator-session", state.sessionRules.single().lastExtractedValue)

        val normalResponse =
            handler
                .handleHttpResponseReceived(
                    response(listOf("X-Session" to "fresh"), ToolType.PROXY, id = 43),
                )
                .response()
        assertEquals("1", normalResponse.headerValue("X-Seen"))
        assertEquals("fresh", state.sessionRules.single().lastExtractedValue)
    }

    @Test
    fun `the marker never reaches the wire but only exempts extension traffic`() {
        val handler = HttpBridge(api, EventBus(), operatorState()).createGlobalHttpHandler()
        val sent =
            handler.handleHttpRequestToBeSent(request(listOf(marker), ToolType.REPEATER)).request()
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

    @Test
    fun `a send that outlives its hard timeout is no_response and retryable`() {
        val silent: MontoyaApi = fake { m, _ ->
            when (m) {
                "scope" ->
                    fake<Scope> { sm, _ -> if (sm == "isInScope") true else error("Scope.$sm") }
                "http" ->
                    fake<Http> { hm, _ ->
                        if (hm == "sendRequest") Thread.sleep(10_000)
                        error("Http.$hm")
                    }
                else -> error("MontoyaApi.$m")
            }
        }
        val error =
            HttpBridge(silent, EventBus(), StateManager())
                .sendRawBytes(
                    null,
                    "GET / HTTP/1.1\r\n\r\n",
                    "127.0.0.1",
                    9,
                    false,
                    null,
                    timeoutMs = 300,
                )
        assertEquals(
            "http_send_raw_bytes: no response from 127.0.0.1:9 in 300 ms (timed out).",
            error["error"]?.jsonPrimitive?.content,
        )
        assertEquals("no_response", error["code"]?.jsonPrimitive?.content)
        assertEquals(true, error["retryable"]?.jsonPrimitive?.boolean)
        assertEquals(true, error["is_timeout"]?.jsonPrimitive?.boolean)
        assertEquals("timeout", error["close_reason"]?.jsonPrimitive?.content)
    }
}
