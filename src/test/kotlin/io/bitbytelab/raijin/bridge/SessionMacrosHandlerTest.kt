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
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.params.HttpParameter
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.params.ParsedHttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import burp.api.montoya.scope.Scope
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.safety.BoundedHttp
import io.bitbytelab.raijin.state.SessionMacro
import io.bitbytelab.raijin.state.SessionRule
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.state.TrafficRule
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import java.lang.reflect.Proxy
import java.util.Collections
import java.util.IdentityHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
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

/** A request as the fake Burp models it. */
private data class Req(
    val method: String = "GET",
    val path: String = "/api/me",
    val headers: List<Pair<String, String>> = emptyList(),
    val body: String = "",
    val host: String = "target.example",
) {
    val url: String get() = "https://$host$path"

    fun header(name: String): String? = headers.firstOrNull { it.first.equals(name, ignoreCase = true) }?.second

    /** Sets the first header named [name] in place (dropping repeats), appends it when missing, removes it for null. */
    fun withHeader(name: String, value: String?): Req {
        val index = headers.indexOfFirst { it.first.equals(name, ignoreCase = true) }
        return when {
            value == null -> copy(headers = headers.filterNot { it.first.equals(name, ignoreCase = true) })
            index < 0 -> copy(headers = headers + (name to value))
            else -> copy(headers = headers.mapIndexedNotNull { i, h ->
                when {
                    i == index -> name to value
                    h.first.equals(name, ignoreCase = true) -> null
                    else -> h
                }
            })
        }
    }

    fun cookies(): Map<String, String> = header("Cookie")?.split(';')?.map { it.trim() }?.filter { '=' in it }
        ?.associate { it.substringBefore('=') to it.substringAfter('=') }.orEmpty()
}

private data class Res(val status: Int, val headers: List<Pair<String, String>> = emptyList(), val body: String = "") {
    fun header(name: String): String? = headers.firstOrNull { it.first.equals(name, ignoreCase = true) }?.second
}

/**
 * Burp as far as the global handler and the login macros see it: every request a tool or the
 * extension sends goes through [handler] on the way out and on the way back, and [server] answers
 * what reaches [wire]. Montoya objects are proxies over [Req] / [Res] models.
 */
private class MacroBurp(private val server: (Req) -> Res) {

    class Pending(val id: Int, val tool: ToolType, val sent: Req)

    /** What the tool got back: the request as sent, the response, and the annotation notes. */
    class Result(val sent: Req, val response: Res, val notes: String?)

    val state = StateManager()
    val events = EventBus()
    val wire: MutableList<Req> = Collections.synchronizedList(ArrayList())

    private val ids = AtomicInteger(100)
    private val requests: MutableMap<Any, Req> = Collections.synchronizedMap(IdentityHashMap())
    private val responses: MutableMap<Any, Res> = Collections.synchronizedMap(IdentityHashMap())

    val api: MontoyaApi = fake { m, _ ->
        when (m) {
            "scope" -> fake<Scope> { sm, _ -> if (sm == "isInScope") true else error("Scope.$sm") }
            "http" -> fake<Http> { hm, a -> if (hm == "sendRequest") send(a[0] as HttpRequest) else error("Http.$hm") }
            else -> error("MontoyaApi.$m")
        }
    }

    val bridge = HttpBridge(api, events, state)
    val macros: SessionMacroEngine get() = bridge.sessionMacros
    private val handler = bridge.createGlobalHttpHandler()

    val factory: MontoyaObjectFactory = fake { m, a ->
        when (m) {
            "requestResult" -> {
                val request = a[0] as HttpRequest
                val annotations = a.getOrNull(1) as Annotations?
                fake<RequestToBeSentAction> { am, _ ->
                    when (am) {
                        "request" -> request
                        "annotations" -> annotations
                        else -> error("RequestToBeSentAction.$am")
                    }
                }
            }
            "responseResult" -> {
                val response = a[0] as HttpResponse
                val annotations = a.getOrNull(1) as Annotations?
                fake<ResponseReceivedAction> { am, _ ->
                    when (am) {
                        "response" -> response
                        "annotations" -> annotations
                        else -> error("ResponseReceivedAction.$am")
                    }
                }
            }
            "cookieParameter" -> parameter(a[0] as String, a[1] as String)
            "byteArray" -> bytes(a[0] as ByteArray)
            "httpService" -> service(a[0] as String)
            "httpRequest" -> parse(a[0] as HttpService, a[1] as BurpByteArray)
            else -> error("MontoyaObjectFactory.$m")
        }
    }

    // --- traffic ---

    /** [r] leaves [tool]: through the handler onto the wire. */
    fun out(r: Req, tool: ToolType): Pending {
        val id = ids.incrementAndGet()
        val action = handler.handleHttpRequestToBeSent(toBeSent(r, tool, id))
        val sent = model(action.request())
        wire += sent
        return Pending(id, tool, sent)
    }

    /** The target answers [pending] and the answer goes back through the handler. */
    fun back(pending: Pending): Result {
        val res = server(pending.sent)
        val action = handler.handleHttpResponseReceived(received(res, pending.sent, pending.tool, pending.id))
        return Result(pending.sent, model(action.response()), action.annotations()?.notes())
    }

    fun exchange(r: Req, tool: ToolType): Result = back(out(r, tool))

    /** `api.http().sendRequest`: the extension's own traffic goes through the handlers too. */
    private fun send(request: HttpRequest): HttpRequestResponse {
        val result = exchange(model(request), ToolType.EXTENSIONS)
        val sent = request(result.sent)
        val response = response(result.response)
        return fake { m, _ ->
            when (m) {
                "request" -> sent
                "response" -> response
                "hasResponse" -> true
                else -> error("HttpRequestResponse.$m")
            }
        }
    }

    fun logins(): Int = wire.count { it.path.startsWith("/login") }

    // --- Montoya objects over the models ---

    private fun model(request: HttpRequest): Req = requests[request] ?: error("not a request of this fake: $request")
    private fun model(response: HttpResponse): Res = responses[response] ?: error("not a response of this fake: $response")

    fun request(r: Req): HttpRequest = requestProxy(HttpRequest::class.java, r, null, null, 0)

    private fun toBeSent(r: Req, tool: ToolType, id: Int): HttpRequestToBeSent =
        requestProxy(HttpRequestToBeSent::class.java, r, tool, annotations(null), id)

    private fun <T : HttpRequest> requestProxy(type: Class<T>, r: Req, tool: ToolType?, annotations: Annotations?, id: Int): T {
        val proxy = Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { self, method, args ->
            val a = args ?: emptyArray<Any?>()
            when (method.name) {
                "toString" -> r.toString()
                "hashCode" -> System.identityHashCode(self)
                "equals" -> self === a.firstOrNull()
                "toolSource" -> toolSource(tool!!)
                "messageId" -> id
                "annotations" -> annotations
                "url" -> r.url
                "method" -> r.method
                "path" -> r.path
                "httpVersion" -> "HTTP/1.1"
                "httpService" -> service(r.host)
                "headers" -> r.headers.map { (n, v) -> header(n, v) }
                "hasHeader" -> if (a.size == 1 && a[0] is String) r.header(a[0] as String) != null else error("hasHeader overload")
                "headerValue" -> r.header(a[0] as String)
                "withHeader", "withUpdatedHeader" -> request(r.withHeader(a[0] as String, a[1] as String))
                "withAddedHeader" -> request(r.copy(headers = r.headers + (a[0] as String to a[1] as String)))
                "withRemovedHeader" -> request(r.withHeader(a[0] as String, null))
                "parameters" -> {
                    check(a.size == 1 && a[0] == HttpParameterType.COOKIE) { "only cookie parameters are modelled" }
                    r.cookies().map { (n, v) -> parsedCookie(n, v) }
                }
                "hasParameter" -> a[1] == HttpParameterType.COOKIE && (a[0] as String) in r.cookies()
                "parameterValue" -> if (a[1] == HttpParameterType.COOKIE) r.cookies()[a[0] as String] else null
                "withUpdatedParameters", "withAddedParameters" -> {
                    val parameters = (a[0] as? Array<*>)?.toList() ?: (a[0] as List<*>)
                    val jar = LinkedHashMap(r.cookies())
                    for (p in parameters) {
                        p as HttpParameter
                        check(p.type() == HttpParameterType.COOKIE) { "only cookie parameters are modelled" }
                        jar[p.name()] = p.value()
                    }
                    request(r.withHeader("Cookie", jar.entries.joinToString("; ") { "${it.key}=${it.value}" }))
                }
                "bodyToString" -> r.body
                "body" -> bytes(r.body.toByteArray(Charsets.ISO_8859_1))
                else -> error("HttpRequest.${method.name}")
            }
        }
        requests[proxy] = r
        return type.cast(proxy)
    }

    fun response(r: Res): HttpResponse = responseProxy(HttpResponse::class.java, r, null, null, 0)

    private fun received(r: Res, initiating: Req, tool: ToolType, id: Int): HttpResponseReceived =
        responseProxy(HttpResponseReceived::class.java, r, initiating, tool, id)

    private fun <T : HttpResponse> responseProxy(type: Class<T>, r: Res, initiating: Req?, tool: ToolType?, id: Int): T {
        val annotations = annotations(null)
        val proxy = Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { self, method, args ->
            val a = args ?: emptyArray<Any?>()
            when (method.name) {
                "toString" -> r.toString()
                "hashCode" -> System.identityHashCode(self)
                "equals" -> self === a.firstOrNull()
                "messageId" -> id
                "toolSource" -> toolSource(tool!!)
                "annotations" -> annotations
                "initiatingRequest" -> request(initiating!!)
                "statusCode" -> r.status.toShort()
                "httpVersion" -> "HTTP/1.1"
                "reasonPhrase" -> if (r.status == 200) "OK" else "Status ${r.status}"
                "headers" -> r.headers.map { (n, v) -> header(n, v) }
                "hasHeader" -> if (a.size == 1 && a[0] is String) r.header(a[0] as String) != null else error("hasHeader overload")
                "headerValue" -> r.header(a[0] as String)
                "withAddedHeader" -> response(r.copy(headers = r.headers + (a[0] as String to a[1] as String)))
                "withRemovedHeader" -> response(r.copy(headers = r.headers.filterNot { it.first.equals(a[0] as String, ignoreCase = true) }))
                "bodyToString" -> r.body
                else -> error("HttpResponse.${method.name}")
            }
        }
        responses[proxy] = r
        return type.cast(proxy)
    }

    private fun parse(service: HttpService, raw: BurpByteArray): HttpRequest {
        val text = String(raw.bytes, Charsets.ISO_8859_1)
        val lines = text.substringBefore("\r\n\r\n").split("\r\n")
        val (method, path) = lines[0].split(' ')
        val headers = lines.drop(1).filter { ':' in it }.map { it.substringBefore(':').trim() to it.substringAfter(':').trim() }
        return request(Req(method, path, headers, text.substringAfter("\r\n\r\n", ""), service.host()))
    }

    private fun header(name: String, value: String): HttpHeader = fake { m, _ ->
        when (m) {
            "name" -> name
            "value" -> value
            else -> error("HttpHeader.$m")
        }
    }

    private fun parameter(name: String, value: String): HttpParameter = fake { m, _ ->
        when (m) {
            "name" -> name
            "value" -> value
            "type" -> HttpParameterType.COOKIE
            else -> error("HttpParameter.$m")
        }
    }

    private fun parsedCookie(name: String, value: String): ParsedHttpParameter = fake { m, _ ->
        when (m) {
            "name" -> name
            "value" -> value
            "type" -> HttpParameterType.COOKIE
            else -> error("ParsedHttpParameter.$m")
        }
    }

    private fun bytes(data: ByteArray): BurpByteArray = fake { m, _ ->
        when (m) {
            "getBytes" -> data.copyOf()
            "length" -> data.size
            else -> error("ByteArray.$m")
        }
    }

    private fun service(host: String): HttpService = fake { m, _ ->
        when (m) {
            "host" -> host
            "port" -> 443
            "secure" -> true
            else -> error("HttpService.$m")
        }
    }

    private fun toolSource(tool: ToolType): ToolSource = fake { m, a ->
        when (m) {
            "toolType" -> tool
            "isFromTool" -> (a[0] as Array<*>).contains(tool)
            else -> error("ToolSource.$m")
        }
    }

    private fun annotations(notes: String?): Annotations = fake { m, a ->
        when (m) {
            "notes" -> notes
            "hasNotes" -> !notes.isNullOrEmpty()
            "withNotes" -> annotations(a[0] as String)
            else -> error("Annotations.$m")
        }
    }
}

/**
 * The login macro end to end through the global HTTP handler: an expired response runs the macro,
 * the request is sent once more with the refreshed session, and that response replaces the
 * expired one, marked with [HttpExchangeJson.REAUTHENTICATED_HEADER].
 */
class SessionMacrosHandlerTest {

    private val previousFactory: MontoyaObjectFactory? = ObjectFactoryLocator.FACTORY

    @AfterTest
    fun restoreFactory() {
        ObjectFactoryLocator.FACTORY = previousFactory
    }

    private fun burp(server: (Req) -> Res): MacroBurp = MacroBurp(server).also { ObjectFactoryLocator.FACTORY = it.factory }

    private val loginRequest = "POST /login HTTP/1.1\r\nHost: target.example\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=alice&pass=pw"

    private fun macro(
        steps: List<JsonObject> = listOf(buildJsonObject { put("raw_request", loginRequest) }),
        minIntervalMs: Long = SessionMacro.DEFAULT_MIN_INTERVAL_MS,
        maxFailures: Int = SessionMacro.DEFAULT_MAX_FAILURES,
    ) = SessionMacro(name = "login", steps = steps, scope = "all", minIntervalMs = minIntervalMs, maxFailures = maxFailures)

    private fun MacroBurp.define(macro: SessionMacro) {
        val result = macros.set(macro)
        assertNull(result["error"], result.toString())
    }

    private fun MacroBurp.macroState(): JsonObject =
        macros.list().getValue("macros").jsonArray.single().jsonObject.getValue("state").jsonObject

    private fun me(cookie: String) = Req(path = "/api/me", headers = listOf("Host" to "target.example", "Cookie" to cookie))

    private val reauthenticated = HttpExchangeJson.REAUTHENTICATED_HEADER

    @Test
    fun `an expired response runs the macro once and is replaced by the single retry's response`() {
        val burp = burp { req ->
            when {
                req.method == "POST" && req.path == "/login" -> Res(
                    200,
                    listOf(
                        "Set-Cookie" to "session=fresh; Path=/; HttpOnly",
                        "Set-Cookie" to "csrf=c2; Path=/",
                        "Set-Cookie" to "theme=; Max-Age=0",
                    ),
                    "welcome",
                )
                req.cookies()["session"] == "fresh" -> Res(200, body = "me")
                else -> Res(401, body = "login required")
            }
        }
        burp.state.trafficRules.add(TrafficRule(ruleId = "tag", direction = "request", modifyAddHeader = "X-Client: raijin"))
        burp.define(macro())

        val result = burp.exchange(me("session=old; theme=dark"), ToolType.REPEATER)

        assertEquals(200, result.response.status)
        assertEquals("me", result.response.body)
        assertEquals("login", result.response.header(reauthenticated))
        assertTrue(result.notes.orEmpty().contains("login macro 'login'"), result.notes)

        // On the wire: the expired request, the login step as stored, one retry with the new session.
        assertEquals(listOf("GET /api/me", "POST /login", "GET /api/me"), burp.wire.map { "${it.method} ${it.path}" })
        val (original, login, retry) = burp.wire.toList()
        assertEquals("session=old; theme=dark", original.header("Cookie"))
        assertNull(login.header("Cookie"))
        assertEquals("user=alice&pass=pw", login.body)
        assertEquals("session=fresh; theme=dark", retry.header("Cookie"))
        assertTrue(burp.wire.none { it.header(SessionMacroEngine.MARKER_HEADER) != null })
        // Traffic rules apply to the step; the retry already carries their edit once, never twice.
        assertEquals(listOf(1, 1, 1), burp.wire.map { r -> r.headers.count { it.first == "X-Client" } })

        val state = burp.macroState()
        assertEquals(1, state.getValue("automatic_runs").jsonPrimitive.int)
        assertEquals(1, state.getValue("retries_helped").jsonPrimitive.int)
        assertEquals("reauthenticated", state.getValue("last_result").jsonPrimitive.content)
        assertEquals(listOf("session", "csrf"), state.getValue("learned_cookies").jsonArray.map { it.jsonPrimitive.content })
        assertEquals(1, burp.events.getEventsByType(listOf("session.macro.run")).size)
        assertEquals(1, burp.events.getEventsByType(listOf("session.macro.retry")).size)

        // Later covered requests send the new session; a cookie a request does not send is never added.
        assertEquals("session=fresh; lang=en", burp.exchange(me("session=old; lang=en"), ToolType.REPEATER).sent.header("Cookie"))
        val withoutSession = burp.exchange(me("lang=en"), ToolType.REPEATER)
        assertEquals("lang=en", withoutSession.sent.header("Cookie"))
        // It got 401 too, but the macro ran moments ago (min_interval_ms) for a request that already had the new session.
        assertEquals(401, withoutSession.response.status)
        assertNull(withoutSession.response.header(reauthenticated))
        // The browser's traffic (PROXY) is not covered by default: its cookie stays.
        assertEquals("session=old", burp.exchange(me("session=old"), ToolType.PROXY).sent.header("Cookie"))
        assertEquals(1, burp.logins())
    }

    @Test
    fun `a macro step's own 401 never triggers the macro and runs that did not help suspend it`() {
        val burp = burp { Res(401, body = "nope") }
        burp.define(macro(minIntervalMs = 0, maxFailures = 2))

        val first = burp.exchange(me("session=old"), ToolType.REPEATER)
        // The login step got 401 as well: that response went through the handler without re-triggering.
        assertEquals(listOf("GET /api/me", "POST /login", "GET /api/me"), burp.wire.map { "${it.method} ${it.path}" })
        assertEquals(401, first.response.status)
        assertEquals("login", first.response.header(reauthenticated))
        assertFalse(burp.macroState().getValue("suspended").jsonPrimitive.boolean)

        burp.exchange(me("session=old"), ToolType.REPEATER)
        assertEquals(2, burp.logins())
        assertTrue(burp.macroState().getValue("suspended").jsonPrimitive.boolean)
        assertEquals(1, burp.events.getEventsByType(listOf("session.macro.suspended")).size)

        val third = burp.exchange(me("session=old"), ToolType.REPEATER)
        assertEquals(401, third.response.status)
        assertNull(third.response.header(reauthenticated))
        assertEquals(2, burp.logins())
        assertEquals(7, burp.wire.size)
        assertEquals("did_not_help", burp.macroState().getValue("last_result").jsonPrimitive.content)
    }

    @Test
    fun `unauthenticated requests, internal probes and proxy traffic never trigger a login`() {
        val burp = burp { req -> if (req.path == "/login") Res(200, listOf("Set-Cookie" to "session=fresh")) else Res(401) }
        burp.define(macro())

        // A deliberately unauthenticated request stays unauthenticated.
        val anonymous = burp.exchange(Req(path = "/api/me"), ToolType.REPEATER)
        assertEquals(401, anonymous.response.status)
        assertNull(anonymous.response.header(reauthenticated))
        assertEquals(0, burp.logins())

        // Prime the session by hand, then send Raijin's internal probe: no trigger, no macro cookie.
        assertTrue(burp.macros.runNow("login").getValue("success").jsonPrimitive.boolean)
        val probe = burp.exchange(
            Req(path = "/api/me", headers = listOf("Cookie" to "session=old", BoundedHttp.INTERNAL_BYPASS_HEADER to "1")),
            ToolType.EXTENSIONS,
        )
        assertEquals("session=old", probe.sent.header("Cookie"))
        assertNull(probe.sent.header(BoundedHttp.INTERNAL_BYPASS_HEADER))
        assertEquals(401, probe.response.status)
        assertNull(probe.response.header(reauthenticated))

        // The browser's traffic is not covered by default.
        val proxied = burp.exchange(me("session=old"), ToolType.PROXY)
        assertEquals("session=old", proxied.sent.header("Cookie"))
        assertNull(proxied.response.header(reauthenticated))
        assertEquals(1, burp.logins())
    }

    @Test
    fun `a request sent before the run is retried with the new session, a later one within the interval is left alone`() {
        val valid = AtomicReference("fresh")
        val burp = burp { req ->
            when {
                req.path == "/login" -> Res(200, listOf("Set-Cookie" to "session=fresh"))
                req.cookies()["session"] == valid.get() -> Res(200, body = "ok")
                else -> Res(401)
            }
        }
        burp.define(macro(minIntervalMs = 60_000))

        val early = burp.out(me("session=old"), ToolType.SCANNER)
        val first = burp.exchange(me("session=old"), ToolType.REPEATER)
        assertEquals(200, first.response.status)

        // The scanner's request was on its way before the run: it is retried, no second login.
        val late = burp.back(early)
        assertEquals(200, late.response.status)
        assertEquals("login", late.response.header(reauthenticated))
        assertEquals(1, burp.logins())

        // The server now drops the new session too: within min_interval_ms there is no new run.
        valid.set("never")
        val throttled = burp.exchange(me("session=old"), ToolType.REPEATER)
        assertEquals("session=fresh", throttled.sent.header("Cookie"))
        assertEquals(401, throttled.response.status)
        assertNull(throttled.response.header(reauthenticated))
        assertEquals(1, burp.logins())
    }

    @Test
    fun `session rules capture the new token from the login step, which is sent as stored, and the retry carries it`() {
        val burp = burp { req ->
            when {
                req.path == "/login" -> Res(200, listOf("Content-Type" to "application/json"), """{"token":"T2"}""")
                req.header("Authorization") == "Bearer T2" -> Res(200, body = "me")
                else -> Res(401)
            }
        }
        val rule = SessionRule(
            ruleName = "bearer", scope = "all", scopePattern = null, extractFrom = "body", extractHeaderName = null,
            extractRegex = "", injectInto = "header", injectName = "Authorization", injectValueTemplate = "Bearer {value}",
            lastExtractedValue = "T1", extractJsonPath = "$.token", injectIfMissing = false,
        )
        burp.state.sessionRules.add(rule)
        val step = "POST /login HTTP/1.1\r\nHost: target.example\r\nAuthorization: Basic YWxpY2U6cHc=\r\n\r\n"
        burp.define(macro(steps = listOf(buildJsonObject { put("raw_request", step) })))

        val result = burp.exchange(Req(path = "/api/me", headers = listOf("Authorization" to "Bearer T0")), ToolType.EXTENSIONS)

        assertEquals(listOf("Bearer T1", "Basic YWxpY2U6cHc=", "Bearer T2"), burp.wire.map { it.header("Authorization") })
        assertEquals("T2", rule.lastExtractedValue)
        assertEquals(200, result.response.status)
        assertEquals("login", result.response.header(reauthenticated))
    }

    @Test
    fun `a manual run reports each step, the cookies learned and the rules that captured a value`() {
        val burp = burp { req ->
            when {
                req.path == "/login-page" -> Res(200, body = """<input name="csrf" value="c1">""")
                req.path == "/login" && "csrf=c1" in req.body -> Res(
                    200,
                    listOf("Set-Cookie" to "session=fresh; HttpOnly", "Set-Cookie" to "theme=; Max-Age=0"),
                    """{"token":"T9"}""",
                )
                else -> Res(400)
            }
        }
        val rule = SessionRule(
            ruleName = "bearer", scope = "all", scopePattern = null, extractFrom = "body", extractHeaderName = null,
            extractRegex = "", injectInto = "header", injectName = "Authorization", injectValueTemplate = "Bearer {value}",
            extractJsonPath = "$.token",
        )
        burp.state.sessionRules.add(rule)
        val page = buildJsonObject {
            put("raw_request", "GET /login-page HTTP/1.1\r\nHost: target.example\r\n\r\n")
            putJsonArray("extract") { add(buildJsonObject { put("name", "csrf"); put("pattern", "value=\"(\\w+)\"") }) }
        }
        val post = buildJsonObject {
            put("raw_request", "POST /login HTTP/1.1\r\nHost: target.example\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=alice&csrf={{csrf}}")
        }
        burp.define(macro(steps = listOf(page, post)))

        val report = burp.macros.runNow("login")

        assertTrue(report.getValue("success").jsonPrimitive.boolean, report.toString())
        val steps = report.getValue("steps").jsonArray.map { it.jsonObject }
        assertEquals(listOf(200, 200), steps.map { it.getValue("status_code").jsonPrimitive.int })
        assertEquals("c1", steps[0].getValue("extracted").jsonObject.getValue("csrf").jsonPrimitive.content)
        assertEquals("fresh", steps[1].getValue("set_cookies").jsonObject.getValue("session").jsonPrimitive.content)
        assertEquals("user=alice&csrf=c1", burp.wire[1].body)
        val learned = report.getValue("learned_cookies").jsonObject
        assertEquals("fresh", learned.getValue("session").jsonPrimitive.content)
        assertEquals(JsonNull, learned.getValue("theme"))
        assertEquals(listOf("bearer"), report.getValue("session_rules_updated").jsonArray.map { it.jsonPrimitive.content })
        assertEquals("T9", rule.lastExtractedValue)
        val state = report.getValue("state").jsonObject
        assertEquals(1, state.getValue("manual_runs").jsonPrimitive.int)
        assertEquals(listOf("session"), state.getValue("learned_cookies").jsonArray.map { it.jsonPrimitive.content })
        assertTrue(burp.macros.runNow("nope").containsKey("error"))
    }
}
