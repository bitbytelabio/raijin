package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.MimeType
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.requests.MalformedRequestException
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.ProxyHistoryFilter
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketHistoryFilter
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.websocket.Direction
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.state.ProxyRule
import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.lang.reflect.Proxy
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * [ProxyBridge] against fake Montoya history: malformed requests, items without a response, and
 * out-of-range paging must never fail a read or slip through a filter. Also covers host-pattern
 * matching and rule validation, which run before a rule ever reaches live traffic.
 */
class ProxyBridgeTest {

    private val bridges = mutableListOf<ProxyBridge>()

    @AfterTest
    fun shutDown() = bridges.forEach { it.shutdown() }

    // ---- fakes ----------------------------------------------------------

    private fun <T> fake(type: Class<T>, answer: (method: String, args: Array<Any?>) -> Any?): T =
        type.cast(Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { self, m, args ->
            when (m.name) {
                "hashCode" -> System.identityHashCode(self)
                "equals" -> self === args?.get(0)
                else -> answer(m.name, args ?: emptyArray())
            }
        })

    private fun service(host: String) = fake(HttpService::class.java) { name, _ ->
        when (name) {
            "host" -> host
            "port" -> 443
            "secure" -> true
            "toString" -> "https://$host"
            else -> null
        }
    }

    /** A history item; a null [method] makes its request line unparseable, a null [status] means no response. */
    private fun historyItem(id: Int, host: String, method: String?, status: Int?): ProxyHttpRequestResponse {
        val service = service(host)
        val request = fake(HttpRequest::class.java) { name, _ ->
            when (name) {
                "method" -> method ?: throw MalformedRequestException("bad request line")
                "url" -> if (method == null) throw MalformedRequestException("bad request line") else "https://$host/p$id"
                "path" -> if (method == null) throw MalformedRequestException("bad request line") else "/p$id"
                "httpService" -> service
                "headers" -> emptyList<Any>()
                "isInScope" -> true
                "toString" -> "${method ?: "BAD LINE"} /p$id HTTP/1.1\r\nHost: $host\r\n\r\n"
                else -> null
            }
        }
        val response = status?.let { code ->
            fake(HttpResponse::class.java) { name, _ -> if (name == "statusCode") code.toShort() else null }
        }
        return fake(ProxyHttpRequestResponse::class.java) { name, _ ->
            when (name) {
                "id" -> id
                "httpService" -> service
                "request", "finalRequest" -> request
                "hasResponse" -> status != null
                "response" -> response
                "mimeType" -> MimeType.HTML
                "edited" -> false
                else -> null
            }
        }
    }

    private fun wsMessage(id: Int, upgradeHost: String?, direction: Direction): ProxyWebSocketMessage {
        val upgrade = upgradeHost?.let { host ->
            fake(HttpRequest::class.java) { name, _ ->
                when (name) {
                    "httpService" -> service(host)
                    "url" -> "wss://$host/ws"
                    else -> null
                }
            }
        }
        return fake(ProxyWebSocketMessage::class.java) { name, _ ->
            when (name) {
                "id" -> id
                "webSocketId" -> 1
                "listenerPort" -> 8080
                "direction" -> direction
                "upgradeRequest" -> upgrade
                else -> null
            }
        }
    }

    private fun bridge(
        items: List<ProxyHttpRequestResponse> = emptyList(),
        wsItems: List<ProxyWebSocketMessage> = emptyList(),
        state: StateManager = StateManager(),
    ): ProxyBridge {
        val proxy = fake(burp.api.montoya.proxy.Proxy::class.java) { name, args ->
            when (name) {
                "history" -> if (args.isEmpty()) items else items.filter { (args[0] as ProxyHistoryFilter).matches(it) }
                "webSocketHistory" ->
                    if (args.isEmpty()) wsItems else wsItems.filter { (args[0] as ProxyWebSocketHistoryFilter).matches(it) }
                else -> null
            }
        }
        val api = fake(MontoyaApi::class.java) { name, _ -> if (name == "proxy") proxy else null }
        return ProxyBridge(api, EventBus(), state, FindingsBridge(state)).also { bridges += it }
    }

    private fun ids(result: JsonObject, key: String = "index"): List<Int> =
        result["items"]!!.jsonArray.map { it.jsonObject[key]!!.jsonPrimitive.int }

    // ---- history reads --------------------------------------------------

    @Test
    fun `status filters skip items that have no response`() {
        val b = bridge(listOf(historyItem(1, "a.test", "GET", 200), historyItem(2, "a.test", "GET", null), historyItem(3, "a.test", "GET", 404)))

        assertEquals(listOf(1), ids(b.getHistory(0, 100, null, null, 200, null, false)))
        assertEquals(listOf(1, 3), ids(b.getHistory(0, 100, null, null, null, null, false, statusCodeRange = "0-499")))
        assertEquals(listOf(1, 2, 3), ids(b.getHistory(0, 100, null, null, null, null, false)))
    }

    @Test
    fun `a malformed request is listed instead of failing the read`() {
        val b = bridge(listOf(historyItem(1, "a.test", "GET", 200), historyItem(2, "b.test", null, 200)))

        val all = b.getHistory(0, 100, null, null, null, null, false, includeRequest = true)
        assertEquals(2, all["returned"]!!.jsonPrimitive.int)
        val malformed = all["items"]!!.jsonArray[1].jsonObject
        assertEquals(true, malformed["malformed_request"]?.jsonPrimitive?.boolean)
        assertEquals("b.test", malformed["host"]?.jsonPrimitive?.content)
        assertEquals(200, malformed["status_code"]?.jsonPrimitive?.int)
        assertNull(malformed["method"])
        assertNull(all["items"]!!.jsonArray[0].jsonObject["malformed_request"])

        // A method filter cannot match a request whose method is unreadable; a host filter still can.
        assertEquals(listOf(1), ids(b.getHistory(0, 100, null, "get", null, null, false)))
        assertEquals(listOf(2), ids(b.getHistory(0, 100, "B.TEST", null, null, null, false)))
    }

    @Test
    fun `negative or oversized paging values never throw`() {
        val b = bridge((1..5).map { historyItem(it, "a.test", "GET", 200) })

        val negativeStart = b.getHistory(-7, 2, null, null, null, null, false)
        assertEquals(0, negativeStart["start_index"]!!.jsonPrimitive.int)
        assertEquals(listOf(1, 2), ids(negativeStart))

        assertEquals(0, b.getHistory(0, -3, null, null, null, null, false)["returned"]!!.jsonPrimitive.int)
        val pastEnd = b.getHistory(50, 10, null, null, null, null, false)
        assertEquals(0, pastEnd["returned"]!!.jsonPrimitive.int)
        assertEquals(5, pastEnd["total_filtered"]!!.jsonPrimitive.int)
        assertEquals(listOf(4, 5), ids(b.getHistory(3, Int.MAX_VALUE, null, null, null, null, false)))
        assertEquals(0, b.searchHistory("GET", "both", false, -1, false)["returned"]!!.jsonPrimitive.int)
    }

    @Test
    fun `search skips malformed requests without failing`() {
        val b = bridge(listOf(historyItem(1, "a.test", "GET", 200), historyItem(2, "a.test", null, 200)))
        val found = b.searchHistory("/p\\d", "url", false, 100, false)
        assertEquals(listOf(1), ids(found))
        assertNotNull(b.searchHistory("(", "both", false, 100, false)["error"])
    }

    @Test
    fun `websocket host filter skips messages without an upgrade request`() {
        val b = bridge(wsItems = listOf(wsMessage(1, "chat.test", Direction.CLIENT_TO_SERVER), wsMessage(2, null, Direction.SERVER_TO_CLIENT)))

        assertEquals(listOf(1), ids(b.getWebSocketHistory(0, 100, "chat", null), "id"))
        assertEquals(listOf(2), ids(b.getWebSocketHistory(0, 100, null, "server_to_client"), "id"))
        assertEquals(listOf(1, 2), ids(b.getWebSocketHistory(-5, 100, null, "both"), "id"))
    }

    @Test
    fun `an unknown websocket direction is an error instead of no filter`() {
        val b = bridge(wsItems = listOf(wsMessage(1, "chat.test", Direction.CLIENT_TO_SERVER)))
        assertNotNull(b.getWebSocketHistory(0, 100, null, "sideways")["error"])
        assertNotNull(b.searchWebSocketHistory(".*", "sideways", 100)["error"])
    }

    // ---- rules ----------------------------------------------------------

    private fun rule(
        id: String = "prule-1",
        type: String = "request",
        action: String = "tag",
        matchHost: String? = null,
        matchUrl: String? = null,
        matchStatus: Int? = null,
        addHeader: String? = null,
        replaceHeader: Map<String, String>? = null,
        bodyRegex: String? = null,
        bodyReplacement: String? = null,
        tagHighlight: String? = null,
    ) = ProxyRule(
        ruleId = id, type = type, matchHost = matchHost, matchUrl = matchUrl, matchStatus = matchStatus,
        action = action, modifyAddHeader = addHeader, modifyReplaceHeader = replaceHeader,
        modifyBodyRegex = bodyRegex, modifyBodyReplacement = bodyReplacement, tagHighlight = tagHighlight,
    )

    @Test
    fun `setRule replaces a rule in place and rejects invalid ones without storing them`() {
        val state = StateManager()
        val b = bridge(state = state)
        b.setRule(rule("prule-1", matchHost = "*.a.test"))
        b.setRule(rule("prule-2"))
        val updated = b.setRule(rule("prule-1", action = "drop"))

        assertNull(updated["error"])
        assertEquals(listOf("prule-1", "prule-2"), state.proxyRules.map { it.ruleId })
        assertEquals("drop", state.proxyRules[0].action)

        assertNotNull(b.setRule(rule("prule-3", matchUrl = "("))["error"])
        assertEquals(2, state.proxyRules.size)
        assertNotNull(b.listRules("sideways")["error"])
        assertEquals(2, b.listRules("request")["total"]!!.jsonPrimitive.int)
        assertEquals(0, b.listRules("RESPONSE")["total"]!!.jsonPrimitive.int)
        assertTrue(b.removeRule("prule-2")["removed"]!!.jsonPrimitive.boolean)
        assertFalse(b.removeRule("prule-2")["removed"]!!.jsonPrimitive.boolean)
    }

    @Test
    fun `a valid rule passes validation`() {
        assertNull(ProxyBridge.validateRule(rule(action = "modify", addHeader = "X-Test: 1", matchHost = "*.example.com")))
        assertNull(ProxyBridge.validateRule(rule(type = "response", action = "tag", matchStatus = 302, tagHighlight = "red")))
        assertNull(ProxyBridge.validateRule(rule(action = "modify", bodyRegex = "secret=\\w+", bodyReplacement = "")))
    }

    @Test
    fun `invalid patterns, actions and headers are rejected before reaching live traffic`() {
        assertNotNull(ProxyBridge.validateRule(rule(matchUrl = "(unclosed")))
        assertNotNull(ProxyBridge.validateRule(rule(matchHost = "[a-")))
        assertNotNull(ProxyBridge.validateRule(rule(action = "explode")))
        assertNotNull(ProxyBridge.validateRule(rule(type = "both")))
        assertNotNull(ProxyBridge.validateRule(rule(type = "response", matchStatus = 1000)))
        assertNotNull(ProxyBridge.validateRule(rule(tagHighlight = "purple")))
        assertNotNull(ProxyBridge.validateRule(rule(action = "modify")), "modify with nothing to modify")
        assertNotNull(ProxyBridge.validateRule(rule(action = "modify", bodyRegex = "a")), "body regex without replacement")
        assertNotNull(ProxyBridge.validateRule(rule(action = "modify", addHeader = "no colon")))
        assertNotNull(ProxyBridge.validateRule(rule(action = "modify", addHeader = "X-A: 1\r\nX-B: 2")))
        assertNotNull(ProxyBridge.validateRule(rule(action = "modify", replaceHeader = mapOf("X-A" to "1\r\nX-B: 2"))))
    }

    // ---- host patterns --------------------------------------------------

    @Test
    fun `a regex host pattern keeps its meaning instead of having its star rewritten`() {
        // The old `replace("*", ".*")` turned "api.*" into "api..*", which no longer matched "api".
        assertTrue(SafeRegex.matchesHostPattern("api.*", "api"))
        assertTrue(SafeRegex.matchesHostPattern(".*", "anything.example.com"))
        assertTrue(SafeRegex.matchesHostPattern(".*\\.example\\.com", "a.example.com"))
        assertFalse(SafeRegex.matchesHostPattern(".*\\.example\\.com", "example.com"))
    }

    @Test
    fun `a glob host pattern matches whole hosts only`() {
        assertTrue(SafeRegex.matchesHostPattern("*.example.com", "api.EXAMPLE.com"))
        assertTrue(SafeRegex.matchesHostPattern("*.example.com", "a.b.example.com"))
        assertFalse(SafeRegex.matchesHostPattern("*.example.com", "example.com"))
        assertFalse(SafeRegex.matchesHostPattern("*.example.com", "api.example.com.evil.test"))
        assertTrue(SafeRegex.matchesHostPattern("example.com", "example.com"))
        assertFalse(SafeRegex.matchesHostPattern("example.com", "api.example.com"))
        assertTrue(SafeRegex.matchesHostPattern("*", "anything"))
    }

    @Test
    fun `host pattern validation accepts globs and regexes and rejects broken regexes`() {
        assertNull(ProxyBridge.hostPatternError("*.example.com"))
        assertNull(ProxyBridge.hostPatternError(".*\\.example\\.com"))
        assertNull(ProxyBridge.hostPatternError("api.example.com"))
        assertNull(ProxyBridge.hostPatternError("*"))
        assertNotNull(ProxyBridge.hostPatternError("(api|www.example.com"))
        assertNotNull(ProxyBridge.hostPatternError("[a-"))
        assertNotNull(ProxyBridge.hostPatternError("  "))
    }
}
