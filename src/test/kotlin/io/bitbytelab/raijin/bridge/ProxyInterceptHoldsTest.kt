package io.bitbytelab.raijin.bridge

import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import io.bitbytelab.raijin.events.EventBus
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * The proxy intercept tools end to end, with fake Montoya messages: what the agent sees of a held
 * message, how its edits and decisions reach the proxy thread, and that a message nobody decides
 * on goes through by itself.
 */
class ProxyInterceptHoldsTest {

    private val eventBus = EventBus()
    private val holds = ProxyInterceptHolds(eventBus)

    @AfterTest
    fun unload() = holds.shutdown()

    private val ordersRequest = FakeMessage(
        method = "GET",
        url = "https://app.test/api/orders?id=1",
        path = "/api/orders?id=1",
        headers = listOf("Host" to "app.test", "Cookie" to "session=admin"),
    )

    private fun arm(target: String? = null, timeoutSeconds: Int? = 60, matchUrl: String? = null): JsonObject =
        holds.arm(target, null, matchUrl, null, false, timeoutSeconds, null, null)

    /** Offers [request] on a thread of its own, as Burp's proxy thread would. */
    private fun holdRequestAsync(request: HttpRequest, messageId: Int = 1): CompletableFuture<ProxyInterceptHolds.Offered<HttpRequest>?> {
        val result = CompletableFuture<ProxyInterceptHolds.Offered<HttpRequest>?>()
        thread(isDaemon = true) { result.complete(holds.holdRequest(messageId, request) { true }) }
        return result
    }

    private fun holdResponseAsync(response: HttpResponse, request: HttpRequest): CompletableFuture<ProxyInterceptHolds.Offered<HttpResponse>?> {
        val result = CompletableFuture<ProxyInterceptHolds.Offered<HttpResponse>?>()
        thread(isDaemon = true) { result.complete(holds.holdResponse(7, response, request) { true }) }
        return result
    }

    /** The held messages once there are [count] of them. */
    private fun awaitHeld(count: Int): List<JsonObject> {
        val deadline = System.currentTimeMillis() + 5_000
        while (true) {
            val listed = holds.listHeld(1, true, null)
            if (listed["held"]!!.jsonPrimitive.int >= count) return listed["messages"]!!.jsonArray.map { it.jsonObject }
            check(System.currentTimeMillis() < deadline) { "only ${listed["held"]} of $count messages were held" }
        }
    }

    private fun <T> CompletableFuture<T>.result(): T = get(5, TimeUnit.SECONDS)

    private fun JsonObject.text(key: String) = this[key]!!.jsonPrimitive.content

    @Test
    fun `arming checks the filters and clamps the limits with a note`() {
        assertNotNull(holds.arm("sideways", null, null, null, false, null, null, null)["error"])
        assertNotNull(holds.arm(null, "[a-", null, null, false, null, null, null)["error"])
        assertNotNull(holds.arm(null, null, "(", null, false, null, null, null)["error"])
        assertNotNull(holds.arm(null, null, null, " ", false, null, null, null)["error"])

        val armed = holds.arm("both", "*.app.test", "/api/", "post", true, 5000, 0, 3)
        assertNull(armed["error"])
        assertTrue(armed["armed"]!!.jsonPrimitive.boolean)
        assertEquals("both", armed.text("target"))
        assertEquals(HoldPolicy.MAX_TIMEOUT_SECONDS, armed["timeout_seconds"]!!.jsonPrimitive.int)
        assertEquals(1, armed["max_held"]!!.jsonPrimitive.int)
        assertEquals(3, armed["remaining_messages"]!!.jsonPrimitive.int)
        assertEquals(
            listOf("timeout_seconds 5000 is outside 1..600; used 600", "max_held 0 is outside 1..200; used 1"),
            armed["notes"]!!.jsonArray.map { it.jsonPrimitive.content },
        )
        assertTrue(eventBus.getEventsByType(listOf("proxy.intercept.hold")).isNotEmpty())
    }

    @Test
    fun `nothing is held unless the queue is armed and the message matches`() {
        assertNull(holds.holdRequest(1, fakeRequest(ordersRequest)) { true }, "not armed")

        arm(target = "request", matchUrl = "/api/")
        assertNull(holds.holdRequest(1, fakeRequest(ordersRequest.copy(url = "https://app.test/static/app.js"))) { true })
        assertNull(
            holds.holdResponse(1, fakeResponse(FakeMessage()), fakeRequest(ordersRequest)) { true },
            "responses are not held when the target is 'request'",
        )
    }

    @Test
    fun `the agent sees a held request, edits it and forwards it`() {
        arm(target = "request")
        val proxyThread = holdRequestAsync(fakeRequest(ordersRequest), messageId = 42)

        val entry = awaitHeld(1).single()
        assertEquals("request", entry.text("kind"))
        assertEquals(42, entry["message_id"]!!.jsonPrimitive.int)
        assertEquals("GET", entry.text("method"))
        assertEquals("https://app.test/api/orders?id=1", entry.text("url"))
        assertTrue("Cookie: session=admin" in entry.text("raw"))
        assertTrue(entry["expires_in_ms"]!!.jsonPrimitive.long in 1..60_000)
        val id = entry["id"]!!.jsonPrimitive.long

        val forwarded = holds.forward(
            id, false,
            InterceptEdit(method = "POST", path = "/api/orders?id=2", setHeaders = mapOf("cookie" to "session=low"), removeHeaders = listOf("X-Absent")),
        )
        assertNull(forwarded["error"])
        assertTrue(forwarded["modified"]!!.jsonPrimitive.boolean)

        val offered = assertNotNull(proxyThread.result())
        assertFalse(offered.drop)
        assertTrue(offered.decided)
        assertEquals("POST", offered.message.method())
        assertEquals("/api/orders?id=2", offered.message.path())
        assertEquals(listOf("Host" to "app.test", "Cookie" to "session=low"), offered.message.headerPairs())

        val released = eventBus.getEventsByType(listOf("proxy.intercept.released")).single().data
        assertEquals("forward", released.text("verdict"))
        assertEquals("decided", released.text("reason"))
        assertTrue(released["modified"]!!.jsonPrimitive.boolean)
        assertEquals(1, eventBus.getEventsByType(listOf("proxy.intercept.held")).size)
    }

    @Test
    fun `an edit that does not fit the message is refused and the message stays held`() {
        arm(target = "response")
        val proxyThread = holdResponseAsync(fakeResponse(FakeMessage(status = 200, body = "{}")), fakeRequest(ordersRequest))
        val id = awaitHeld(1).single()["id"]!!.jsonPrimitive.long

        assertTrue("held request" in holds.forward(id, false, InterceptEdit(method = "PUT")).text("error"))
        assertTrue("'status_code'" in holds.forward(id, false, InterceptEdit(statusCode = 70_000)).text("error"))
        assertEquals(1, holds.listHeld(0, false, null)["held"]!!.jsonPrimitive.int)

        assertNull(holds.forward(id, false, InterceptEdit(statusCode = 500, body = "{\"admin\":true}"))["error"])
        val offered = assertNotNull(proxyThread.result())
        assertEquals(500, offered.message.statusCode().toInt())
        assertEquals("{\"admin\":true}", offered.message.bodyToString())
    }

    @Test
    fun `a dropped message never goes on, and a late decision says what happened to it`() {
        arm(target = "both")
        val proxyThread = holdRequestAsync(fakeRequest(ordersRequest))
        val id = awaitHeld(1).single()["id"]!!.jsonPrimitive.long

        assertTrue(holds.drop(id, false)["dropped"]!!.jsonPrimitive.boolean)
        assertTrue(assertNotNull(proxyThread.result()).drop)

        val late = holds.forward(id, false, InterceptEdit())
        assertEquals("Message $id is no longer held: it was already dropped.", late.text("error"))
        assertTrue("No held message" in holds.drop(9_999, false).text("error"))
        assertNotNull(holds.forward(null, false, InterceptEdit())["error"], "an id or all=true is needed")
    }

    @Test
    fun `an unanswered hold is forwarded unchanged when it times out`() {
        arm(target = "request", timeoutSeconds = 1)
        val request = fakeRequest(ordersRequest)
        val offered = assertNotNull(holds.holdRequest(1, request) { true })
        assertSame(request, offered.message)
        assertFalse(offered.drop)
        assertFalse(offered.decided)

        val listed = holds.listHeld(0, false, null)
        val released = listed["recently_released"]!!.jsonArray.single().jsonObject
        assertEquals("timeout", released.text("reason"))
        val id = released["id"]!!.jsonPrimitive.long
        assertEquals(
            "Message $id is no longer held: its hold timed out and it was forwarded unchanged.",
            holds.forward(id, false, InterceptEdit()).text("error"),
        )
    }

    @Test
    fun `forwarding all and releasing send everything on unchanged`() {
        arm(target = "request")
        val first = holdRequestAsync(fakeRequest(ordersRequest), messageId = 1)
        val second = holdRequestAsync(fakeRequest(ordersRequest.copy(path = "/api/cart")), messageId = 2)
        awaitHeld(2)

        assertNotNull(holds.forward(null, true, InterceptEdit(body = "x"))["error"], "an edit applies to one message")
        assertEquals(2, holds.forward(null, true, InterceptEdit())["forwarded"]!!.jsonPrimitive.int)
        listOf(first, second).forEach {
            val offered = assertNotNull(it.result())
            assertTrue(offered.decided)
            assertFalse(offered.drop)
        }

        val third = holdRequestAsync(fakeRequest(ordersRequest), messageId = 3)
        awaitHeld(1)
        val release = holds.release()
        assertFalse(release["armed"]!!.jsonPrimitive.boolean)
        assertEquals(1, release["released"]!!.jsonPrimitive.int)
        assertFalse(assertNotNull(third.result()).decided)
        assertNull(holds.holdRequest(4, fakeRequest(ordersRequest)) { true }, "released: nothing is held any more")
    }

    @Test
    fun `unloading releases held messages and stops holding for good`() {
        arm(target = "request")
        val proxyThread = holdRequestAsync(fakeRequest(ordersRequest))
        awaitHeld(1)

        holds.shutdown()

        val offered = assertNotNull(proxyThread.result())
        assertFalse(offered.drop)
        assertFalse(offered.decided)
        assertTrue("unloading" in arm(target = "request").text("error"))
    }
}
