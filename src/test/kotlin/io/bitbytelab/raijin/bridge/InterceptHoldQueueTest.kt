package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.bridge.InterceptHoldQueue.Outcome
import io.bitbytelab.raijin.bridge.InterceptHoldQueue.Reason
import io.bitbytelab.raijin.bridge.InterceptHoldQueue.Verdict
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The hold queue behind the proxy intercept tools: a held proxy thread comes back with the agent's
 * decision, and without one it always comes back by itself (timeout, disarm, unload).
 */
class InterceptHoldQueueTest {

    private val longTimeout = 10_000L

    /** Holds [message] on a thread of its own, as a proxy handler thread would; completes with the outcome. */
    private fun holdAsync(queue: InterceptHoldQueue<String>, message: String): CompletableFuture<Outcome<String>> {
        val result = CompletableFuture<Outcome<String>>()
        thread(isDaemon = true) { result.complete(queue.hold(message)) }
        return result
    }

    /** Waits until [count] messages are held. */
    private fun awaitHeldCount(queue: InterceptHoldQueue<String>, count: Int) {
        val deadline = System.currentTimeMillis() + 5_000
        while (queue.list().size < count) {
            check(System.currentTimeMillis() < deadline) { "only ${queue.list().size} of $count messages were held" }
            queue.awaitHeld(50)
            Thread.sleep(5)
        }
    }

    private fun <T> CompletableFuture<T>.result(): T = get(5, TimeUnit.SECONDS)

    @Test
    fun `nothing is held until the queue is armed`() {
        val queue = InterceptHoldQueue<String>()
        val outcome = queue.hold("GET /")
        assertEquals(Outcome<String>(Verdict.FORWARD, Reason.NOT_ARMED), outcome)
        assertFalse(outcome.wasHeld)
        assertTrue(queue.list().isEmpty())
    }

    @Test
    fun `a held message comes back with the agent's edit or drop`() {
        val queue = InterceptHoldQueue<String>()
        assertTrue(queue.arm(maxHeld = 5, timeoutMs = longTimeout))

        val first = holdAsync(queue, "GET /a")
        val second = holdAsync(queue, "GET /b")
        awaitHeldCount(queue, 2)
        val held = queue.list().associateBy { it.message }
        assertEquals(setOf("GET /a", "GET /b"), held.keys)

        assertTrue(queue.decide(held.getValue("GET /a").id, Verdict.FORWARD, "PUT /a"))
        assertTrue(queue.decide(held.getValue("GET /b").id, Verdict.DROP))
        assertEquals(Outcome(Verdict.FORWARD, Reason.DECIDED, "PUT /a"), first.result())
        assertEquals(Outcome<String>(Verdict.DROP, Reason.DECIDED), second.result())

        assertFalse(queue.decide(held.getValue("GET /a").id, Verdict.DROP), "a message is decided once")
        assertEquals(Reason.DECIDED, queue.released(held.getValue("GET /a").id)?.reason)
        assertEquals(true, queue.released(held.getValue("GET /a").id)?.modified)
        val status = queue.status()
        assertEquals(2L, status.decided)
        assertEquals(0, status.held)
    }

    @Test
    fun `an unanswered hold forwards the message unchanged when it times out`() {
        val queue = InterceptHoldQueue<String>()
        queue.arm(maxHeld = 5, timeoutMs = 50)
        val started = System.nanoTime()
        val outcome = queue.hold("GET /slow")
        assertEquals(Outcome<String>(Verdict.FORWARD, Reason.TIMEOUT), outcome)
        assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started) >= 45)

        val id = queue.recentlyReleased(1).single().id
        assertFalse(queue.decide(id, Verdict.DROP), "too late: the timeout already forwarded it")
        assertEquals(Reason.TIMEOUT, queue.released(id)?.reason)
        assertEquals(1L, queue.status().timedOut)
        assertTrue(queue.armed, "one timeout does not disarm")
    }

    @Test
    fun `timeouts in a row disarm the queue and release everything it holds`() {
        val queue = InterceptHoldQueue<String>(unansweredLimit = 2)
        queue.arm(maxHeld = 10, timeoutMs = 60)
        val waiting = (1..3).map { holdAsync(queue, "GET /$it") }
        val outcomes = waiting.map { it.result() }

        assertTrue(outcomes.all { it.verdict == Verdict.FORWARD && it.replacement == null })
        assertTrue(outcomes.count { it.reason == Reason.TIMEOUT } >= 2)
        assertFalse(queue.armed)
        assertEquals("2 holds in a row timed out without a decision", queue.status().disarmReason)
        assertEquals(Reason.NOT_ARMED, queue.hold("GET /after").reason, "nothing is held once disarmed")
    }

    @Test
    fun `a decision resets the run of timeouts`() {
        val queue = InterceptHoldQueue<String>(unansweredLimit = 2)
        queue.arm(maxHeld = 5, timeoutMs = 1_000)
        assertEquals(Reason.TIMEOUT, queue.hold("GET /1").reason)

        val decided = holdAsync(queue, "GET /2")
        awaitHeldCount(queue, 1)
        assertTrue(queue.decide(queue.list().single().id, Verdict.FORWARD))
        assertEquals(Reason.DECIDED, decided.result().reason)

        // Without the decision in between this would be the second timeout in a row.
        assertEquals(Reason.TIMEOUT, queue.hold("GET /3").reason)
        assertTrue(queue.armed, "the decision started the count of timeouts again")
    }

    @Test
    fun `beyond max_held a message passes straight through`() {
        val queue = InterceptHoldQueue<String>()
        queue.arm(maxHeld = 1, timeoutMs = longTimeout)
        val parked = holdAsync(queue, "GET /1")
        awaitHeldCount(queue, 1)

        assertEquals(Outcome<String>(Verdict.FORWARD, Reason.QUEUE_FULL), queue.hold("GET /2"))
        assertEquals(1L, queue.status().passedQueueFull)

        assertEquals(1, queue.resolveAll(Verdict.FORWARD, Reason.DECIDED))
        assertEquals(Reason.DECIDED, parked.result().reason)
    }

    @Test
    fun `a message budget disarms the queue but keeps what is already held`() {
        val queue = InterceptHoldQueue<String>()
        queue.arm(maxHeld = 5, timeoutMs = longTimeout, maxMessages = 1)
        val parked = holdAsync(queue, "GET /1")
        awaitHeldCount(queue, 1)

        assertFalse(queue.armed)
        assertEquals("max_messages reached", queue.status().disarmReason)
        assertEquals(Reason.NOT_ARMED, queue.hold("GET /2").reason)
        assertEquals(1, queue.status().held)

        queue.decide(queue.list().single().id, Verdict.DROP)
        assertEquals(Verdict.DROP, parked.result().verdict)
    }

    @Test
    fun `closing releases every held message and refuses to hold again`() {
        val queue = InterceptHoldQueue<String>()
        queue.arm(maxHeld = 5, timeoutMs = longTimeout)
        val parked = listOf(holdAsync(queue, "GET /1"), holdAsync(queue, "GET /2"))
        awaitHeldCount(queue, 2)

        queue.close()

        parked.forEach { assertEquals(Outcome<String>(Verdict.FORWARD, Reason.RELEASED), it.result()) }
        assertFalse(queue.armed)
        assertFalse(queue.arm(maxHeld = 5, timeoutMs = longTimeout))
        assertEquals(Reason.NOT_ARMED, queue.hold("GET /3").reason)
    }

    @Test
    fun `waiting for a held message returns once one arrives, and at once when nothing can arrive`() {
        val queue = InterceptHoldQueue<String>()
        assertFalse(queue.awaitHeld(5_000), "not armed: nothing can arrive")

        queue.arm(maxHeld = 5, timeoutMs = longTimeout)
        thread(isDaemon = true) {
            Thread.sleep(50)
            queue.hold("GET /late")
        }
        assertTrue(queue.awaitHeld(5_000))
        assertNotNull(queue.find(queue.list().single().id))
        queue.resolveAll(Verdict.FORWARD, Reason.RELEASED)
        assertNull(queue.find(1))
    }

    @Test
    fun `a hold policy matches the side, host, URL, method and scope it names`() {
        val policy = HoldPolicy(requests = true, responses = false, matchHost = "*.shop.test", matchUrl = "/api/", matchMethod = "post")
        var scopeAsked = false
        val inScope = { scopeAsked = true; false }

        assertTrue(policy.matches(true, "www.shop.test", "https://www.shop.test/api/cart", "POST", inScope))
        assertFalse(scopeAsked, "scope is only asked for when the policy needs it")
        assertFalse(policy.matches(false, "www.shop.test", "https://www.shop.test/api/cart", "POST", inScope), "responses are not held")
        assertFalse(policy.matches(true, "shop.test", "https://shop.test/api/cart", "POST", inScope))
        assertFalse(policy.matches(true, "www.shop.test", "https://www.shop.test/static/x", "POST", inScope))
        assertFalse(policy.matches(true, "www.shop.test", "https://www.shop.test/api/cart", "GET", inScope))
        assertFalse(policy.matches(true, null, null, null, inScope), "unreadable values never match a condition")

        val scoped = HoldPolicy(requests = true, responses = true, inScopeOnly = true)
        assertFalse(scoped.matches(false, null, null, null, inScope))
        assertTrue(scoped.matches(false, null, null, null) { true })
        assertEquals("both", scoped.target)
    }

    @Test
    fun `the hold target parses request, response and both`() {
        assertEquals(true to false, HoldPolicy.sides(null))
        assertEquals(true to false, HoldPolicy.sides(" Request "))
        assertEquals(false to true, HoldPolicy.sides("response"))
        assertEquals(true to true, HoldPolicy.sides("BOTH"))
        assertNull(HoldPolicy.sides("sideways"))
    }
}
