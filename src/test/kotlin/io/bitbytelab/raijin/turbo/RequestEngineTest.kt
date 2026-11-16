package io.bitbytelab.raijin.turbo

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertTimeoutPreemptively
import java.time.Duration

class RequestEngineTest {

    private lateinit var engine: TestRequestEngine

    @BeforeEach
    fun setup() {
        engine = TestRequestEngine()
        engine.start()
    }

    @Test
    fun `queue stores connectionId on request`() {
        engine.queue("GET / HTTP/1.1\r\nHost: test.local\r\n\r\n", emptyList<Any>(), 0, null, null, "", 0, 1000, emptyList(), 0, null, null, true, "my-conn")

        val queued = engine.requestQueue.poll()
        assertNotNull(queued)
        assertEquals("my-conn", queued!!.connectionId)
    }

    @Test
    fun `queue allows null connectionId`() {
        engine.queue("GET / HTTP/1.1\r\nHost: test.local\r\n\r\n", emptyList<Any>(), 0, null, null, "", 0, 1000, emptyList(), 0, null, null, true, null)

        val queued = engine.requestQueue.poll()
        assertNotNull(queued)
        assertNull(queued!!.connectionId)
    }

    @Test
    fun `queue throws when both gate and connectionId specified`() {
        val exception = assertThrows<Exception> {
            engine.queue("GET / HTTP/1.1\r\nHost: test.local\r\n\r\n", emptyList<Any>(), 0, null, "my-gate", "", 0, 1000, emptyList(), 0, null, null, true, "my-conn")
        }
        assertTrue(exception.message!!.contains("mutually exclusive"))
    }

    @Test
    fun `queue allows gate without connectionId`() {
        assertDoesNotThrow {
            engine.queue("GET / HTTP/1.1\r\nHost: test.local\r\n\r\n", emptyList<Any>(), 0, null, "my-gate", "", 0, 1000, emptyList(), 0, null, null, true, null)
        }
    }

    @Test
    fun `queue allows connectionId without gate`() {
        assertDoesNotThrow {
            engine.queue("GET / HTTP/1.1\r\nHost: test.local\r\n\r\n", emptyList<Any>(), 0, null, null, "", 0, 1000, emptyList(), 0, null, null, true, "my-conn")
        }
    }

    private fun get(path: String) = "GET $path HTTP/1.1\r\nHost: test.local\r\n\r\n"

    private fun path(request: Request) = request.template.substringAfter("GET ").substringBefore(" ")

    @Test
    fun `requests queued before start beyond the queue's capacity wait in order instead of being dropped`() {
        val unstarted = TestRequestEngine()
        val queue = unstarted.requestQueue
        repeat(120) { unstarted.queue(get("/$it")) }

        assertSame(queue, unstarted.requestQueue, "the queue was replaced")
        assertEquals(100, queue.size)
        assertTrue(unstarted.statusString().contains("Queued: 120"))

        repeat(30) { queue.poll() }
        unstarted.start()
        unstarted.queue(get("/last"))

        val paths = generateSequence { queue.poll() }.map(::path).toList()
        assertEquals((30 until 120).map { "/$it" } + "/last", paths)
    }

    @Test
    fun `userState takes None values, which a concurrent map would reject`() {
        @Suppress("UNCHECKED_CAST")
        (engine.userState as MutableMap<String, Any?>)["nothing"] = null
        engine.userState["count"] = 1

        assertTrue(engine.userState.containsKey("nothing"))
        assertEquals(1, engine.userState["count"])
    }

    @Test
    fun `applySetting changes a known setting and rejects an unknown one`() {
        engine.applySetting("calculateAnomalyRank", false)

        assertEquals(false, engine.internalSettings["calculateAnomalyRank"])
        assertThrows<Exception> { engine.applySetting("noSuchSetting", true) }
    }

    @Test
    fun `an idle timeout cancels the run off the thread that noticed it`() {
        engine.idleTimeout = 50
        engine.lastLife = System.currentTimeMillis() - 1_000

        assertTrue(engine.shouldAbandonRun())

        val deadline = System.currentTimeMillis() + 2_000
        while (engine.runState.get() != 3 && System.currentTimeMillis() < deadline) Thread.sleep(10)
        assertEquals(3, engine.runState.get())
    }

    @Test
    fun `cancelling a completed run leaves it completed`() {
        engine.setRunState(4)

        engine.cancel()

        assertEquals(4, engine.runState.get())
    }

    @Test
    fun `the first terminal state stands`() {
        engine.finish(3)
        engine.finish(4)

        assertEquals(3, engine.runState.get())
    }

    @Test
    fun `a stop before the run goes live stands, and the run takes no more requests`() {
        val unstarted = TestRequestEngine()
        unstarted.cancel()

        // start() used to set the run live outright, undoing a stop that landed while it waited.
        unstarted.start()

        assertEquals(3, unstarted.runState.get())
        assertThrows<IllegalStateException> { unstarted.queue(get("/late")) }
    }

    @Test
    fun `a run put back to live is cancelled again`() {
        engine.cancel()
        engine.setRunState(1)

        // The first cancel used to claim a one-shot flag, which made this one a no-op.
        engine.cancel()

        assertEquals(3, engine.runState.get())
    }

    @Test
    fun `once started, requests queued while the pre-start backlog waits join it without blocking`() {
        val unstarted = TestRequestEngine()
        val queue = unstarted.requestQueue
        repeat(101) { unstarted.queue(get("/$it")) } // the queue holds 100: one waits in the backlog
        unstarted.start()

        // Nothing takes from the queue here, as when every worker is in a callback queueing
        // follow-ups. Those callbacks used to wait for the backlog to fit, and so for good.
        assertTimeoutPreemptively(Duration.ofSeconds(5)) {
            repeat(3) { unstarted.queue(get("/follow-$it")) }
        }
        assertEquals((0 until 100).map { "/$it" }, List(100) { path(queue.poll()) })

        unstarted.queue(get("/after"))

        val paths = generateSequence { queue.poll() }.map(::path).toList()
        assertEquals(listOf("/100", "/follow-0", "/follow-1", "/follow-2", "/after"), paths)
    }

    @Test
    fun `complete's timeout also bounds draining the pre-start backlog`() {
        val unstarted = TestRequestEngine()
        // The queue holds 100, so one request waits in the backlog, and nothing here ever takes
        // from the queue to make room for it.
        repeat(101) { unstarted.queue(get("/$it")) }

        assertTimeoutPreemptively(Duration.ofSeconds(10)) { unstarted.showStats(1) }

        assertEquals(3, unstarted.runState.get(), "the run should have been aborted at its timeout")
    }
}
