package io.bitbytelab.raijin.turbo

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.assertDoesNotThrow

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
}
