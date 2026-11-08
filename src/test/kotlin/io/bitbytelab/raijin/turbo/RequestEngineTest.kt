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
}
