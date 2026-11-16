package io.bitbytelab.raijin.turbo

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

class FloodgateTest {

    private fun gatedRequest(engine: TestRequestEngine, gate: String): Request {
        engine.queue("GET / HTTP/1.1\r\nHost: test.local\r\n\r\n", emptyList<Any>(), 0, null, gate)
        return engine.requestQueue.poll()!!
    }

    /** Runs waitForGo on its own thread; the reference ends up holding what it threw, if anything. */
    private fun waiter(gate: Floodgate, outcome: AtomicReference<Throwable?>, released: CountDownLatch): Thread =
        thread {
            try {
                gate.waitForGo()
            } catch (failure: Throwable) {
                outcome.set(failure)
            } finally {
                released.countDown()
            }
        }

    @Test
    fun `cancel before openGate releases a parked worker instead of leaving it blocked`() {
        val engine = TestRequestEngine().apply { start() }
        val gate = gatedRequest(engine, "race").gate!!
        val outcome = AtomicReference<Throwable?>()
        val released = CountDownLatch(1)
        val worker = waiter(gate, outcome, released)

        engine.cancel()

        assertTrue(released.await(2, TimeUnit.SECONDS), "the worker is still parked on the gate")
        assertInstanceOf(InterruptedException::class.java, outcome.get())
        assertFalse(gate.isOpen.get())
        worker.join(1000)
    }

    @Test
    fun `a waiter notices the end of the run even when nobody wakes it`() {
        val engine = TestRequestEngine().apply { start() }
        val gate = Floodgate("race", engine)
        val outcome = AtomicReference<Throwable?>()
        val released = CountDownLatch(1)
        waiter(gate, outcome, released)

        engine.setRunState(3)

        assertTrue(released.await(2, TimeUnit.SECONDS))
        assertInstanceOf(InterruptedException::class.java, outcome.get())
    }

    @Test
    fun `open on a cancelled run does not release the requests`() {
        val engine = TestRequestEngine().apply { start() }
        val gate = Floodgate("race", engine)
        gate.addWaiter() // two requests, neither ready
        val opened = AtomicReference<Boolean?>()
        val opener = thread { opened.set(gate.open()) }

        engine.setRunState(3)
        opener.join(2000)

        assertFalse(opener.isAlive, "open() is still waiting on a cancelled run")
        assertEquals(false, opened.get())
        assertFalse(gate.isOpen.get())
    }

    @Test
    fun `open releases every waiter once all are ready`() {
        val engine = TestRequestEngine().apply { start() }
        val gate = Floodgate("race", engine)
        gate.addWaiter()
        val released = CountDownLatch(2)
        val outcomes = List(2) { AtomicReference<Throwable?>() }
        outcomes.forEach { waiter(gate, it, released) }

        assertTrue(gate.open())

        assertTrue(released.await(2, TimeUnit.SECONDS))
        outcomes.forEach { assertNull(it.get()) }
        assertTrue(gate.isOpen.get())
        assertFalse(gate.open(), "a gate opens once")
    }
}
