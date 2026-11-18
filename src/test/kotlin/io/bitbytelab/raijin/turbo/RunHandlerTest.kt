package io.bitbytelab.raijin.turbo

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

class RunHandlerTest {

    private lateinit var handler: RunHandler

    @BeforeEach
    fun setUp() {
        handler = RunHandler()
    }

    @Test
    fun `status returns running initially`() {
        assertEquals("running", handler.status())
    }

    @Test
    fun `statusString returns warming up when no engine`() {
        assertEquals("Engine warming up...", handler.statusString())
    }

    @Test
    fun `status returns running when engine state below 3`() {
        val engine = TestRequestEngine()
        engine.setRunState(1) // live

        handler.setRequestEngine(engine)

        assertEquals("running", handler.status())
    }

    @Test
    fun `status returns exited-early when engine state is 3 (cancelled)`() {
        val engine = TestRequestEngine()
        engine.setRunState(3) // cancelled
        engine.finalized = true

        handler.setRequestEngine(engine)

        assertEquals("exited-early", handler.status())
    }

    @Test
    fun `status returns completed when engine state is 4`() {
        val engine = TestRequestEngine()
        engine.setRunState(4) // completed
        engine.finalized = true

        handler.setRequestEngine(engine)
        handler.markScriptCompleted()

        assertEquals("completed", handler.status())
    }

    @Test
    fun `a finished engine reads running until it is ranked and the script is done`() {
        val engine = TestRequestEngine()
        engine.setRunState(4)
        handler.setRequestEngine(engine)
        assertEquals("running", handler.status(), "not ranked yet")

        engine.finalized = true
        assertEquals("running", handler.status(), "script still in completed()")

        handler.markScriptCompleted()
        assertEquals("completed", handler.status())
    }

    @Test
    fun `status returns completed when script completes without engine`() {
        handler.markScriptCompleted()

        assertEquals("completed", handler.status())
    }

    @Test
    fun `status returns failed when hasError is true regardless of engine state`() {
        val engine = TestRequestEngine()
        engine.setRunState(4) // completed
        handler.setRequestEngine(engine)

        handler.overrideStatus("Something went wrong")

        assertEquals("failed", handler.status())
    }

    @Test
    fun `status returns failed when hasError is true and engine cancelled`() {
        val engine = TestRequestEngine()
        engine.setRunState(3) // cancelled
        handler.setRequestEngine(engine)

        handler.overrideStatus("Validation failed")

        assertEquals("failed", handler.status())
    }

    @Test
    fun `overrideStatus replaces status string`() {
        val engine = TestRequestEngine()
        handler.setRequestEngine(engine)

        handler.overrideStatus("Custom status")

        assertEquals("Custom status", handler.statusString())
    }

    @Test
    fun `setMessage updates msg field`() {
        handler.setMessage("test message")

        assertEquals("test message", handler.msg)
    }

    @Test
    fun `statusString includes message when engine present`() {
        val engine = TestRequestEngine()
        handler.setRequestEngine(engine)
        handler.setMessage("processing")

        val status = handler.statusString()

        assertTrue(status.contains("processing"))
    }

    @Test
    fun `hasError returns false initially`() {
        assertFalse(handler.hasError())
    }

    @Test
    fun `hasError returns true after overrideStatus called`() {
        handler.overrideStatus("User Python error: something failed")

        assertTrue(handler.hasError())
    }

    @Test
    fun `hasError returns false when overrideStatus called with isError false`() {
        handler.overrideStatus("Non-error status", isError = false)

        assertFalse(handler.hasError())
    }

    /** A stand-in script thread: binds itself, then sleeps until interrupted. */
    private fun sleepingScript(attached: CountDownLatch, interrupted: AtomicBoolean): Thread = thread {
        handler.attachScriptThread()
        attached.countDown()
        try {
            Thread.sleep(10_000)
        } catch (e: InterruptedException) {
            interrupted.set(true)
        }
    }

    @Test
    fun `abort before the engine exists interrupts the script thread`() {
        val attached = CountDownLatch(1)
        val interrupted = AtomicBoolean(false)
        val script = sleepingScript(attached, interrupted)
        assertTrue(attached.await(2, TimeUnit.SECONDS))

        handler.abort()
        script.join(2000)

        assertTrue(interrupted.get(), "the stop waited for the script instead of interrupting it")
        assertEquals("exited-early", handler.status())
        assertEquals("Stopped before the request engine started", handler.statusString())
    }

    @Test
    fun `a stop requested before the script thread attaches interrupts it as it attaches`() {
        handler.abort()

        val attached = CountDownLatch(1)
        val interrupted = AtomicBoolean(false)
        sleepingScript(attached, interrupted).join(2000)

        assertTrue(interrupted.get())
    }

    @Test
    fun `an engine attached after the stop is cancelled at once`() {
        handler.abort()
        val engine = TestRequestEngine().apply { start() }

        handler.setRequestEngine(engine)

        assertEquals(3, engine.runState.get())
        assertEquals("exited-early", handler.status())
    }

    @Test
    fun `abort with an engine cancels the engine, not the script thread`() {
        val engine = TestRequestEngine().apply { start() }
        val attached = CountDownLatch(1)
        val interrupted = AtomicBoolean(false)
        val script = sleepingScript(attached, interrupted)
        assertTrue(attached.await(2, TimeUnit.SECONDS))
        handler.setRequestEngine(engine)

        handler.abort()

        assertEquals(3, engine.runState.get())
        assertFalse(interrupted.get())
        script.interrupt()
        script.join(2000)
    }

    @Test
    fun `the error a stop causes in the script does not mark the run failed`() {
        handler.abort()

        handler.overrideStatus("User Python error, check extender for full details: interrupted sleep")

        assertFalse(handler.hasError())
        assertEquals("exited-early", handler.status())
    }

    @Test
    fun `a completed run stays completed when it is stopped afterwards`() {
        val engine = TestRequestEngine().apply { start() }
        engine.setRunState(4)
        engine.finalized = true
        handler.setRequestEngine(engine)

        handler.abort()

        assertEquals(4, engine.runState.get())
        assertEquals("completed", handler.status())
    }
}
