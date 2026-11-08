package io.bitbytelab.raijin.turbo

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach

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

        handler.setRequestEngine(engine)

        assertEquals("exited-early", handler.status())
    }

    @Test
    fun `status returns completed when engine state is 4`() {
        val engine = TestRequestEngine()
        engine.setRunState(4) // completed

        handler.setRequestEngine(engine)

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
}
