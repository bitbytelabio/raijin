package io.bitbytelab.raijin.turbo.mcp

import io.bitbytelab.raijin.turbo.ResultStore
import io.bitbytelab.raijin.turbo.RunHandler
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class ActiveRunTest {

    @Test
    fun `creates ActiveRun with unique id`() {
        val run1 = ActiveRun()
        val run2 = ActiveRun()

        assertNotNull(run1.id)
        assertNotNull(run2.id)
        assertNotEquals(run1.id, run2.id)
    }

    @Test
    fun `provides access to RunHandler and ResultStore`() {
        val run = ActiveRun()

        assertNotNull(run.handler)
        assertNotNull(run.store)
    }

    @Test
    fun `tracks creation time`() {
        val before = System.currentTimeMillis()
        val run = ActiveRun()
        val after = System.currentTimeMillis()

        assertTrue(run.createdAt >= before)
        assertTrue(run.createdAt <= after)
    }

    @Test
    fun `responsesStripped defaults to false`() {
        val run = ActiveRun()
        assertFalse(run.responsesStripped)
    }
}
