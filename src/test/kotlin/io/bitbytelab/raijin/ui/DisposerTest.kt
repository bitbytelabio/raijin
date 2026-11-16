package io.bitbytelab.raijin.ui

import io.bitbytelab.raijin.state.McpActivityEntry
import io.bitbytelab.raijin.state.StateManager
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DisposerTest {

    private fun StateManager.record(tool: String) = addMcpActivity(
        toolName = tool, timestamp = "2026-11-16T00:00:00Z", durationMs = 1, method = "", url = "", host = "",
        statusCode = 0, isError = false, argsSummary = "{}", resultSummary = "{}",
    )

    @Test
    fun `disposing a tab keeps the persistence listener registered and working`() {
        val state = StateManager()
        val persisted = mutableListOf<String>()
        // RaijinExtension registers the disk-persistence listener before the tab exists.
        state.mcpActivityListeners.add { entry -> persisted += entry.toolName }

        val oldTab = Disposer()
        val shownByOldTab = mutableListOf<String>()
        val tabListener: (McpActivityEntry) -> Unit = { entry -> shownByOldTab += entry.toolName }
        oldTab.listen("activity", state.mcpActivityListeners, tabListener)

        state.record("before_reload")
        oldTab.dispose()
        state.record("after_reload")

        assertEquals(listOf("before_reload", "after_reload"), persisted)
        assertEquals(listOf("before_reload"), shownByOldTab)
        assertEquals(1, state.mcpActivityListeners.size)
    }

    @Test
    fun `a second tab instance releases only its own listener`() {
        val state = StateManager()
        val first = Disposer()
        val second = Disposer()
        val seenByFirst = mutableListOf<String>()
        val seenBySecond = mutableListOf<String>()
        val firstListener: (McpActivityEntry) -> Unit = { e -> seenByFirst += e.toolName }
        val secondListener: (McpActivityEntry) -> Unit = { e -> seenBySecond += e.toolName }
        first.listen("activity", state.mcpActivityListeners, firstListener)
        second.listen("activity", state.mcpActivityListeners, secondListener)

        first.dispose()
        state.record("tool")

        assertEquals(emptyList<String>(), seenByFirst)
        assertEquals(listOf("tool"), seenBySecond)
    }

    @Test
    fun `actions run once, newest first`() {
        val order = mutableListOf<String>()
        val disposer = Disposer()
        disposer.add("pool") { order += "pool" }
        disposer.add("timer") { order += "timer" }
        disposer.add("subscription") { order += "subscription" }

        disposer.dispose()
        disposer.dispose()

        assertEquals(listOf("subscription", "timer", "pool"), order)
        assertTrue(disposer.isDisposed)
    }

    @Test
    fun `a failing action is reported and the others still run`() {
        val errors = mutableListOf<String>()
        val ran = mutableListOf<String>()
        val disposer = Disposer { name, _ -> errors += name }
        disposer.add("first") { ran += "first" }
        disposer.add("broken") { throw IllegalStateException("boom") }
        disposer.add("last") { ran += "last" }

        disposer.dispose()

        assertEquals(listOf("broken"), errors)
        assertEquals(listOf("last", "first"), ran)
    }

    @Test
    fun `an action registered after dispose runs immediately`() {
        val disposer = Disposer()
        disposer.dispose()
        var stopped = false
        disposer.add("late timer") { stopped = true }
        assertTrue(stopped)
    }
}
