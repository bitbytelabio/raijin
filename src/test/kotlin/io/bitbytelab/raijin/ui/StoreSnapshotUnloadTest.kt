package io.bitbytelab.raijin.ui

import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.state.StoredFinding
import io.bitbytelab.raijin.transport.ActivityFileStore
import io.bitbytelab.raijin.transport.FindingsFileStore
import java.io.File
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * On unload the extension disposes the Raijin tab, stops the servers (an MCP call still in flight can
 * record a finding or an activity entry meanwhile), then clears StateManager. A store write the operator
 * queued before that, still waiting behind a slow write, must save the state as it was up to the clear:
 * never the cleared list, which would delete the project's saved findings or activity, and never a copy
 * that misses what the in-flight calls stored.
 */
class StoreSnapshotUnloadTest {
    private val dir: File = Files.createTempDirectory("raijin-unload").toFile()

    private fun finding(id: String) =
        StoredFinding(id, "idor", "high", "https://t.test/$id", "param:id", "detail", "evidence", "2026-11-17T00:00:00Z")

    @Test
    fun `a findings write queued before unload saves the findings as they were at the clear`() {
        val store = FindingsFileStore(File(dir, "findings.jsonl"))
        val state = StateManager()
        state.restoreFindings(listOf(finding("finding-001"), finding("finding-002")))
        store.replaceProject("p", state.findings.toList())
        // Wired as RaijinExtension wires the store.
        state.findingsListeners.add { f -> store.append(f, "p") }
        state.findingsRemoveListeners.add { _ -> store.replaceProject("p") { state.findings.toList() } }
        val tasks = UiTasks { _, _ -> }
        val saved = RaijinTab.findingsSnapshot(tasks, state)

        val gate = CountDownLatch(1)
        val done = CountDownLatch(1)
        tasks.persist("slow write") { gate.await(5, TimeUnit.SECONDS) }
        // The operator deletes a finding; the tab queues the rewrite as syncFindingsStore does.
        state.findings.removeIf { it.id == "finding-001" }
        tasks.persist("Save findings") { store.replaceProject("p") { saved.read() }; done.countDown() }

        tasks.dispose()
        state.addFinding(finding("finding-003"))
        state.removeFinding("finding-002")
        state.cleanup()
        gate.countDown()

        assertTrue(done.await(5, TimeUnit.SECONDS))
        assertEquals(listOf("finding-003"), store.load("p").map { it.id })
    }

    @Test
    fun `an activity flush queued before unload saves the activity as it was at the clear`() {
        val store = ActivityFileStore(File(dir, "activity.jsonl"))
        val state = StateManager()
        val tasks = UiTasks { _, _ -> }
        val saved = RaijinTab.activitySnapshot(tasks, state)
        fun record(tool: String) =
            state.addMcpActivity(tool, "2026-11-17T00:00:00Z", 1, "GET", "https://t.test/", "t.test", 200, false, "{}", "ok")
        record("first")
        record("second")
        // Persistence switched on: new entries are appended, and the tab flushes what memory holds,
        // the way ActivityStore.flushProject does (snapshot newest first, file oldest first).
        state.mcpActivityListeners.add { e -> store.append(e, "p", enabled = true) }

        val gate = CountDownLatch(1)
        val done = CountDownLatch(1)
        tasks.persist("slow write") { gate.await(5, TimeUnit.SECONDS) }
        tasks.persist("Save MCP activity") { store.rewriteProject("p") { saved.read().asReversed() }; done.countDown() }

        tasks.dispose()
        record("third")
        state.cleanup()
        gate.countDown()

        assertTrue(done.await(5, TimeUnit.SECONDS))
        assertEquals(listOf("third", "second", "first"), store.load("p", 10).map { it.toolName })
    }
}
