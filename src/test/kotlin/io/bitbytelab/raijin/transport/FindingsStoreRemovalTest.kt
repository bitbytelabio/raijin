package io.bitbytelab.raijin.transport

import io.bitbytelab.raijin.state.StoredFinding
import org.junit.jupiter.api.io.TempDir
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class FindingsStoreRemovalTest {
    @TempDir lateinit var directory: File

    private fun finding(id: String) = StoredFinding(
        id, "idor", "high", "https://example.test/$id", "id", "detail", "evidence", "2026-11-17T00:00:00Z"
    )

    @Test
    fun `late removal deletes only its id after live state has been unloaded`() {
        val file = File(directory, "findings.jsonl")
        val store = FindingsFileStore(file)
        val removed = finding("finding-1")
        val retained = finding("finding-2")
        store.append(removed, "project")
        store.append(retained, "project")
        store.append(removed, "other-project")
        val live = mutableListOf(removed, retained)
        live.remove(removed)
        // The listener may resume after StateManager.cleanup(), which clears the live list.
        live.clear()
        store.remove("project", removed.id)

        val reloaded = FindingsFileStore(file)
        assertEquals(listOf(retained), reloaded.load("project"))
        assertEquals(listOf(removed), reloaded.load("other-project"))
        assertNull(store.lastError)
    }

    @Test
    fun `removal of unknown id preserves persisted records`() {
        val store = FindingsFileStore(File(directory, "findings.jsonl"))
        val retained = finding("finding-1")
        store.append(retained, "project")
        store.remove("project", "missing")
        assertEquals(listOf(retained), store.load("project"))
    }
}
