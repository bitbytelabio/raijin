package io.bitbytelab.raijin.transport

import io.bitbytelab.raijin.state.McpActivityEntry
import io.bitbytelab.raijin.state.StoredFinding
import kotlinx.serialization.json.Json
import java.io.File
import java.nio.file.Files
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The three JSONL stores: one lock per file, lossless off-EDT rewrites, rotation, and failure reporting. */
class JsonlStoresTest {

    private val dir: File = Files.createTempDirectory("raijin-stores").toFile()

    @AfterTest fun cleanup() {
        JsonlStoreSupport.errorSink = null
        dir.deleteRecursively()
    }

    private fun finding(n: Int) = StoredFinding("finding-%03d".format(n), "xss", "high", "https://x/$n", "q", "d", "e", "2026-01-01T00:00:${n % 60}Z")

    private fun activity(id: Long) = McpActivityEntry(id, "t", "2026-01-01T00:00:00.${id}Z", 1, "GET", "https://x/$id", "x", 200, false, "{}", "ok")

    @Test fun `every store instance on one file shares the lock`() {
        val file = File(dir, "shared.jsonl")
        assertTrue(JsonlStoreSupport.lockFor(file) === JsonlStoreSupport.lockFor(File(dir, "./shared.jsonl")))
        val a = FindingsFileStore(file)
        val b = FindingsFileStore(file)
        val pool = Executors.newFixedThreadPool(8)
        repeat(400) { i -> pool.submit { (if (i % 2 == 0) a else b).append(finding(i), "P") } }
        pool.shutdown()
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS))
        val lines = file.readLines()
        assertEquals(400, lines.size)
        lines.forEach { Json.parseToJsonElement(it) } // no torn or interleaved line
        assertEquals(400, a.load("P").size)
    }

    @Test fun `a snapshot replace racing with appends loses no finding`() {
        val store = FindingsFileStore(File(dir, "findings.jsonl"))
        val memory = CopyOnWriteArrayList<StoredFinding>()
        val pool = Executors.newFixedThreadPool(2)
        val done = CountDownLatch(1)
        pool.submit {
            for (n in 1..300) {
                val f = finding(n)
                memory.add(f)            // StateManager.addFinding: memory first, then the listener appends
                store.append(f, "P")
            }
            done.countDown()
        }
        pool.submit {
            // A remove listener moved off the EDT, rewriting while findings keep arriving.
            while (done.count > 0) {
                store.replaceProject("P") { memory.toList() }
                Thread.sleep(1)
            }
        }
        pool.shutdown()
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS))
        assertEquals(memory.map { it.id }.toSet(), store.load("P").map { it.id }.toSet())
        assertEquals(300, store.load("P").size, "duplicates from the race are dropped on load")
    }

    @Test fun `dedupe keeps one record per entry and project`() {
        val f = finding(1)
        val parsed = listOf(f to "A", f to "A", f to "B", finding(2) to "A")
        assertEquals(3, FindingsStore.dedupe(parsed).size)
        val e = activity(7)
        assertEquals(2, ActivityStore.dedupe(listOf(e to "A", e to "A", e.copy(timestamp = "later") to "A")).size)
    }

    @Test fun `the activity file is trimmed while running, not only at startup`() {
        val file = File(dir, "activity.jsonl")
        val store = ActivityFileStore(file, maxLines = 100)
        for (id in 1L..600L) store.append(activity(id), "P", enabled = true)
        val lines = file.readLines().size
        assertTrue(lines < 600, "expected the 500th append to trim the file, got $lines lines")
        assertEquals(600L, store.load("P", 1).single().id, "the newest entries are kept")
    }

    @Test fun `the activity snapshot flush keeps entries recorded meanwhile`() {
        val file = File(dir, "flush.jsonl")
        val store = ActivityFileStore(file)
        store.append(activity(1), "Other", enabled = true)
        store.rewriteProject("P") { listOf(activity(2), activity(3)) }
        store.append(activity(4), "P", enabled = true)
        assertEquals(listOf(4L, 3L, 2L), store.load("P", 10).map { it.id })
        assertEquals(listOf(1L), store.load("Other", 10).map { it.id })
    }

    @Test fun `the audit log rotates on size as well as line count`() {
        val file = File(dir, "audit.jsonl")
        val store = AuditFileStore(file, maxLines = 10_000, maxBytes = 4_000)
        repeat(100) { store.record("turbo_start_run", "ts", 1, false, null, "https://x/${"a".repeat(60)}", "", "", 0) }
        store.compactIfNeeded()
        assertTrue(file.length() <= 3_000 + 200, "kept ${file.length()} bytes for a 4000-byte cap")
        assertTrue(file.readLines().isNotEmpty())
        file.readLines().forEach { Json.parseToJsonElement(it) }
    }

    @Test fun `write failures reach the error sink once per failure, again after recovery`() {
        val reported = mutableListOf<String>()
        JsonlStoreSupport.errorSink = { reported += it }
        val blocker = File(dir, "blocker").apply { writeText("not a directory") }
        val store = FindingsFileStore(File(blocker, "findings.jsonl"))

        repeat(3) { store.append(finding(1), "P") }
        assertNotNull(store.lastError)
        assertEquals(1, reported.size, "a repeated failure is reported once: $reported")
        assertTrue(reported.single().contains("FindingsStore.append"))

        blocker.delete()
        blocker.mkdirs()
        store.append(finding(2), "P")
        assertNull(store.lastError)

        blocker.deleteRecursively()
        blocker.writeText("not a directory again")
        store.append(finding(3), "P")
        assertEquals(2, reported.size, "a failure after recovery is reported again")
    }

    @Test fun `a line with a lone surrogate is written and read back, after a cut-off last line`() {
        val file = File(dir, "surrogate.jsonl")
        file.writeText("{\"cut\":") // a crash left the last record without its newline
        JsonlStoreSupport.appendLine(file, "{\"v\":\"a\uD800b\"}")
        val lines = file.readLines(Charsets.UTF_8)
        assertEquals(listOf("{\"cut\":", "{\"v\":\"a\uFFFDb\"}"), lines)
        assertEquals("a\uFFFDb", Json.parseToJsonElement(lines[1]).let { (it as kotlinx.serialization.json.JsonObject)["v"].toString().trim('"') })
    }
}
