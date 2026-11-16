package io.bitbytelab.raijin.turbo.mcp

import io.bitbytelab.raijin.turbo.Request
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Assertions.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class RunManagerTest {

    private lateinit var manager: RunManager

    @BeforeEach
    fun setup() {
        manager = RunManager()
    }

    @Test
    fun `startRun creates a new run and returns it`() {
        val run = manager.startRun()
        assertNotNull(run.id)
        assertNotNull(manager.getRun(run.id))
    }

    @Test
    fun `startRun preserves existing runs`() {
        val run1 = manager.startRun()
        val run2 = manager.startRun()

        assertNotNull(manager.getRun(run1.id))
        assertNotNull(manager.getRun(run2.id))
    }

    @Test
    fun `getRun returns null for unknown id`() {
        assertNull(manager.getRun("unknown-id"))
    }

    @Test
    fun `stopRun aborts the run handler`() {
        val run = manager.startRun()
        val result = manager.stopRun(run.id)
        assertEquals("stopped", result)
    }

    @Test
    fun `stopRun returns not_found for unknown id`() {
        val result = manager.stopRun("unknown-id")
        assertEquals("not_found", result)
    }

    @Test
    fun `deleteRun removes run from manager`() {
        val run = manager.startRun()
        val result = manager.deleteRun(run.id)

        assertEquals("deleted", result)
        assertNull(manager.getRun(run.id))
    }

    @Test
    fun `deleteRun returns not_found for unknown id`() {
        val result = manager.deleteRun("unknown-id")
        assertEquals("not_found", result)
    }

    @Test
    fun `evicts oldest completed run when cap is exceeded`() {
        val manager = RunManager(maxCompletedRuns = 2)
        val run1 = manager.startRun()
        run1.handler.markScriptCompleted()
        val run2 = manager.startRun()
        run2.handler.markScriptCompleted()
        val run3 = manager.startRun()
        run3.handler.markScriptCompleted()

        // 3 completed runs, cap is 2 — starting a new run triggers eviction of oldest
        val run4 = manager.startRun()

        assertNull(manager.getRun(run1.id))
        assertNotNull(manager.getRun(run2.id))
        assertNotNull(manager.getRun(run3.id))
        assertNotNull(manager.getRun(run4.id))
    }

    @Test
    fun `does not evict runs that are still running`() {
        val manager = RunManager(maxCompletedRuns = 2)
        val run1 = manager.startRun() // still running - not completed
        val run2 = manager.startRun()
        run2.handler.markScriptCompleted()
        val run3 = manager.startRun()
        run3.handler.markScriptCompleted()
        val run4 = manager.startRun()
        run4.handler.markScriptCompleted()

        // 3 completed runs, cap 2 — starting a new run evicts oldest completed (run2), not run1
        val run5 = manager.startRun()

        assertNotNull(manager.getRun(run1.id)) // still running, kept
        assertNull(manager.getRun(run2.id))     // oldest completed, evicted
        assertNotNull(manager.getRun(run3.id))
        assertNotNull(manager.getRun(run4.id))
        assertNotNull(manager.getRun(run5.id))
    }

    @Test
    fun `evicted run is reported as evicted not unknown`() {
        val manager = RunManager(maxCompletedRuns = 1)
        val run1 = manager.startRun()
        run1.handler.markScriptCompleted()
        val run2 = manager.startRun()
        run2.handler.markScriptCompleted()

        // 2 completed, cap 1 — triggers eviction of run1
        val run3 = manager.startRun()

        assertNull(manager.getRun(run1.id))
        assertTrue(manager.isEvicted(run1.id))
        assertFalse(manager.isEvicted(run2.id))
        assertFalse(manager.isEvicted("never-existed"))
    }

    @Test
    fun `strips response bodies from runs beyond maxFullResponseRuns`() {
        val manager = RunManager(maxCompletedRuns = 4, maxFullResponseRuns = 2)

        val run1 = manager.startRun()
        run1.handler.markScriptCompleted()
        val req1 = io.bitbytelab.raijin.turbo.Request("GET /1 HTTP/1.1").apply {
            response = "HTTP/1.1 200 OK\r\n\r\nBody1"; id = 1
        }
        run1.store.add(req1)

        val run2 = manager.startRun()
        run2.handler.markScriptCompleted()
        val req2 = io.bitbytelab.raijin.turbo.Request("GET /2 HTTP/1.1").apply {
            response = "HTTP/1.1 200 OK\r\n\r\nBody2"; id = 2
        }
        run2.store.add(req2)

        val run3 = manager.startRun()
        run3.handler.markScriptCompleted()
        val req3 = io.bitbytelab.raijin.turbo.Request("GET /3 HTTP/1.1").apply {
            response = "HTTP/1.1 200 OK\r\n\r\nBody3"; id = 3
        }
        run3.store.add(req3)

        // Trigger eviction — 3 completed, maxFullResponseRuns=2
        val run4 = manager.startRun()

        // run1 is oldest — should be stripped (beyond newest 2)
        assertNull(req1.response)
        assertTrue(run1.responsesStripped)
        assertEquals(200, req1.code) // metadata preserved

        // run2 and run3 should keep responses (newest 2 completed)
        assertNotNull(req2.response)
        assertFalse(run2.responsesStripped)
        assertNotNull(req3.response)
        assertFalse(run3.responsesStripped)
    }

    @Test
    fun `does not re-strip already stripped runs`() {
        val manager = RunManager(maxCompletedRuns = 4, maxFullResponseRuns = 1)

        val run1 = manager.startRun()
        run1.handler.markScriptCompleted()
        val req1 = io.bitbytelab.raijin.turbo.Request("GET /1 HTTP/1.1").apply {
            response = "HTTP/1.1 200 OK\r\n\r\nBody1"; id = 1
        }
        run1.store.add(req1)

        val run2 = manager.startRun()
        run2.handler.markScriptCompleted()

        // First trigger — strips run1
        val run3 = manager.startRun()
        assertTrue(run1.responsesStripped)

        // Second trigger — run1 already stripped, should not error
        run3.handler.markScriptCompleted()
        val run4 = manager.startRun()
        assertTrue(run1.responsesStripped)
    }

    @Test
    fun `default maxFullResponseRuns is 50`() {
        val manager = RunManager()
        // Create 51 completed runs
        val runs = (1..51).map {
            manager.startRun().also { r ->
                r.handler.markScriptCompleted()
                val req = io.bitbytelab.raijin.turbo.Request("GET / HTTP/1.1").apply {
                    response = "HTTP/1.1 200 OK\r\n\r\nBody"; id = 1
                }
                r.store.add(req)
            }
        }

        // Trigger — 51 completed, oldest should be stripped
        manager.startRun()

        assertTrue(runs.first().responsesStripped)
        assertFalse(runs.last().responsesStripped)
    }

    @Test
    fun `emergencyCleanup strips all completed runs regardless of threshold`() {
        val manager = RunManager(maxCompletedRuns = 100, maxFullResponseRuns = 50)

        val run1 = manager.startRun()
        run1.handler.markScriptCompleted()
        val req1 = io.bitbytelab.raijin.turbo.Request("GET /1 HTTP/1.1").apply {
            response = "HTTP/1.1 200 OK\r\n\r\nBody1"; id = 1
        }
        run1.store.add(req1)

        val run2 = manager.startRun()
        run2.handler.markScriptCompleted()
        val req2 = io.bitbytelab.raijin.turbo.Request("GET /2 HTTP/1.1").apply {
            response = "HTTP/1.1 200 OK\r\n\r\nBody2"; id = 2
        }
        run2.store.add(req2)

        // Emergency cleanup should strip even though we're under maxFullResponseRuns (50)
        manager.emergencyCleanup()

        assertTrue(run1.responsesStripped)
        assertTrue(run2.responsesStripped)
        assertNull(req1.response)
        assertNull(req2.response)
        // Runs are still accessible (not evicted)
        assertNotNull(manager.getRun(run1.id))
        assertNotNull(manager.getRun(run2.id))
    }

    @Test
    fun `emergencyCleanup evicts oldest stripped runs if all already stripped`() {
        val manager = RunManager(maxCompletedRuns = 100, maxFullResponseRuns = 50)

        val run1 = manager.startRun()
        run1.handler.markScriptCompleted()
        run1.store.add(io.bitbytelab.raijin.turbo.Request("GET /1 HTTP/1.1").apply {
            response = "HTTP/1.1 200 OK\r\n\r\nBody"; id = 1
        })

        val run2 = manager.startRun()
        run2.handler.markScriptCompleted()
        run2.store.add(io.bitbytelab.raijin.turbo.Request("GET /2 HTTP/1.1").apply {
            response = "HTTP/1.1 200 OK\r\n\r\nBody"; id = 2
        })

        // First emergency — strips all
        manager.emergencyCleanup()
        assertTrue(run1.responsesStripped)
        assertTrue(run2.responsesStripped)

        // Second emergency — evicts oldest since all already stripped
        manager.emergencyCleanup()
        assertNull(manager.getRun(run1.id))
        assertTrue(manager.isEvicted(run1.id))
        assertNotNull(manager.getRun(run2.id)) // newest kept
    }

    @Test
    fun `emergencyCleanup does not evict running runs`() {
        val manager = RunManager(maxCompletedRuns = 100, maxFullResponseRuns = 50)

        val runningRun = manager.startRun() // still running
        val completedRun = manager.startRun()
        completedRun.handler.markScriptCompleted()
        completedRun.store.add(io.bitbytelab.raijin.turbo.Request("GET / HTTP/1.1").apply {
            response = "HTTP/1.1 200 OK\r\n\r\nBody"; id = 1
        })

        // First emergency — strips completed
        manager.emergencyCleanup()
        assertTrue(completedRun.responsesStripped)

        // Second emergency — evicts completed, keeps running
        manager.emergencyCleanup()
        assertNull(manager.getRun(completedRun.id))
        assertNotNull(manager.getRun(runningRun.id))
    }

    @Test
    fun `startMemoryMonitor starts a daemon thread`() {
        val manager = RunManager()
        manager.startMemoryMonitor()

        // Thread should be running — verify by checking it's a daemon
        val thread = Thread.getAllStackTraces().keys.find { it.name == "turbo-memory-monitor" }
        assertNotNull(thread, "Memory monitor thread should exist")
        assertTrue(thread!!.isDaemon, "Memory monitor thread should be daemon")

        // Cleanup
        manager.stopMemoryMonitor()
    }

    @Test
    fun `default cap is 100`() {
        val manager = RunManager()
        val runs = (1..101).map { manager.startRun().also { r -> r.handler.markScriptCompleted() } }

        // 101 completed, cap 100 — starting a new run evicts the first
        val triggerRun = manager.startRun()

        assertNull(manager.getRun(runs.first().id))
        assertNotNull(manager.getRun(runs.last().id))
        assertNotNull(manager.getRun(triggerRun.id))
    }

    private fun finishedRunWithBody(manager: RunManager): Pair<ActiveRun, Request> {
        val run = manager.startRun()
        run.handler.markScriptCompleted()
        val req = Request("GET / HTTP/1.1").apply { response = "HTTP/1.1 200 OK\r\n\r\nBody"; id = 1 }
        run.store.add(req)
        return run to req
    }

    @Test
    fun `low memory is judged against the size of the heap`() {
        val oneGb = 1L shl 30
        // A 1 GB heap with 300 MB free is fine; the old flat 1 GB rule called every 1 GB heap low.
        assertFalse(RunManager.isLowOnMemory(oneGb, oneGb - 300_000_000))
        assertTrue(RunManager.isLowOnMemory(oneGb, oneGb - 100_000_000))
        // A large heap keeps the 1 GB headroom.
        val bigHeap = 32L shl 30
        assertTrue(RunManager.isLowOnMemory(bigHeap, bigHeap - 900_000_000))
        assertFalse(RunManager.isLowOnMemory(bigHeap, bigHeap - 2_000_000_000))
        // An unbounded heap never is.
        assertFalse(RunManager.isLowOnMemory(Long.MAX_VALUE, 50L shl 30))
    }

    @Test
    fun `low memory with no finished run to free costs no collection`() {
        val manager = RunManager()
        var collections = 0
        assertFalse(manager.relieveMemoryPressure(1000, { 999 }, { collections++ }, 0))

        val running = manager.startRun()
        assertFalse(manager.relieveMemoryPressure(1000, { 999 }, { collections++ }, 5_000_000_000))

        assertEquals(0, collections)
        assertNotNull(manager.getRun(running.id))
    }

    @Test
    fun `pressure that one collection clears keeps every body and is rechecked at most once a minute`() {
        val manager = RunManager()
        val (run, req) = finishedRunWithBody(manager)
        var used = 990L
        var collections = 0
        val collect = {
            collections++
            used = 500L
        }

        assertFalse(manager.relieveMemoryPressure(1000, { used }, collect, 0))
        assertEquals(1, collections)
        assertNotNull(req.response)
        assertFalse(run.responsesStripped)

        used = 990L
        assertFalse(manager.relieveMemoryPressure(1000, { used }, collect, 5_000_000_000))
        assertEquals(1, collections, "collected again within the minute")

        used = 990L
        manager.relieveMemoryPressure(1000, { used }, collect, 61_000_000_000)
        assertEquals(2, collections)
    }

    @Test
    fun `pressure a collection does not clear strips finished runs, then evicts the oldest`() {
        val manager = RunManager()
        val (older, olderReq) = finishedRunWithBody(manager)
        val (newer, _) = finishedRunWithBody(manager)
        var collections = 0

        assertTrue(manager.relieveMemoryPressure(1000, { 990 }, { collections++ }, 0))
        assertEquals(2, collections)
        assertTrue(older.responsesStripped)
        assertTrue(newer.responsesStripped)
        assertNull(olderReq.response)
        assertEquals(200, olderReq.code)

        assertTrue(manager.relieveMemoryPressure(1000, { 990 }, { collections++ }, 5_000_000_000))
        assertTrue(manager.isEvicted(older.id))
        assertNotNull(manager.getRun(newer.id))
    }

    @Test
    fun `finished runs past the cap are evicted without waiting for a new run`() {
        val manager = RunManager(maxCompletedRuns = 1)
        val first = manager.startRun().also { it.handler.markScriptCompleted() }
        val second = manager.startRun().also { it.handler.markScriptCompleted() }

        manager.relieveMemoryPressure(maxHeap = 1000, usedHeap = { 0 }, collectGarbage = {}, nowNanos = 0)

        assertTrue(manager.isEvicted(first.id))
        assertNotNull(manager.getRun(second.id))
    }

    @Test
    fun `stopRun stops a script that has not built its engine yet`() {
        val run = manager.startRun()
        val attached = CountDownLatch(1)
        val interrupted = CountDownLatch(1)
        val script = thread {
            run.handler.attachScriptThread()
            attached.countDown()
            try {
                Thread.sleep(10_000)
            } catch (e: InterruptedException) {
                interrupted.countDown()
            }
        }
        assertTrue(attached.await(2, TimeUnit.SECONDS))

        assertEquals("stopped", manager.stopRun(run.id))

        assertTrue(interrupted.await(2, TimeUnit.SECONDS), "the script was not interrupted")
        assertEquals("exited-early", run.handler.status())
        script.join(1000)
    }
}
