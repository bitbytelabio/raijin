package io.bitbytelab.raijin.turbo.mcp

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Assertions.*

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
}
