package io.bitbytelab.raijin.turbo.mcp

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Assertions.*
import java.io.File

class McpResourceHandlersTest {

    private lateinit var manager: RunManager
    private lateinit var handlers: McpResourceHandlers

    @BeforeEach
    fun setup() {
        manager = RunManager()
        handlers = McpResourceHandlers(manager)
    }

    @Test
    fun `getRunStatus returns error for nonexistent run`() {
        val result = handlers.getRunStatus("nonexistent")

        assertEquals("not_found", result["error"])
    }

    @Test
    fun `getRunStatus returns evicted for evicted run`() {
        val manager = RunManager(maxCompletedRuns = 1)
        val handlers = McpResourceHandlers(manager)
        val run1 = manager.startRun()
        run1.handler.markScriptCompleted()
        val run2 = manager.startRun()
        run2.handler.markScriptCompleted()
        // run1 is now over the cap; starting run3 triggers eviction
        manager.startRun()

        val result = handlers.getRunStatus(run1.id)

        assertEquals("evicted", result["error"])
    }

    @Test
    fun `getRunStatus returns run info with status field`() {
        val run = manager.startRun()

        val result = handlers.getRunStatus(run.id)

        assertNotNull(result["run_id"])
        assertEquals("running", result["status"])
        assertFalse(result.containsKey("running"), "Should not contain 'running' boolean")
        assertFalse(result.containsKey("finished"), "Should not contain 'finished' boolean")
        assertNotNull(result["result_count"])
        assertEquals(0, result["fails"])
    }

    @Test
    fun `getRunStatus includes summary when run is finished`() {
        val run = manager.startRun()

        // Add some results
        val req1 = io.bitbytelab.raijin.turbo.Request("GET /1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req1.id = 1
        req1.response = "HTTP/1.1 200 OK\r\n\r\nok"
        req1.anomalyRank = 100

        val req2 = io.bitbytelab.raijin.turbo.Request("GET /2 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req2.id = 2
        req2.response = "HTTP/1.1 404 Not Found\r\n\r\nnot found"
        req2.anomalyRank = 50

        run.store.add(req1)
        run.store.add(req2)

        // Mark run as finished (no engine created, so markScriptCompleted will trigger status=completed)
        run.handler.markScriptCompleted()

        val result = handlers.getRunStatus(run.id)

        assertEquals("completed", result["status"])
        // Should include summary when not running
        @Suppress("UNCHECKED_CAST")
        val summary = result["summary"] as? List<Map<String, Any?>>
        assertNotNull(summary, "Status should include summary when run is finished")
        assertEquals(2, summary!!.size)
        // Summary should be sorted by anomaly_rank descending
        assertEquals(100, summary[0]["anomaly_rank"])
        assertEquals(50, summary[1]["anomaly_rank"])
    }

    @Test
    fun `getRunStatus does not include summary when run is still running`() {
        val run = manager.startRun()

        // Add a result but don't mark as finished
        val req = io.bitbytelab.raijin.turbo.Request("GET /1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req.id = 1
        req.response = "HTTP/1.1 200 OK\r\n\r\nok"
        run.store.add(req)

        val result = handlers.getRunStatus(run.id)

        assertEquals("running", result["status"])
        assertNull(result["summary"], "Status should NOT include summary when run is still running")
    }

    @Test
    fun `getRunScript returns script for run`() {
        val run = manager.startRun()
        run.handler.code = "def queueRequests(target, wordlists):\n    pass"

        val result = handlers.getRunScript(run.id)

        assertEquals("def queueRequests(target, wordlists):\n    pass", result["script"])
    }

    @Test
    fun `getRunScript returns error for nonexistent run`() {
        val result = handlers.getRunScript("nonexistent")
        assertEquals("not_found", result["error"])
    }

    @Test
    fun `getResults returns empty list when no results`() {
        val run = manager.startRun()

        val result = handlers.getResults(run.id, "id", true, 100, 0)

        assertEquals(0, result["total_count"])
        assertTrue((result["results"] as List<*>).isEmpty())
    }

    @Test
    fun `getRequestDetail returns error for invalid request`() {
        val run = manager.startRun()

        val result = handlers.getRequestDetail(run.id, 999)

        assertEquals("request_not_found", result["error"])
    }

    @Test
    fun `getRequestDetail returns headers and truncated body by default`() {
        val run = manager.startRun()
        val request = io.bitbytelab.raijin.turbo.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        request.response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
            (1..500).joinToString("\n") { "A$it" }  // 500-line body
        run.store.add(request)

        val result = handlers.getRequestDetail(run.id,1, bodyLimit = 100)

        assertEquals("HTTP/1.1 200 OK\r\nContent-Type: text/html", result["response_headers"])
        assertEquals((1..100).joinToString("\n") { "A$it" }, result["response_body"])
        assertEquals(200, result["status"])
    }

    @Test
    fun `getRequestDetail respects custom body_limit`() {
        val run = manager.startRun()
        val request = io.bitbytelab.raijin.turbo.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        request.response = "HTTP/1.1 200 OK\r\n\r\n" + (1..1000).joinToString("\n") { "B$it" }
        run.store.add(request)

        val result = handlers.getRequestDetail(run.id,1, bodyLimit = 250)

        assertEquals((1..250).joinToString("\n") { "B$it" }, result["response_body"])
    }

    @Test
    fun `getRequestDetail returns full body when shorter than limit`() {
        val run = manager.startRun()
        val request = io.bitbytelab.raijin.turbo.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        request.response = "HTTP/1.1 200 OK\r\n\r\nshort"
        run.store.add(request)

        val result = handlers.getRequestDetail(run.id,1, bodyLimit = 100)

        assertEquals("short", result["response_body"])
    }

    @Test
    fun `getRequestDetail includes truncation metadata when truncated`() {
        val run = manager.startRun()
        val request = io.bitbytelab.raijin.turbo.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        request.response = "HTTP/1.1 200 OK\r\n\r\n" + (1..500).joinToString("\n") { "A$it" }
        run.store.add(request)

        val result = handlers.getRequestDetail(run.id,1, bodyLimit = 100)

        assertEquals(true, result["response_body_truncated"])
        assertEquals(500, result["response_body_total_lines"])
    }

    @Test
    fun `getRequestDetail truncation metadata shows false when not truncated`() {
        val run = manager.startRun()
        val request = io.bitbytelab.raijin.turbo.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        request.response = "HTTP/1.1 200 OK\r\n\r\nshort"
        run.store.add(request)

        val result = handlers.getRequestDetail(run.id,1, bodyLimit = 100)

        assertEquals(false, result["response_body_truncated"])
        assertEquals(5, result["response_body_total_length"])
    }

    @Test
    fun `getRequestDetail with exportFile writes response to file and returns path`() {
        val run = manager.startRun()
        val request = io.bitbytelab.raijin.turbo.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        val fullResponse = "HTTP/1.1 200 OK\r\n\r\n" + "X".repeat(1000)
        request.response = fullResponse
        run.store.add(request)

        val result = handlers.getRequestDetail(run.id,1, exportFile = true)

        assertNotNull(result["response_file"])
        val filePath = result["response_file"] as String
        val fileContent = java.io.File(filePath).readText()
        assertEquals(fullResponse, fileContent)
        // Should not include inline body when exporting to file
        assertNull(result["response_body"])
    }

    @Test
    fun `getRequestDetail with exportFile also exports request`() {
        val run = manager.startRun()
        val request = io.bitbytelab.raijin.turbo.Request("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        request.response = "HTTP/1.1 200 OK\r\n\r\nok"
        run.store.add(request)

        val result = handlers.getRequestDetail(run.id,1, exportFile = true)

        assertNotNull(result["request_file"])
        val filePath = result["request_file"] as String
        val fileContent = java.io.File(filePath).readText()
        assertTrue(fileContent.contains("GET /test HTTP/1.1"))
    }

    @Test
    fun `getRequestDetail respects body_limit parameter`() {
        val run = manager.startRun()
        val request = io.bitbytelab.raijin.turbo.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        request.response = "HTTP/1.1 200 OK\r\n\r\n" + (1..500).joinToString("\n") { "Z$it" }
        run.store.add(request)

        val result = handlers.getRequestDetail(run.id,1, bodyLimit = 50)

        assertEquals((1..50).joinToString("\n") { "Z$it" }, result["response_body"])
    }

    @Test
    fun `getRequestDetail respects exportFile parameter`() {
        val run = manager.startRun()
        val request = io.bitbytelab.raijin.turbo.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        request.response = "HTTP/1.1 200 OK\r\n\r\ndata"
        run.store.add(request)

        val result = handlers.getRequestDetail(run.id,1, exportFile = true)

        assertNotNull(result["response_file"])
        assertNull(result["response_body"])
    }

    @Test
    fun `getResults includes anomaly_rank in results`() {
        val run = manager.startRun()
        val request = io.bitbytelab.raijin.turbo.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        request.response = "HTTP/1.1 200 OK\r\n\r\nok"
        request.anomalyRank = 42
        run.store.add(request)

        val result = handlers.getResults(run.id,"id", true, 100, 0)

        val results = result["results"] as List<Map<String, Any?>>
        assertEquals(1, results.size)
        assertEquals(42, results[0]["anomaly_rank"])
    }

    @Test
    fun `getResults includes ttfb and ttlb instead of time`() {
        val run = manager.startRun()
        val request = io.bitbytelab.raijin.turbo.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        request.response = "HTTP/1.1 200 OK\r\n\r\nok"
        request.ttfb = 500L
        request.ttlb = 1000L
        run.store.add(request)

        val result = handlers.getResults(run.id, "id", true, 100, 0)

        @Suppress("UNCHECKED_CAST")
        val results = result["results"] as List<Map<String, Any?>>
        assertEquals(500L, results[0]["ttfb"])
        assertEquals(1000L, results[0]["ttlb"])
        assertFalse(results[0].containsKey("time"))
    }

    @Test
    fun `getRequestDetail returns result by id for current run`() {
        val run = manager.startRun()
        val request = io.bitbytelab.raijin.turbo.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 36
        request.response = "HTTP/1.1 200 OK\r\n\r\ntest body"
        run.store.add(request)

        val result = handlers.getRequestDetail(run.id,36)

        assertEquals("test body", result["response_body"])
        assertEquals(200, result["status"])
    }

    @Test
    fun `getResults can sort by anomaly_rank descending`() {
        val run = manager.startRun()

        val req1 = io.bitbytelab.raijin.turbo.Request("GET /1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req1.id = 1
        req1.response = "HTTP/1.1 200 OK\r\n\r\nok"
        req1.anomalyRank = 10

        val req2 = io.bitbytelab.raijin.turbo.Request("GET /2 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req2.id = 2
        req2.response = "HTTP/1.1 200 OK\r\n\r\nok"
        req2.anomalyRank = 100

        val req3 = io.bitbytelab.raijin.turbo.Request("GET /3 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req3.id = 3
        req3.response = "HTTP/1.1 200 OK\r\n\r\nok"
        req3.anomalyRank = 50

        run.store.add(req1)
        run.store.add(req2)
        run.store.add(req3)

        // Call getResults with anomaly_rank sorting
        val result = handlers.getResults(run.id,"anomaly_rank", true, 100, 0)

        @Suppress("UNCHECKED_CAST")
        val results = result["results"] as List<Map<String, Any?>>
        assertEquals(3, results.size)
        // Should be sorted by anomaly_rank descending: 100, 50, 10
        assertEquals(100, results[0]["anomaly_rank"])
        assertEquals(50, results[1]["anomaly_rank"])
        assertEquals(10, results[2]["anomaly_rank"])
    }

    @Test
    fun `getResults includes status_codes field with all unique status codes`() {
        val run = manager.startRun()

        val req200a = io.bitbytelab.raijin.turbo.Request("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req200a.id = 1
        req200a.response = "HTTP/1.1 200 OK\r\n\r\nok"

        val req200b = io.bitbytelab.raijin.turbo.Request("GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req200b.id = 2
        req200b.response = "HTTP/1.1 200 OK\r\n\r\nok"

        val req404 = io.bitbytelab.raijin.turbo.Request("GET /c HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req404.id = 3
        req404.response = "HTTP/1.1 404 Not Found\r\n\r\nnot found"

        val req500 = io.bitbytelab.raijin.turbo.Request("GET /d HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req500.id = 4
        req500.response = "HTTP/1.1 500 Error\r\n\r\nerror"

        run.store.add(req200a)
        run.store.add(req200b)
        run.store.add(req404)
        run.store.add(req500)

        val result = handlers.getResults(run.id,"id", true, 100, 0)

        @Suppress("UNCHECKED_CAST")
        val statusCodes = result["status_codes"] as Set<Int>
        assertEquals(setOf(200, 404, 500), statusCodes)
    }

    // Desync mode Connection header stripping tests

    @Test
    fun `getRequestDetail strips Connection header when desync mode enabled`() {
        val handlersWithDesync = McpResourceHandlers(manager, desyncMode = { true })
        val run = manager.startRun()
        val request = io.bitbytelab.raijin.turbo.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        request.response = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: text/html\r\n\r\nbody"
        run.store.add(request)

        val result = handlersWithDesync.getRequestDetail(run.id,1)

        assertEquals("HTTP/1.1 200 OK\r\nContent-Type: text/html", result["response_headers"])
    }

    @Test
    fun `getRequestDetail preserves Connection header when desync mode disabled`() {
        val handlersNoDesync = McpResourceHandlers(manager, desyncMode = { false })
        val run = manager.startRun()
        val request = io.bitbytelab.raijin.turbo.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        request.response = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: text/html\r\n\r\nbody"
        run.store.add(request)

        val result = handlersNoDesync.getRequestDetail(run.id,1)

        assertEquals("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: text/html", result["response_headers"])
    }

    @Test
    fun `getRequestDetail strips Connection header case-insensitively`() {
        val handlersWithDesync = McpResourceHandlers(manager, desyncMode = { true })
        val run = manager.startRun()
        val request = io.bitbytelab.raijin.turbo.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        request.id = 1
        request.response = "HTTP/1.1 200 OK\r\nconnection: close\r\nContent-Type: text/html\r\n\r\nbody"
        run.store.add(request)

        val result = handlersWithDesync.getRequestDetail(run.id,1)

        assertEquals("HTTP/1.1 200 OK\r\nContent-Type: text/html", result["response_headers"])
    }

    // Long-poll tests

    @Test
    fun `getRunStatus with waitMs returns immediately when run is finished`() {
        val run = manager.startRun()
        run.handler.markScriptCompleted()

        val start = System.currentTimeMillis()
        val result = handlers.getRunStatus(run.id, waitMs = 5000)
        val elapsed = System.currentTimeMillis() - start

        assertEquals("completed", result["status"])
        assertTrue(elapsed < 1000, "Should return immediately for finished run, took ${elapsed}ms")
    }

    @Test
    fun `getRunStatus with waitMs blocks until run finishes`() {
        val run = manager.startRun()

        Thread {
            Thread.sleep(200)
            run.handler.markScriptCompleted()
        }.start()

        val start = System.currentTimeMillis()
        val result = handlers.getRunStatus(run.id, waitMs = 5000)
        val elapsed = System.currentTimeMillis() - start

        assertEquals("completed", result["status"])
        assertNotNull(result["summary"], "Should include summary when run finishes during wait")
        assertTrue(elapsed in 100..2000, "Should return shortly after run finishes, took ${elapsed}ms")
    }

    @Test
    fun `getRunStatus with waitMs times out if run does not finish`() {
        val run = manager.startRun()

        val start = System.currentTimeMillis()
        val result = handlers.getRunStatus(run.id, waitMs = 300)
        val elapsed = System.currentTimeMillis() - start

        assertEquals("running", result["status"])
        assertNull(result["summary"], "Should not include summary when still running")
        assertTrue(elapsed in 200..1000, "Should return after timeout, took ${elapsed}ms")
    }

    @Test
    fun `getRunStatus without waitMs returns immediately for in-progress run`() {
        val run = manager.startRun()

        val start = System.currentTimeMillis()
        val result = handlers.getRunStatus(run.id)
        val elapsed = System.currentTimeMillis() - start

        assertEquals("running", result["status"])
        assertTrue(elapsed < 500, "Should return immediately without wait, took ${elapsed}ms")
    }

    @Test
    fun `getRunStatus with waitMs returns not_found immediately for missing run`() {
        val start = System.currentTimeMillis()
        val result = handlers.getRunStatus("nonexistent", waitMs = 5000)
        val elapsed = System.currentTimeMillis() - start

        assertEquals("not_found", result["error"])
        assertTrue(elapsed < 500, "Should return immediately for missing run, took ${elapsed}ms")
    }

    // Example script resource tests

    @Test
    fun `listExamples returns list of available example scripts`() {
        val result = handlers.listExamples()

        @Suppress("UNCHECKED_CAST")
        val examples = result["examples"] as List<Map<String, Any?>>
        assertTrue(examples.isNotEmpty())
        // Check that basic.py is in the list
        assertTrue(examples.any { it["name"] == "basic" })
    }

    @Test
    fun `listExamples returns name for each example`() {
        val result = handlers.listExamples()

        @Suppress("UNCHECKED_CAST")
        val examples = result["examples"] as List<Map<String, Any?>>
        val basic = examples.find { it["name"] == "basic" }
        assertNotNull(basic)
    }

    @Test
    fun `getExample returns script content for valid example`() {
        val result = handlers.getExample("basic")

        assertNotNull(result["content"])
        val content = result["content"] as String
        assertTrue(content.contains("def queueRequests"))
    }

    @Test
    fun `getExample returns error for unknown example`() {
        val result = handlers.getExample("nonexistent-script")

        assertEquals("not_found", result["error"])
    }

    @Test
    fun `listExamples auto-discovers all py files in examples directory`() {
        val result = handlers.listExamples()

        @Suppress("UNCHECKED_CAST")
        val examples = result["examples"] as List<Map<String, Any?>>
        val names = examples.map { it["name"] }

        // These are actual files in resources/examples/ - includes ones NOT in any hardcoded list
        assertTrue(names.contains("basic"), "Should discover basic.py")
        assertTrue(names.contains("timing"), "Should discover timing.py")
        assertTrue(names.contains("customSortOrder"), "Should discover customSortOrder.py")
        assertTrue(names.contains("pinwheel"), "Should discover pinwheel.py")
        assertTrue(names.contains("email-link-extraction"), "Should discover email-link-extraction.py")
        // Should NOT include __init__.py
        assertFalse(names.contains("__init__"), "Should not include __init__.py")
    }

    @Test
    fun `getRequestDetail indicates when response was stripped`() {
        val run = manager.startRun()
        val req = io.bitbytelab.raijin.turbo.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req.id = 1
        req.response = "HTTP/1.1 200 OK\r\n\r\nBody"
        run.store.add(req)

        // Strip
        run.store.stripResponseBodies()
        run.responsesStripped = true

        val handlers = McpResourceHandlers(manager)
        val result = handlers.getRequestDetail(run.id, 1)

        assertTrue(result.containsKey("warning"))
        assertTrue((result["warning"] as String).contains("stripped"))
        // Metadata should still be present
        assertEquals(200, result["status"])
    }

    @Test
    fun `hardcoded example list matches files in resources examples directory`() {
        val dir = File("src/main/resources/examples")
        assertTrue(dir.exists(), "src/main/resources/examples directory should exist")

        val filesOnDisk = dir.listFiles()!!
            .filter { it.extension == "py" && it.name != "__init__.py" }
            .map { it.nameWithoutExtension }
            .toSet()

        @Suppress("UNCHECKED_CAST")
        val listed = (handlers.listExamples()["examples"] as List<Map<String, Any?>>)
            .map { it["name"] as String }
            .toSet()

        val missing = filesOnDisk - listed
        val extra = listed - filesOnDisk

        assertTrue(missing.isEmpty(), "Examples on disk but not in hardcoded list: $missing")
        assertTrue(extra.isEmpty(), "Examples in hardcoded list but not on disk: $extra")
    }

    @Test
    fun `every turbo doc shipped as a resource is a doc topic and loads`() {
        val dir = File("src/main/resources/turbo-docs")
        assertTrue(dir.exists(), "src/main/resources/turbo-docs directory should exist")
        val filesOnDisk = dir.listFiles()!!.filter { it.extension == "md" }.map { it.nameWithoutExtension }.toSet()

        assertEquals(filesOnDisk, handlers.docTopics.keys)
        for (topic in filesOnDisk) {
            val doc = handlers.getDoc(topic)
            assertNull(doc["error"], "topic $topic")
            assertTrue((doc["content"] as String).isNotBlank(), "topic $topic")
        }
    }

    @Test
    fun `getDoc lists the topics for an unknown one`() {
        val result = handlers.getDoc("nope")

        assertEquals("unknown_topic", result["error"])
        assertEquals(handlers.docTopics.keys.toList(), result["available_topics"])
    }

    private fun runWithStatuses(vararg statuses: Int): ActiveRun {
        val run = manager.startRun()
        statuses.forEachIndexed { index, status ->
            val request = io.bitbytelab.raijin.turbo.Request("GET /$index HTTP/1.1\r\nHost: example.com\r\n\r\n")
            request.id = index + 1
            request.response = "HTTP/1.1 $status X\r\n\r\nbody"
            run.store.add(request)
        }
        return run
    }

    @Suppress("UNCHECKED_CAST")
    private fun ids(result: Map<String, Any?>) = (result["results"] as List<Map<String, Any?>>).map { it["id"] }

    @Test
    fun `getResults without sort_by follows the order the script set`() {
        val run = runWithStatuses(500, 200, 404)
        run.store.setSortOrder(2, false) // Status, ascending

        val result = handlers.getResults(run.id, null, null, 100, 0)

        assertEquals(listOf(2, 3, 1), ids(result))
        assertEquals("status", result["sort_by"])
        assertEquals(false, result["descending"])
        assertEquals("script", result["sort_source"])
    }

    @Test
    fun `getResults without sort_by or a script order uses id, newest first`() {
        val run = runWithStatuses(500, 200, 404)

        val result = handlers.getResults(run.id, null, null, 100, 0)

        assertEquals(listOf(3, 2, 1), ids(result))
        assertEquals("id", result["sort_by"])
        assertNull(result["sort_source"])
    }

    @Test
    fun `an explicit sort_by overrides the script order`() {
        val run = runWithStatuses(500, 200, 404)
        run.store.setSortOrder(2, false)

        val result = handlers.getResults(run.id, "id", false, 100, 0)

        assertEquals(listOf(1, 2, 3), ids(result))
        assertNull(result["sort_source"])
    }

    @Test
    fun `getResults rejects an unknown sort_by with the valid fields`() {
        val run = runWithStatuses(200)

        val result = handlers.getResults(run.id, "speed", true, 100, 0)

        assertTrue((result["error"] as String).contains("speed"))
        assertEquals(McpResourceHandlers.SORT_FIELDS, result["valid_sort_fields"])
        assertTrue("anomaly_rank" in McpResourceHandlers.SORT_FIELDS)
    }

    @Test
    fun `getResults sort_by is case-insensitive`() {
        val run = runWithStatuses(500, 200)

        val result = handlers.getResults(run.id, "STATUS", false, 100, 0)

        assertEquals(listOf(2, 1), ids(result))
    }

    @Test
    fun `getResults counts a negative limit or offset as zero and says so`() {
        val run = runWithStatuses(200, 200, 200)

        val result = handlers.getResults(run.id, "id", false, 100, -5)

        assertEquals(listOf(1, 2, 3), ids(result))
        assertNotNull(result["note"])
        assertTrue(ids(handlers.getResults(run.id, "id", false, -1, 0)).isEmpty())
    }
}
