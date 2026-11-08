# MCP Server Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add an MCP server to Turbo Intruder enabling Claude Code to start/stop runs and query results.

**Architecture:** HTTP server on localhost:31337 using MCP Java SDK. Hybrid API: Tools for actions, Resources for read-only data. RunManager handles multiple concurrent runs.

**Tech Stack:** MCP Java SDK (`io.modelcontextprotocol.sdk:mcp`), Kotlin, JUnit 5

---

## Task 1: Add MCP SDK Dependency

**Files:**
- Modify: `build.gradle`

**Step 1: Add the MCP SDK dependency**

```gradle
dependencies {
    // ... existing dependencies ...

    // MCP Server
    implementation 'io.modelcontextprotocol.sdk:mcp:0.10.0'
}
```

**Step 2: Sync gradle and verify it compiles**

Run: `./gradlew compileKotlin`
Expected: BUILD SUCCESSFUL

**Step 3: Commit**

```bash
git add build.gradle
git commit -m "chore: add MCP Java SDK dependency"
```

---

## Task 2: Create ActiveRun Data Class

**Files:**
- Create: `src/mcp/ActiveRun.kt`
- Test: `test/kotlin/mcp/ActiveRunTest.kt`

**Step 1: Write the test**

```kotlin
package mcp

import burp.ResultStore
import burp.RunHandler
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
}
```

**Step 2: Run test to verify it fails**

Run: `./gradlew test --tests "mcp.ActiveRunTest"`
Expected: FAIL - class not found

**Step 3: Write minimal implementation**

```kotlin
package mcp

import burp.ResultStore
import burp.RunHandler
import java.util.UUID

class ActiveRun {
    val id: String = UUID.randomUUID().toString()
    val handler: RunHandler = RunHandler()
    val store: ResultStore = ResultStore()
    val createdAt: Long = System.currentTimeMillis()
}
```

**Step 4: Run test to verify it passes**

Run: `./gradlew test --tests "mcp.ActiveRunTest"`
Expected: PASS

**Step 5: Commit**

```bash
git add src/mcp/ActiveRun.kt test/kotlin/mcp/ActiveRunTest.kt
git commit -m "feat(mcp): add ActiveRun data class"
```

---

## Task 3: Create RunManager

**Files:**
- Create: `src/mcp/RunManager.kt`
- Test: `test/kotlin/mcp/RunManagerTest.kt`

**Step 1: Write the test**

```kotlin
package mcp

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
    fun `startRun clears existing runs and creates new current run`() {
        val run1 = manager.startConcurrentRun()
        val run2 = manager.startRun()

        assertNull(manager.getRun(run1.id))
        assertNotNull(manager.currentRun)
        assertEquals(run2.id, manager.currentRun?.id)
    }

    @Test
    fun `startConcurrentRun preserves existing runs`() {
        val run1 = manager.startConcurrentRun()
        val run2 = manager.startConcurrentRun()

        assertNotNull(manager.getRun(run1.id))
        assertNotNull(manager.getRun(run2.id))
    }

    @Test
    fun `getRun with null returns current run`() {
        val run = manager.startRun()

        assertEquals(run.id, manager.getRun(null)?.id)
    }

    @Test
    fun `getRun with id returns specific run`() {
        val run1 = manager.startConcurrentRun()
        val run2 = manager.startConcurrentRun()

        assertEquals(run1.id, manager.getRun(run1.id)?.id)
        assertEquals(run2.id, manager.getRun(run2.id)?.id)
    }

    @Test
    fun `getAllRuns returns all runs`() {
        manager.startConcurrentRun()
        manager.startConcurrentRun()

        assertEquals(2, manager.getAllRuns().size)
    }

    @Test
    fun `stopRun aborts the run handler`() {
        val run = manager.startRun()

        val result = manager.stopRun(null)

        assertEquals("stopped", result)
    }

    @Test
    fun `stopRun returns not_found for unknown id`() {
        val result = manager.stopRun("unknown-id")

        assertEquals("not_found", result)
    }

    @Test
    fun `deleteRun removes run from manager`() {
        val run = manager.startConcurrentRun()

        val result = manager.deleteRun(run.id)

        assertEquals("deleted", result)
        assertNull(manager.getRun(run.id))
    }

    @Test
    fun `deleteAllRuns clears everything`() {
        manager.startConcurrentRun()
        manager.startConcurrentRun()
        manager.startRun()

        val count = manager.deleteAllRuns()

        assertEquals(3, count)
        assertNull(manager.currentRun)
    }
}
```

**Step 2: Run test to verify it fails**

Run: `./gradlew test --tests "mcp.RunManagerTest"`
Expected: FAIL - class not found

**Step 3: Write implementation**

```kotlin
package mcp

import java.util.concurrent.ConcurrentHashMap

class RunManager {
    private val runs = ConcurrentHashMap<String, ActiveRun>()
    var currentRun: ActiveRun? = null
        private set

    fun startRun(): ActiveRun {
        deleteAllRuns()
        val run = ActiveRun()
        runs[run.id] = run
        currentRun = run
        return run
    }

    fun startConcurrentRun(): ActiveRun {
        val run = ActiveRun()
        runs[run.id] = run
        currentRun = run
        return run
    }

    fun getRun(runId: String?): ActiveRun? {
        return if (runId == null || runId == "current") currentRun else runs[runId]
    }

    fun getAllRuns(): List<ActiveRun> {
        return runs.values.toList()
    }

    fun stopRun(runId: String?): String {
        val run = getRun(runId) ?: return if (runId == null) "no_current_run" else "not_found"
        run.handler.abort()
        return "stopped"
    }

    fun deleteRun(runId: String?): String {
        val run = getRun(runId) ?: return if (runId == null) "no_current_run" else "not_found"
        run.handler.abort()
        runs.remove(run.id)
        if (currentRun?.id == run.id) {
            currentRun = null
        }
        return "deleted"
    }

    fun deleteAllRuns(): Int {
        val count = runs.size
        runs.values.forEach { it.handler.abort() }
        runs.clear()
        currentRun = null
        return count
    }
}
```

**Step 4: Run test to verify it passes**

Run: `./gradlew test --tests "mcp.RunManagerTest"`
Expected: PASS

**Step 5: Commit**

```bash
git add src/mcp/RunManager.kt test/kotlin/mcp/RunManagerTest.kt
git commit -m "feat(mcp): add RunManager for multi-run support"
```

---

## Task 4: Create McpToolHandlers (Actions Only)

**Files:**
- Create: `src/mcp/McpToolHandlers.kt`
- Test: `test/kotlin/mcp/McpToolHandlersTest.kt`

**Step 1: Write the test**

```kotlin
package mcp

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Assertions.*

class McpToolHandlersTest {

    private lateinit var manager: RunManager
    private lateinit var handlers: McpToolHandlers

    @BeforeEach
    fun setup() {
        manager = RunManager()
        handlers = McpToolHandlers(manager)
    }

    @Test
    fun `startRun creates new run and returns status`() {
        val result = handlers.startRun(
            script = "def queueRequests(target, wordlists):\n    pass\ndef completed(results):\n    pass",
            baseRequest = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            endpoint = "https://example.com:443",
            baseInput = ""
        )

        assertEquals("started", result["status"])
        assertNotNull(manager.currentRun)
    }

    @Test
    fun `startConcurrentRun preserves existing runs`() {
        handlers.startRun(
            script = "def queueRequests(target, wordlists):\n    pass\ndef completed(results):\n    pass",
            baseRequest = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            endpoint = "https://example.com:443",
            baseInput = ""
        )
        val firstRunId = manager.currentRun?.id

        val result = handlers.startConcurrentRun(
            script = "def queueRequests(target, wordlists):\n    pass\ndef completed(results):\n    pass",
            baseRequest = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            endpoint = "https://example.com:443",
            baseInput = ""
        )

        assertEquals("started", result["status"])
        assertNotNull(result["run_id"])
        assertNotNull(manager.getRun(firstRunId))
    }

    @Test
    fun `stopRun stops current run`() {
        handlers.startRun(
            script = "def queueRequests(target, wordlists):\n    pass\ndef completed(results):\n    pass",
            baseRequest = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            endpoint = "https://example.com:443",
            baseInput = ""
        )

        val result = handlers.stopRun(null)

        assertEquals("stopped", result["status"])
    }

    @Test
    fun `deleteAllRuns returns count`() {
        manager.startConcurrentRun()
        manager.startConcurrentRun()

        val result = handlers.deleteAllRuns()

        assertEquals(2, result["deleted_count"])
    }
}
```

**Step 2: Run test to verify it fails**

Run: `./gradlew test --tests "mcp.McpToolHandlersTest"`
Expected: FAIL - class not found

**Step 3: Write implementation**

```kotlin
package mcp

import burp.evalJython
import kotlin.concurrent.thread

class McpToolHandlers(private val manager: RunManager) {

    fun startRun(
        script: String,
        baseRequest: String,
        endpoint: String,
        baseInput: String
    ): Map<String, Any?> {
        val run = manager.startRun()
        launchRun(run, script, baseRequest, endpoint, baseInput)
        return mapOf("status" to "started")
    }

    fun startConcurrentRun(
        script: String,
        baseRequest: String,
        endpoint: String,
        baseInput: String
    ): Map<String, Any?> {
        val run = manager.startConcurrentRun()
        launchRun(run, script, baseRequest, endpoint, baseInput)
        return mapOf(
            "status" to "started",
            "run_id" to run.id
        )
    }

    fun stopRun(runId: String?): Map<String, String> {
        return mapOf("status" to manager.stopRun(runId))
    }

    fun deleteRun(runId: String?): Map<String, String> {
        return mapOf("status" to manager.deleteRun(runId))
    }

    fun deleteAllRuns(): Map<String, Int> {
        return mapOf("deleted_count" to manager.deleteAllRuns())
    }

    private fun launchRun(
        run: ActiveRun,
        script: String,
        baseRequest: String,
        endpoint: String,
        baseInput: String
    ) {
        val host = endpoint
            .removePrefix("https://")
            .removePrefix("http://")
            .substringBefore(":")
            .substringBefore("/")

        thread {
            evalJython(
                code = script,
                baseRequest = baseRequest,
                rawRequest = baseRequest.toByteArray(Charsets.ISO_8859_1),
                endpoint = endpoint,
                host = host,
                baseInput = baseInput,
                store = run.store,
                handler = run.handler,
                reqs = null,
                requestTable = null
            )
        }
    }
}
```

**Step 4: Run test to verify it passes**

Run: `./gradlew test --tests "mcp.McpToolHandlersTest"`
Expected: PASS

**Step 5: Commit**

```bash
git add src/mcp/McpToolHandlers.kt test/kotlin/mcp/McpToolHandlersTest.kt
git commit -m "feat(mcp): add tool handlers for start/stop/delete actions"
```

---

## Task 5: Create McpResourceHandlers

**Files:**
- Create: `src/mcp/McpResourceHandlers.kt`
- Test: `test/kotlin/mcp/McpResourceHandlersTest.kt`

**Step 1: Write the test**

```kotlin
package mcp

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Assertions.*

class McpResourceHandlersTest {

    private lateinit var manager: RunManager
    private lateinit var handlers: McpResourceHandlers

    @BeforeEach
    fun setup() {
        manager = RunManager()
        handlers = McpResourceHandlers(manager)
    }

    @Test
    fun `listRuns returns empty when no runs`() {
        val result = handlers.listRuns()

        assertTrue((result["runs"] as List<*>).isEmpty())
    }

    @Test
    fun `listRuns returns all runs`() {
        manager.startConcurrentRun()
        manager.startConcurrentRun()

        val result = handlers.listRuns()
        val runs = result["runs"] as List<*>

        assertEquals(2, runs.size)
    }

    @Test
    fun `getRunStatus returns error for no current run`() {
        val result = handlers.getRunStatus(null)

        assertEquals("no_current_run", result["error"])
    }

    @Test
    fun `getRunStatus returns run info`() {
        manager.startRun()

        val result = handlers.getRunStatus(null)

        assertNotNull(result["run_id"])
        assertNotNull(result["running"])
        assertNotNull(result["finished"])
        assertNotNull(result["result_count"])
    }

    @Test
    fun `getResults returns empty list when no results`() {
        manager.startRun()

        val result = handlers.getResults(null, "id", true, 100, 0)

        assertEquals(0, result["total_count"])
        assertTrue((result["results"] as List<*>).isEmpty())
    }

    @Test
    fun `getRequestDetail returns error for invalid request`() {
        manager.startRun()

        val result = handlers.getRequestDetail(null, 999)

        assertEquals("request_not_found", result["error"])
    }

    @Test
    fun `parseUri extracts run_id correctly`() {
        assertEquals("abc123", handlers.parseRunId("turbo://runs/abc123"))
        assertEquals("abc123", handlers.parseRunId("turbo://runs/abc123/results"))
        assertEquals("current", handlers.parseRunId("turbo://runs/current"))
        assertNull(handlers.parseRunId("turbo://runs"))
    }

    @Test
    fun `parseUri extracts request_id correctly`() {
        assertEquals(42, handlers.parseRequestId("turbo://runs/abc123/requests/42"))
        assertNull(handlers.parseRequestId("turbo://runs/abc123/results"))
    }

    @Test
    fun `parseQueryParams extracts parameters`() {
        val params = handlers.parseQueryParams("turbo://runs/abc/results?sort_by=status&limit=50")

        assertEquals("status", params["sort_by"])
        assertEquals("50", params["limit"])
    }
}
```

**Step 2: Run test to verify it fails**

Run: `./gradlew test --tests "mcp.McpResourceHandlersTest"`
Expected: FAIL - class not found

**Step 3: Write implementation**

```kotlin
package mcp

import burp.SortField

class McpResourceHandlers(private val manager: RunManager) {

    fun listRuns(): Map<String, Any> {
        val runs = manager.getAllRuns().map { run ->
            mapOf(
                "run_id" to run.id,
                "running" to run.handler.isRunning(),
                "finished" to run.handler.hasFinished(),
                "result_count" to run.store.count(),
                "created_at" to run.createdAt
            )
        }
        return mapOf("runs" to runs)
    }

    fun getRunStatus(runId: String?): Map<String, Any?> {
        val run = manager.getRun(runId)
            ?: return mapOf("error" to if (runId == null || runId == "current") "no_current_run" else "not_found")

        return mapOf(
            "run_id" to run.id,
            "running" to run.handler.isRunning(),
            "finished" to run.handler.hasFinished(),
            "status_message" to run.handler.statusString(),
            "result_count" to run.store.count(),
            "created_at" to run.createdAt
        )
    }

    fun getResults(
        runId: String?,
        sortBy: String,
        descending: Boolean,
        limit: Int,
        offset: Int
    ): Map<String, Any?> {
        val run = manager.getRun(runId)
            ?: return mapOf("error" to if (runId == null || runId == "current") "no_current_run" else "not_found")

        val sortField = try {
            SortField.valueOf(sortBy.uppercase())
        } catch (e: IllegalArgumentException) {
            SortField.ID
        }

        val results = run.store.getResults(sortField, descending, limit, offset)

        return mapOf(
            "results" to results.map { req ->
                mapOf(
                    "id" to req.id,
                    "status" to req.code,
                    "length" to req.length,
                    "time" to req.time,
                    "wordcount" to req.wordcount,
                    "words" to req.words,
                    "label" to req.label
                )
            },
            "total_count" to run.store.count()
        )
    }

    fun getRequestDetail(runId: String?, requestId: Int): Map<String, Any?> {
        val run = manager.getRun(runId)
            ?: return mapOf("error" to if (runId == null || runId == "current") "no_current_run" else "not_found")

        val request = run.store.getRequest(requestId)
            ?: return mapOf("error" to "request_not_found")

        return mapOf(
            "request" to request.getRequest(),
            "response" to request.response,
            "status" to request.code,
            "length" to request.length,
            "time" to request.time,
            "words" to request.words
        )
    }

    // URI parsing utilities

    fun parseRunId(uri: String): String? {
        val match = Regex("turbo://runs/([^/\\?]+)").find(uri)
        return match?.groupValues?.get(1)
    }

    fun parseRequestId(uri: String): Int? {
        val match = Regex("turbo://runs/[^/]+/requests/(\\d+)").find(uri)
        return match?.groupValues?.get(1)?.toIntOrNull()
    }

    fun parseQueryParams(uri: String): Map<String, String> {
        val queryStart = uri.indexOf('?')
        if (queryStart == -1) return emptyMap()

        return uri.substring(queryStart + 1)
            .split('&')
            .mapNotNull { param ->
                val parts = param.split('=', limit = 2)
                if (parts.size == 2) parts[0] to parts[1] else null
            }
            .toMap()
    }

    fun handleResourceRead(uri: String): Map<String, Any?> {
        return when {
            uri == "turbo://runs" -> listRuns()
            uri.matches(Regex("turbo://runs/[^/]+/requests/\\d+.*")) -> {
                val runId = parseRunId(uri)
                val requestId = parseRequestId(uri) ?: return mapOf("error" to "invalid_request_id")
                getRequestDetail(runId, requestId)
            }
            uri.matches(Regex("turbo://runs/[^/]+/results.*")) -> {
                val runId = parseRunId(uri)
                val params = parseQueryParams(uri)
                getResults(
                    runId = runId,
                    sortBy = params["sort_by"] ?: "id",
                    descending = params["descending"] != "false",
                    limit = params["limit"]?.toIntOrNull() ?: 100,
                    offset = params["offset"]?.toIntOrNull() ?: 0
                )
            }
            uri.matches(Regex("turbo://runs/[^/]+.*")) -> {
                val runId = parseRunId(uri)
                getRunStatus(runId)
            }
            else -> mapOf("error" to "unknown_resource")
        }
    }
}
```

**Step 4: Run test to verify it passes**

Run: `./gradlew test --tests "mcp.McpResourceHandlersTest"`
Expected: PASS

**Step 5: Commit**

```bash
git add src/mcp/McpResourceHandlers.kt test/kotlin/mcp/McpResourceHandlersTest.kt
git commit -m "feat(mcp): add resource handlers for status, results, request detail"
```

---

## Task 6: Create TurboMcpServer

**Files:**
- Create: `src/mcp/TurboMcpServer.kt`
- Test: `test/kotlin/mcp/TurboMcpServerTest.kt`

**Step 1: Write test for server creation**

```kotlin
package mcp

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class TurboMcpServerTest {

    @Test
    fun `server can be created with port`() {
        val server = TurboMcpServer(port = 31337)
        assertNotNull(server)
    }

    @Test
    fun `server exposes tool and resource handlers`() {
        val server = TurboMcpServer(port = 31337)
        assertNotNull(server.toolHandlers)
        assertNotNull(server.resourceHandlers)
    }
}
```

**Step 2: Run test to verify it fails**

Run: `./gradlew test --tests "mcp.TurboMcpServerTest"`
Expected: FAIL - class not found

**Step 3: Write implementation skeleton**

```kotlin
package mcp

import burp.Utils

class TurboMcpServer(private val port: Int = 31337) {

    private val manager = RunManager()
    val toolHandlers = McpToolHandlers(manager)
    val resourceHandlers = McpResourceHandlers(manager)

    fun start() {
        // TODO: Implement MCP server startup
        Utils.out("MCP server started on localhost:$port")
    }

    fun stop() {
        // TODO: Implement MCP server shutdown
        Utils.out("MCP server stopped")
    }
}
```

**Step 4: Run test to verify it passes**

Run: `./gradlew test --tests "mcp.TurboMcpServerTest"`
Expected: PASS

**Step 5: Commit**

```bash
git add src/mcp/TurboMcpServer.kt test/kotlin/mcp/TurboMcpServerTest.kt
git commit -m "feat(mcp): add TurboMcpServer skeleton"
```

---

## Task 7: Implement MCP Server with SDK

**Files:**
- Modify: `src/mcp/TurboMcpServer.kt`

**Step 1: Implement full server with tools and resources**

Note: The exact API may vary based on MCP SDK version. This is the expected structure:

```kotlin
package mcp

import burp.Utils
import com.fasterxml.jackson.databind.ObjectMapper
import io.modelcontextprotocol.server.McpServer
import io.modelcontextprotocol.server.McpSyncServer
import io.modelcontextprotocol.spec.McpSchema.*

class TurboMcpServer(private val port: Int = 31337) {

    private val manager = RunManager()
    val toolHandlers = McpToolHandlers(manager)
    val resourceHandlers = McpResourceHandlers(manager)
    private val objectMapper = ObjectMapper()
    private var mcpServer: McpSyncServer? = null

    fun start() {
        try {
            val serverInfo = Implementation("turbo-intruder", "1.0.0")
            val capabilities = ServerCapabilities.builder()
                .tools(true)
                .resources(true, false) // resources, no subscriptions yet
                .build()

            mcpServer = McpServer.sync(createTransport())
                .serverInfo(serverInfo)
                .capabilities(capabilities)
                .tools(createToolSpecs())
                .resources(createResourceSpecs())
                .resourceTemplates(createResourceTemplates())
                .build()

            Utils.out("MCP server started on localhost:$port")
        } catch (e: Exception) {
            Utils.err("Failed to start MCP server: ${e.message}")
            e.printStackTrace()
        }
    }

    fun stop() {
        mcpServer?.close()
        Utils.out("MCP server stopped")
    }

    private fun createTransport(): Any {
        // Transport setup depends on SDK version
        // May need HttpServletSseServerTransport or similar
        TODO("Implement based on SDK API")
    }

    private fun createToolSpecs(): List<Any> {
        return listOf(
            createTool("start_run", "Start a new run, clearing any existing runs") { args ->
                toolHandlers.startRun(
                    script = args["script"] as String,
                    baseRequest = args["base_request"] as String,
                    endpoint = args["endpoint"] as String,
                    baseInput = (args["base_input"] as? String) ?: ""
                )
            },
            createTool("start_concurrent_run", "Start a new run without clearing existing runs") { args ->
                toolHandlers.startConcurrentRun(
                    script = args["script"] as String,
                    baseRequest = args["base_request"] as String,
                    endpoint = args["endpoint"] as String,
                    baseInput = (args["base_input"] as? String) ?: ""
                )
            },
            createTool("stop_run", "Stop a running run") { args ->
                toolHandlers.stopRun(args["run_id"] as? String)
            },
            createTool("delete_run", "Delete a run and free memory") { args ->
                toolHandlers.deleteRun(args["run_id"] as? String)
            },
            createTool("delete_all_runs", "Delete all runs") { _ ->
                toolHandlers.deleteAllRuns()
            }
        )
    }

    private fun createTool(name: String, description: String, handler: (Map<String, Any?>) -> Map<String, Any?>): Any {
        // Tool creation depends on SDK API
        TODO("Implement based on SDK API")
    }

    private fun createResourceSpecs(): List<Any> {
        return listOf(
            createResource("turbo://runs", "List all runs", "application/json")
        )
    }

    private fun createResource(uri: String, name: String, mimeType: String): Any {
        TODO("Implement based on SDK API")
    }

    private fun createResourceTemplates(): List<Any> {
        return listOf(
            createResourceTemplate(
                "turbo://runs/{run_id}",
                "Run status",
                "Get status of a specific run"
            ),
            createResourceTemplate(
                "turbo://runs/{run_id}/results",
                "Run results",
                "Get results for a run with optional sort/pagination query params"
            ),
            createResourceTemplate(
                "turbo://runs/{run_id}/requests/{request_id}",
                "Request detail",
                "Get full request/response for a specific result"
            )
        )
    }

    private fun createResourceTemplate(uriTemplate: String, name: String, description: String): Any {
        TODO("Implement based on SDK API")
    }

    // Resource read handler - called when client reads a resource
    fun handleResourceRead(uri: String): String {
        val result = resourceHandlers.handleResourceRead(uri)
        return objectMapper.writeValueAsString(result)
    }
}
```

**Step 2: Build and verify**

Run: `./gradlew compileKotlin`
Expected: BUILD SUCCESSFUL (may have TODOs)

**Step 3: Commit**

```bash
git add src/mcp/TurboMcpServer.kt
git commit -m "feat(mcp): implement MCP server structure with tools and resources"
```

---

## Task 8: Integrate MCP Server into Main Entry Points

**Files:**
- Modify: `src/fast-http.kt`
- Modify: `src/BurpExtender.kt`

**Step 1: Add --mcp flag to standalone mode**

Add to `main()` in `fast-http.kt` at the beginning:

```kotlin
if (args.contains("--mcp")) {
    val server = mcp.TurboMcpServer(port = 31337)
    server.start()

    Runtime.getRuntime().addShutdownHook(Thread {
        server.stop()
    })

    // Keep main thread alive
    Thread.currentThread().join()
    return
}
```

**Step 2: Start MCP server in Burp extension**

In `BurpExtender.kt`, add field:

```kotlin
private var mcpServer: mcp.TurboMcpServer? = null
```

In `registerExtenderCallbacks()`, add:

```kotlin
mcpServer = mcp.TurboMcpServer(port = 31337)
mcpServer?.start()
```

Register unload handler:

```kotlin
callbacks.registerExtensionStateListener {
    mcpServer?.stop()
}
```

**Step 3: Build and verify**

Run: `./gradlew fatJar`
Expected: BUILD SUCCESSFUL

**Step 4: Commit**

```bash
git add src/fast-http.kt src/BurpExtender.kt
git commit -m "feat(mcp): integrate MCP server into main and Burp extension"
```

---

## Task 9: Integration Test

**Files:**
- Create: `test/kotlin/mcp/McpIntegrationTest.kt`

**Step 1: Write integration test**

```kotlin
package mcp

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*

class McpIntegrationTest {

    private lateinit var server: TurboMcpServer

    @BeforeEach
    fun setup() {
        server = TurboMcpServer(port = 31338)
        server.start()
        Thread.sleep(500)
    }

    @AfterEach
    fun teardown() {
        server.stop()
    }

    @Test
    fun `tool handlers work end to end`() {
        // Test via handlers directly since HTTP client setup is complex
        val result = server.toolHandlers.startRun(
            script = "def queueRequests(t, w): pass\ndef completed(r): pass",
            baseRequest = "GET / HTTP/1.1\r\nHost: test\r\n\r\n",
            endpoint = "https://test.com:443",
            baseInput = ""
        )
        assertEquals("started", result["status"])
    }

    @Test
    fun `resource handlers work end to end`() {
        server.toolHandlers.startRun(
            script = "def queueRequests(t, w): pass\ndef completed(r): pass",
            baseRequest = "GET / HTTP/1.1\r\nHost: test\r\n\r\n",
            endpoint = "https://test.com:443",
            baseInput = ""
        )

        val status = server.resourceHandlers.getRunStatus(null)
        assertNotNull(status["run_id"])
    }

    @Test
    fun `resource URI routing works`() {
        server.toolHandlers.startRun(
            script = "def queueRequests(t, w): pass\ndef completed(r): pass",
            baseRequest = "GET / HTTP/1.1\r\nHost: test\r\n\r\n",
            endpoint = "https://test.com:443",
            baseInput = ""
        )

        val result = server.resourceHandlers.handleResourceRead("turbo://runs/current")
        assertNotNull(result["run_id"])
    }
}
```

**Step 2: Run integration test**

Run: `./gradlew test --tests "mcp.McpIntegrationTest"`
Expected: PASS

**Step 3: Commit**

```bash
git add test/kotlin/mcp/McpIntegrationTest.kt
git commit -m "test(mcp): add integration tests"
```

---

## Task 10: Final Verification

**Step 1: Run all tests**

Run: `./gradlew test`
Expected: All tests PASS

**Step 2: Build fat jar**

Run: `./gradlew fatJar`
Expected: BUILD SUCCESSFUL

**Step 3: Manual smoke test**

Run: `java -jar build/libs/turbo-intruder-all.jar --mcp`
Expected: "MCP server started on localhost:31337"

**Step 4: Final commit**

```bash
git add -A
git commit -m "feat(mcp): complete MCP server implementation

Hybrid API with Tools and Resources:

Tools (actions):
- start_run, start_concurrent_run
- stop_run, delete_run, delete_all_runs

Resources (read-only):
- turbo://runs - list all runs
- turbo://runs/{run_id} - run status
- turbo://runs/{run_id}/results - query results
- turbo://runs/{run_id}/requests/{id} - request detail

Works in both standalone (--mcp flag) and Burp extension modes.
HTTP transport on localhost:31337."
```

---

## Notes for Implementation

1. **MCP SDK API Discovery** - Task 7 has TODOs because the exact SDK API needs to be discovered. The SDK may use different class names or patterns than shown.

2. **Transport Setup** - The hardest part will be setting up HTTP transport. May need to:
   - Use `HttpServletSseServerTransport` with an embedded servlet container
   - Or use a simpler HTTP server like NanoHTTPD and implement JSON-RPC manually
   - Or find SDK's built-in HTTP server support

3. **Resource Template Query Params** - MCP resource templates (RFC 6570) may not support query parameters natively. May need to handle `?sort_by=...` separately from the URI template.

4. **Thread Safety** - `currentRun` access in `RunManager` may need `@Volatile` or synchronization.
