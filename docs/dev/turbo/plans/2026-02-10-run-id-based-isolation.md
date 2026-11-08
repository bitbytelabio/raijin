# Run-ID-Based Isolation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Remove session and "current run" concepts from the MCP server so multiple concurrent agents can safely use it, with run_id as the sole identity mechanism.

**Architecture:** RunManager becomes a simple `ConcurrentHashMap<String, ActiveRun>` keyed by run_id. All operations require an explicit run_id. The `start_concurrent_run` and `delete_all_runs` MCP tools are removed. `start_run_async` is merged into `start_run` behavior (all runs are now concurrent by default). `sessionId` is removed from all handler signatures.

**Tech Stack:** Kotlin, MCP Java SDK

---

### Task 1: Simplify RunManager

**Files:**
- Modify: `src/mcp/RunManager.kt`
- Test: `test/kotlin/mcp/RunManagerTest.kt`

**Step 1: Write the new RunManager tests**

Replace `test/kotlin/mcp/RunManagerTest.kt` with tests for the simplified API:

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
}
```

**Step 2: Run tests to verify they fail**

Run: `./gradlew test --tests "mcp.RunManagerTest" 2>&1 | tail -20`
Expected: Compilation errors (signature mismatches)

**Step 3: Rewrite RunManager**

Replace `src/mcp/RunManager.kt`:

```kotlin
package mcp

import java.util.concurrent.ConcurrentHashMap

class RunManager {
    private val runs = ConcurrentHashMap<String, ActiveRun>()

    fun startRun(): ActiveRun {
        val run = ActiveRun()
        runs[run.id] = run
        return run
    }

    fun getRun(runId: String): ActiveRun? {
        return runs[runId]
    }

    fun stopRun(runId: String): String {
        val run = runs[runId] ?: return "not_found"
        run.handler.abort()
        return "stopped"
    }

    fun deleteRun(runId: String): String {
        val run = runs.remove(runId) ?: return "not_found"
        run.handler.abort()
        return "deleted"
    }
}
```

**Step 4: Remove ownerSessionId from ActiveRun**

Replace `src/mcp/ActiveRun.kt`:

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

**Step 5: Run tests to verify they pass**

Run: `./gradlew test --tests "mcp.RunManagerTest" 2>&1 | tail -20`
Expected: All PASS

**Step 6: Commit**

```bash
git add src/mcp/RunManager.kt src/mcp/ActiveRun.kt test/kotlin/mcp/RunManagerTest.kt
git commit -m "refactor: simplify RunManager to run_id-based lookup only"
```

---

### Task 2: Update McpToolHandlers

**Files:**
- Modify: `src/mcp/McpToolHandlers.kt`
- Test: `test/kotlin/mcp/McpToolHandlersTest.kt`

**Step 1: Update tests**

Remove `sessionId` from all handler calls. Remove `startConcurrentRunAsync` and `deleteAllRuns` tests. Remove assertions on `manager.currentRun`. Change `startRunAsync` to call `startRun` on manager directly (since the handler method is renamed). Update `stopRun`/`deleteRun`/`saveToOrganizer`/`searchResponses` to pass `runId` as required (not nullable).

Key test changes:
- `startRun(sessionId=..., ...)` → `startRun(...)`
- `startRunAsync(sessionId=..., ...)` → `startRunAsync(...)`
- `stopRun(testSessionId, null)` → `stopRun(run.id)` (need to capture run_id from startRunAsync first)
- `saveToOrganizer(sessionId=..., runId=null, ...)` → `saveToOrganizer(runId=run.id, ...)`
- `searchResponses(sessionId=..., runId=null, ...)` → `searchResponses(runId=run.id, ...)`
- Delete `startConcurrentRunAsync preserves existing runs` test
- Delete `deleteAllRuns returns count` test

**Step 2: Run tests to verify they fail**

Run: `./gradlew test --tests "mcp.McpToolHandlersTest" --tests "mcp.CollaboratorToolHandlersTest" 2>&1 | tail -20`
Expected: Compilation errors

**Step 3: Update McpToolHandlers implementation**

- Remove `sessionId` parameter from all methods
- Remove `startConcurrentRunAsync` method
- Remove `deleteAllRuns` method
- Change `stopRun(sessionId, runId)` → `stopRun(runId: String)` (required, not nullable)
- Change `deleteRun(sessionId, runId)` → `deleteRun(runId: String)` (required, not nullable)
- Change `saveToOrganizer(sessionId, runId, items)` → `saveToOrganizer(runId: String, items: String)` (required)
- Change `searchResponses(sessionId, runId, query)` → `searchResponses(runId: String, query: String)` (required)
- In `startRun`, call `manager.startRun()` (no session)
- In `startRunAsync`, call `manager.startRun()` (no session)

**Step 4: Run tests to verify they pass**

Run: `./gradlew test --tests "mcp.McpToolHandlersTest" --tests "mcp.CollaboratorToolHandlersTest" 2>&1 | tail -20`
Expected: All PASS

**Step 5: Commit**

```bash
git add src/mcp/McpToolHandlers.kt test/kotlin/mcp/McpToolHandlersTest.kt
git commit -m "refactor: remove sessionId from McpToolHandlers, drop concurrent/deleteAll"
```

---

### Task 3: Update McpResourceHandlers

**Files:**
- Modify: `src/mcp/McpResourceHandlers.kt`
- Test: `test/kotlin/mcp/McpResourceHandlersTest.kt`

**Step 1: Update tests**

- Remove `sessionId` from all handler method calls
- Remove `listRuns` tests (method being removed)
- Change `runId=null` / `runId="current"` to use explicit run IDs from `manager.startRun()`
- Update `getRunStatus`, `getResults`, `getRequestDetail` calls to pass explicit `runId`

**Step 2: Run tests to verify they fail**

Run: `./gradlew test --tests "mcp.McpResourceHandlersTest" 2>&1 | tail -20`

**Step 3: Update McpResourceHandlers implementation**

- Remove `sessionId` parameter from all methods
- Remove `listRuns` method entirely
- Change `getRunStatus(sessionId, runId)` → `getRunStatus(runId: String)` (required)
- Change `getResults(sessionId, runId, ...)` → `getResults(runId: String, ...)` (required)
- Change `getRequestDetail(sessionId, runId, ...)` → `getRequestDetail(runId: String, ...)` (required)
- Remove "no_current_run" error messages — just use "not_found"

**Step 4: Run tests to verify they pass**

Run: `./gradlew test --tests "mcp.McpResourceHandlersTest" 2>&1 | tail -20`

**Step 5: Commit**

```bash
git add src/mcp/McpResourceHandlers.kt test/kotlin/mcp/McpResourceHandlersTest.kt
git commit -m "refactor: remove sessionId from McpResourceHandlers, drop listRuns"
```

---

### Task 4: Update MCP resource definitions

**Files:**
- Modify: `src/mcp/resource/McpResourceDefinitions.kt`

**Step 1: Update resource handlers**

- Remove `turbo://runs` resource (was list of runs — no longer meaningful without sessions)
- Remove `sessionId` from all `handle` lambdas — the resource DSL's handler signature will need `sessionId` dropped or ignored
- Change `params.path("run_id")` calls to pass `run_id` as required

**Step 2: Run full test suite**

Run: `./gradlew test 2>&1 | tail -30`

**Step 3: Commit**

```bash
git add src/mcp/resource/McpResourceDefinitions.kt
git commit -m "refactor: remove sessionId from resource definitions, drop runs list"
```

---

### Task 5: Update TurboMcpServer tool definitions

**Files:**
- Modify: `src/mcp/TurboMcpServer.kt`

**Step 1: Update stateless tool builders**

- Remove `buildStatelessStartConcurrentRunAsyncTool` and `buildStatelessDeleteAllRunsTool`
- Remove `buildStartConcurrentRunAsyncTool` and `buildDeleteAllRunsTool`
- Remove from `allTools` and `allStatelessTools` lists
- Update `start_run` description: remove "This clears any previous runs and starts fresh"
- Update `start_run_async` description: remove "This clears any previous runs"
- Make `run_id` required in `stop_run`, `delete_run`, `save_to_organizer`, `search_responses` schemas
- Remove "Omit or use 'current'" from all `run_id` descriptions
- Remove `STATELESS_SESSION_ID` constant
- Stop passing `sessionId` to tool handler methods
- Stop passing `exchange.sessionId()` to tool handler methods

**Step 2: Update `TurboMcpServer.invokeResourceHandler` and test helpers**

Remove `sessionId` parameter from `invokeResourceHandler`.

**Step 3: Run full test suite**

Run: `./gradlew test 2>&1 | tail -30`
Expected: All PASS

**Step 4: Commit**

```bash
git add src/mcp/TurboMcpServer.kt
git commit -m "refactor: remove concurrent_run/delete_all tools, require run_id everywhere"
```

---

### Task 6: Update resource DSL to remove sessionId

**Files:**
- Modify: `src/mcp/resource/ResourceDefinition.kt`
- Modify: `src/mcp/resource/ResourceDsl.kt`
- Modify: `src/mcp/resource/ResourceRegistry.kt`

**Step 1: Remove sessionId from handler signature**

The `handle` lambda currently takes `(sessionId: String, params: ParsedParams)`. Change to `(params: ParsedParams)` only. Update `ResourceRegistry.buildStatelessSpecs()` and `buildStatefulSpecs()` accordingly.

**Step 2: Run full test suite**

Run: `./gradlew test 2>&1 | tail -30`
Expected: All PASS

**Step 3: Commit**

```bash
git add src/mcp/resource/
git commit -m "refactor: remove sessionId from resource handler DSL"
```

---

### Task 7: Final verification and cleanup

**Step 1: Search for any remaining sessionId references**

```bash
grep -rn "sessionId\|currentRun\|currentRunBySession\|STATELESS_SESSION_ID\|ownerSessionId\|getAllRuns\|deleteAllRuns\|startConcurrentRun\|no_current_run" src/ test/
```

Fix any remaining references.

**Step 2: Build the jar**

Run: `./gradlew jar`
Expected: BUILD SUCCESSFUL

**Step 3: Run full test suite one final time**

Run: `./gradlew test 2>&1 | tail -30`
Expected: All PASS

**Step 4: Commit any remaining cleanup**

```bash
git add -A && git commit -m "chore: final cleanup of session-related references"
```
