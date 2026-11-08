# Response Body Stripping Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Strip response bodies from old completed runs to prevent heap exhaustion, with emergency memory-pressure cleanup.

**Architecture:** Three-tier retention in RunManager (full data / metadata-only / evicted). Request gets `stripResponseBody()` to null out heavy fields after caching metadata. A daemon thread monitors available memory and triggers progressive cleanup when below 1GB.

**Tech Stack:** Kotlin, JUnit 5

**Spec:** `docs/superpowers/specs/2026-03-13-response-body-stripping-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `src/Request.kt` | Modify | Add `materializeAttributes()` and `stripResponseBody()` |
| `src/ResultStore.kt` | Modify | Add `stripResponseBodies()` |
| `src/mcp/ActiveRun.kt` | Modify | Add `responsesStripped` flag |
| `src/mcp/RunManager.kt` | Modify | Three-tier eviction + memory pressure daemon |
| `src/mcp/McpToolHandlers.kt` | Modify | Handle stripped runs in `searchResponses` |
| `src/mcp/McpResourceHandlers.kt` | Modify | Handle stripped runs in `getRequestDetail` |
| `test/kotlin/BurpRequestTest.kt` | Modify | Tests for `stripResponseBody()` and `materializeAttributes()` |
| `test/kotlin/ResultStoreTest.kt` | Modify | Tests for `stripResponseBodies()` |
| `test/kotlin/mcp/RunManagerTest.kt` | Modify | Tests for three-tier eviction and memory pressure |
| `test/kotlin/mcp/McpToolHandlersTest.kt` | Modify | Tests for stripped-run behavior in search |
| `test/kotlin/mcp/McpResourceHandlersTest.kt` | Modify | Tests for stripped-run behavior in getRequestDetail |

---

## Chunk 1: Request.stripResponseBody()

### Task 1: Request.materializeAttributes() and stripResponseBody()

**Files:**
- Modify: `src/Request.kt:19-70`
- Test: `test/kotlin/BurpRequestTest.kt`

- [ ] **Step 1: Write failing tests for materializeAttributes()**

In `test/kotlin/BurpRequestTest.kt`, add:

```kotlin
@Test
fun `materializeAttributes caches code length and wordcount`() {
    val req = Request("GET / HTTP/1.1")
    req.response = "HTTP/1.1 200 OK\r\n\r\nHello World"

    req.materializeAttributes()

    // Null out response to prove values are cached
    req.response = null
    assertEquals(200, req.code)
    assertEquals("HTTP/1.1 200 OK\r\n\r\nHello World".length, req.length)
    assertTrue(req.wordcount > 0)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew test --tests "burp.BurpRequestTest.materializeAttributes caches code length and wordcount"`
Expected: compilation error — `materializeAttributes` doesn't exist yet

- [ ] **Step 3: Implement materializeAttributes()**

In `src/Request.kt`, add after the `getAttribute` method (after line 70):

```kotlin
fun materializeAttributes() {
    getAttribute("code")
    getAttribute("length")
    getAttribute("wordcount")
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew test --tests "burp.BurpRequestTest.materializeAttributes caches code length and wordcount"`
Expected: PASS

- [ ] **Step 5: Write failing tests for stripResponseBody()**

In `test/kotlin/BurpRequestTest.kt`, add:

```kotlin
@Test
fun `stripResponseBody nulls response and heavy fields but preserves metadata`() {
    val req = Request("GET / HTTP/1.1", listOf("test"), 0, "my-label")
    req.response = "HTTP/1.1 200 OK\r\n\r\nHello World"
    req.engine = Object()
    req.callback = { _, _ -> false }
    req.gate = null // already null, but explicit
    req.id = 42
    req.ttfb = 100L
    req.ttlb = 200L
    req.anomalyRank = 5

    req.stripResponseBody()

    // Heavy fields nulled
    assertNull(req.response)
    assertNull(req.details)
    assertNull(req.montoyaReq)
    assertNull(req.engine)
    assertNull(req.callback)
    assertNull(req.gate)

    // Metadata preserved
    assertEquals(200, req.code)
    assertEquals("HTTP/1.1 200 OK\r\n\r\nHello World".length, req.length)
    assertTrue(req.wordcount > 0)
    assertEquals("my-label", req.label)
    assertEquals(42, req.id)
    assertEquals(100L, req.ttfb)
    assertEquals(200L, req.ttlb)
    assertEquals(5, req.anomalyRank)
    assertEquals("GET / HTTP/1.1", req.template)
    assertEquals(listOf("test"), req.words)
}

@Test
fun `stripResponseBody handles null response gracefully`() {
    val req = Request("GET / HTTP/1.1")
    req.response = null

    req.stripResponseBody()

    assertEquals(0, req.code)
    assertEquals(0, req.length)
}
```

- [ ] **Step 6: Run tests to verify they fail**

Run: `./gradlew test --tests "burp.BurpRequestTest.stripResponseBody*"`
Expected: compilation error — `stripResponseBody` doesn't exist yet

- [ ] **Step 7: Implement stripResponseBody()**

In `src/Request.kt`, add after `materializeAttributes()`:

```kotlin
fun stripResponseBody() {
    materializeAttributes()
    response = null
    details = null
    montoyaReq = null
    engine = null
    callback = null
    gate = null
}
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `./gradlew test --tests "burp.BurpRequestTest"`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add src/Request.kt test/kotlin/BurpRequestTest.kt
git commit -m "feat: add materializeAttributes() and stripResponseBody() to Request"
```

---

### Task 2: ResultStore.stripResponseBodies()

**Files:**
- Modify: `src/ResultStore.kt`
- Test: `test/kotlin/ResultStoreTest.kt`

- [ ] **Step 1: Write failing test**

In `test/kotlin/ResultStoreTest.kt`, add:

```kotlin
@Test
fun `stripResponseBodies nulls all response bodies but preserves metadata`() {
    val req1 = Request("GET /1 HTTP/1.1").apply {
        response = "HTTP/1.1 200 OK\r\n\r\nBody1"
        id = 1
    }
    val req2 = Request("GET /2 HTTP/1.1").apply {
        response = "HTTP/1.1 404 Not Found\r\n\r\nBody2"
        id = 2
    }
    store.add(req1)
    store.add(req2)

    store.stripResponseBodies()

    assertNull(req1.response)
    assertNull(req2.response)
    assertEquals(200, req1.code)
    assertEquals(404, req2.code)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew test --tests "burp.ResultStoreTest.stripResponseBodies*"`
Expected: compilation error — `stripResponseBodies` doesn't exist yet

- [ ] **Step 3: Implement stripResponseBodies()**

In `src/ResultStore.kt`, add after the `clear()` method:

```kotlin
fun stripResponseBodies() {
    synchronized(results) {
        results.forEach { it.stripResponseBody() }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew test --tests "burp.ResultStoreTest"`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/ResultStore.kt test/kotlin/ResultStoreTest.kt
git commit -m "feat: add stripResponseBodies() to ResultStore"
```

---

### Task 3: ActiveRun.responsesStripped flag

**Files:**
- Modify: `src/mcp/ActiveRun.kt`
- Test: `test/kotlin/mcp/ActiveRunTest.kt`

- [ ] **Step 1: Write failing test**

In `test/kotlin/mcp/ActiveRunTest.kt`, add:

```kotlin
@Test
fun `responsesStripped defaults to false`() {
    val run = ActiveRun()
    assertFalse(run.responsesStripped)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew test --tests "mcp.ActiveRunTest.responsesStripped*"`
Expected: compilation error — `responsesStripped` doesn't exist yet

- [ ] **Step 3: Implement**

In `src/mcp/ActiveRun.kt`, add field:

```kotlin
@Volatile
var responsesStripped: Boolean = false
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew test --tests "mcp.ActiveRunTest"`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/mcp/ActiveRun.kt test/kotlin/mcp/ActiveRunTest.kt
git commit -m "feat: add responsesStripped flag to ActiveRun"
```

---

## Chunk 2: Three-tier eviction in RunManager

### Task 4: RunManager three-tier eviction

**Files:**
- Modify: `src/mcp/RunManager.kt:1-51`
- Test: `test/kotlin/mcp/RunManagerTest.kt`

- [ ] **Step 1: Write failing test for response stripping tier**

In `test/kotlin/mcp/RunManagerTest.kt`, add:

```kotlin
@Test
fun `strips response bodies from runs beyond maxFullResponseRuns`() {
    val manager = RunManager(maxCompletedRuns = 4, maxFullResponseRuns = 2)

    val run1 = manager.startRun()
    run1.handler.markScriptCompleted()
    val req1 = burp.Request("GET /1 HTTP/1.1").apply {
        response = "HTTP/1.1 200 OK\r\n\r\nBody1"; id = 1
    }
    run1.store.add(req1)

    val run2 = manager.startRun()
    run2.handler.markScriptCompleted()
    val req2 = burp.Request("GET /2 HTTP/1.1").apply {
        response = "HTTP/1.1 200 OK\r\n\r\nBody2"; id = 2
    }
    run2.store.add(req2)

    val run3 = manager.startRun()
    run3.handler.markScriptCompleted()
    val req3 = burp.Request("GET /3 HTTP/1.1").apply {
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
    val req1 = burp.Request("GET /1 HTTP/1.1").apply {
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
            val req = burp.Request("GET / HTTP/1.1").apply {
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./gradlew test --tests "mcp.RunManagerTest.strips*" --tests "mcp.RunManagerTest.does not re-strip*" --tests "mcp.RunManagerTest.default maxFullResponseRuns*"`
Expected: compilation error — `maxFullResponseRuns` parameter doesn't exist

- [ ] **Step 3: Implement three-tier eviction**

Replace `src/mcp/RunManager.kt` contents:

```kotlin
package mcp

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

class RunManager(
    private val maxCompletedRuns: Int = 100,
    private val maxFullResponseRuns: Int = 50
) {
    private val runs = ConcurrentHashMap<String, ActiveRun>()
    private val evictedIds = ConcurrentHashMap.newKeySet<String>()
    private val sequenceCounter = AtomicLong(0)

    fun startRun(): ActiveRun {
        evictCompletedRuns()
        val run = ActiveRun(sequenceCounter.getAndIncrement())
        runs[run.id] = run
        return run
    }

    fun getRun(runId: String): ActiveRun? {
        return runs[runId]
    }

    fun isEvicted(runId: String): Boolean {
        return runId in evictedIds
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

    private fun evictCompletedRuns() {
        val completed = runs.values
            .filter { it.handler.status() != "running" }
            .sortedByDescending { it.sequenceNumber }

        // Strip response bodies from runs beyond the full-response threshold
        completed.drop(maxFullResponseRuns).forEach { run ->
            if (!run.responsesStripped) {
                run.store.stripResponseBodies()
                run.responsesStripped = true
            }
        }

        // Evict runs beyond the total retention limit
        val excess = completed.size - maxCompletedRuns
        if (excess > 0) {
            completed.takeLast(excess).forEach { run ->
                runs.remove(run.id)
                evictedIds.add(run.id)
            }
        }
    }
}
```

- [ ] **Step 4: Run all RunManager tests**

Run: `./gradlew test --tests "mcp.RunManagerTest"`
Expected: PASS

- [ ] **Step 5: Run full test suite to check for regressions**

Run: `./gradlew test`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/mcp/RunManager.kt test/kotlin/mcp/RunManagerTest.kt
git commit -m "feat: three-tier eviction — strip response bodies before full eviction"
```

---

## Chunk 3: Memory pressure daemon

### Task 5: Memory pressure monitoring thread

**Files:**
- Modify: `src/mcp/RunManager.kt`
- Test: `test/kotlin/mcp/RunManagerTest.kt`

- [ ] **Step 1: Write failing test for emergency stripping**

In `test/kotlin/mcp/RunManagerTest.kt`, add:

```kotlin
@Test
fun `emergencyCleanup strips all completed runs regardless of threshold`() {
    val manager = RunManager(maxCompletedRuns = 100, maxFullResponseRuns = 50)

    val run1 = manager.startRun()
    run1.handler.markScriptCompleted()
    val req1 = burp.Request("GET /1 HTTP/1.1").apply {
        response = "HTTP/1.1 200 OK\r\n\r\nBody1"; id = 1
    }
    run1.store.add(req1)

    val run2 = manager.startRun()
    run2.handler.markScriptCompleted()
    val req2 = burp.Request("GET /2 HTTP/1.1").apply {
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
    run1.store.add(burp.Request("GET /1 HTTP/1.1").apply {
        response = "HTTP/1.1 200 OK\r\n\r\nBody"; id = 1
    })

    val run2 = manager.startRun()
    run2.handler.markScriptCompleted()
    run2.store.add(burp.Request("GET /2 HTTP/1.1").apply {
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
    completedRun.store.add(burp.Request("GET / HTTP/1.1").apply {
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./gradlew test --tests "mcp.RunManagerTest.emergencyCleanup*"`
Expected: compilation error — `emergencyCleanup` doesn't exist

- [ ] **Step 3: Implement emergencyCleanup()**

In `src/mcp/RunManager.kt`, add the `emergencyCleanup()` method after `evictCompletedRuns()`:

```kotlin
fun emergencyCleanup() {
    val completed = runs.values
        .filter { it.handler.status() != "running" }
        .sortedByDescending { it.sequenceNumber }

    // First pass: strip any unstripped runs
    val stripped = completed.filter { !it.responsesStripped }
    if (stripped.isNotEmpty()) {
        stripped.forEach { run ->
            run.store.stripResponseBodies()
            run.responsesStripped = true
        }
        return
    }

    // Second pass: evict oldest completed run
    if (completed.isNotEmpty()) {
        val oldest = completed.last()
        runs.remove(oldest.id)
        evictedIds.add(oldest.id)
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `./gradlew test --tests "mcp.RunManagerTest"`
Expected: PASS

- [ ] **Step 5: Write test for memory monitor thread startup**

In `test/kotlin/mcp/RunManagerTest.kt`, add:

```kotlin
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
```

- [ ] **Step 6: Run test to verify it fails**

Run: `./gradlew test --tests "mcp.RunManagerTest.startMemoryMonitor*"`
Expected: compilation error

- [ ] **Step 7: Implement memory monitor thread**

In `src/mcp/RunManager.kt`, add the following fields and methods:

```kotlin
@Volatile
private var monitorThread: Thread? = null

fun startMemoryMonitor() {
    if (monitorThread != null) return
    monitorThread = Thread({
        while (!Thread.currentThread().isInterrupted) {
            try {
                Thread.sleep(5000)
                val runtime = Runtime.getRuntime()
                val available = runtime.maxMemory() - runtime.totalMemory() + runtime.freeMemory()
                if (available < 1_000_000_000L) {
                    emergencyCleanup()
                    System.gc()
                }
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                break
            }
        }
    }, "turbo-memory-monitor").apply {
        isDaemon = true
        start()
    }
}

fun stopMemoryMonitor() {
    monitorThread?.interrupt()
    monitorThread = null
}
```

Update `startRun()` to auto-start the monitor:

```kotlin
fun startRun(): ActiveRun {
    startMemoryMonitor()
    evictCompletedRuns()
    val run = ActiveRun(sequenceCounter.getAndIncrement())
    runs[run.id] = run
    return run
}
```

- [ ] **Step 8: Run all RunManager tests**

Run: `./gradlew test --tests "mcp.RunManagerTest"`
Expected: PASS

- [ ] **Step 9: Run full test suite**

Run: `./gradlew test`
Expected: PASS

- [ ] **Step 10: Commit**

```bash
git add src/mcp/RunManager.kt test/kotlin/mcp/RunManagerTest.kt
git commit -m "feat: add memory pressure daemon with emergencyCleanup"
```

---

## Chunk 4: MCP tool/resource handling of stripped runs

### Task 6: searchResponses handles stripped runs

**Files:**
- Modify: `src/mcp/McpToolHandlers.kt:154-172`
- Test: `test/kotlin/mcp/McpToolHandlersTest.kt`

- [ ] **Step 1: Write failing test**

In `test/kotlin/mcp/McpToolHandlersTest.kt`, add:

```kotlin
@Test
fun `searchResponses notes when responses are stripped for response search`() {
    val run = manager.startRun()
    val req1 = burp.Request("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n")
    req1.id = 1
    req1.label = "interesting"
    req1.response = "HTTP/1.1 200 OK\r\n\r\nHello"
    run.store.add(req1)

    // Strip the run
    run.store.stripResponseBodies()
    run.responsesStripped = true

    val result = handlers.searchResponses(runId = run.id, query = "Hello", searchIn = "responses")

    // Should indicate responses were stripped
    assertTrue(result.containsKey("warning"))
    assertTrue((result["warning"] as String).contains("stripped"))
}

@Test
fun `searchResponses still searches labels on stripped runs`() {
    val run = manager.startRun()
    val req1 = burp.Request("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n")
    req1.id = 1
    req1.label = "interesting"
    req1.response = "HTTP/1.1 200 OK\r\n\r\nHello"
    run.store.add(req1)

    run.store.stripResponseBodies()
    run.responsesStripped = true

    val result = handlers.searchResponses(runId = run.id, query = "interesting", searchIn = "labels")

    val matches = result["matches"] as List<Int>
    assertEquals(listOf(1), matches)
    // No warning for label-only search
    assertFalse(result.containsKey("warning"))
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./gradlew test --tests "mcp.McpToolHandlersTest.searchResponses notes*" --tests "mcp.McpToolHandlersTest.searchResponses still searches*"`
Expected: FAIL — no `warning` key in result

- [ ] **Step 3: Implement stripped-run handling in searchResponses**

In `src/mcp/McpToolHandlers.kt`, update `searchResponses()`:

```kotlin
fun searchResponses(runId: String, query: String, searchIn: String = "all"): Map<String, Any> {
    val run = manager.getRun(runId)
        ?: return mapOf("error" to runNotFoundMessage(runId))

    val matches = run.store.getAllRquests()
        .filter { req ->
            when (searchIn) {
                "labels" -> req.label.contains(query)
                "responses" -> req.response?.contains(query) == true
                else -> req.response?.contains(query) == true || req.label.contains(query)
            }
        }
        .map { it.id }

    val result = mutableMapOf<String, Any>(
        "matches" to matches,
        "match_count" to matches.size
    )

    if (run.responsesStripped && searchIn != "labels") {
        result["warning"] = "Response bodies have been stripped from this run to free memory. Only label search is available."
    }

    return result
}
```

- [ ] **Step 4: Write test for default searchIn (all) on stripped run**

In `test/kotlin/mcp/McpToolHandlersTest.kt`, add:

```kotlin
@Test
fun `searchResponses with default searchIn warns and still matches labels on stripped run`() {
    val run = manager.startRun()
    val req1 = burp.Request("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n")
    req1.id = 1
    req1.label = "interesting"
    req1.response = "HTTP/1.1 200 OK\r\n\r\nHello"
    run.store.add(req1)

    run.store.stripResponseBodies()
    run.responsesStripped = true

    val result = handlers.searchResponses(runId = run.id, query = "interesting")

    val matches = result["matches"] as List<Int>
    assertEquals(listOf(1), matches)
    assertTrue(result.containsKey("warning"))
}
```

- [ ] **Step 5: Run all McpToolHandlers tests**

Run: `./gradlew test --tests "mcp.McpToolHandlersTest"`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/mcp/McpToolHandlers.kt test/kotlin/mcp/McpToolHandlersTest.kt
git commit -m "feat: searchResponses warns when run responses are stripped"
```

---

### Task 7: getRequestDetail handles stripped runs

**Files:**
- Modify: `src/mcp/McpResourceHandlers.kt:115-159`
- Test: `test/kotlin/mcp/McpResourceHandlersTest.kt`

- [ ] **Step 1: Write failing test**

In `test/kotlin/mcp/McpResourceHandlersTest.kt`, add (or create the test class if tests for `getRequestDetail` don't exist yet — check existing file first):

```kotlin
@Test
fun `getRequestDetail indicates when response was stripped`() {
    val run = manager.startRun()
    val req = burp.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew test --tests "mcp.McpResourceHandlersTest.getRequestDetail indicates*"`
Expected: FAIL — no `warning` key

- [ ] **Step 3: Implement stripped-run handling in getRequestDetail**

In `src/mcp/McpResourceHandlers.kt`, in `getRequestDetail()`, add after the `request` null check (around line 126):

```kotlin
if (run.responsesStripped && request.response == null) {
    return mapOf(
        "warning" to "Response body was stripped from this run to free memory. Metadata is still available.",
        "request" to request.getRequest(),
        "status" to request.code,
        "length" to request.length,
        "ttfb" to request.ttfb,
        "ttlb" to request.ttlb,
        "wordcount" to request.wordcount,
        "words" to request.words,
        "label" to request.label,
        "anomaly_rank" to request.anomalyRank
    )
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew test --tests "mcp.McpResourceHandlersTest"`
Expected: PASS

- [ ] **Step 5: Run full test suite**

Run: `./gradlew test`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/mcp/McpResourceHandlers.kt test/kotlin/mcp/McpResourceHandlersTest.kt
git commit -m "feat: getRequestDetail returns warning for stripped response bodies"
```

---

## Chunk 5: Final verification

### Task 8: Full integration test and build

- [ ] **Step 1: Run full test suite**

Run: `./gradlew test`
Expected: All tests PASS

- [ ] **Step 2: Build JAR**

Run: `./gradlew jar`
Expected: BUILD SUCCESSFUL, JAR at `build/libs/turbo-intruder.jar`

- [ ] **Step 3: Final commit if any cleanup needed**

Review all changes and ensure consistency.
