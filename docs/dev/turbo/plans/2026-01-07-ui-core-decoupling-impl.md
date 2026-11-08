# UI-Core Decoupling Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extract data storage from RequestTable into ResultStore, enabling programmatic access for future MCP integration.

**Architecture:** Create ResultStore implementing OutputHandler with sorting/pagination. RequestTable becomes pure UI that polls ResultStore for updates. No behavioral changes to existing functionality.

**Tech Stack:** Kotlin, Swing (for UI), CopyOnWriteArrayList (thread-safe storage)

---

### Task 1: Create ResultStore Class

**Files:**
- Create: `src/ResultStore.kt`

**Step 1: Create the ResultStore file with SortField enum and basic structure**

```kotlin
package burp

import java.util.concurrent.CopyOnWriteArrayList

enum class SortField {
    ID,
    STATUS,
    LENGTH,
    TIME,
    WORDCOUNT,
    ANOMALY_RANK,
    ARRIVAL
}

class ResultStore : OutputHandler {
    private val results = CopyOnWriteArrayList<Request>()

    override fun add(req: Request) {
        results.add(req)
    }

    override fun getAllRquests(): List<Request> = results.toList()

    fun count(): Int = results.size

    fun clear() {
        results.clear()
    }

    fun getRequest(index: Int): Request? {
        return if (index >= 0 && index < results.size) results[index] else null
    }

    fun getResults(
        sortBy: SortField = SortField.ID,
        descending: Boolean = true,
        limit: Int = 100,
        offset: Int = 0
    ): List<Request> {
        val comparator: Comparator<Request> = when (sortBy) {
            SortField.ID -> compareBy { results.indexOf(it) }
            SortField.STATUS -> compareBy { it.code }
            SortField.LENGTH -> compareBy { it.length }
            SortField.TIME -> compareBy { it.time }
            SortField.WORDCOUNT -> compareBy { it.wordcount }
            SortField.ANOMALY_RANK -> compareBy { it.anomalyRank ?: 0 }
            SortField.ARRIVAL -> compareBy { it.arrival }
        }

        val sorted = if (descending) {
            results.sortedWith(comparator.reversed())
        } else {
            results.sortedWith(comparator)
        }

        return sorted.drop(offset).take(limit)
    }
}
```

**Step 2: Verify it compiles**

Run: `./gradlew compileKotlin`
Expected: BUILD SUCCESSFUL

**Step 3: Commit**

```bash
git add src/ResultStore.kt
git commit -m "feat: add ResultStore class for decoupled data storage"
```

---

### Task 2: Modify RequestTable Constructor to Accept ResultStore

**Files:**
- Modify: `src/RequestTable.kt:54-71`

**Step 1: Update RequestTable constructor signature and remove internal model storage delegation**

Change line 54 from:
```kotlin
class RequestTable(val service: IHttpService, val handler: AttackHandler): JPanel(), OutputHandler {
```

To:
```kotlin
class RequestTable(val store: ResultStore, val service: IHttpService, val handler: AttackHandler): JPanel() {
```

Note: RequestTable no longer implements OutputHandler - it delegates to the store.

**Step 2: Verify it compiles (expect errors - we haven't updated callers yet)**

Run: `./gradlew compileKotlin`
Expected: Compile errors about missing arguments - this is expected

**Step 3: Commit partial progress**

```bash
git add src/RequestTable.kt
git commit -m "refactor: update RequestTable to accept ResultStore (WIP)"
```

---

### Task 3: Update RequestTable to Read from ResultStore

**Files:**
- Modify: `src/RequestTable.kt:277-290`

**Step 1: Remove OutputHandler method implementations from RequestTable**

Delete or comment out lines 277-290:
```kotlin
    override fun add(req: Request) {
        synchronized(lock) {
            model.addRow(req)
        }

        if (firstEntry) {
            setCurrentRequest(req)
            firstEntry = false
        }
    }

    override fun getAllRquests(): List<Request> {
        return model.getAllRequests()
    }
```

**Step 2: Add polling mechanism to RequestTable init block**

Add after line 190 (after the status bar timer setup), inside the init block:

```kotlin
        // Poll ResultStore for new results
        var lastKnownSize = 0
        val storePoller = javax.swing.Timer(100) {
            val currentSize = store.count()
            if (currentSize > lastKnownSize) {
                for (i in lastKnownSize until currentSize) {
                    val req = store.getRequest(i)
                    if (req != null) {
                        model.addRow(req)
                        if (lastKnownSize == 0) {
                            setCurrentRequest(req)
                        }
                    }
                }
                lastKnownSize = currentSize
            }
        }
        storePoller.start()
```

**Step 3: Verify it compiles (still expect errors from callers)**

Run: `./gradlew compileKotlin`
Expected: Errors in fast-http.kt about RequestTable constructor

**Step 4: Commit**

```bash
git add src/RequestTable.kt
git commit -m "refactor: RequestTable polls ResultStore instead of storing data"
```

---

### Task 4: Update TurboIntruderFrame to Create and Wire ResultStore

**Files:**
- Modify: `src/fast-http.kt:404-435`

**Step 1: Add ResultStore variable declaration**

Find line ~386 where `requestTable = null` is set. Add a store variable nearby. Look for the class-level variable `var requestTable: RequestTable? = null` (around line 163) and add:

```kotlin
var resultStore: ResultStore? = null
```

**Step 2: Update the attack start block**

Change lines 404-435. Replace:
```kotlin
requestTable = RequestTable(newService, handler)
```

With:
```kotlin
resultStore = ResultStore()
requestTable = RequestTable(resultStore!!, newService, handler)
```

And change line 435 from:
```kotlin
evalJython(script, baseRequest, messageEditor.message, target, inputHost, baseInput, requestTable!!, handler, reqs)
```

To:
```kotlin
evalJython(script, baseRequest, messageEditor.message, target, inputHost, baseInput, resultStore!!, handler, reqs)
```

**Step 3: Update the Configure button block to reset resultStore**

Find line ~384-386 where requestTable is cleared. Add:
```kotlin
resultStore?.clear()
resultStore = null
```

**Step 4: Verify it compiles**

Run: `./gradlew compileKotlin`
Expected: BUILD SUCCESSFUL (or errors in main() which we fix next)

**Step 5: Commit**

```bash
git add src/fast-http.kt
git commit -m "refactor: TurboIntruderFrame creates ResultStore for attacks"
```

---

### Task 5: Update Headless main() Function

**Files:**
- Modify: `src/fast-http.kt:521-557`

**Step 1: Update main() to use ResultStore**

Change line 545 from:
```kotlin
val outputHandler = ConsolePrinter()
```

To:
```kotlin
val store = ResultStore()
```

Change line 546 from:
```kotlin
evalJython(code, req, rawReq, endpoint, "", baseInput, outputHandler, attackHandler, mutableListOf())
```

To:
```kotlin
evalJython(code, req, rawReq, endpoint, "", baseInput, store, attackHandler, mutableListOf())
```

**Step 2: Add result printing after attack completes**

After the evalJython call (around line 546), add:
```kotlin
// Print results to console (replaces ConsolePrinter behavior)
println("ID | Word | Status | Wordcount | Length | Time")
store.getAllRquests().forEachIndexed { index, req ->
    println("${index + 1} | ${req.words.joinToString("/")} | ${req.code} | ${req.wordcount} | ${req.length} | ${req.time}")
}
```

**Step 3: Verify it compiles**

Run: `./gradlew compileKotlin`
Expected: BUILD SUCCESSFUL

**Step 4: Commit**

```bash
git add src/fast-http.kt
git commit -m "refactor: headless mode uses ResultStore"
```

---

### Task 6: Update evalJython Signature

**Files:**
- Modify: `src/fast-http.kt:60-90`

**Step 1: Change parameter type in evalJython**

Change line 60 from:
```kotlin
fun evalJython(code: String, baseRequest: String, rawRequest: ByteArray, endpoint: String, host: String, baseInput: String, outputHandler: OutputHandler, handler: AttackHandler, reqs: MutableList<HttpRequestResponse>?) {
```

To:
```kotlin
fun evalJython(code: String, baseRequest: String, rawRequest: ByteArray, endpoint: String, host: String, baseInput: String, store: ResultStore, handler: AttackHandler, reqs: MutableList<HttpRequestResponse>?) {
```

**Step 2: Update variable references inside evalJython**

Change line 74-75 from:
```kotlin
        pyInterp.set("outputHandler", outputHandler)
        pyInterp.set("table", outputHandler)
```

To:
```kotlin
        pyInterp.set("outputHandler", store)
        pyInterp.set("table", store)
```

Change line 90 from:
```kotlin
        pyInterp.exec("completed(outputHandler.getAllRquests())".trimMargin())
```

To:
```kotlin
        pyInterp.exec("completed(store.getAllRquests())".trimMargin())
```

Change line 98 from:
```kotlin
                pyInterp.exec("completed(outputHandler.getAllRquests())".trimMargin())
```

To:
```kotlin
                pyInterp.exec("completed(store.getAllRquests())".trimMargin())
```

**Step 3: Verify it compiles**

Run: `./gradlew compileKotlin`
Expected: BUILD SUCCESSFUL

**Step 4: Commit**

```bash
git add src/fast-http.kt
git commit -m "refactor: evalJython accepts ResultStore parameter"
```

---

### Task 7: Build and Manual Test

**Files:**
- None (testing only)

**Step 1: Build the fat JAR**

Run: `./gradlew fatJar`
Expected: BUILD SUCCESSFUL, JAR created in build/libs/

**Step 2: Test headless mode**

Create a simple test script and request file, then run:
```bash
java -jar build/libs/turbo-intruder.jar resources/examples/basic.py resources/examples/request.txt https://example.com:443 test
```

Expected: Attack runs, results printed to console

**Step 3: Test in Burp Suite**

1. Load the extension in Burp Suite
2. Send a request to Turbo Intruder
3. Run a simple attack
4. Verify results appear in the table

**Step 4: Final commit**

```bash
git add -A
git commit -m "feat: complete UI-core decoupling for MCP readiness"
```

---

### Task 8: Clean Up ConsolePrinter (Optional)

**Files:**
- Modify: `src/RequestTable.kt:37-51`

**Decision point:** ConsolePrinter is now unused. Options:
1. Delete it (simpler codebase)
2. Keep it (backward compatibility if anyone imports it)

If deleting, remove lines 37-51 from RequestTable.kt.

**Step 1: Delete ConsolePrinter class**

Remove:
```kotlin
class ConsolePrinter() : OutputHandler {
    private val requestID = AtomicInteger(0)

    init {
        Utils.out("ID | Word | Status | Wordcount | Length | Time")
    }

    override fun add(req: Request) {
        Utils.out(String.format("%s | %s | %s | %s | %s | %s", requestID.incrementAndGet(), req.words.joinToString(separator="/"), req.code, req.wordcount, req.length, req.time))
    }

    override fun getAllRquests(): List<Request> {
        return listOf()
    }
}
```

**Step 2: Verify it compiles**

Run: `./gradlew compileKotlin`
Expected: BUILD SUCCESSFUL

**Step 3: Commit**

```bash
git add src/RequestTable.kt
git commit -m "chore: remove unused ConsolePrinter class"
```

---

## Summary

| Task | Description | Files |
|------|-------------|-------|
| 1 | Create ResultStore class | src/ResultStore.kt (new) |
| 2 | Update RequestTable constructor | src/RequestTable.kt |
| 3 | Add polling mechanism | src/RequestTable.kt |
| 4 | Wire up TurboIntruderFrame | src/fast-http.kt |
| 5 | Update headless main() | src/fast-http.kt |
| 6 | Update evalJython signature | src/fast-http.kt |
| 7 | Build and test | - |
| 8 | Clean up ConsolePrinter (optional) | src/RequestTable.kt |

Total: ~8 tasks, each 5-10 minutes
