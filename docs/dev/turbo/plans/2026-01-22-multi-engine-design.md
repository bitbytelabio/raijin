# Multi-Engine Support

Support multiple named request engines in a single script for connection isolation, protocol comparison, and multi-target scanning.

## Use Cases

- **Request smuggling verification** - Send smuggle payload on engine A, verify with victim request on fresh connection via engine B
- **Session/state pollution testing** - Test whether server-side state from one connection affects another
- **Connection coalescing attacks** - HTTP/2 connection reuse across different virtual hosts
- **Protocol comparison** - Compare HTTP/1.1 vs HTTP/2 behavior on same target
- **Multi-target scanning** - Coordinated attacks across multiple hosts

## Script Interface

```python
def queueRequests(target, wordlists):
    # Create engines with different configs
    smuggler = RequestEngine(endpoint=target, name="smuggler",
                             engine=Engine.THREADED, concurrentConnections=1)
    verifier = RequestEngine(endpoint=target, name="verifier",
                             engine=Engine.BURP)

    smuggler.queue(smugglePayload)
    smuggler.complete()  # wait for poison to land

    verifier.queue(victimRequest)
    verifier.complete()

def handleResponse(req, interesting):
    # req.engineName available for filtering (or req.engine.name via Python wrapper)
    if req.engineName == "verifier" and "smuggled" in req.response:
        table.add(req)
```

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Engine coordination | Independent (manual) | KISS - scripts manage timing via `complete()` |
| Result storage | Merged with engine tag | Simple, filter by `req.engineName` in callbacks |
| Status display | Aggregated totals | Clean UI: "Engines: 2 \| Reqs: 500 \| ..." |
| Engine column in table | Always shown | Needed to disambiguate Queue ID and Connection ID |
| Request IDs | Global `globalId` assigned by ResultStore | Avoid ID collisions, stable across sorts (see Issue #1) |
| Floodgates | Per-engine scope | Each engine has independent gates (documented limitation) |

## Issues Identified During Review

### Issue #1: Request ID Collision (Critical) - RESOLVED

Each engine has its own `lastRequestID` counter. With multiple engines, both could have requests with id=1, id=2, etc.

**Affected code:**
- `ResultStore.getRequest(id)` - returns first match, ambiguous
- MCP endpoints like `turbo://runs/current/results/5`
- Queue ID column in table

**Solution:** Assign global `globalId` atomically when results are added to ResultStore.

- `globalId` assigned via `AtomicInteger.getAndIncrement()` - thread-safe, unique across concurrent engines
- `globalId` is stable regardless of sort order (unlike list index)
- MCP client uses `globalId` for lookups - unified view, no engine reasoning needed
- Per-engine `request.id` unchanged - backwards compatible for scripts
- MCP responses include both: `{"globalId": 42, "id": 5, "engine": "smuggler", ...}`

### Issue #2: Engine Name Access (Fixed)

**Problem:** Design incorrectly used `request.engine` (Python wrapper) instead of `request._engine` (Kotlin engine).

**Fix:** Use `request._engine?.name ?: "default"` in RequestTableModel, or add `engineName: String` field to Request for cleaner access.

### Issue #3: Anomaly Ranking Race Condition (Fixed)

**Problem:** Each engine calls `calculateAnomalyRankings()` on completion, operating on the shared ResultStore. Multiple engines completing causes redundant work and potential UI races.

**Fix:** Move anomaly ranking to RunHandler. Calculate once when ALL engines have completed.

### Issue #4: Duration Tracking (Fixed)

**Problem:** Aggregated status needs total run duration, but each engine tracks its own `start` time.

**Fix:** RunHandler tracks `earliestStart` timestamp, updated when each engine is added. Duration = `now - earliestStart`.

### Issue #5: Floodgates Are Per-Engine (Documentation)

**Behavior:** Gate names are scoped to each engine. `engineA.openGate("sync")` won't affect `engineB`'s "sync" gate.

**Fix:** Document this limitation. Cross-engine synchronization requires Python-level coordination.

## Changes Required

### RunHandler.kt

Replace single engine with thread-safe list, centralize anomaly ranking:

```kotlin
private val engines = CopyOnWriteArrayList<RequestEngine>()
private var earliestStart: Long = Long.MAX_VALUE
private var outputHandler: OutputHandler? = null  // set during script init

fun setOutputHandler(handler: OutputHandler) {
    this.outputHandler = handler
}

fun addRequestEngine(engine: RequestEngine) {
    if (engine.start < earliestStart) {
        earliestStart = engine.start
    }
    engines.add(engine)  // CopyOnWriteArrayList is thread-safe
    running = true
}

fun hasFinished(): Boolean {
    if (engines.isEmpty()) return scriptCompleted
    return engines.all { it.runState.get() >= 3 }
}

fun abort() {
    running = false
    engines.forEach { it.cancel() }
}

fun setComplete() {
    engines.forEach { it.showStats(-1) }
    // Calculate anomaly rankings once, after all engines complete
    calculateAnomalyRankings()
}

fun statusString(): String {
    if (statusOverride != null) return statusOverride!!
    if (engines.isEmpty()) return "Engine warming up..."

    val totalReqs = engines.sumOf { it.successfulRequests.get() }
    val totalQueued = engines.sumOf { it.requestQueue.size }
    val totalConns = engines.sumOf { it.connections.get() }
    val totalRetries = engines.sumOf { it.retries.get() }
    val totalFails = engines.sumOf { it.permaFails.get() }
    val duration = ceil(((System.nanoTime().toFloat() - earliestStart) / 1000000000).toDouble()).toInt()

    return String.format(
        "Engines: %d | Reqs: %d | Queued: %d | Duration: %d | Connections: %d | Retries: %d | Fails: %d%s",
        engines.size, totalReqs, totalQueued, duration, totalConns, totalRetries, totalFails,
        if (msg.isNotEmpty()) " | $msg" else ""
    )
}

private fun calculateAnomalyRankings() {
    // Move logic from RequestEngine.calculateAnomalyRankings() here
    // Uses this.outputHandler to get all requests
    // Operates once after all engines complete
}
```

### RequestEngine.kt

Add name field, remove per-engine anomaly ranking from `showStats()`:

```kotlin
var name: String = "default"

// In showStats(), remove the calculateAnomalyRankings() call:
fun showStats(delay: Int) {
    if (delay == -1) {
        while (attackState.get() < 3) {
            showStats()
            Thread.sleep(500)
        }
        showStats()
        // REMOVED: calculateAnomalyRankings() - now handled by RunHandler.setComplete()
        return
    }
    // ... rest unchanged
}
```

### Request.kt

Add engineName and globalId fields (keep existing `id` unchanged):

```kotlin
var engineName: String = "default"
var globalId: Int = -1    // assigned by ResultStore, used for MCP lookups
// var id: Int = -1       // unchanged, per-engine queue position
```

Set engineName in RequestEngine.queue():
```kotlin
request.engineName = this.name
// request.id assignment unchanged
```

### ScriptEnvironment.py

Add name parameter and use addRequestEngine:

```python
class RequestEngine:
    def __init__(self, endpoint, name=None, callback=None, ...):
        self.name = name or "default"
        self.engine.name = self.name
        # ...
        handler.addRequestEngine(self.engine)  # was setRequestEngine
```

### fast-http.kt (script initialization)

Wire up outputHandler to RunHandler for anomaly ranking:

```kotlin
// In evalJython() or similar
handler.setOutputHandler(store)  // new line
pyInterp.set("outputHandler", store)  // existing
```

### RequestTableModel.kt

Add Engine column using the new engineName field:

```kotlin
companion object {
    internal val columns = listOf(
        "Row", "Payload", "Status", "Anomaly rank", "Words", "Length",
        "Time", "Arrival", "Label", "Queue ID", "Connection ID", "Engine"
    )
}

override fun getColumnClass(columnIndex: Int): Class<*> {
    return when (columnIndex) {
        // ... existing cases 0-10 ...
        11 -> String::class.java
        else -> throw RuntimeException("Invalid column requested")
    }
}

override fun getValueAt(rowIndex: Int, columnIndex: Int): Any {
    val request = requests[rowIndex]
    return when (columnIndex) {
        // ... existing cases 0-10 ...
        11 -> request.engineName
        else -> throw RuntimeException("Invalid column requested")
    }
}
```

### ResultStore.kt

Assign global ID atomically on result insertion:

```kotlin
class ResultStore : OutputHandler {
    private val results = CopyOnWriteArrayList<Request>()
    private val nextGlobalId = AtomicInteger(0)

    override fun add(req: Request) {
        req.globalId = nextGlobalId.getAndIncrement()  // Thread-safe, unique IDs
        results.add(req)
    }

    fun getRequestByGlobalId(globalId: Int): Request? {
        // Can't use index lookup since globalId may not match position if
        // concurrent adds complete out of order. Search instead:
        return results.find { it.globalId == globalId }
    }

    fun clear() {
        results.clear()
        nextGlobalId.set(0)  // Reset counter on clear
    }

    // getRequest(id) unchanged - still looks up by per-engine request.id
}
```

Note: `globalId` is assigned atomically but results may be added to the list out of order under high concurrency. This means `globalId` may not equal list index. The `getRequestByGlobalId()` method searches by field value rather than assuming index correspondence.

### MCP Resource/Tool Handlers

Update to use `globalId` for lookups and include engine info in responses:

```kotlin
// McpResourceHandlers.kt - result listings
"globalId" to req.globalId,
"id" to req.id,  // per-engine queue order, kept for backwards compat
"engine" to req.engineName,

// getRequest lookup uses globalId
val request = run.store.getRequestByGlobalId(globalId)
```

### Tests

Update RunHandlerTest.kt for multi-engine behavior.

## Files Changed

| File | Change | Effort |
|------|--------|--------|
| `RunHandler.kt` | Multi-engine list, aggregated stats, centralized anomaly ranking | Medium |
| `RequestEngine.kt` | Add `name` field, remove per-engine anomaly ranking | Small |
| `Request.kt` | Add `engineName`, `globalId` fields | Tiny |
| `ScriptEnvironment.py` | Add `name` param, `addRequestEngine()` | Small |
| `fast-http.kt` | Wire outputHandler to RunHandler | Tiny |
| `RequestTableModel.kt` | Add Engine column | Small |
| `ResultStore.kt` | Add globalId assignment, update getRequest lookup | Small |
| `McpResourceHandlers.kt` | Use globalId for lookups, include both IDs in responses | Small |
| `McpToolHandlers.kt` | Use globalId in result responses | Tiny |
| `RunHandlerTest.kt` | Update tests | Small |

## Not Changed

- **Core engine implementations** (ThreadedRequestEngine, BurpRequestEngine, HTTP2RequestEngine) - No changes needed

## Limitations

- **Floodgates are per-engine** - Gate names don't synchronize across engines. Use Python-level coordination for cross-engine synchronization.

## Estimated Effort

~150-180 lines of code changes. Small-medium scope.
