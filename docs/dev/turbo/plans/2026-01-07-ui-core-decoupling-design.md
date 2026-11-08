# UI-Core Decoupling Design

Decouple attack/result management from the Swing UI to enable future MCP integration.

## Problem

`RequestTable` currently mixes two responsibilities:
1. **Data storage** - tracking all requests, answering `getAllRquests()`
2. **UI rendering** - JPanel, JTable, message editors

This coupling prevents programmatic access to attack results without instantiating Swing components.

## Solution

Extract data storage into a new `ResultStore` class. `RequestTable` becomes a pure UI that observes the store.

```
┌─────────────────┐     ┌──────────────┐     ┌─────────────────┐
│ RequestEngine   │────▶│ ResultStore  │◀────│ RequestTable    │
│                 │     │ (data only)  │     │ (UI only)       │
└─────────────────┘     └──────────────┘     └─────────────────┘
                              │
                              ▼
                        ┌──────────────┐
                        │ MCP Handler  │
                        │ (future)     │
                        └──────────────┘
```

## Components

### ResultStore (new)

Pure data storage with query capabilities:

```kotlin
class ResultStore : OutputHandler {
    private val results = CopyOnWriteArrayList<Request>()

    override fun add(req: Request) { results.add(req) }
    override fun getAllRquests(): List<Request> = results.toList()

    fun getResults(
        sortBy: SortField = SortField.ID,
        descending: Boolean = true,
        limit: Int = 100,
        offset: Int = 0
    ): List<Request>

    fun count(): Int
    fun clear()
}

enum class SortField {
    ID,           // insertion order
    STATUS,       // HTTP status code
    LENGTH,       // response length
    TIME,         // response time
    WORDCOUNT,
    ANOMALY_RANK
}
```

### RequestTable (modified)

Becomes pure UI - no longer implements `OutputHandler`:

```kotlin
class RequestTable(
    val store: ResultStore,  // injected, replaces internal storage
    val service: IHttpService,
    val handler: AttackHandler
) : JPanel() {
    private var lastKnownSize = 0

    init {
        // Poll store for updates at 100ms intervals
        Timer(100) {
            val currentSize = store.count()
            if (currentSize > lastKnownSize) {
                model.fireTableRowsInserted(lastKnownSize, currentSize - 1)
                lastKnownSize = currentSize
            }
        }.start()
    }
}
```

### AttackHandler (unchanged)

Already clean - no UI dependencies. Provides:
- `isRunning()`, `hasFinished()` - state queries
- `statusString()` - progress info
- `abort()` - cancel attack

### evalJython() (minor change)

Change parameter type from `OutputHandler` to `ResultStore`:

```kotlin
fun evalJython(
    code: String,
    baseRequest: String,
    rawRequest: ByteArray,
    endpoint: String,
    host: String,
    baseInput: String,
    store: ResultStore,  // was: outputHandler: OutputHandler
    handler: AttackHandler,
    reqs: MutableList<HttpRequestResponse>?
)
```

## Data Flow

### UI Mode

```kotlin
val store = ResultStore()
val handler = AttackHandler()
val requestTable = RequestTable(store, service, handler)

thread {
    evalJython(code, baseRequest, rawRequest, endpoint, host, input, store, handler, reqs)
}
```

### Headless Mode

```kotlin
val store = ResultStore()
val handler = AttackHandler()
evalJython(code, baseRequest, rawRequest, endpoint, host, input, store, handler, null)

// Results available via store.getResults(...)
```

### Future MCP Mode

```kotlin
val store = ResultStore()
val handler = AttackHandler()

thread {
    evalJython(script, request, rawRequest, endpoint, host, input, store, handler, null)
}

// MCP can:
// - Poll: handler.statusString(), handler.hasFinished()
// - Cancel: handler.abort()
// - Query: store.getResults(sortBy = ANOMALY_RANK, limit = 100)
```

## Migration

1. Create `ResultStore` class implementing `OutputHandler`
2. Add `getResults()`, `count()`, `clear()` methods with sorting/pagination
3. Modify `RequestTable` to accept `ResultStore` in constructor
4. Remove data storage from `RequestTable`, poll `ResultStore` instead
5. Update `TurboIntruderFrame` to create `ResultStore` and pass to both
6. Update `evalJython()` signature
7. Decide: keep `ConsolePrinter` for CLI backward compat, or migrate to `ResultStore`

## Backward Compatibility

- Python scripts using `table.add(req)` continue to work (ResultStore implements OutputHandler)
- `outputHandler` and `table` variables in Python context point to same ResultStore
- Existing attack scripts require no changes
