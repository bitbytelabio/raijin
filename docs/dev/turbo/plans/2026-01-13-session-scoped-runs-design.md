# Session-Scoped Run Management

## Problem

All MCP sessions share a single global `RunManager`. This causes:
- `start_run()` from one session clears another session's runs
- `delete_all_runs()` affects all sessions
- The `currentRun` pointer is global

## Solution

Add session awareness to `RunManager` while keeping runs globally accessible by ID.

### Scoping Rules

| Operation | Scope |
|-----------|-------|
| `turbo://runs` (list) | Session's runs only |
| `turbo://runs/{id}` (explicit ID) | Global - any run |
| `turbo://runs/current` | Session's current |
| `start_run()` | Clears session's runs only, then starts |
| `delete_all_runs()` | Deletes session's runs only |
| `delete_run(id)` | Global - can delete any run |

### Data Model

```kotlin
class RunManager {
    // Global: all runs, accessible by ID from any session
    private val runs = ConcurrentHashMap<String, ActiveRun>()

    // Per-session: current run pointer (run ID)
    private val currentRunBySession = ConcurrentHashMap<String, String>()
}

class ActiveRun(
    val id: String = UUID.randomUUID().toString().take(8),
    val ownerSessionId: String,  // NEW
    // ... rest unchanged
)
```

### API Changes

All handler methods receive `sessionId: String` as first parameter:

```kotlin
// McpToolHandlers
fun startRun(sessionId: String, script: String, ...)
fun deleteAllRuns(sessionId: String)

// McpResourceHandlers
fun listRuns(sessionId: String)
fun getRun(sessionId: String, runId: String?)
```

In `TurboMcpServer`, handlers use `exchange.sessionId()`:

```kotlin
.callHandler { exchange, request ->
    toolHandlers.startRun(
        sessionId = exchange.sessionId(),
        ...
    )
}
```

## Files to Modify

- `src/mcp/ActiveRun.kt` - Add `ownerSessionId` field
- `src/mcp/RunManager.kt` - Add session tracking, update methods
- `src/mcp/McpToolHandlers.kt` - Add `sessionId` param to all methods
- `src/mcp/McpResourceHandlers.kt` - Add `sessionId` param to all methods
- `src/mcp/TurboMcpServer.kt` - Use `exchange.sessionId()` in handlers

## Verification

1. Build: `./gradlew jar`
2. Tests: `./gradlew test`
3. Manual: Connect two clients, verify isolation
