# Start Run Error Visibility Design

## Problem

The `start_run` MCP tool returns `"status": "completed"` even when the run fails with an error. The error message is only visible by reading the resource `turbo://runs/{run_id}` separately. This is misleading for MCP clients.

## Solution

Add explicit error tracking to the attack handler and surface errors in tool responses.

## Changes

### 1. AttackHandler

Add error flag and accessor:

```kotlin
private var hasError: Boolean = false

fun hasError(): Boolean = hasError

fun overrideStatus(status: String, isError: Boolean = true) {
    this.statusString = status
    this.hasError = isError
}
```

The `isError` parameter defaults to `true` for backward compatibility with existing callers.

### 2. McpToolHandlers.startRun()

Check error flag and return appropriate status:

```kotlin
val failed = run.handler.hasError()

val result = mutableMapOf<String, Any?>(
    "status" to if (failed) "failed" else "completed",
    "run_id" to run.id,
    "result_count" to run.store.count(),
    "results" to results.map { ... }
)

if (failed) {
    result["error_message"] = run.handler.statusString()
}
```

### 3. McpResourceHandlers

No changes. Resources continue to use `status_message` for full state inspection.

## Response Examples

Success:
```json
{"status": "completed", "run_id": "abc", "result_count": 3, "results": [...]}
```

Failure:
```json
{
  "status": "failed",
  "run_id": "abc",
  "result_count": 0,
  "results": [],
  "error_message": "User Python error: desync-agent-mode is enabled..."
}
```

## Files to Modify

1. `src/BurpExtender.kt` - AttackHandler class
2. `src/mcp/McpToolHandlers.kt` - startRun() method
