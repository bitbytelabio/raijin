# Clear Run Status

## Problem

LLM agents polling `turbo://runs/{run_id}` can't easily determine when a run is done. The resource returns `"running"` and `"finished"` booleans that can contradict each other, and there's no clear single-field status. The `start_run` tool uses different status terminology (`"in_progress"`) from what would be natural for the resource.

## Design

### Single `status` field

Add `status(): String` to `RunHandler` returning one of four values:

- `"running"` - not finished
- `"completed"` - engine state 4, or script completed without engine, no error
- `"exited-early"` - engine state 3 (cancel called), no error
- `"failed"` - `hasError()` true (wins over all other states)

### Remove redundant fields

From `RunHandler`:
- Remove `isRunning()` public method (keep internal `running` field for `abort()`)
- Remove `hasFinished()` - callers use `status() != "running"` instead

From resource response (`getRunStatus`):
- Drop `"running"` and `"finished"` booleans
- Add `"status"` field from `handler.status()`
- Include `"summary"` when status is not `"running"`

From tool response (`startRun`):
- Replace `"in_progress"` with `"running"` in timeout case
- Use `handler.status()` for completion case (replaces hasError check)
- Drop `"running"` and `"finished"` booleans from timeout response

### Status priority

`failed` wins over all other states. If `hasError()` is true, status is `"failed"` regardless of engine state. This handles the case where a script sets an error via `overrideStatus()` and then cancels the engine.

## Files to change

1. `src/RunHandler.kt` - Add `status()`, remove `isRunning()` and `hasFinished()`
2. `src/mcp/McpResourceHandlers.kt` - Use `status()` in `getRunStatus()`
3. `src/mcp/McpToolHandlers.kt` - Use `status()` in `startRun()` timeout and completion paths
4. `test/kotlin/RunHandlerTest.kt` - Update tests for new `status()` method
5. `test/kotlin/mcp/McpResourceHandlersTest.kt` - Update for new response shape
6. `test/kotlin/mcp/McpToolHandlersTest.kt` - Update for new response shape
