# Plan: Expose TTFB and TTLB as separate timing columns

## Context

Currently, `Request.time` measures time-to-end-of-headers (effectively TTFB). TTLB is not tracked. The user wants both exposed as separate columns in the UI and MCP, with the old `time` field kept for script backward compatibility but hidden from UI/MCP.

## Design decisions

- **TTFB** = time from request send to end of response headers (current `time` semantics)
- **TTLB** = time from request send to response fully received
- `req.time` stays as TTFB for user script backward compat (not exposed in UI/MCP)
- New `req.ttfb` and `req.ttlb` fields added
- All values in microseconds (matching existing convention)

## Changes

### 1. `src/Request.kt` — Add fields (line 30)

Add after `time`:
```kotlin
var ttfb: Long = 0L
var ttlb: Long = 0L
```

### 2. `src/ThreadedRequestEngine.kt` — Capture TTLB

Currently `endTime` is set at `\r\n\r\n` detection (line ~314/327/341). Body is then read through 3 paths (Content-Length lines 386-406, chunked 408-431, fallback 433-464) all converging at line 466.

- Add `var bodyEndTime: Long = 0` alongside `endTime` (line 222)
- Insert `bodyEndTime = System.nanoTime()` just before line 466 (`if (shouldAbandonRun())`)
- Update line 485: set `ttfb = (endTime - startTime) / 1000`, `ttlb = (bodyEndTime - startTime) / 1000`, `time = ttfb`
- Update error path (line 525-527): set all three fields

### 3. `src/BurpRequestEngine.kt` — Use Montoya TimingData everywhere

**Non-gated HTTP/1 path** (lines 64-86, 224-236): Replace `Utils.callbacks.makeHttpRequest()` with Montoya's `Utils.montoyaApi.http().sendRequest()`. This gives us `TimingData` with separate TTFB/TTLB. Change `request()` to return the Montoya `HttpRequestResponse` directly instead of `Pair<IHttpRequestResponse?, Long>`, then extract timing at the call site (lines 224-236).

For the non-gated HTTP/2 branch (`Utils.h2request`), keep wall-clock timing as fallback (TTFB = TTLB) since this is the deprecated H2 path.

**Gated path** (lines 136-174): Already uses Montoya API. Add TTLB from `timeBetweenRequestSentAndEndOfResponse()` alongside existing TTFB from `timeBetweenRequestSentAndStartOfResponse()`. Update line 154-155. Sort at line 166: `it.time` → `it.ttfb`.

**endpointOverride path** (lines 200-221): Already uses Montoya `sendRequest()`. Add timing from `montoyaResp.timingData()`.

### 4. `src/H2Connection.kt` + `src/Stream.kt` — Skip (deprecated)

H2Connection engine is deprecated. Leave `req.time` working as-is. `ttfb`/`ttlb` will remain 0 for H2 requests — acceptable since this engine is not actively used.

### 5. `src/RequestTableModel.kt` — UI columns

- Replace `"Time"` with `"TTFB"`, add `"TTLB"` after it in columns list (line 93)
- Add column 7 (TTLB = Long) in `getColumnClass`, shift subsequent columns +1
- Update `getValueAt`: col 6 → `request.ttfb`, col 7 → `request.ttlb`, shift rest +1

### 6. `src/ResultStore.kt` — Sort fields

- Add `TTFB` and `TTLB` to `SortField` enum
- Update sorting: `TIME` sorts by `ttfb` (backward compat), add `TTFB` and `TTLB` cases

### 7. `src/mcp/McpResourceHandlers.kt` — MCP output

- `toSummaryMap()`: replace `"time" to time` with `"ttfb" to ttfb` and add `"ttlb" to ttlb`
- `getRequestDetail()`: same replacement in both export-file and inline paths

### 8. `src/mcp/resource/McpResourceDefinitions.kt` — sort_by

Update line 71 sort_by description: `"id|status|length|ttfb|ttlb|wordcount|anomaly_rank"`

### 9. `src/fast-http.kt` — Console output (lines 569-572)

Update header to `"TTFB | TTLB"`, print both `req.ttfb` and `req.ttlb`.

### 10. `src/RequestTable.kt` — HTML export (lines 234-246)

Replace `Time` with `TTFB` and `TTLB` in header and data rows.

### 11. Tests

- `test/kotlin/ResultStoreTest.kt`: Update time sort test to also set `ttfb`. Add `TTFB`/`TTLB` sort tests.
- `test/kotlin/mcp/McpResourceHandlersTest.kt`: Update any assertions checking for `"time"` key to check `"ttfb"`/`"ttlb"`.

## Verification

1. `./gradlew test` — all tests pass
2. `./gradlew jar` — builds successfully
3. Run MCP server, start a run, read `turbo://runs/{id}/summary` — verify `ttfb` and `ttlb` in output, no `time`
4. Sort by `ttfb` and `ttlb` via MCP summary resource
