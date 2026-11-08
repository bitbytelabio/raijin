# Response Body Stripping for Completed Runs

## Problem

Completed runs retain full HTTP response bodies in memory indefinitely. With 100 retained runs and potentially millions of requests per run at ~7.5KB average response size, this consumes the entire heap.

## Design

### Three-tier retention

RunManager manages completed runs in three tiers based on age (sequence number):

1. **Full data** (newest 50 completed runs) — all fields intact including response bodies
2. **Metadata-only** (completed runs 51-100) — response bodies stripped, metadata preserved
3. **Evicted** (beyond 100) — fully removed from memory

### Changes by file

**RunManager.kt** — Add `maxFullResponseRuns: Int = 50` constructor parameter. In `evictCompletedRuns()`, after sorting completed runs by sequence number:
- Completed runs beyond the newest 100: evict (existing behavior)
- Completed runs ranked 51st-100th newest: call `store.stripResponseBodies()` and set `run.responsesStripped = true`, if not already stripped

**ResultStore.kt** — Add `stripResponseBodies()` method:
- Iterates all requests, calling `stripResponseBody()` on each

**Request.kt** — Add two methods:
- `materializeAttributes()` — forces eager computation of `code`, `length`, and `wordcount` into the `attributes` cache (these are currently lazy-computed from `response`)
- `stripResponseBody()` — calls `materializeAttributes()`, then sets `response = null`, `details = null`, `montoyaReq = null`, `engine = null`, `callback = null`, `gate = null`

**ActiveRun.kt** — Add `responsesStripped: Boolean = false` field. Set to `true` when RunManager strips the run. MCP tools can use this to return a clear message (e.g. "response bodies have been stripped from this run") instead of a confusing null.

### Stripping triggers

**On new run creation:** Stripping happens inside `evictCompletedRuns()`, called from `startRun()`. This applies the three-tier policy based on completed run count.

**On memory pressure:** A daemon thread in RunManager polls available memory every 5 seconds (`Runtime.maxMemory() - Runtime.totalMemory() + Runtime.freeMemory()`). When available memory drops below 1GB, it progressively reclaims memory:

1. First pass: strip response bodies from all completed runs (regardless of the 50-run threshold)
2. If still under 1GB after stripping: evict oldest completed runs one at a time until memory recovers or no completed runs remain
3. After each strip/evict action, call `System.gc()` and re-check

The thread is started lazily on first `startRun()` call and runs for the lifetime of the RunManager. It uses the same `evictCompletedRuns()` method but with an `emergency: Boolean` parameter that bypasses the `maxFullResponseRuns` threshold.

The 1GB threshold is a constant, not configurable.

### What is preserved after stripping

Per request: template, words, label, code, length, wordcount, time, ttfb, ttlb, sent, arrival, interesting, anomalyRank, id, targetUrl, order.

Per run: RunHandler state, ResultStore (with stripped requests), ActiveRun metadata.

### What is removed

Per request: response (full HTTP response string), details (IResponseVariations), montoyaReq (HttpRequestResponse), engine, callback, gate.

### MCP tool behavior on stripped runs

- `search_responses`: when searching response content in a stripped run, skip it and include a note in the result that some runs had responses stripped
- `get_response`: if the request's response is null and `run.responsesStripped` is true, return a message explaining the response body was stripped due to age, with the preserved metadata
- Resource handlers: same approach — surface the `responsesStripped` flag rather than returning empty/null silently

### Thread safety note

`stripResponseBody()` calls `materializeAttributes()` before nulling `response`. This ordering is sufficient: once `getAttribute` caches a value via `getOrPut`, subsequent calls return the cached value regardless of `response` state. No synchronization beyond per-request call ordering is needed.
