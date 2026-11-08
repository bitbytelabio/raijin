# Memory Leak Analysis — 2026-03-13

## Summary

Burp Suite running at 12GB/12GB heap, almost entirely consumed by Turbo Intruder response data retained in memory.

## Heap Evidence

From `jcmd GC.class_histogram`:

| Class | Instances | Bytes | Notes |
|-------|-----------|-------|-------|
| `byte[]` | 10,736,307 | **10.98 GB** | Raw response bodies |
| `String` | 10,653,243 | 255 MB | Wrappers around byte[] |
| `burp.Request` | 1,441,118 | 207 MB | Each holds a full response |
| `burp.BurpRequestEngine` | 131 | 16 KB | Engines not GC'd |
| `burp.ResultStore` | 126 | 2 KB | Stores not GC'd |
| `mcp.ActiveRun` | 103 | 4 KB | ~100 completed + running |
| `burp.RunHandler` | 127 | 5 KB | One per engine |

~1.4M Request objects × ~7.5 KB avg response = ~10.5 GB. This matches the byte[] total.

## Root Causes

### 1. Request._engine back-reference prevented GC (FIXED)

Every `Request` held a reference back to its `RequestEngine` via `_engine`. Since the engine also held an `outputHandler` pointing to the `ResultStore` (which held all Requests), this created a retention cycle that kept entire engines alive as long as any single Request was referenced.

**Fix:** Replaced `Request._engine: RequestEngine?` with `Request.targetUrl: URL?` (the only data actually needed). The engine's default callback is now copied onto each Request at queue time instead of being looked up via back-reference.

### 2. RunManager retains 100 completed runs with full response bodies

`RunManager(maxCompletedRuns = 100)` keeps up to 100 completed runs in its `ConcurrentHashMap`. Each run's `ResultStore` holds an `ArrayList<Request>`, and each `Request.response: String` contains the **entire HTTP response** (headers + body).

Retention chain (after fix):
```
RunManager.runs (ConcurrentHashMap)
  └─ ActiveRun
       ├─ ResultStore → ArrayList<Request>
       │    └─ Request.response: String → byte[] (full HTTP response)
       └─ RunHandler
```

Even a single run with 100K requests at 7.5KB avg = 750MB. With 100 retained runs, this easily fills any heap.

### 3. Eviction only triggers on new run creation

`evictCompletedRuns()` is only called from `startRun()`. If a user stops creating new runs, completed runs sit in memory indefinitely with no further eviction pressure.

### 4. GUI path retains engines independently

`TurboIntruderFrame` creates its own `ResultStore` and `RequestEngine` instances outside `RunManager`. These are only cleaned up on explicit "Configure" button click or window close. The heap shows 131 `BurpRequestEngine` vs 103 `ActiveRun`, so ~28 engines are retained by the GUI path.

### 5. Request.response stores full response as String

Every `Request` stores the complete HTTP response (headers + body) as a `String`. This is the fundamental amplifier — even with few runs, large responses consume enormous memory. There is no truncation, streaming, or disk-backed storage.

## Remaining Fixes Needed

### A. Lower maxCompletedRuns (quick fix)

Reduce from 100 to something like 5-10. Simple but doesn't address per-run memory when a single run has millions of requests.

### B. Strip response bodies from completed runs

When a run completes, discard `Request.response` (or truncate to headers-only), keeping only metadata (status, length, timing, wordcount). The MCP `search_responses` tool already filters by these fields — full body access could be limited to running/recent runs.

### C. Memory budget instead of count limit

Instead of capping completed run count, cap total retained response bytes. Evict oldest completed runs when budget exceeded. More adaptive to varying run sizes.

### D. Disk-backed ResultStore

Spill response bodies to disk after completion, load on demand. Most complex but allows retaining full data for analysis.

### E. GUI cleanup on run completion

The GUI path should clear old ResultStore contents when starting a new run, not just on "Configure" click.
