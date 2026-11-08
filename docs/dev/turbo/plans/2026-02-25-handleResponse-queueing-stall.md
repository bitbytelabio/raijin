# handleResponse queueing causes engine stall

## Problem

Scripts that queue requests from `handleResponse` (rather than `queueRequests`) stall because the engine kills worker threads prematurely.

## Root Cause

When `queueRequests()` returns, `showStats()` sets `runState = 2` (fully queued). Worker threads in `BurpRequestEngine.sendRequests()` check:

```kotlin
val req = requestQueue.poll(100, TimeUnit.MILLISECONDS)
if (req == null) {
    if (runState.get() == 2) {
        return  // EXIT the thread
    }
}
```

With `concurrentConnections=50` and only 3 validation requests queued in `queueRequests()`:
1. 3 threads grab validation requests, 47 threads idle
2. `showStats()` sets `runState = 2`
3. The 47 idle threads see empty queue + state 2 and **exit**
4. Validation completes, last `handleResponse` calls `run_attack()` which queues 100+ items
5. But most/all worker threads have already exited
6. Queue items sit unprocessed, engine appears stalled

## Observed Behavior

From agent trace (run `6fdcc8cc`):
```
55s:  Reqs: 3 | Queued: 100 | Fails: 0 | Connections: 3
110s: Reqs: 3 | Queued: 100 | Fails: 0 | Connections: 3
```

Zero progress for 55+ seconds despite 100 queued items and identical request types that worked during validation.

## Affected Pattern

Any script that:
- Queues a small number of validation/probe requests in `queueRequests()`
- Conditionally queues attack requests from `handleResponse()` based on validation results

This includes the VRT template script used by the investigator agent.

## Potential Fixes

1. **Don't exit threads when queue is empty + state 2 if callbacks are still in flight** - track active callbacks and only exit when queue is empty AND no callbacks are executing
2. **Let scripts signal "more queuing expected"** - e.g. `engine.setStreamingMode()` that prevents the state 2 transition from killing threads
3. **Change the template** to queue all requests in `queueRequests()` and use a different mechanism to skip execution if validation fails (e.g. gate all attack requests behind validation)
