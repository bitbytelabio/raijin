# ScanProfiler: Performance Profiling Harness for VThreadRequestEngine

## Overview

An in-process profiling harness for VThreadRequestEngine that enables an AI agent to measure performance, identify bottlenecks, and validate optimisations. Runs as JUnit tests with an embedded mock server, producing structured JSON reports and JFR recordings.

## Key Decisions

1. **In-process:** Mock server, VThreadRequestEngine, and profiler all run in one JVM. Simplicity and fast iteration outweigh resource isolation concerns — the mock is lightweight (mostly idle threads accepting and writing bytes).
2. **Stateless reports:** Each run produces a self-contained JSON file. The agent loads and compares reports itself. No run history database.
3. **Phase-level + system-level + JFR:** Three layers of bottleneck attribution. Phase timing says *where*, system metrics say *why*, JFR says *which code path*.
4. **Tiered scale presets:** `SMALL` (1K hosts), `MEDIUM` (10K), `LARGE` (50K). Agent picks based on what it's investigating.
5. **Mock + real targets:** Mock for fast deterministic iteration; real-target runs for validation that improvements aren't artifacts of the mock.

## Mock Server

### MockTargetServer

An embedded TLS server simulating many hosts on localhost.

**Design:**
- Single `ServerSocket` listener on one port, bound to `127.0.0.1`
- All hosts connect to the same `127.0.0.1` address. Host identity is determined by the `Host` header in the request, not by distinct IPs.
- TLS via self-signed certificate

**Response profiles:**

| Profile | Behaviour | Default distribution |
|---------|-----------|---------------------|
| Normal | Immediate 200, configurable body size | 90% |
| Slow | Configurable delay before response | 5% |
| Hanging | Accepts connection, never responds | 3% |
| Large body | Response exceeding VThreadRequestEngine's body cap | 1% |
| Connection reset | Accepts then immediately closes | 1% |

**What it doesn't simulate:** DNS resolution (VThreadRequestEngine receives pre-resolved addresses), real TLS certificate chains (self-signed throughout). These are covered by real-target runs.

### Host/IP Generation

At startup, based on the tier, generate synthetic hostnames:
- `host-0000.mock`, `host-0001.mock`, ...up to tier limit
- All resolve to `127.0.0.1`

Each host is assigned a response profile based on the configured distribution. The mapping is deterministic (seeded) for reproducibility.

## Phase Timing Instrumentation

Baked into VThreadRequestEngine's `sendRequest()`, not added by the harness. Available for real-target runs too.

### Phases

| Phase | Start | End |
|-------|-------|-----|
| DNS resolve | Before `getByName()` | After |
| TCP connect | Before `socket.connect()` | After |
| TLS handshake | Before `startHandshake()` | After |
| Request send | Before `write()` | After `flush()` |
| TTFB wait | After flush | First response byte |
| Body read | First response byte | Body complete |

All times captured via `System.nanoTime()`. Stored in a `RequestTimings` object attached to each `Request`.

The existing `ttfb` and `ttlb` fields are derived from these phases, maintaining backward compatibility.

**Overhead:** Six `nanoTime()` calls per request (~20-30ns each). At 50K requests: ~1ms total. Negligible.

## System Metrics Sampling

A daemon thread samples system-level metrics every 500ms during a run.

### Metrics

| Metric | Source |
|--------|--------|
| Heap used / max | `MemoryMXBean` |
| GC count, cumulative pause time | `GarbageCollectorMXBean` |
| Live virtual thread count | Counter maintained by VThreadRequestEngine |
| Carrier thread pool utilisation | JFR `jdk.VirtualThreadPinned` / `jdk.ThreadPark` events (the carrier pool is `jdk.virtualThreadScheduler`, not `commonPool()`) |
| Open file descriptor count | `OperatingSystemMXBean.getOpenFileDescriptorCount()` |

Stored as a list of timestamped snapshots, written into the JSON report as a `systemMetrics` array.

## JFR Integration

### Approach

The harness starts a JFR recording programmatically (`jdk.jfr` API, built into Java 21) at the beginning of each run and stops it at the end.

### Events Captured

| Event | Purpose |
|-------|---------|
| `jdk.CPULoad` | Per-process CPU usage |
| `jdk.GCPhasePause` | Individual GC pauses with duration |
| `jdk.JavaMonitorEnter` | Lock contention (threshold: 1ms) |
| `jdk.ThreadPark` | Virtual thread parking / carrier handoff |
| `jdk.ObjectAllocationSample` | Allocation hotspots |
| `jdk.SocketRead`, `jdk.SocketWrite` | IO timing per socket |
| `jdk.TLSHandshake` | TLS negotiation detail |

### Configuration

Lightweight custom JFR config (not the default `profile` config). CPU sampling period: 20ms. Lock/IO event threshold: 1ms.

### Output

A `.jfr` file saved alongside the JSON report in `build/profiler-runs/`. The agent parses it via `jdk.jfr.consumer.RecordingFile` to extract specific events programmatically.

**Overhead:** JFR is designed for production use. Typical overhead: 1-2%.

## Report Format

```json
{
  "run": {
    "tier": "small",
    "hostCount": 1000,
    "startTime": "2026-04-10T14:30:00Z",
    "durationMs": 12340,
    "jfrFile": "runs/run-20260410-143000.jfr"
  },
  "phases": {
    "dnsResolve":   { "p50": 0, "p95": 0, "p99": 0, "mean": 0, "totalMs": 0, "pctOfTotal": 0.0 },
    "tcpConnect":   { "p50": 1.2, "p95": 3.4, "p99": 8.1, "mean": 1.8, "totalMs": 1800, "pctOfTotal": 12.3 },
    "tlsHandshake": { "p50": 5.1, "p95": 12.0, "p99": 25.0, "mean": 6.2, "totalMs": 6200, "pctOfTotal": 42.1 },
    "requestSend":  { "p50": 0.1, "p95": 0.3, "p99": 0.5, "mean": 0.2, "totalMs": 200, "pctOfTotal": 1.4 },
    "ttfbWait":     { "p50": 2.0, "p95": 5.0, "p99": 10.0, "mean": 2.5, "totalMs": 2500, "pctOfTotal": 17.0 },
    "bodyRead":     { "p50": 1.0, "p95": 3.0, "p99": 8.0, "mean": 1.5, "totalMs": 1500, "pctOfTotal": 10.2 }
  },
  "throughput": {
    "connectionsPerSec": 812,
    "requestsPerSec": 1540,
    "bytesPerSec": 15400000
  },
  "failures": {
    "total": 42,
    "byType": {
      "connectTimeout": 20,
      "readTimeout": 15,
      "connectionReset": 5,
      "tlsError": 2
    }
  },
  "systemMetrics": [
    {
      "timestampMs": 0,
      "heapUsedMb": 512,
      "heapMaxMb": 4096,
      "gcPauseMs": 0,
      "gcCount": 0,
      "virtualThreads": 1000,
      "carrierThreadsActive": 8,
      "openFds": 1024
    }
  ]
}
```

## Harness API

```kotlin
class ScanProfiler(
    val tier: Tier = Tier.SMALL,
    val hostProfiles: HostProfileConfig = HostProfileConfig.DEFAULT,
    val jfrEnabled: Boolean = true
) {
    fun run(scanCheck: (VThreadRequestEngine) -> Unit): ProfileReport
}

enum class Tier(val hostCount: Int) {
    SMALL(1000),
    MEDIUM(10000),
    LARGE(50000)
}

data class HostProfileConfig(
    val normalPct: Int = 90,
    val slowPct: Int = 5,
    val hangingPct: Int = 3,
    val largePct: Int = 1,
    val resetPct: Int = 1,
    val slowDelayMs: Long = 2000,
    val largeBodyBytes: Int = 10_000_000
)
```

### CLI Entry Point

```bash
java -jar build/libs/turbo-intruder.jar --profile [--tier small|medium|large] [--jfr]
```

Runs the profiler, writes JSON report and optional JFR file to `build/profiler-runs/`, prints the report path to stdout.

**Agent workflow:**
1. Run the CLI command with desired tier
2. Read the JSON report from the output path
3. Compare with previous reports by loading JSON

## Dependencies

- **VThreadRequestEngine must be built first.** The harness API takes a `(VThreadRequestEngine) -> Unit` lambda, so the engine is a compile-time dependency.

## Out of Scope

- Run history database or built-in comparison
- Two-process or external orchestrator mode
- Custom JFR event definitions
- DNS simulation (covered by real-target runs)
- MCP integration (may add later)
