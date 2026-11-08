# VThreadHttpLib + VThreadRequestEngine

## Overview

Two layers:

1. **VThreadHttpLib** — The primary deliverable. A standalone HTTP/1 library using Java 25 virtual threads. Blocking socket IO, raw request bytes in, parsed responses out. Designed for high-concurrency use cases (50K+ simultaneous connections) requiring raw socket control, crafted/malformed requests, and precise timing. This is the foundation for all future HTTP/1 work in Turbo Intruder.

2. **VThreadRequestEngine** — A thin `RequestEngine` subclass that uses VThreadHttpLib as its transport. Exists to plug VThreadHttpLib into Turbo Intruder's existing ecosystem (RunHandler, MCP, UI) and provide a migration path off `ThreadedRequestEngine`. Supports multi-host runs via the existing `endpointOverride` parameter on queued requests.

## Key Decisions

1. **Concurrency model:** Java 25 virtual threads. Blocking IO throughout — no NIO, no coroutines.
2. **Fork strategy:** VThreadHttpLib gets its own copy of the HTTP/1 socket and parsing code, forked from `ThreadedRequestEngine`. No shared layer. Free to diverge. `ThreadedRequestEngine` stays frozen, eventually deprecated, probably never removed.
3. **Transport only (library layer):** The library sends raw bytes and returns parsed responses. Request construction is the caller's responsibility.
4. **Java API:** Public API uses standard Java types. No Kotlin-specific types (no `suspend`, `Flow`, inline classes).
5. **Direct to targets:** Connections go direct to hosts, not through Burp's HTTP stack.
6. **TLS first-class:** Virtually all targets will be HTTPS. TLS certificate verification is disabled — the library accepts all certificates (security tooling connects to arbitrary hosts). TLS handshake performance is a primary concern.
7. **Timeouts:** `socket.soTimeout` for per-request timeouts. Per-host wall-clock deadline by tracking elapsed time and shrinking remaining socket timeouts before each phase.

## Architecture

```
┌──────────────────────────────────────────────────┐
│             VThreadRequestEngine                  │
│             (extends RequestEngine)               │
│                                                   │
│  queue() → virtual thread per request             │
│  endpointOverride → route to different hosts      │
│  Integrates with RunHandler, MCP, UI              │
│                                                   │
│  ┌──────────────────────────────────────────┐    │
│  │           VThreadHttpLib                  │    │
│  │                                           │    │
│  │  connect(host, port) → Connection         │    │
│  │  Connection.send(bytes) → Response        │    │
│  │                                           │    │
│  │  Virtual threads + blocking sockets       │    │
│  │  Own HTTP/1 parser (forked)               │    │
│  │  TLS with cert verification disabled      │    │
│  └──────────────────────────────────────────┘    │
└──────────────────────────────────────────────────┘
```

VThreadRequestEngine processes queued requests using virtual threads. Each request blocks its virtual thread during DNS, TCP connect, TLS handshake, send, and response parsing. The JVM's virtual thread scheduler multiplexes onto a small number of carrier threads (default: core count).

Connection reuse is disabled by default (one connection per request), but must be supported for single-target and repeated-host scenarios via keep-alive, as with `ThreadedRequestEngine`.

### Multi-Host via endpointOverride

The existing `queue()` API already supports `endpoint` parameter (stored as `Request.endpointOverride` as a full URL string). `BurpRequestEngine` routes these through Burp's HTTP stack. `VThreadRequestEngine` parses the URL to extract host/port/scheme, then passes pre-parsed values to VThreadHttpLib — the library layer never sees URL strings. This enables mass multi-host runs (50K+ hosts) without Burp routing overhead.

## Bottlenecks at 50K Scale

### 1. DNS Resolution

**Problem:** Java's `InetAddress.getByName()` is blocking and hits the system resolver. 50K virtual threads resolving simultaneously will overwhelm the OS resolver (typically limited to 3 nameservers, each with 5s timeout).

**Mitigation:** Batch DNS pre-resolution with bounded parallelism before launching connections. Alternatively, use an async DNS library (dnsjava, Netty DNS) that talks directly to nameservers over UDP, bypassing the system resolver.

### 2. TLS Handshake Thundering Herd

**Problem:** 50K simultaneous TLS handshakes are CPU-intensive (ECDHE key exchange) and each requires 1-2 network round-trips. Carrier threads will be saturated doing crypto.

**Mitigation:** The virtual thread scheduler's carrier pool (core count) naturally throttles CPU-bound work. This may be sufficient — crypto runs on carrier threads, limiting true parallelism. If handshake latency queuing is excessive, stagger connection establishment.

### 3. File Descriptor Limits

**Problem:** Default `ulimit -n` is 1024-4096. Need 50K+ fds.

**Mitigation:** Document as prerequisite. Detect at startup, fail fast with clear error message.

### 4. Ephemeral Port Exhaustion

**Problem:** Default range is ~28K ports. 50K outbound connections from one IP may not fit.

**Mitigation:** Connections to different remote IPs reuse the same ephemeral port (5-tuple is unique), so this may not bite unless many hosts share an IP (CDNs). Needs empirical verification. Widen port range via `sysctl` if needed.

### 5. Memory — Response Bodies

**Problem:** 50K concurrent responses at ~10KB average = ~500MB. Outlier responses (10MB+) cause GC pressure.

**Mitigation:** Cap response body reads at a configurable limit (e.g. 256KB default). Stream-discard beyond the cap.

### 6. Memory — TLS Session State

**Problem:** Each `SSLSocket` holds ~20-50KB of session state. At 50K: ~1-2.5GB.

**Mitigation:** Budget for it. Disable TLS session caching since each host is typically visited once.

### 7. GC Pressure

**Problem:** High allocation rate from 50K response objects, socket buffers, byte arrays.

**Mitigation:** Use ZGC. Buffer pooling for socket reads. Minimise intermediate String/byte[] copies in the HTTP parser.

### 8. Connection Timeouts and Slow Hosts

**Problem:** Some of 50K hosts will be unreachable, slow, or hang. Virtual threads sit blocked, consuming memory.

**Mitigation:** Aggressive `socket.soTimeout` (e.g. 10s). Connect timeout via `socket.connect(addr, timeout)`. Per-host wall-clock deadline by tracking elapsed time and shrinking remaining socket timeouts before each phase.

## VThreadRequestEngine Constructor

Exact 1:1 copy of `ThreadedRequestEngine`'s constructor signature for drop-in replacement:

```kotlin
class VThreadRequestEngine(
    url: String,
    val threads: Int,
    maxQueueSize: Int,
    val readFreq: Int,
    val requestsPerConnection: Int,
    override val maxRetriesPerRequest: Int,
    override var idleTimeout: Long = 0,
    override val callback: (Request, Boolean) -> Boolean,
    var timeout: Int,
    override var readCallback: ((String) -> Boolean)?,
    val readSize: Int,
    val resumeSSL: Boolean,
    var explodeOnEarlyRead: Boolean = false
): RequestEngine()
```

`threads` controls max concurrent virtual threads (and therefore max concurrent connections), preserving the same throttling semantics as `ThreadedRequestEngine`'s OS thread pool.

## Relationship to Existing Code

- **RequestEngine base class:** `VThreadRequestEngine` extends it. Gets RunHandler/RunManager/MCP/UI integration for free.
- **ThreadedRequestEngine:** Stays frozen. Not modified. Eventually deprecated. `VThreadRequestEngine` is the replacement path.
- **BurpRequestEngine:** Unrelated. Routes through Burp's HTTP stack. Already supports `endpointOverride` via Burp's Montoya API.
- **HTTP2RequestEngine:** Unrelated. Different protocol.

## Out of Scope

- HTTP/2 support
- Proxy/Burp routing
- Request construction or templating
- Profiling harness (separate design)
