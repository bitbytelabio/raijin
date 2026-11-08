# VRT (Variable Response Timing) - Socket-Level Analysis

## Response Queue Poisoning Recap

Front-end servers match responses to requests in order. When you smuggle a complete request:
1. Attacker sends: [Wrapper Request][Smuggled Request]
2. Front-end sees 1 request, back-end sees 2
3. Back-end sends 2 responses
4. Response 1 goes to attacker (for wrapper)
5. Response 2 (for smuggled) queues on connection
6. Victim sends their request
7. Victim gets Response 2 (smuggled response) - this is "response poisoning"
8. Victim's actual response queues for NEXT request
9. **Attacker's follow-up request receives victim's response - THIS IS VRT**

## Why VRT is Often Difficult

The core challenge is **connection pool arbitration**. After step 8, the victim's response is queued on one specific back-end connection out of potentially many in the front-end's pool. The attacker's follow-up request needs to be routed to *that exact connection*.

**Connection pool size is the dominant factor.** If the front-end maintains N connections to the back-end, a single follow-up request has roughly a 1/N chance of landing on the poisoned connection:

- **Small pools (N~1-5):** VRT is easy - tens of requests/sec is sufficient to reliably hit the right connection.
- **Large pools (N~50-200):** Requires thousands of requests/sec to get enough attempts, and it looks like a race condition because you're probabilistically competing for one connection out of many.
- **Dynamic/multiplexed pools:** If the front-end uses HTTP/2 to the back-end with stream multiplexing, responses are matched by stream ID, not queue order - VRT becomes impossible through this mechanism.

**Secondary factors that compound the difficulty:**

1. **Concurrent traffic** - Other users' requests also compete for the poisoned connection, and they might consume the queued response before the attacker does.
2. **Connection recycling** - Some front-ends close idle connections or rotate them on error/timeout, so the poisoned state may disappear before the attacker can exploit it.
3. **Desync detection** - Some front-ends notice unexpected data on a connection (e.g., response bytes arriving when no request is pending) and close it.
4. **Response read timing** - If the front-end eagerly reads from back-end sockets, the smuggled response may be consumed and discarded (or cause an error) before any victim request is routed there.

## What a Pentester Can Adjust

1. **Reduce effective pool size by saturating connections.** Send slow/long-running requests to occupy most connections in the pool, leaving only a few available. If you can force N_effective down to 2-3, your per-attempt probability jumps dramatically. Slow-read or slow-body techniques work here.

2. **Poison multiple connections simultaneously.** Instead of smuggling one request and trying to catch the response, smuggle across many connections in parallel. If you poison K connections out of N, follow-up probability becomes K/N.

3. **Use timing as a signal.** A follow-up request that lands on the poisoned connection will receive the victim's response, which likely has a different TTFB and content-length than expected. Use timing anomalies (TTFB deltas) to detect which of your follow-up requests hit a poisoned connection, even before reading the body. This lets you scale up attempts without manually checking each response.

4. **Precisely time the follow-up.** The window between "victim's response is queued" and "connection is recycled or another request consumes it" can be narrow. Techniques like the single-packet attack can synchronize the attacker's follow-up request to arrive in a tight timing window.

5. **Target low-traffic periods.** Less concurrent traffic means fewer connections in active use (some front-ends scale pool size with demand), and less competition for the poisoned connection.

6. **Choose smuggled requests with predictable, fast responses.** If the smuggled request targets a fast endpoint (like a static 404 or redirect), the poison completes quickly and predictably, giving you a tighter timing model for the follow-up. Slow back-end responses widen the uncertainty window.

7. **Understand the specific front-end technology.** Connection pool behavior varies enormously - Apache mod_proxy, HAProxy, Nginx, cloud load balancers all behave differently. Knowing the pool size, selection algorithm (round-robin vs least-connections vs random), and recycling policy lets you optimize your approach.

## VRT is Impossible When

- The front-end uses HTTP/2 with stream multiplexing to the back-end (responses keyed by stream ID, not order)
- The front-end validates response pairing (e.g., checks Content-Length matches before forwarding)
- The front-end detects and drops connections with unexpected queued data
- Connection-per-request architecture (no pooling at all)

**Takeaway:** VRT success is primarily a function of `(poisoned_connections / total_pool_connections) * request_rate * timing_precision`, and the pentester's main levers are increasing the numerator (poison more) and decreasing the denominator (saturate the pool).

---

## Deep Dive: Front-End Detection of Orphaned Response Data

### There Is No "Response Queue"

The phrase "response queue poisoning" implies some kind of queue data structure. There isn't one. The "queue" is just the **kernel's TCP receive buffer** - a flat byte array that the front-end's socket accumulates data into. The front-end reads from it sequentially, and the HTTP parser imposes structure on the raw byte stream. That's it.

So "poisoning the queue" really means: **leaving unexpected bytes in the kernel receive buffer (or the application's read buffer) on the front-end's connection to the back-end.**

### Where the Bytes Actually Live

When the back-end sends response 2, those bytes pass through:

```
Back-end app -> back-end kernel send buffer -> network -> front-end kernel recv buffer -> front-end app read buffer
```

The critical question for detection is: **where are response 2's bytes when the front-end finishes processing response 1?**

There are three possibilities:

**Case 1: Still in the kernel recv buffer (or not yet arrived)**

The front-end's `read()` for response 1 didn't consume response 2's bytes because they weren't there yet, or the front-end read exactly Content-Length bytes. The bytes sit in the kernel buffer. The front-end application has no idea they exist.

**Case 2: In the application's read buffer**

The front-end called `read(fd, buf, 16384)` and the kernel returned *both* responses' bytes in one call (because both were in the recv buffer). The HTTP parser consumed response 1's portion. Response 2's bytes are leftover in the application's userspace buffer.

**Case 3: Bytes were consumed and discarded**

Some implementations create a fresh buffered reader per response cycle. If the `read()` pulled in response 2's bytes but the buffered reader is discarded after response 1 is parsed, those bytes are gone - neither in kernel space nor application space. This actually *breaks* the poisoning entirely. But it also breaks HTTP pipelining on back-end connections, so most implementations preserve buffer state across the connection lifecycle.

### Three Detection Points (and Their Gaps)

**1. Post-response trailing data check**

After parsing a complete response (Content-Length bytes consumed, or final chunk read), the front-end checks whether additional bytes are available in its read buffer or on the socket. If yes, something is wrong - close the connection.

*Gap:* This only catches response 2 if it arrived before or during the read of response 1. If the back-end is slow processing the smuggled request, response 2 hasn't arrived yet, and the check passes cleanly.

**2. Read-on-return-to-pool check**

When a connection is returned to the idle pool, do a non-blocking `recv()` with `MSG_PEEK`. If there's data available on a supposedly idle connection, close it.

*Gap:* Same timing issue. If response 2 hasn't arrived by the time this check runs, the connection looks clean. There's a window between "check passes" and "connection is picked up for the next request" where response 2 can arrive undetected.

**3. Continuous event-loop monitoring of idle connections**

The connection stays registered in epoll/kqueue while idle. If the socket becomes readable, the event handler closes it rather than reading.

*Gap:* This is the strongest defense, but there's still a race. When the front-end decides to use this connection for a new request, it transitions from "idle-monitored" to "active-request-pending." If response 2 arrives during that transition, it might be interpreted as the response to the new legitimate request. The event-loop approach also has a more fundamental gap: if the new request is dispatched onto the connection *before* the event loop's next iteration processes the readable event, the poisoned data is consumed as a "response."

### The Edge-Triggered Blind Spot

High-performance front-ends (nginx, envoy) typically use **edge-triggered** epoll/kqueue for efficiency. Edge-triggered means: "notify me when the state *changes* from not-readable to readable."

Here's the sequence:

1. Front-end is reading response 1 from the back-end socket. The socket is readable; the edge already fired and was handled.
2. While the front-end is processing response 1, response 2's bytes arrive in the kernel recv buffer. But the socket was *already* readable - **no new edge fires**.
3. Front-end finishes response 1, returns the connection to the pool.
4. The event loop is watching this socket, but since no new edge occurred, `epoll_wait()` doesn't report it.
5. Response 2's bytes sit silently in the kernel buffer. The socket *is* readable, but nobody's asking.
6. Next request dispatched on this connection. Front-end calls `read()` expecting the new response. Gets response 2's bytes instead.

**Edge-triggered mode creates a natural blind spot for orphaned response data.** The data arrived during an already-active read cycle, so no new notification is generated.

With **level-triggered** mode (report readable *whenever* data is available), the idle connection would be reported as readable on every `epoll_wait()` cycle, giving the front-end a chance to notice and close it.

### The read() Size Matters

The front-end's `read()` buffer size affects which case you land in. If the front-end reads in small chunks (matching Content-Length precisely), response 2's bytes stay in the kernel buffer even if they've arrived. If it reads in large chunks (16KB at a time), it's more likely to pull in response 2's bytes along with response 1's, putting them in application space where they're more visible to the parser.

Ironically, **more efficient I/O (large reads) makes detection easier**, while **precise reads leave the poison hidden in kernel space**.

### Detection vs Smuggled Response Latency

| Detection mechanism | Fast smuggled response | Slow smuggled response |
|---|---|---|
| Post-read trailing byte check | Detectable (bytes in app buffer) | Invisible (bytes not yet arrived) |
| Return-to-pool `recv(MSG_PEEK)` | Likely detected | Likely missed |
| Edge-triggered event loop | Edge already fired, might miss | Edge already fired, definitely misses |
| Level-triggered event loop | Detected on next poll cycle | Detected, but with a window |

A slow smuggled response defeats every detection mechanism except continuous level-triggered monitoring - and even then, there's a race between the poll cycle detecting readability and the next request being dispatched on that connection.

---

## Key Insight: Send a Slow Smuggled Request

The whole analysis boils down to this: **if the smuggled response arrives while the connection is idle in the pool, detection is possible. If it arrives while the connection is actively serving another request, it's indistinguishable from a legitimate response.**

### The Ideal Sequence

1. Send wrapper + smuggled request. The smuggled request targets a **slow endpoint**.
2. Back-end responds to the wrapper immediately. Front-end forwards it, returns the connection to the pool.
3. All detection checks pass. Kernel buffer is empty. Socket reports not-readable. Connection looks clean.
4. Victim's request gets dispatched on this connection. Front-end sends it to the back-end.
5. The back-end now has two pending requests: the slow smuggled request (received first) and the victim's request. HTTP/1.1 requires responses in request order - the smuggled response **must** come first.
6. Smuggled request finishes. Front-end reads the response, believes it's the victim's. Poisoning succeeds.
7. Victim's actual response follows immediately. It's now the orphaned data in the buffer - but this time, the front-end is in an active read cycle, so no idle-connection detection applies.

The response 2 bytes **never sit unattended in a buffer**. They arrive while the front-end is actively waiting for data on that socket. There's nothing to detect.

### The TTFB Signal for VRT

This also hands you a detection mechanism for step 9. When you flood follow-up requests to catch the victim's response:

- Requests hitting **clean connections**: normal TTFB (network RTT + back-end processing)
- Request hitting the **poisoned connection**: the victim's response bytes are already in the kernel recv buffer. The front-end calls `read()` and gets data immediately. **TTFB drops to near-zero** - just the front-end's forwarding overhead, no back-end round-trip.

That TTFB anomaly is your signal. You don't need to inspect every response body - just look for the one that came back suspiciously fast.

### What "Slow" Means in Practice

You need the smuggled response to arrive *after* a new request is dispatched on the connection, but *before* the front-end times out waiting. That window is typically seconds to tens of seconds. You're looking for endpoints like:

- Anything with a controllable delay parameter
- Heavy database queries
- External API calls / webhooks
- Large file operations
- Redirects that chain through slow resolution

Even a few hundred milliseconds is probably enough - the connection returns to the pool and gets reused quickly under load. You just need to beat the pool's idle check cycle.

### The Remaining Hard Part

None of this solves the connection pool arbitration problem. Your follow-up still needs to land on the right connection out of N. But you've now eliminated the detection variable entirely - the poisoning reliably succeeds, every time, with no bytes left sitting in idle buffers. That lets you focus purely on the pool problem, which you attack through volume (poison many connections), saturation (reduce effective pool size), and TTFB-based hit detection.
