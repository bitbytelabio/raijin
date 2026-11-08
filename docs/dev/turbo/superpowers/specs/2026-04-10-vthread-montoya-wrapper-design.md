# VThreadHttp: Montoya-Compatible Wrapper for VThreadHttpLib

## Overview

A thin wrapper that gives VThreadHttpLib a Montoya-compatible API. Accepts `HttpRequest`, returns `HttpRequestResponse` with real timing data. Enables existing Burp extensions that call `montoyaApi.http().sendRequest()` to swap to VThreadHttpLib with a one-line change per call site.

## Key Decisions

1. **Does not implement the `Http` interface.** `Http` includes unrelated methods (`registerHttpHandler`, etc.). VThreadHttp has matching `sendRequest`/`sendRequests` signatures only. Migration is `montoyaApi.http().sendRequest(req)` → `vthreadHttp.sendRequest(req)`.
2. **Implements `HttpRequestResponse` directly.** `VThreadRequestResponse` is constructed from raw parts (not wrapping a Burp-created object). Follows the `MontoyaRequestResponse` pattern from albinowaxUtils but with real TTFB/TTLB from VThreadHttpLib's phase timing.
3. **Implements `TimingData` directly.** `VThreadTimingData` provides separate TTFB and TTLB values. Essential for organizer integration.
4. **Montoya dependency is isolated.** VThreadHttpLib itself has no Montoya dependency. The wrapper is the only code that touches Montoya types.

## Architecture

```
┌─────────────────────────────┐  ┌─────────────────────────────┐
│         VThreadHttp         │  │    VThreadRequestEngine      │
│   (Montoya-compatible       │  │    (extends RequestEngine)   │
│    wrapper for extensions)  │  │                              │
│                             │  │  Integrates with             │
│  sendRequest(HttpRequest)   │  │  RunHandler, MCP, UI         │
│    → HttpRequestResponse    │  │                              │
└──────────────┬──────────────┘  └──────────────┬──────────────┘
               │                                │
               └───────────────┬────────────────┘
                               │
               ┌───────────────▼───────────────┐
               │        VThreadHttpLib          │
               │                                │
               │  connect(host, port)           │
               │    → Connection                │
               │  Connection.send(bytes)        │
               │    → Response                  │
               │                                │
               │  Raw bytes in, raw bytes out   │
               │  No Montoya dependency         │
               └────────────────────────────────┘
```

Three layers, each with a single responsibility:
- **VThreadHttpLib:** Raw transport. No Montoya dependency. Java standard types only.
- **VThreadHttp:** Montoya adapter. Converts types, manages connection IDs, builds `VThreadRequestResponse`.
- **VThreadRequestEngine:** Turbo Intruder integration. Uses VThreadHttpLib directly (not the Montoya wrapper), plugs into RunHandler/MCP/UI.

## VThreadHttp API

```java
class VThreadHttp {
    HttpRequestResponse sendRequest(HttpRequest request)
    HttpRequestResponse sendRequest(HttpRequest request, HttpMode httpMode)
    HttpRequestResponse sendRequest(HttpRequest request, HttpMode httpMode, String connectionId)
    HttpRequestResponse sendRequest(HttpRequest request, RequestOptions requestOptions)

    List<HttpRequestResponse> sendRequests(List<HttpRequest> requests)
    List<HttpRequestResponse> sendRequests(List<HttpRequest> requests, HttpMode httpMode)
}
```

**HttpMode handling:**
- `HTTP_1` and `AUTO`: work normally.
- `HTTP_2` and `HTTP_2_IGNORE_ALPN`: throw `UnsupportedOperationException`.

**RequestOptions handling:**
- `httpMode`: honoured (same rules as above).
- `connectionId`: honoured (pins to a named connection for keep-alive reuse).
- `responseTimeout`: honoured (overrides default socket timeout).
- `serverNameIndicator`: honoured (sets TLS SNI).
- `redirectionMode`: ignored (VThreadHttpLib does not follow redirects).
- `upstreamTLSVerification`: ignored (all certs accepted).

**Connection lifecycle:**
- With `connectionId`: pinned to a specific connection, reused across calls with the same ID (keep-alive).
- Without `connectionId`: fresh connection every time, no pooling.

**Batch sending:** `sendRequests()` launches each request on its own virtual thread, all concurrently. Results returned in the same order as the input list.

**Error handling:** Connection failures / timeouts return an `HttpRequestResponse` with `response() == null` and `hasResponse() == false`, matching Burp's behaviour.

## VThreadRequestResponse

```java
class VThreadRequestResponse implements HttpRequestResponse {
    private final HttpRequest request;
    private final HttpResponse response;
    private final VThreadTimingData timingData;
    private Annotations annotations;
    private List<Marker> requestMarkers;
    private List<Marker> responseMarkers;
}
```

Constructed from raw parts:
- `HttpRequest`: the original input, preserved as-is.
- `HttpResponse`: built via `HttpResponse.httpResponse(ByteArray.byteArray(rawBytes))`. Raw bytes preserved exactly, consistent with `ThreadedRequestEngine`'s `ISO_8859_1` convention.
- `VThreadTimingData`: built from VThreadHttpLib's phase timing.

**Method implementations:**
- `request()`, `response()`, `httpService()`, `hasResponse()`: direct field access.
- `timingData()`: returns `Optional.of(timingData)`.
- `annotations()`: returns stored annotations (empty by default).
- `contains(String, boolean)` / `contains(Pattern)`: searches across request + response strings.
- `copyToTempFile()`: returns `this` (no Burp temp file system).
- `withAnnotations()` / `withRequestMarkers()` / `withResponseMarkers()`: return new copies with updated fields.

## VThreadTimingData

```java
class VThreadTimingData implements TimingData {
    private final Duration ttfb;
    private final Duration ttlb;
    private final ZonedDateTime sendTime;

    Duration timeBetweenRequestSentAndStartOfResponse()  // ttfb
    Duration timeBetweenRequestSentAndEndOfResponse()     // ttlb
    ZonedDateTime timeRequestSent()                       // sendTime
}
```

Values come from VThreadHttpLib's phase timing instrumentation. Unlike the albinowaxUtils `TimeLog` which uses the same duration for both TTFB and TTLB, this provides real separate values.

## Internal Flow

```
sendRequest(HttpRequest montoyaReq)
  │
  ├─ Extract: host, port, tls from montoyaReq.httpService()
  ├─ Extract: raw request bytes from montoyaReq.toByteArray()
  │
  ├─ VThreadHttpLib.connect(host, port, tls, options)
  │   └─ Returns: Connection (reused if connectionId matches)
  │
  ├─ connection.send(rawBytes)
  │   └─ Returns: raw response bytes + phase timings
  │
  ├─ Build HttpResponse.httpResponse(ByteArray.byteArray(rawBytes))
  ├─ Build VThreadTimingData(ttfb, ttlb, sendTime)
  ├─ Build VThreadRequestResponse(montoyaReq, httpResponse, timingData)
  │
  └─ Return HttpRequestResponse
```

## Out of Scope

- **HTTP/2 support.** `HttpMode.HTTP_2` throws. Extensions needing HTTP/2 stay on `montoyaApi.http()`.
- **Redirect following.** Callers handle redirects themselves.
- **TLS certificate verification.** All certs accepted (security tooling).
- **Proxy/Burp routing.** Direct to targets only.
- **Request construction.** VThreadHttp sends what it's given. No URL rewriting, no Content-Length fixing.
