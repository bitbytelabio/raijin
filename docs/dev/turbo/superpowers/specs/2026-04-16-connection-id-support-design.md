# Connection ID Support for BurpRequestEngine

## Overview

Add a `connectionId` parameter to `queue()` allowing users to pin requests to named connections. Requests with the same `connectionId` reuse the same underlying connection; different IDs use different connections.

**Primary use case:** Testing whether requests sent on one connection affect a different connection.

## Key Decisions

1. **Simple parameter addition** over RequestOptions passthrough or Connection objects. Matches existing Turbo Intruder patterns.
2. **Mutually exclusive with gates.** Gates batch requests onto a single connection for race conditions; connectionId pins requests to named connections. Combining them is confusing and unsupported.
3. **String type for connectionId.** Matches Montoya API. The existing `connectionID: Int` field remains as an output-only sequence counter for display.
4. **BurpRequestEngine only (initially).** API supports future ThreadedRequestEngine implementation via socket pooling.

## API

### Python (ScriptEnvironment.py)

```python
def queue(self, template, payloads=None, learn=0, callback=None, gate=None, 
          label="", pauseBefore=0, pauseTime=1000, pauseMarker=[], delay=0, 
          endpoint=None, fixContentLength=True, connectionId=None):
```

### Usage

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=5)
    
    # Requests pinned to conn-1
    engine.queue(req, "payload-a", connectionId="conn-1")
    engine.queue(req, "payload-b", connectionId="conn-1")
    
    # Requests pinned to conn-2
    engine.queue(req, "payload-c", connectionId="conn-2")
    
    # No connectionId = fresh connection each time (existing behavior)
    engine.queue(req, "payload-d")
```

## Implementation

### Request.kt

Add input field:

```kotlin
var connectionId: String? = null   // user-specified connection name (input)
var connectionID: Int = -1         // existing: sequence counter (output)
```

### RequestEngine.kt

Add parameter to `queue()` with validation:

```kotlin
fun queue(template: String, payloads: List<Any?> = emptyList(), 
          learnBoring: Int = 0, callback: ((Request, Boolean) -> Boolean)? = null, 
          gateName: String? = null, label: String = "", pauseBefore: Int = 0, 
          pauseTime: Int = 1000, pauseMarkers: List<String> = emptyList(), 
          delay: Long = 0, endpoint: String? = null, pythonEngine: Any? = null, 
          fixContentLength: Boolean = true, connectionId: String? = null) {
    
    if (gateName != null && connectionId != null) {
        throw Exception("Cannot specify both gate and connectionId - they are mutually exclusive")
    }
    
    // ... existing code ...
    
    request.connectionId = connectionId
}
```

### ScriptEnvironment.py

Add parameter and pass through:

```python
def queue(self, template, payloads=None, learn=0, callback=None, gate=None, 
          label="", pauseBefore=0, pauseTime=1000, pauseMarker=[], delay=0, 
          endpoint=None, fixContentLength=True, connectionId=None):
    if payloads == None:
        payloads = []
    elif not isinstance(payloads, list):
        payloads = [str(payloads)]
    self.engine.queue(template, payloads, learn, callback, gate, label, 
                      pauseBefore, pauseTime, pauseMarker, delay, endpoint, 
                      self, fixContentLength, connectionId)
```

### BurpRequestEngine.kt

Use connectionId when calling Montoya in the single-request path:

```kotlin
private fun request(service: IHttpService, req: Request) {
    val montoyaService = HttpService.httpService(service.host, service.port, "https".equals(service.protocol))
    val protocolVersion = if (useHTTP1) HttpMode.HTTP_1 else HttpMode.HTTP_2
    
    val montoyaResp = if (req.connectionId != null) {
        Utils.montoyaApi.http().sendRequest(
            HttpRequest.httpRequest(montoyaService, req.getRequest()), 
            protocolVersion, 
            req.connectionId
        )
    } else {
        Utils.montoyaApi.http().sendRequest(
            HttpRequest.httpRequest(montoyaService, req.getRequest()), 
            protocolVersion
        )
    }
    
    req.ttfb = montoyaResp.timingData().get().timeBetweenRequestSentAndStartOfResponse().toNanos() / 1000
    req.ttlb = montoyaResp.timingData().get().timeBetweenRequestSentAndEndOfResponse().toNanos() / 1000
    req.time = req.ttfb
    if (montoyaResp.response() != null) {
        req.response = montoyaResp.response().toString()
    }
}
```

## Files Changed

1. `resources/ScriptEnvironment.py` - add `connectionId` param, pass through
2. `src/RequestEngine.kt` - add param to `queue()`, validation, store on request
3. `src/Request.kt` - add `connectionId: String?` field
4. `src/BurpRequestEngine.kt` - use `connectionId` when calling Montoya

## Out of Scope

- **ThreadedRequestEngine support** - API ready, implementation deferred. Would require `Map<String, Socket>` pooling.
- **Returning connectionId in responses** - For reusing connection from prior response.
- **Connection lifecycle management** - Close, timeout, max requests per connection.
