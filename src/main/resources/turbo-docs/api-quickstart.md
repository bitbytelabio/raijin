# Raijin Turbo API Quickstart

Quick reference for scripting. See linked docs for full details.

## Basic Script Structure

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           engine=Engine.THREADED)

    for word in open('/usr/share/dict/words'):
        engine.queue(target.req, word.rstrip())

def handleResponse(req, interesting):
    table.add(req)
```

## RequestEngine Constructor (Essential)

```python
engine = RequestEngine(
    endpoint=target.endpoint,     # Required: "protocol://host:port"
    concurrentConnections=5,      # Parallel connections
    requestsPerConnection=100,    # Requests per connection
    engine=Engine.THREADED        # Engine type (see engines.md)
)
```

See [settings.md](settings.md) for all parameters.

If you don't want to configure your own engine, just use:

```python
engine = RequestEngine(endpoint=target.endpoint)
```

Omitting `engine` selects `Engine.AUTO` in Burp Suite Professional and `Engine.THREADED`
otherwise. Desync-agent mode always selects `Engine.BURP`.

## engine.queue() (Essential)

```python
engine.queue(target.req, "payload")              # Single payload
engine.queue(target.req, ["p1", "p2"])           # Multiple payloads
engine.queue(target.req, payload, gate='race1')  # Gated request (see race-conditions.md)
engine.queue(target.req, payload, label='test')  # Labeled for analysis
engine.queue(target.req, kettled=True)           # Malformed fields; BURP2/HTTP3 or compatible AUTO
```

Use `%s` as injection point in request template. See [settings.md](settings.md) for all parameters.

A request written in a triple-quoted string has the script's own line endings: CRLF in the Turbo
dialog, which converts them, but LF when the script arrives over MCP and its lines all end in LF. When a
request you build yourself must carry CRLF (desync, exact Content-Length), write `\r\n` explicitly, as
the desync and 0.CL examples do. `target.req` uses CRLF (an LF-only `base_request` is converted).

## Request Object Properties

In `handleResponse(req, interesting)`:

| Property | Type | Description |
|----------|------|-------------|
| `req.response` | str | Full HTTP response |
| `req.request` | str | Full HTTP request (with payloads injected) |
| `req.status` | int | HTTP status code |
| `req.code` | int | HTTP status code (alias for `status`) |
| `req.length` | int | Response body length |
| `req.wordcount` | int | Word count in response |
| `req.time` | long | Response time in microseconds: to the first byte on THREADED, BURP and BURP2, to the last byte on HTTP2 and HTTP3 |
| `req.ttfb`, `req.ttlb` | long | Time to first / last byte (μs), where the engine measures them |
| `req.words` | list | Injected payloads |
| `req.label` | str | Custom label (writable) |
| `req.template` | str | Original request template |
| `req.engine` | obj | Engine instance (for recursive queueing) |
| `req.order` | int | Response order within a gate, ranked by arrival (0 = the request the server answered first). Set by `Engine.BURP`, `Engine.BURP2` and `Engine.HTTP3`. On BURP and BURP2 a gated request that got no response has `-1` and is called back after the ranked ones; HTTP3 ranks only answered requests |
| `req.id` | int | Unique request ID |
| `req.connectionId` | str | Connection identifier (user-specified or auto-assigned) |
| `req.gateMode` | str | For a gated `Engine.HTTP3` request, which gate released it: `'sda'` or `'qpack'`. None otherwise |

## Engine Types

| Engine | Protocol | Use Case |
|--------|----------|----------|
| `Engine.AUTO` | Highest available | Ease of use (Burp Suite Pro) |
| `Engine.THREADED` | HTTP/1.1 | Fast custom stack for tuned HTTP/1.1 use cases |
| `Engine.BURP` | HTTP/1.1 | Needs Burp's proxy/auth |
| `Engine.BURP2` | HTTP/2 | HTTP/2, single-packet attacks |
| `Engine.HTTP3` | HTTP/3 | HTTP/3, single datagram attack (Burp Suite Pro) |

See [engines.md](engines.md) for details.

## Global Variables

| Variable | Description |
|----------|-------------|
| `target` | Target with `.endpoint`, `.req` (the request with `%s` markers) and `.baseInput` (the text the markers replaced in the Turbo dialog, or `base_input` over MCP) |
| `table` | Results table (`table.add(req)`, `table.setSortOrder(column, descending)`) |
| `wordlists` | Access `.clipboard`, `.observedWords`, `.bruteforce` |
| `handler` | Run handler (`.setMessage()`, `.abort()`) |
| `api` | Montoya API (Burp integration) |
| `turbo` | Engine classes such as `turbo.DesyncTechniques` (`import io...` does not work in Jython) |

The helpers `randstr`, `mean`, `stddev`, `queueForever` and the decorators are defined before your
script runs; use them without importing anything.

## Quick Links

- [Engine Types](engines.md) - AUTO, THREADED, BURP, BURP2, and HTTP3
- [Performance Tuning](performance.md) - Maximize requests per second
- [Race Conditions](race-conditions.md) - Gated requests, synchronization
- [All Settings](settings.md) - Full parameter reference
- [Response Processing](response-processing.md) - Callbacks, filtering
- [Decorators](decorators.md) - @MatchStatus, @FilterRegex, etc.
- [Wordlists & Misc](misc.md) - Bruteforce, clipboard, utilities
