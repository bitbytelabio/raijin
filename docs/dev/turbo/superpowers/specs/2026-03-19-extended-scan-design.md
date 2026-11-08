# Extended Scan Design

## Overview

An extensible scanning framework that runs targeted security checks against endpoints discovered by micro-crawl. Uses a registry pattern where each scan is a function that receives crawl results and adds labeled findings to a shared result table.

## Architecture

### micro-crawl.py refactoring

Extract core logic into reusable functions:

- `MicroCrawl` class encapsulating state (seen set, count, canary, config)
- `crawl(engine, template)` — seeds BFS queue and processes responses
- Standalone `queueRequests`/`handleResponse` become thin wrappers creating a `MicroCrawl` instance

### desync-gadget-hunter.py

New script with:

1. **Input modes**: If `target.baseInput` contains JSON (array of crawl result objects), parse and use as seeds. Otherwise, run micro-crawl first.
2. **Scan registry**: `SCANS = [find_redir_gadget]` — list of scan functions.
3. **Orchestration**: Run crawl (or parse input), then call each scan with results.

### Scan function signature

```python
def scan_name(engine, template, host, crawl_results, table):
    """
    engine: RequestEngine for sending requests
    template: base HTTP request template
    host: target hostname
    crawl_results: list of dicts with keys: path, status, response
    table: ResultStore for adding findings
    """
```

### Crawl result format (base_input JSON)

```json
[
  {"path": "/static", "status": 301, "response": "HTTP/1.1 301..."},
  {"path": "/about", "status": 200, "response": "HTTP/1.1 200..."}
]
```

MCP client fetches `turbo://runs/{run_id}/summary`, transforms into this format, and passes as `base_input`.

## find_redir_gadget

### Phase 1: Find local redirects

Sources:
- Root folders derived from crawl results (e.g., `/static/foo.html` → `/static`)
- `/%2f`
- (More tricks to come)

A "local redirect" is a 3xx response where the Location header points to the same host or is a relative path.

### Phase 2: Test redirects for external control

For each local redirect found, test:

1. **Host prefix**: Add `evil.` prefix to Host header → check if Location contains injected host
2. **X-Forwarded-Host**: Add `X-Forwarded-Host: evil.com` (and X-Forwarded-Scheme, X-Original-URL, etc.) → check Location
3. **Absolute URL in request line**: `GET https://evil.com/path HTTP/1.1` with normal Host → check Location
4. **Absolute URL + Host injection**: `GET https://realhost/path HTTP/1.1` with `Host: evil.com` → check Location
5. **Host casing**: Uppercase a letter in Host → check if casing reflected in Location (partial success, no early exit)

### Labels

- `redir:local` — local redirect found (phase 1)
- `redir:host-prefix` — host prefix reflected in redirect
- `redir:xfh` — X-Forwarded-Host reflected
- `redir:absolute-url` — absolute URL in request line works
- `redir:absolute-url+host` — absolute URL + host injection works
- `redir:casing` — host casing reflected (partial)

### Detection logic

A test "succeeds" when the injected marker string appears in the Location header of the response. The marker is a distinctive string unlikely to appear naturally (e.g., `evil.` prefix or `evil.com` domain).

## Testing

- Unit tests for redirect detection helpers (is_local_redirect, extract_location)
- Unit tests for root folder extraction
- Integration test via MCP server against live target (applegiftcard.apple.com)
