# Micro-Crawl Script Design

## Goal

A Turbo Simulator script that performs a breadth-first micro-crawl to quickly find diverse endpoints for security testing. Max 500 requests, using Burp's request engine.

## Script Structure

**`queueRequests`**: Seeds the BFS queue with paths from a hardcoded wordlist (~62 entries loaded from `resources/micro-crawl-wordlist.txt`). Each entry is prepended with `/` if it doesn't already start with one.

**`handleResponse`**: For every response that isn't a 404:
1. Run a generic regex over the response body to extract path-like strings
2. Normalize each path, deduplicate by path-only (ignoring query string)
3. Skip already-seen paths, external URLs, and static asset extensions
4. Queue new paths via `req.engine.queue()` - these are naturally BFS level N+1
5. `table.add(req)` to record the result

**Global state** (Python globals, safe because single connection = no concurrency):
- `seen` - set of path-only strings already queued
- `count` - counter to enforce the 500-request cap

## Engine Config

```python
engine = RequestEngine(
    endpoint=target.endpoint,
    concurrentConnections=1,
    requestsPerConnection=100,
    pipeline=False,
    engine=Engine.BURP
)
```

Single connection avoids concurrency issues - `handleResponse` is effectively single-threaded.

## Base Request

Caller provides a template with `%s` in the path position:

```
GET %s HTTP/1.1
Host: example.com

```

Payloads are full paths like `/robots.txt`, `/admin/config?tab=users`.

## Path Extraction

Single generic regex that catches paths from any response format (HTML href/src, robots.txt Disallow, sitemap.xml loc, JS string literals, etc.):

```python
re.findall(r'/[a-zA-Z0-9._\-/]+(?:\?[^\s"\'<>]*)?', response)
```

This matches any path-like string starting with `/`. False positives are acceptable - a 404 is cheap.

## Normalization and Deduplication

- Keep full path + query string for the request payload
- Deduplicate on path portion only (everything before `?`)
- Skip static asset extensions: `.png`, `.jpg`, `.gif`, `.css`, `.js`, `.woff`, `.woff2`, `.svg`, `.ico`, `.ttf`, `.eot`
- Skip paths that are just `/`

## Request Budget

- ~62 wordlist entries queued as seeds (BFS level 0)
- Extracted links fill remaining budget up to 500 total
- BFS ordering emerges naturally: seeds processed first, their links next, etc.

## Wordlist

Stored at `resources/micro-crawl-wordlist.txt`. Loaded by the script at init time. Contains high-value paths like `robots.txt`, `sitemap.xml`, `.well-known/security.txt`, `login`, `admin`, `api`, etc.
