# HTTP Request Smuggling: Desync Technique Catalog

`turbo.DesyncTechniques`, `turbo.DesyncProbePayloads`, and `turbo.DesyncCanary` give Turbo
scripts the obfuscation/confirmation building blocks for CL.TE / TE.CL / H2-downgrade request
smuggling research — ported from HTTP Request Smuggler's technique catalog. Read this before
running `desync-smuggler` or `desync-h2-downgrade` (`turbo_docs(action=get_example, name=...)`).

## Why this is Turbo scripts, not a dedicated MCP tool

The hard part of request smuggling — holding a connection open and sending only part of a
request before pausing (`pauseBefore`/`pauseTime` in `engine.queue()`, see the `engines`/
`settings` docs) — is something Raijin's Turbo engine already does. These three objects are
*only* the pure byte/string mutation catalog; combine them with Turbo's existing engine/
connection-pinning primitives rather than reaching for a new tool.

## `turbo.DesyncTechniques`

```python
mutated = turbo.DesyncTechniques.apply(request, header, technique)
```

- `request`: a request as text (or a `byte[]`) — mutation is byte-level (ISO-8859-1), so binary
  bodies are safe.
- `header`: `"Content-Length"` or `"Transfer-Encoding"` — which header's syntax to obfuscate.
- `technique`: a name from `turbo.DesyncTechniques.allTechniques()`.
- Returns the mutated request, or `None` if `header` is `"Content-Length"` and the technique had
  no observable effect on this particular request (not worth sending) — for `"Transfer-Encoding"`
  a no-effect technique is still returned.

Technique families (`turbo.DesyncTechniques.SHARED_TECHNIQUES` / `H1_TECHNIQUES` /
`H2_TECHNIQUES` / `CL_TECHNIQUES`, plus `SPECIAL_CHARS`-parameterized `spacefix1:n` /
`prefix1:n` / `suffix1:n` / `namesuffix1:n`):

| Family | Example names | Idea |
|---|---|---|
| Shared (either header) | `spacejoin1`, `nameprefix1`, `backslash`, `spjunk`, `0dsuffix`, `nested` | Obfuscate the header name/value so one parser recognizes it and another doesn't |
| H1-specific | `badsetupCR`, `multiCase`, `0dspam`, `h1case`, `http1.0` | Header-line/version quirks specific to HTTP/1.1 parsers |
| H2-specific | `h2colon`, `h2auth`, `h2path`, `h2method`, `http2case` | Pseudo-header confusion once an HTTP/2-downgrading gateway re-serializes to HTTP/1.1 — see `desync-h2-downgrade` |
| Content-Length-specific | `CL-plus`, `CL-minus`, `CL-dualCL`, `CL-expect` | Malform/duplicate/pad the Content-Length value itself |

H2-family techniques produce text using `^`/`~`/`` ` `` as `\r`/`\n`/`:` markers — exactly the
convention Raijin's `Engine.BURP2`/HTTP2 engines already rewrite (see the `http2` example), so
send the mutated text straight through, no extra translation needed.

## `turbo.DesyncProbePayloads`

The CL.0/0-CL probe body catalog (`turbo.DesyncProbePayloads.PAYLOADS`,
`.defaultPayload()`, `.randomPayload()`, `.byId(id)`) — smuggled-request prefixes used as the
attack body once you've picked a technique. Canary injection is separate (see below); this is
just the payload shapes.

## `turbo.DesyncCanary`

Confirms a smuggled request actually landed on *someone else's* response, rather than just
reflecting back on its own:

```python
canary = turbo.DesyncCanary.generate(techniqueId, batch, position)
smuggled_request = turbo.DesyncCanary.injectIntoRequestLine(raw_request, techniqueId, batch, position)
...
found = turbo.DesyncCanary.findCanary(later_response)
if found is not None and turbo.DesyncCanary.isReflectionOfEarlierRequest(found, techniqueId, currentBatch, currentPosition):
    # desync confirmed: an earlier/lower-position request's canary leaked into this response
    ...
```

`injectIntoRequestLine` places the canary in the path (or a `xyz=` query parameter for `/`,
well-known files, or already-percent-encoded paths) so it survives most proxies untouched.

## Already covered elsewhere

0-CL desync (the `Utilities`/`TurboHelper`-style timing attack) already has worked examples —
`0cl-exploit`, `0cl-find-offset`, `0cl-poc` — and gadget-hunting (redirects, header reflection,
path normalization) has `desync-gadget-hunter`. This catalog is for the CL.TE/TE.CL header-
obfuscation family those don't cover.
