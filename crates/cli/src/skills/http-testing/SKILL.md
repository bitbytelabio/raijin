---
name: http-testing
description: Use when sending, chaining, pipelining, fuzzing or racing HTTP requests through Burp. Senders, rules, macros.
---
# HTTP testing

Build and send requests with the `http_*` tools, compare the answers with `analyze`, and keep sessions alive
with traffic rules, token rules and login macros. Reading traffic Burp's Proxy captured is `proxy-traffic`;
scripted high-volume runs are `turbo-scripting`; one vulnerability class end to end is `recon-probes`.

## Pick the call

| Goal | Call |
|---|---|
| One request (start here) | `run {"do":"http_send_request","url":"https://example.com/","method":"GET"}` |
| One request from raw text | `run {"do":"http_send_request","raw_request":"<raw>","host":"<host>"}` |
| Exact HTTP/2 header list, pseudo-headers included | `run {"do":"http_send_request","url":"<url>","http2_headers":["<...>"]}` |
| Login, then use the token | `run {"do":"http_send_request_chain","steps":["<...>"]}` |
| Independent requests at once | `run {"do":"http_send_requests_parallel","requests":["<...>"]}` |
| Exact bytes, never normalised | `run {"do":"http_send_raw_bytes","raw_request_hex":"<hex>","host":"<host>"}` |
| Several requests over one socket (0.CL, CL.TE) | `run {"do":"http_send_pipeline","requests":["<...>"],"host":"<host>"}` |
| Payloads at marked positions | `run {"do":"http_fuzz","request":"<raw>","host":"<host>","payload_library":"sqli"}` |
| Race one request | `run {"do":"http_race","request":"<raw>","host":"<host>","count":20}` |
| Compare responses | `run {"do":"analyze.diff","item1":"<response>","item2":"<response>","type":"response"}` |
| Find Raijin's own traffic | `run {"do":"sitemap.query","note_contains":"[MCP]"}` |

## Workflow
1. Inspect parameters first: `run {"do":"analyze.extract_params","request":"<raw>"}` and
   `run {"do":"analyze.insertion_points","request":"<raw>","host":"<host>","port":443}`.
2. Send one request with `http_send_request` and read the answer.
3. Vary it: `http_fuzz` for payloads at positions, `http_race` for simultaneous requests, `http_send_pipeline`
   or `http_send_raw_bytes` for desync and framing work.
4. Compare: `run {"do":"analyze.http_variations","responses":["<...>"]}`, `analyze.diff`, and keyword counts
   in one response with `run {"do":"analyze.http_keywords","response":"<raw>","keywords":["<...>"]}`.
5. Keep the session alive with a cookie jar seed, a token rule or a login macro
   (`guide {"topic":"http-testing/references/rules-sessions.md"}`).
6. Hand a request to the Burp UI: `run {"do":"send_to_tool.repeater","request":"<raw>","host":"<host>","port":443}`,
   also `send_to_tool.intruder` or `organizer.send`; `send_to_tool.comparer` and `send_to_tool.decoder` take
   `data` instead of a request.

## Pitfalls
- What the `http_send_*` tools, `http_fuzz` and `http_race` send is recorded in the Burp **site map** (notes
  starting `[MCP]`), not Proxy history: `proxy_history_search` never finds it. Query the site map with
  `note_contains`, or `search_in` (`request`, `response` or `all`) with `search_pattern`.
  `http_send_pipeline` and `http_race` with `"sync":"last_byte"` are the exception: they write to sockets of
  their own, so nothing they send passes through Burp (no site map entry, no traffic rule, token rule or
  login macro).
- Content-Length is recomputed in the bytes actually sent after a substitution (`http_fuzz`, `http_race`) or
  when a raw request's length does not match its body (`http_send_request`), unless
  `"auto_fix_content_length":false`. `http_send_raw_bytes` and `http_send_pipeline` change nothing.
- Request text goes out as ISO-8859-1 (one byte per char), or as UTF-8 when it holds a char above U+00FF.
  Structured inputs (`url`, `method`, `headers`) lose raw CR/LF only, reported in `warnings`.
- Fuzz or race: `http_fuzz` walks payloads through positions and clusters the responses; `http_race` releases
  identical (or `FUZZ`-varied) requests together. For HTTP/3, several endpoints at once or a scripted
  sequence, use `turbo_run`.
- `timeout_ms` (0 = default, -1 = no hard timeout, at most 600000, default 25000) bounds one request, each chain step or
  fuzz request, a whole parallel batch or race; a timed-out send returns `is_timeout: true`. A number out of
  range (`count`, `concurrency`, `max_responses`, ...) is clamped and reported in `notes`, not refused.

## Done when
The behaviour reproduces with one minimal `http_send_request` (or the raw sender that showed it) and its
response is the evidence: `run {"do":"findings.add","type":"<type>","url":"<url>","evidence":"<response>"}`.

## References
- `guide {"topic":"http-testing/references/sending.md"}`: every sender's options, HTTP/2 header lists,
  chains and `extract`, raw bytes, structured-input and encoding rules.
- `guide {"topic":"http-testing/references/pipeline.md"}`: `http_send_pipeline` framing, `close_reason`,
  bytes and timing, mid-write pauses, kept connections.
- `guide {"topic":"http-testing/references/fuzz-race.md"}`: `http_fuzz` modes, payloads, encoders and
  clustering; `http_race` sync modes; Content-Length auto-fix; response comparison.
- `guide {"topic":"http-testing/references/rules-sessions.md"}`: cookie jar, traffic rules, token rules,
  login macros and their safeguards, handing requests to the Burp UI.
