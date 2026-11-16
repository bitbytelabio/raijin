---
name: http-testing
description: Sending and varying HTTP requests with the http_* tools; when to use each.
---
# HTTP testing

Results from every `http_send_*` tool are recorded in the Burp **site map** (annotated `[MCP] Raijin`), not Proxy history —
`proxy_history_search` will never find them. Use `sitemap(action=query, note_contains="[MCP]")` (or `search_in=request|response|all`
with `search_pattern`) instead.

- `http_send_request`: one request, from `url` + `method` + `headers` + `body` or from `raw_request`. Start here. `http_mode` picks `AUTO`, `HTTP_1`, `HTTP_2` or `HTTP_2_IGNORE_ALPN`; `connection_id` reuses one Burp connection (the request still completes before the call returns).
- `http_send_request_chain`: dependent requests (login, then use the token). A step's `extract` is an array of `{name, pattern, from}` (`from` = `body` or `header`, the pattern's first group is the value) that fills `{{name}}` in later steps; extract rules are checked before the step is sent.
- `http_send_requests_parallel`: independent requests at once, across hosts.
- `http_send_raw_bytes`: exact bytes, one request and one response, when the request must not be normalised (smuggling, CRLF injection). `raw_request_hex` is byte-exact; in `raw_request`, literal `\r\n` escapes are decoded only when the text has no real line break, and a character above U+00FF sends the whole text as UTF-8.
- `http_send_pipeline`: several raw HTTP/1.1 requests over ONE socket, every response read back in order, for 0.CL and CL.TE probes where one request can draw two responses. Content-Length is never fixed. Framing is strict: a bad length or chunk stops reading with `close_reason: "error"` instead of guessing. Each response carries `framing`, `trailers` and `warnings`; `close_reason` says why reading stopped (`max_responses`, `idle`, `total_timeout`, `fin`, `rst`, `error`, or `switching_protocols` after a 101). Set `max_responses` when a probe may draw more or fewer responses than requests. `write_mode=single_write` with `write_pause_ms` writes request by request; `keep_open` plus `connection_id` continue on the same socket in a later call, only when the server kept it open.
- `http_fuzz`: replace marked positions with `payloads` and/or a built-in `payload_library` (`xss`, `sqli`, `traversal`, `ssti`, `cmdi`, `ssrf`, `xxe`, `crlf`, `nosqli`, `open_redirect`, `prototype_pollution`). Mark positions with `FUZZ` or `§value§` pairs (the pair not being fuzzed keeps its value); one request at a time, `stop_on_match` stops at the first matching response, and a failed request is recorded without stopping the run.
- `http_race`: simultaneous requests for race conditions (`count`, or `FUZZ` with `payloads`); best effort. For sub-millisecond precision (single-packet), use `turbo_run`.
- After a substitution (`http_fuzz`, `http_race`) or when a raw request's Content-Length does not match its body (`http_send_request`, unless `auto_fix_content_length=false`), Content-Length is recomputed in the bytes actually sent. Only the header block's bare line feeds become CRLF; the body is sent as typed. `http_send_raw_bytes` and `http_send_pipeline` change nothing.
- `timeout_ms` (1–600000, default 25000) bounds one request, each chain step or fuzz request, a whole parallel batch or race. A timed-out send returns `is_timeout: true`.
- `analyze(action=http_variations)`, `analyze(action=http_keywords)`, `analyze(action=diff)`: compare responses.
- `http_state(action=cookie_jar_get)`, `http_state(action=cookie_jar_set)`, `http_state(action=cookie_jar_delete)`: inspect, seed or remove Burp's cookies.
- `http_rule(action=traffic_rule_set, direction=request|response, rule_action=...)` rewrites outgoing traffic: `rule_action=modify` (default) adds, removes or replaces headers; `drop` suppresses the request and `spoof_response` answers it with the `spoof_response` text without sending it (both `direction=request` only). `tool_filter` limits a rule to traffic from some Burp tools; Raijin's own unauthenticated probes (`auth_diff`, `autorize`, `probe(action=idor)`) only get rules whose `tool_filter` names `EXTENSIONS`. List and remove with `http_rule(action=traffic_rule_list)` and `http_rule(action=traffic_rule_remove)`.
- `http_rule(action=token_rule_create)`, `http_rule(action=token_rule_list)`, `http_rule(action=token_rule_remove)`: extract a value from responses (regex) and inject it into later requests (header, body or cookie) to keep CSRF or session tokens fresh. Internal unauthenticated probes never receive it.

Hand a request to the Burp UI with `send_to_tool(action=repeater)`, `send_to_tool(action=intruder)`, `send_to_tool(action=comparer)`, `send_to_tool(action=decoder)` or `organizer(action=send)`.
Inspect parameters first with `analyze(action=extract_params)` and `analyze(action=insertion_points)`.
