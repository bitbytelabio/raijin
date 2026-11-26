---
name: proxy-traffic
description: Use when reading or changing traffic through Burp's Proxy. History, annotations, intercept/hold, rules, Autorize, WebSockets.
---
# Proxy traffic

Read, annotate and change what passes through Burp's Proxy, and mine it for endpoints. Requests Raijin sends
itself land in the site map instead (`http-testing`); yesterday's `.burp` files without Burp are
`offline-history`.

## Pick the call

| Goal | Call |
|---|---|
| Recent Proxy history, metadata only | `run {"do":"proxy_history","count":20,"host":"example.com"}` |
| Regex over Proxy history | `run {"do":"proxy_history_search","pattern":"<regex>","search_in":"both"}` |
| Full request and response of matches | `run {"do":"proxy_history_search","pattern":"<regex>","include_request":true,"include_response":true}` |
| Raijin's own traffic | `run {"do":"sitemap.query","note_contains":"[MCP]"}` |
| Mark an item to come back to | `run {"do":"proxy_annotate","id":"<id>","comment":"<note>","highlight":"RED"}` |
| Park requests to edit before they go out | `run {"do":"proxy_intercept.hold","target":"request","match_host":"<host>"}` |
| Rewrite every matching request | `run {"do":"proxy_rule.set_request_rule","rule_action":"modify","match_host":"*.example.com"}` |
| Replay traffic under other identities | `run {"do":"autorize.set_rule","identities":["<...>"]}` |
| WebSocket frames Burp saw | `run {"do":"websocket.history","host":"<host>"}` |

## Workflow
1. Read: `proxy_history` is paged with `start_index`/`count` and filtered by `host`, `method`, `status_code`,
   `status_code_range`, `mime_type`, `in_scope_only`. `proxy_history_search` runs a regex over `url`,
   `request`, `response` or `both` (`search_in`). Paging above the cap is served at the cap with a note.
2. Keep results small: metadata only is the default. `include_request` / `include_response` add the full
   text (and unmask `Cookie`, `Authorization` and other sensitive request headers, which are otherwise
   redacted); `max_response_length` cuts it.
3. Annotate: `proxy_annotate` marks items worth returning to; `sitemap.annotate` does the same for site map
   entries, `organizer.annotate` for Organizer items.
4. Mine: `run {"do":"recon.js_endpoints"}` and `run {"do":"analyze.passive_intel"}` summarise what traffic
   already revealed.
5. Change live traffic only when reading is not enough: Burp's Intercept switch, a hold queue that lets you
   edit, forward or drop messages, proxy rules, or an auth header on every request
   (`guide {"topic":"proxy-traffic/references/intercept-rules.md"}`).
6. Authorization over live traffic: `autorize.set_rule`, then browse the app as normal and read
   `run {"do":"autorize.list_matches"}`. For a one-off check of requests you already have, use `auth_diff` or
   `probe.access_control` (`guide {"topic":"recon-probes"}`).

## Pitfalls
- Proxy history only covers traffic that passed through Burp's Proxy. Requests the `http_*` tools send through
  Burp land in the **site map**: use `sitemap.query` for those. Turbo keeps its exchanges in the run
  (`run {"do":"turbo_run.results","run_id":"<id>"}`).
- Burp's Montoya API has no way to annotate Repeater tabs, Intruder runs or the Logger from an extension.
- Intercept: turn Burp's own Intercept tab back off when finished (`run {"do":"proxy_intercept.disable"}`)
  or the browser hangs. The hold queue forwards a message nobody decides on within `timeout_seconds`.
- Autorize replays only authenticated originals, and `POST`/`PUT`/`DELETE`/`PATCH` only with
  `"include_mutating":true`.
- Regexes in WebSocket `wait_message`, `fuzz` and the history search ignore case; start the pattern with
  `(?-i)` for an exact match.

## Done when
The item that shows the behaviour is annotated, its request is replayed with `http_send_request` to confirm
it, and the result is recorded with `run {"do":"findings.add","type":"<type>","url":"<url>"}`. A
critical/high Autorize match is already in `findings`.

## References
- `guide {"topic":"proxy-traffic/references/intercept-rules.md"}`: Intercept on/off, hold, forward, drop and
  release; proxy rules and their matchers and modify actions; config match/replace; `proxy_auto_auth`;
  Autorize.
- `guide {"topic":"proxy-traffic/references/websocket.md"}`: open, send, wait, read, fuzz and intercept
  WebSockets.
