---
name: offline-history
description: Use when reviewing a target's .burp projects without Burp. API map, filters, secret and reflection search, diffs, export.
---
# Offline history review

The `history` tools read every `.burp` project of this target (in parallel, Burp not needed) plus Raijin's
archive: the requests Raijin's own tools sent (`http_send_request`, `http_race`, chains, raw bytes, pipelines)
and the scanner issues Burp reported. Live data of a running Burp is `proxy-traffic`.

## Pick the call

| Goal | Call |
|---|---|
| API map of everything seen | `run {"do":"history_endpoints"}` |
| Filtered exchanges | `run {"do":"history_list","host":"api.example.com","method":"POST","status":[200]}` |
| Secrets in raw bytes | `run {"do":"history_search","pattern":"(?i)(api[_-]?key|secret|bearer)\\s*[:=]","in":"both"}` |
| One exchange | `run {"do":"history_show","ref":"day1:42"}` |
| Two responses side by side | `run {"do":"history_diff","a":"day1:42","b":"day2:17"}` |
| Scanner issues | `run {"do":"history_list","source":"issues"}` |
| JSON export for jq | `run {"do":"history_export"}` |

## Refs
- `<project>:<id>`: a Proxy history entry of `<project>.burp`.
- `<project>:a<seq>`: an archived exchange a Raijin tool sent.
- `<project>:i<seq>`: an archived scanner issue.

## Workflow
1. API map: `history_endpoints` groups every exchange by host, method and path, with query and body
   parameter names, statuses and the projects that saw it. Pick targets from it.
2. Narrow with `history_list`. Filters: `host`, `url` (substring), `method`, `status` (list), `since`/`until`
   (epoch ms), `mime`, `tool`, `comment`, `highlight`. `source`: `proxy`, `archive`, `issues`, or `all`
   (default: proxy + archive). `"dedupe":true` keeps one row per method + URL + body. Page with
   `limit`/`offset`: `run {"do":"history_list","host":"api.example.com","limit":50,"offset":50}`.
3. Search raw bytes with `history_search` (`in`: `req`, `resp` or `both`). For reflections, search the
   response for a value you sent: `run {"do":"history_search","pattern":"<value you sent>","in":"resp"}`.
   Up to 3 hits per entry, with context.
4. Inspect: `history_show` cuts bodies at `max_body` (default 4096);
   `run {"do":"history_show","ref":"day1:42","full":true}` shows them whole. `history_diff` diffs two
   responses; `run {"do":"history_diff","a":"day1:42","b":"day2:17","part":"request"}` diffs the requests.
5. Issues: `history_list` with `"source":"issues"`, then `history_show` on an `i…` ref for detail and
   evidence: `run {"do":"history_show","ref":"day1:i3"}`.
6. Hand off: `history_export` writes amber's JSON export per project (plus the archive files) under
   `.raijin/exports/`; parse it with jq.

## Pitfalls
- For a large target, give each subagent one project: pass `project` (a name or a list) in every history call:
  `run {"do":"history_list","project":"day1","limit":100}`.
- A project whose Burp is running is still read, with a warning that its data may be incomplete; for live data
  use `proxy_history` on the running Burp instead.
- `history_search` patterns are Rust regexes over raw bytes; `(?i)` makes them case-insensitive.

## Done when
The exchange that shows the behaviour is named by its ref and shown with `history_show`; to confirm it live,
start Burp (`run {"do":"burp_up"}`) and replay it with `http_send_request`, then record it with `findings.add`.
