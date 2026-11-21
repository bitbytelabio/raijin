---
name: offline-history
description: Next-day review of a target's .burp projects and Raijin's archive without starting Burp: API map, filters, secret and reflection search, diffs, one subagent per project.
---
# Offline history review

The `history` tools read every `.burp` project of this target (in parallel, Burp not needed) plus
Raijin's archive: the requests Raijin's own tools sent (`http_send_request`, `http_race`, chains,
raw bytes, pipelines) and the scanner issues Burp reported. Run them through `execute`.

## Refs
- `<project>:<id>`: a Proxy history entry of `<project>.burp`.
- `<project>:a<seq>`: an archived exchange a Raijin tool sent.
- `<project>:i<seq>`: an archived scanner issue.

## Playbook
1. API map: `execute('history_endpoints', {})` groups every exchange by host, method and path, with
   query and body parameter names, statuses and the projects that saw it. Pick targets from it.
2. Narrow: `execute('history_list', {"host": "api.example.com", "method": "POST", "status": [200]})`.
   Filters: `host`, `url` (substring), `method`, `status` (list), `since`/`until` (epoch ms), `mime`,
   `tool`, `comment`, `highlight`. `source`: `proxy`, `archive`, `issues`, or `all` (default: proxy
   + archive). `dedupe: true` keeps one row per method + URL + body. Page with `limit`/`offset`.
3. Search raw bytes: `execute('history_search', {"pattern": "(?i)(api[_-]?key|secret|bearer)\\s*[:=]", "in": "both"})`.
   For reflections, search the response for a value you sent. Up to 3 hits per entry, with context.
4. Inspect: `execute('history_show', {"ref": "day1:42"})` (bodies cut at `max_body`, default 4096;
   `full: true` for all). `execute('history_diff', {"a": "day1:42", "b": "day2:17"})` diffs two
   responses (`part: "request"` for requests).
5. Issues: `history_list` with `source: "issues"`, then `history_show` on an `i…` ref for detail and evidence.
6. Hand off: `execute('history_export', {})` writes amber's JSON export per project (plus the archive
   files) under `.raijin/exports/`; parse it with jq.

## Fan out
For a large target, give each subagent one project: pass `"project": "day1"` (or a list) in the
arguments of every history call. A project whose Burp is running is still read, with a warning that
its data may be incomplete; for live data use `proxy_history` on the running Burp instead.
