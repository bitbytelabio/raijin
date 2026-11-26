---
name: turbo-scripting
description: Use when a test needs volume, scripted races, HTTP/2 or HTTP/3 gates or desync work. Python Turbo scripts and runs.
---
# Turbo scripting

Turbo runs a Python script against the request engine. Use it for high-volume sends, scripted or
multi-endpoint race conditions, HTTP/2 and HTTP/3 gates and desync work. For ordinary requests, and for a
single-packet or last-byte race of one request, prefer `http_*` (`http_race`, `guide {"topic":"http-testing"}`).

## Pick the call

| Goal | Call |
|---|---|
| List the doc topics | `run {"do":"turbo_docs.get_docs"}` |
| Read one topic | `run {"do":"turbo_docs.get_docs","topic":"api-quickstart"}` |
| List example scripts | `run {"do":"turbo_docs.list_examples"}` |
| Get one example | `run {"do":"turbo_docs.get_example","name":"desync-smuggler"}` |
| Run and wait | `run {"do":"turbo_run.start","script":"<script>","base_request":"<raw>","endpoint":"<url>"}` |
| Run in the background | `run {"do":"turbo_run.start_async","script":"<script>","base_request":"<raw>","endpoint":"<url>"}` |
| Wait for a run | `run {"do":"turbo_run.status","run_id":"<id>","wait":true}` |
| Page through results | `run {"do":"turbo_run.results","run_id":"<id>","limit":50,"offset":0}` |
| One exchange | `run {"do":"turbo_run.result","run_id":"<id>","id":"<result id>"}` |

## Workflow
1. Read docs: `turbo_docs.get_docs` with no topic lists the 12 topics; start with `api-quickstart`, then
   `engines`, `settings`, `race-conditions`, `response-processing`, `decorators`, `performance`,
   `desync-techniques`, `misc` as needed.
2. Pick an example: `turbo_docs.list_examples`, then `turbo_docs.get_example`. Pass it on as `script` without
   changing its line endings.
3. Run: `turbo_run.start` blocks until the run finishes or `timeout_ms` (default 55000) passes, then returns
   the most anomalous results, or a `run_id` while it keeps running. `turbo_run.start_async` returns the
   `run_id` at once; use it when the run may outlast your own call timeout. `base_request` marks injection
   points with `%s`; `base_input` reaches the script as `target.baseInput`.
4. Poll: `turbo_run.status` with `"wait":true` long-polls up to 50 s. `run {"do":"turbo_run.list"}` recovers a
   lost `run_id` (runs from the GUI included).
5. Read: `turbo_run.results` pages through results (`limit`, `offset`). Without `sort_by` they follow the
   order the script set with `table.setSortOrder(...)` (`sort_source: "script"`), else arrival order.
   `ttfb`/`ttlb` are microseconds. `turbo_run.result` returns one exchange with the body cut to `body_limit`
   lines (default 100) and at most 200,000 characters; `"body_limit":0` returns it whole and `"export":true`
   writes it to files. `run {"do":"turbo_run.search_responses","run_id":"<id>","query":"<text>"}` finds
   result ids by substring; `run {"do":"turbo_run.script","run_id":"<id>"}` returns a run's script.
6. Stop or clean up: `run {"do":"turbo_run.stop","run_id":"<id>"}`, `run {"do":"turbo_run.delete","run_id":"<id>"}`.
   Keep interesting results with `turbo_run.save_to_organizer`; `items` is a JSON array, as text, of
   `{"request_id": int, "notes": string}`: `run {"do":"turbo_run.save_to_organizer","run_id":"<id>","items":"<json>"}`.

## Pitfalls
- `idleTimeout` is milliseconds without activity; `req.time` is microseconds.
- `engine.queue(delay=...)` is accepted but ignored.
- `randstr`, `mean`, `stddev` and the decorators are already defined (no import).
- Engine classes come from the injected `turbo` object (`import io...` does not work in Jython).
- A request written in a triple-quoted string has the script's own line endings, which are LF over MCP: build
  raw requests with explicit `\r\n` as the examples do.
- Turbo runs are advisory under the scope check: flagged, never refused.

## Desync
For HTTP request smuggling / CL.TE-TE.CL desync testing, read
`run {"do":"turbo_docs.get_docs","topic":"desync-techniques"}` first, then run the example `desync-smuggler`
(obfuscated Content-Length/Transfer-Encoding sweep with canary-based confirmation) or
`run {"do":"turbo_docs.get_example","name":"desync-h2-downgrade"}` (HTTP/2 pseudo-header obfuscation for a
downgrading gateway, sent with `kettled=True`). 0-CL desync already has `0cl-exploit`/`0cl-find-offset`/
`0cl-poc`, and redirect/header-reflection gadget hunting has `desync-gadget-hunter`. For a few raw requests
over one socket without a script, `http_send_pipeline` is simpler.

## Done when
The anomalous result is read in full with `turbo_run.result`, reproduced (by a second run or one
`http_send_request`), kept with `turbo_run.save_to_organizer`, and recorded with
`run {"do":"findings.add","type":"<type>","url":"<url>"}`.
