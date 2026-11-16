---
name: turbo-scripting
description: When to use Turbo runs and where the Turbo docs and examples live.
---
# Turbo scripting

Turbo runs a Python script against the request engine. Use it for high-volume sends, single-packet race conditions, HTTP/2 and HTTP/3 gates and desync work. For ordinary requests prefer `http_*`.

1. Read docs: `turbo_docs(action=get_docs)` with no topic lists the 12 topics; start with `api-quickstart`, then `engines`, `settings`, `race-conditions`, `response-processing`, `decorators`, `performance`, `desync-techniques`, `misc` as needed.
2. Pick an example: `turbo_docs(action=list_examples)`, then `turbo_docs(action=get_example, name=...)`. Pass it on as `script` without changing its line endings.
3. Run: `turbo_run(action=start, script=..., base_request=..., endpoint=...)` blocks until the run finishes or `timeout_ms` (default 55000) passes, then returns the most anomalous results, or a `run_id` while it keeps running. `turbo_run(action=start_async)` returns the `run_id` at once; use it when the run may outlast your own call timeout. `base_request` marks injection points with `%s`; `base_input` reaches the script as `target.baseInput`.
4. Poll: `turbo_run(action=status, run_id=..., wait=true)` long-polls up to 50 s. `turbo_run(action=list)` recovers a lost `run_id` (runs from the GUI included).
5. Read: `turbo_run(action=results)` pages through results (`limit`, `offset`). Without `sort_by` they follow the order the script set with `table.setSortOrder(...)` (`sort_source: "script"`), else arrival order. `ttfb`/`ttlb` are microseconds. `turbo_run(action=result, id=...)` returns one exchange with the body cut to `body_limit` lines (default 100) and at most 200,000 characters; `body_limit=0` returns it whole and `export=true` writes it to files. `turbo_run(action=search_responses)` finds result ids by substring; `turbo_run(action=script)` returns a run's script.
6. Stop or clean up: `turbo_run(action=stop)`, `turbo_run(action=delete)`. Keep interesting results with `turbo_run(action=save_to_organizer)`.

Script facts that trip agents up: `idleTimeout` is milliseconds without activity; `req.time` is microseconds; `engine.queue(delay=...)` is accepted but ignored; `randstr`, `mean`, `stddev` and the decorators are already defined (no import); engine classes come from the injected `turbo` object (`import io...` does not work in Jython). A request written in a triple-quoted string has the script's own line endings, which are LF over MCP: build raw requests with explicit `\r\n` as the examples do.

For HTTP request smuggling / CL.TE-TE.CL desync testing: read `turbo_docs(action=get_docs, topic=desync-techniques)` first, then run `turbo_docs(action=get_example, name=desync-smuggler)` (obfuscated Content-Length/Transfer-Encoding sweep with canary-based confirmation) or `name=desync-h2-downgrade` (HTTP/2 pseudo-header obfuscation for a downgrading gateway, sent with `kettled=True`). 0-CL desync already has `0cl-exploit`/`0cl-find-offset`/`0cl-poc`, and redirect/header-reflection gadget hunting has `desync-gadget-hunter`. For a few raw requests over one socket without a script, `http_send_pipeline` is simpler.
