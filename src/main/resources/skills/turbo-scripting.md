---
name: turbo-scripting
description: When to use Turbo runs and where the Turbo docs and examples live.
---
# Turbo scripting

Turbo runs a Python script against the request engine. Use it for high-volume sends, single-packet race conditions, HTTP/2 and HTTP/3 gates and desync work. For ordinary requests prefer `http_*`.

1. Read docs: `turbo_docs(action=get_docs)` (no topic lists topics; start with `api-quickstart`).
2. Pick an example: `turbo_docs(action=list_examples)`, then `turbo_docs(action=get_example)`.
3. Run: `turbo_run(action=start)` (blocks until done or timeout, then returns the most anomalous results) or `turbo_run(action=script)`.
4. Poll long runs: `turbo_run(action=status)`; fetch with `turbo_run(action=results)` / `turbo_run(action=result)`; search with `turbo_run(action=search_responses)`.
5. Stop or clean up: `turbo_run(action=stop)`, `turbo_run(action=delete)`. Keep interesting results with `turbo_run(action=save_to_organizer)`.

For HTTP request smuggling / CL.TE-TE.CL desync testing: read `turbo_docs(action=get_docs, topic=desync-techniques)` first, then run `turbo_docs(action=get_example, name=desync-smuggler)` (obfuscated Content-Length/Transfer-Encoding sweep with canary-based confirmation) or `name=desync-h2-downgrade` (HTTP/2 pseudo-header obfuscation for a downgrading gateway). 0-CL desync already has `0cl-exploit`/`0cl-find-offset`/`0cl-poc`, and redirect/header-reflection gadget hunting has `desync-gadget-hunter`.
