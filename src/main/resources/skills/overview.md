---
name: overview
description: Start here: tool map, scope rules, and standard Burp testing workflow.
---
# Raijin overview

Raijin exposes Burp Suite through MCP as about 45 tools. Most tools take an `action` parameter: call `<tool>(action=<action>, ...)`; the tool description lists every action and its parameters (`*` = required for that action).

| Tool | What it does |
|---|---|
| `http_send_request`, `http_send_requests_parallel`, `http_send_request_chain`, `http_send_raw_bytes`, `http_send_pipeline`, `http_fuzz`, `http_race` | Send requests (`http_send_pipeline`: several raw HTTP/1.1 requests over one socket; `http_fuzz`: Intruder's attack types; `http_race`: single-packet or last-byte races) |
| `http_rule`, `http_state` | Outgoing traffic rules, session token rules, login macros; cookie jar, kept `http_send_pipeline` connections |
| `proxy_history`, `proxy_history_search`, `proxy_annotate`, `proxy_auto_auth` | Read and annotate proxy traffic |
| `proxy_rule`, `proxy_intercept` | Proxy rules; Burp's Intercept switch and a hold queue to edit, forward or drop proxied messages |
| `scanner`, `scanner_task`, `custom_check`, `bambda_import`, `bambda_templates` | Audits, crawls, tasks, BChecks, scan checks, Bambdas |
| `recon`, `probe` | Guided recon and probes (`probe` actions: `cors`, `cache`, `graphql`, `injection`, `access_control`, `idor`, `jwt`) |
| `auth_diff`, `autorize` | One request compared across identities; live replay of proxied traffic under other identities |
| `api_import_openapi` | Turn an OpenAPI/Swagger document into requests |
| `jwt_keys` | Key ring for `probe(action=jwt)` |
| `turbo_run`, `turbo_docs` | Python-scripted high-volume or timing-critical runs |
| `findings`, `organizer`, `sitemap` | Record and read results |
| `collaborator` | Out-of-band payloads and polling |
| `scope`, `config`, `burp`, `persistence`, `events`, `log`, `ai`, `send_to_tool` | Burp configuration and integration |
| `analyze`, `util`, `websocket` | Offline analysis, encoding helpers, WebSockets |
| `search_skills`, `load_skill` | These guides |

## Standard workflow
1. `scope(action=get_config)`, then `scope(action=include)` for the target. Outbound requests are checked against Burp's scope by the operator's `mcp_scope_mode`: `warn` (default) sends them and adds `scope_warning` to the result, `enforce` refuses them (`out_of_scope: true`, nothing sent), `off` skips the check. Turbo runs, Scanner tasks, WebSocket opens and followed redirects are advisory only: flagged under `warn` and `enforce`, never refused. Batch tools check every item and report `skipped_out_of_scope` / `sent_out_of_scope`.
2. Look at existing traffic first: `proxy_history`, `proxy_history_search` for traffic that passed through Burp's Proxy; `sitemap(action=query)` for everything else, including anything this server itself sent with `http_send_*` (which never reaches Proxy history).
3. Understand a request with `analyze(action=request)`, `analyze(action=insertion_points)`, `analyze(action=response)`.
4. Run focused tests with `http_*` or a guided probe. Use `turbo_run` only when you need volume or timing.
5. Record results with `findings(action=add)`; review with `findings(action=list)`.

## Rules
- Only run against targets you are authorised to test.
- Prefer one small request over a broad run; keep result sets small. Most tools page or cap their output; a limit above the cap is clamped and reported as `<param>_clamped_to`.
- A result with `isError: true` says why in `error`: fix the argument instead of retrying the same call.
- Other skills: `http-testing`, `proxy-traffic`, `scanner-audit`, `recon-probes`, `findings-reporting`, `collaborator-oob`, `turbo-scripting`. Load one with `load_skill(name="<name>")`, read its `skill://<name>/SKILL.md` resource, or run the `<name>` MCP prompt.
