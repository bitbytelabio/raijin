---
name: raijin-overview
description: Start here. How the Raijin MCP server is organised, the standard workflow, and the scope rules.
---
# Raijin overview

Raijin exposes Burp Suite through MCP as about 40 tools. Most tools take an `action` parameter: call `tool(action=name, ...)`; the tool description lists every action and its parameters (`*` = required).

| Tool | What it does |
|---|---|
| `http_send_request`, `http_send_requests_parallel`, `http_send_request_chain`, `http_send_raw_bytes`, `http_fuzz`, `http_race` | Send requests |
| `http_rule`, `http_state` | Outgoing traffic rules, session token rules, cookie jar |
| `proxy_history`, `proxy_history_search`, `proxy_annotate`, `proxy_auto_auth` | Read and annotate proxy traffic |
| `proxy_rule`, `proxy_intercept` | Proxy rules and the intercept switch |
| `scanner`, `scanner_task`, `custom_check` | Audits, crawls, tasks, BChecks and scan checks |
| `recon`, `probe` | Guided recon and probes (scope-gated) |
| `turbo_run`, `turbo_docs` | Python scripted high-volume or timing-critical runs |
| `findings`, `organizer`, `sitemap` | Record and read results |
| `collaborator` | Out-of-band payloads and polling |
| `scope`, `config`, `burp`, `persistence`, `events`, `log`, `ai`, `send_to_tool` | Burp configuration and integration |
| `analyze`, `util`, `websocket` | Offline analysis, encoding helpers, WebSockets |
| `skill` | These guides |

## Standard workflow
1. `scope(action=get_config)`, then `scope(action=include)` for the target. Probes refuse out-of-scope hosts.
2. Look at existing traffic first: `proxy_history`, `proxy_history_search`, `sitemap(action=query)`.
3. Understand a request with `analyze(action=request)`, `analyze(action=insertion_points)`, `analyze(action=response)`.
4. Run focused tests with `http_*` or a guided probe. Use `turbo_*` only when you need volume or timing.
5. Record results with `findings(action=add)`; review with `findings(action=list)`.

## Rules
- Only run against targets you are authorised to test.
- Prefer one small request over a broad run; keep result sets small (most tools page or cap output).
- Load other skills with `skill(action=get, name=...)`: `http-testing`, `proxy-traffic`, `scanner-audit`, `recon-and-probes`, `findings-reporting`, `collaborator-oob`, `turbo-scripting`. The same text is available as MCP resources at `raijin://skills/<name>`.
