---
name: overview
description: Use when starting any Burp task through raijin. The guide/run loop, Burp lifecycle, scope rules, routing, errors.
---
# Raijin overview

Raijin drives Burp Suite through two MCP tools, `guide` and `run`; the 43 Raijin tools and the CLI's own
lifecycle and offline history tools all run through `run`. Read this first, then the playbook of the domain
you work in (map below). Offline `.burp` review without Burp is `offline-history`.

## Pick the call

| Goal | Call |
|---|---|
| What runs, every tool by domain, the playbooks | `guide {}` |
| One tool's parameters (`inputSchema`) and annotations | `guide {"topic":"http_send_request"}` |
| One action of a grouped tool | `guide {"topic":"scope.check"}` |
| A domain's tools | `guide {"topic":"proxy"}` |
| Start Burp for the default project | `run {"do":"burp_up"}` |
| Run a grouped tool's action | `run {"do":"scope.check","url":"https://example.com"}` |
| Pick a Burp when several run | `run {"do":"proxy_history","count":5,"project":"day1"}` |

Several calls in order: give `run` a `"batch"` list of steps, each one `{"do":"<tool>", ...}`, plus
`"bail":true` to stop at the first failed step; a top-level `"project"` applies to every step without one.

Most tools are grouped: `do` is `<tool>.<action>` and the action's parameters sit next to it. The tool
description lists every action and its parameters (`*` = required). Copy parameter names from the
`inputSchema` that `guide` shows: a name the tool does not accept is rejected.

## Workflow
1. Burp: `run {"do":"burp_status"}` lists every project of this target and its state (stopped, starting,
   running). `run {"do":"burp_up","project":"day2"}` starts Burp with Raijin for that project, headless by
   default; `run {"do":"burp_up","project":"day2","mode":"ui"}` opens a window. It keeps running after this
   session. `wait_seconds` (default 60) bounds the wait; a `starting` result means call `burp_status` again
   shortly. `run {"do":"burp_down","project":"day2"}` stops it, `run {"do":"burp_down","all":true}` stops all.
2. Scope: `run {"do":"scope.get_config"}`, then `run {"do":"scope.include","url":"https://example.com"}`.
3. Existing traffic first: `run {"do":"proxy_history","count":20}` and
   `run {"do":"proxy_history_search","pattern":"<regex>"}` for traffic that passed through Burp's Proxy;
   `run {"do":"sitemap.query","url_prefix":"https://example.com/"}` for everything else, including anything
   Raijin itself sent with `http_send_*` (which never reaches Proxy history).
4. Understand a request: `run {"do":"analyze.request","request":"<raw>"}`,
   `run {"do":"analyze.insertion_points","request":"<raw>","host":"<host>","port":443}`, `run {"do":"analyze.response","response":"<raw>"}`.
5. Test with `http_*` or a guided probe (`probe.*`). Use `turbo_run` only when you need volume or timing.
6. Record: `run {"do":"findings.add","type":"<type>","url":"<url>"}`; review with `run {"do":"findings.list"}`.

## Pitfalls
- Scope: outbound requests are checked against Burp's scope by the operator's `mcp_scope_mode`. `warn`
  (default) sends them and adds `scope_warning` to the result, `enforce` refuses them (`out_of_scope: true`,
  nothing sent), `off` skips the check. Turbo runs, Scanner tasks, WebSocket opens and followed redirects are
  advisory only: flagged under `warn` and `enforce`, never refused. Batch tools check every item and report
  `skipped_out_of_scope` / `sent_out_of_scope`.
- Nothing starts Burp on its own: a Burp tool with no Burp running fails with `no Burp running for this
  target`. In remote mode Burp is managed elsewhere and only `burp_status` exists.
- Routing: live captured traffic of a running Burp is `proxy` (`proxy_history`, `proxy_history_search`);
  yesterday's `.burp` files, read without Burp, are `history` (`history_list`, `history_search`, ...).
  Sending a request is `http` (`http_send_request`, `http_fuzz`, `http_race`, ...), not `proxy`. Testing one
  vulnerability class (CORS, JWT, IDOR, injection, cache poisoning) is `recon` (`probe`), not `scanner`, which
  is a full Burp Scanner crawl/audit. Comparing one request across privilege levels is `authz` (`auth_diff`,
  `autorize`). Check scope (`settings`, tool `scope`) before sending traffic.
- Errors: an error result is JSON: `error` (what is wrong and what to do), `code`, and when they help `param`,
  `got`, `allowed`, `did_you_mean`, `usage` (every accepted parameter), `example` and `retry` (a complete
  corrected call: resend `retry` as it is), `retryable` and `see`. `unknown_tool` / `unknown_action` /
  `unknown_topic`: use `retry` or a name from `did_you_mean`, else `guide {}`. `unknown_parameter`,
  `missing_parameter`, `invalid_type`, `invalid_enum`, `out_of_range`, `invalid_arguments`: fix the arguments
  from `retry`, `usage` and `example`. `burp_not_running`: `run {"do":"burp_up"}`, then resend.
  `project_not_running`: start that project as `example` shows. `project_required`: add `"project":"<name>"`
  next to `do`. `retryable: false` (`raijin_unreachable`, `tool_failed`, `config_error`, `not_supported`,
  `internal`): never resend the same call; change it or tell the user. A result may carry `notes`: what the
  server changed in your call (a string read as a number, a name matched without case); use that form next time.
- Several projects: each project is its own Burp with its own `.burp` file. With more than one running, pass
  `project`; with one running, or the default project running, leave it out.
- Large results come back as `{"saved_to":"...","bytes":N,"preview":"...","hint":"..."}`; the preview is the
  first 2 KiB. Parse the file with `jq` or a short Python script, or hand it to a subagent; never read it
  whole into context. Narrow the next call instead (filters, `limit`, `max_body`).
- Only run against targets you are authorised to test. Prefer one small request over a broad run and keep
  result sets small. Most tools page or cap their output; a limit above the cap is clamped and reported as
  `<param>_clamped_to`.

## Done when
A result is confirmed by a minimal request you sent and its response, then recorded with
`run {"do":"findings.add","type":"<type>","url":"<url>","severity":"high","evidence":"<what you saw>"}`.

## Playbooks
Read one with `guide {"topic":"<playbook>"}`. Domain → playbook: `http`, `analysis` → `http-testing`;
`proxy` → `proxy-traffic`; `recon`, `authz` → `recon-probes`; `scanner` → `scanner-audit`; `turbo` →
`turbo-scripting`; `oob` → `collaborator-oob`; `findings` → `findings-reporting`; `history` →
`offline-history`; `settings`, `lifecycle` → this playbook (`overview`).

## References
- `guide {"topic":"overview/references/tool-map.md"}`: every published tool, its actions and what it does.
