---
name: raijin-gateway
description: Read first. How to drive Burp through the raijin gateway (discover, execute, skill), routing traps, Burp lifecycle and saved results.
---
# Raijin gateway

The `raijin` MCP server exposes three tools. Every Raijin and Burp tool runs through them.

## The loop
1. `discover()` lists the domains, the running Burp instances of this target and routing notes.
   Pick ONE domain by what you want to do.
2. `discover(domain)` gives the exact tool names and parameter schemas of that domain. Never guess
   parameter names; most Raijin tools take an `action` plus action-specific parameters.
3. `execute(tool, arguments, project?)` runs one tool. `arguments` is the tool's own parameter object.
4. Read the domain's playbook with `skill(name)` when a task is new to you; `skill()` lists them.
   Tool names inside playbooks run through `execute`.

## Routing traps
- Live captured traffic of a running Burp is `proxy` (`proxy_history`, `proxy_history_search`).
  Yesterday's `.burp` files, read without Burp, are `history` (`history_list`, `history_search`, …).
- Sending a request is `http` (`http_send_request`, `http_fuzz`, `http_race`, …), not `proxy`.
- Testing one vulnerability class (CORS, JWT, IDOR, injection, cache poisoning) is `recon`
  (`probe`), not `scanner`. `scanner` is a full Burp Scanner crawl/audit.
- Comparing one request across privilege levels is `authz` (`auth_diff`, `autorize`).
- Check scope (`settings` → `scope`) before sending traffic.

## Burp lifecycle (domain `lifecycle`)
- `execute('burp_status', {})`: every project of this target and its state (stopped, starting, running).
- `execute('burp_up', {"project": "day2"})`: starts Burp with Raijin for that project (headless by
  default; `"mode": "ui"` opens a window). It keeps running after this session. `wait_seconds`
  (default 60) bounds the wait; a `starting` result means call `burp_status` again shortly.
- `execute('burp_down', {"project": "day2"})` or `{"all": true}` stops it.
- Nothing starts Burp on its own: a Burp tool with no Burp running fails with
  `no Burp running for this target`; start one with `burp_up` first.
- In remote mode Burp is managed elsewhere; only `burp_status` exists.

## Several projects
Each project is its own Burp with its own `.burp` file. With more than one running, pass
`project` to `execute` (`execute('proxy_history', {...}, project='day1')`). With one running,
or the default project running, `project` can be left out.

## Large results
Results over the inline limit come back as
`{"saved_to": "...", "bytes": N, "preview": "...", "hint": "..."}`. The preview is the first 2 KiB.
Parse the file with `jq` or a short Python script, or hand it to a subagent; never read it whole
into context. Narrow the next call instead (filters, `limit`, `max_body`).
