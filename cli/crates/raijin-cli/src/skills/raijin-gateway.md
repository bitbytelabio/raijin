---
name: raijin-gateway
description: Read first. How to drive Burp through the raijin gateway (discover, execute, skill), routing traps, Burp lifecycle and saved results.
---
# Raijin gateway

The `raijin` MCP server exposes three tools. Every Raijin and Burp tool runs through them.

## The loop
1. `discover()` lists the domains, the running Burp instances of this target and routing notes.
   Pick ONE domain by what you want to do.
2. `discover({"domain":"http"})` gives the exact tool names, annotations and `inputSchema` of that
   domain. Copy parameter names from `inputSchema`; never guess them. A tool name works as the
   domain too: `discover({"domain":"http_send_request"})`.
3. `execute` runs one tool. `arguments` is that tool's own parameter object, always a JSON object:
   `execute({"tool":"http_send_request","arguments":{"url":"https://example.com/","method":"GET"}})`
4. Grouped tools take `action` inside `arguments`, plus that action's parameters (the tool
   description lists them, `*` = required):
   `execute({"tool":"scope","arguments":{"action":"include","url":"https://example.com"}})`
5. Read the domain's playbook when a task is new to you: `skill({"name":"http-testing"})`;
   `skill()` lists them. Tool names inside playbooks run through `execute`.

## Errors and how to recover
- `unknown_parameter`: the tool or action does not take that name. Use `did_you_mean` or the names in `usage`.
- `missing_parameter`: add every parameter marked `*` in `usage`; `example` is a correct call to adapt.
- `unknown_action` / `missing_action`: set `action` to one of `available`.
- `no Burp running for this target`: `execute({"tool":"burp_up","arguments":{}})`, then retry.
- `several projects running`: pass `"project": "<name>"` next to `tool`.
Never resend an identical call after an error; change the arguments first.

## Routing traps
- Live captured traffic of a running Burp is `proxy` (`proxy_history`, `proxy_history_search`).
  Yesterday's `.burp` files, read without Burp, are `history` (`history_list`, `history_search`, …).
- Sending a request is `http` (`http_send_request`, `http_fuzz`, `http_race`, …), not `proxy`.
- Testing one vulnerability class (CORS, JWT, IDOR, injection, cache poisoning) is `recon`
  (`probe`), not `scanner`. `scanner` is a full Burp Scanner crawl/audit.
- Comparing one request across privilege levels is `authz` (`auth_diff`, `autorize`).
- Check scope (`settings` → `scope`) before sending traffic.

## Burp lifecycle (domain `lifecycle`)
- `execute({"tool":"burp_status","arguments":{}})`: every project of this target and its state
  (stopped, starting, running).
- `execute({"tool":"burp_up","arguments":{"project":"day2"}})`: starts Burp with Raijin for that
  project (headless by default; `"mode": "ui"` opens a window). It keeps running after this
  session. `wait_seconds` (default 60) bounds the wait; a `starting` result means call
  `burp_status` again shortly.
- `execute({"tool":"burp_down","arguments":{"project":"day2"}})`, or `"arguments":{"all":true}`,
  stops it.
- Nothing starts Burp on its own: a Burp tool with no Burp running fails with
  `no Burp running for this target`; start one with `burp_up` first.
- In remote mode Burp is managed elsewhere; only `burp_status` exists.

## Several projects
Each project is its own Burp with its own `.burp` file. With more than one running, pass
`project` next to `tool`: `execute({"tool":"proxy_history","arguments":{"limit":5},"project":"day1"})`.
With one running, or the default project running, `project` can be left out.

## Large results
Results over the inline limit come back as
`{"saved_to": "...", "bytes": N, "preview": "...", "hint": "..."}`. The preview is the first 2 KiB.
Parse the file with `jq` or a short Python script, or hand it to a subagent; never read it whole
into context. Narrow the next call instead (filters, `limit`, `max_body`).
