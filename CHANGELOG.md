# Changelog

## 2.4.1

### Tool calls
- Every error is one JSON object: `error`, `code`, and when they help `param`, `got`, `allowed`, `did_you_mean`, `usage`, `example`, `retry` (a complete corrected call, given only when the fix is certain), `retryable` and `see`. A handler error about a value outside its enum becomes `invalid_enum` with `allowed`; other argument errors get `code: invalid_arguments`.
- Strings that clearly mean a number or boolean (`"20"`, `"true"`), whole floats for integers (`5.0`) and enum values in another case or spelling (`sha256` for `SHA_256`) are read as the declared type; the result says so in `notes`. A misnamed parameter from another tool's vocabulary (`limit`, `offset`, `uri`, ...) suggests the right one with a ready `retry`.
- Tool names are resolved forgivingly: case and `-`/`.`/space separators (`Burp.Version`), old member names, `group.action`, and `util.sha256` / `sha256` as `util.hash` with that algorithm. A destructive tool never runs from an inexact name; it comes back as `unknown_tool` with the exact call in `retry`.

### Extension
- Tool API: `GET /api/v1/info` carries the server instructions; `GET /api/v1/resources` and `GET /api/v1/resources/read?uri=` expose the MCP resources. `POST /api/v1/tools/<name>` answers an unknown name with an `unknown_tool` result (suggestions, `retry`) instead of a 404, and gives error `example`/`retry` as `run` calls (`{"do":"tool.action",...}`).

### raijin CLI
- `run` and `guide` errors use the same envelope: `run {}` shows a working example, a `batch` sent as a JSON string is parsed, a bailed batch says which step failed and which did not run, an unknown `guide` topic lists suggestions instead of the whole overview, and `guide` matches topics without case (`HTTP_SEND_REQUEST`).
- The CLI's own tools (`burp_*`, `history_*`) read `"1"` as `1`, match enum values without case, accept their names in any case (`History.List`), and refuse wrong types, enum values, negative counts and missing parameters with `param`, `usage` and `example`.
- Names the CLI does not own go to the extension as given; it resolves them. `raijin mcp` lists and reads the running Burp's `burp://` resources next to the playbooks.

## 2.4.0

### Extension
- New JSON tool API on both MCP listeners: `GET /api/v1/info`, `GET /api/v1/tools`, `POST /api/v1/tools/<name>` (body = the tool's arguments). It sits behind the same Host/Origin, source-IP and bearer checks as `/mcp`, and its calls show up in activity and the audit log.
- Skills are gone from the extension's MCP server: no prompts, no `skill://` resources, no `burp://skills/manifest`, no `search_skills` / `load_skill` (43 tools remain). The playbooks ship with the `raijin` CLI. A client pointed at `:9876/mcp` directly no longer gets them.

### raijin CLI
- `raijin update` installs the latest release of the CLI and of `raijin.jar` beside it (`--check` only reports; `raijin update <version>` installs that release, older ones included; `--force` reinstalls and restarts the current target's running Burp projects). `raijin up` notes when a newer release exists (checked at most once a day, off with `RAIJIN_NO_UPDATE_CHECK=1`).
- `raijin mcp` speaks MCP 2026-07-28 (`server/discover`, stateless `_meta`) and the legacy `initialize` handshake. Two tools replace `discover` / `execute` / `skill`: `guide` (no topic: running Burp instances, every tool by domain with its actions, the playbooks; with a topic: one tool's `inputSchema`, a domain's tools, a playbook or a playbook file) and `run` (`{"do":"scope.check","url":"..."}`, `project` to pick the Burp, `batch` with `bail` for several steps).
- Burp tools go through the extension's `/api/v1` tool API instead of an MCP client session.
- The nine playbooks (`overview` now includes the old `raijin-gateway`) are rewritten as `SKILL.md` + `references/*.md`, with every call in `run {"do":...}` form, and served as prompts, Skills-extension entries (`io.modelcontextprotocol/skills`) and `skill://` resources.

## 2.3.1

### Tool calls
- Every published tool rejects parameters it does not declare (`code: unknown_parameter`, with `did_you_mean`), instead of ignoring them. Argument errors carry `code`, `usage` (every accepted parameter, `*` = required) and `example` (a correct call to adapt); `missing_action`, `unknown_action` and `missing_parameter` replace the old `error`/`message` pair. `http_race` no longer accepts the retired `gate_delay`; `auth_diff` and `probe(action=idor)` declare the `tls` alias they already read.
- Grouped tools accept the action as the old tool name (`scope_list`), in any case, or dotted (`scope.list`). A value sent as a JSON string where an object or array is declared, an object where a string is declared, or a single value where an array is declared is converted to the declared type.
- Tool descriptions call grouped actions as `scope(action=list)` instead of old tool names and show an example call. Every tool carries MCP annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`); `catalog/tools.json` adds them plus `aliases` (old tool name -> `{tool, action}`).

### raijin CLI
- `execute` accepts `name` for `tool`, `args`/`params`/`parameters`/`input` for `arguments`, `arguments` as a JSON string, and tool parameters put next to `tool`. Old tool names (`scanner_start_crawl`) and `scope.list` run the grouped tool with that action. On the lean surface, a Raijin tool called directly runs as `execute`.
- `discover` takes a tool name as the domain (adds `matched_tool`) and shows each tool's annotations. Unknown parameters and skills get "did you mean" hints. Instructions, tool descriptions and the `raijin-gateway` skill show literal JSON calls and how to recover from each error.
- Archived scanner issues also store the issue type's `background` and `remediation_background` (Burp's issue definition), which `history show` returns: Burp's built-in passive issues leave `detail` and `remediation` empty.
- `history show` of a proxy ref that does not exist says `no proxy entry <project>:<id>` instead of calling the project malformed.
- `history list` with `limit: 0` returns only `total`, as `proxy_history count=0` does, instead of raising the limit to 1.
- `history endpoints` skips blank body parameter names (a form body of a single space).
- The jar default is `raijin.jar` beside the `raijin` binary (where `install.sh` puts it) when its SHA-256 is this release's, else the download to `~/.raijin/jars/`.

## 2.3.0

### raijin CLI
- New Rust CLI `raijin` (`cli/`), released per platform as `raijin-cli-<version>-<target>.tar.gz`. `raijin init` makes a folder a target (`raijin.toml`, `burp/`, `.raijin/`) and registers `raijin mcp` in `.mcp.json` and `.omp/mcp.json`. With no `raijin.toml` in the folder or above it, every other command (and `raijin mcp`) creates the default one (project `main`) in the current folder and continues; it does not touch the agent MCP files.
- `raijin up [project] [--ui]` starts Burp with Raijin for a named `.burp` project, headless by default, detached, on free ports, under an isolated profile (`~/.raijin/burp-profile`, seeded once from your Burp user config without its extensions); several projects run at once. `raijin down`, `raijin status`. On macOS Burp is started through its app launcher: PortSwigger's bundled `java` refuses other parents.
- `raijin mcp`: a stdio MCP gateway with three tools (`discover`, `execute`, `skill`), so an agent loads tool schemas per domain instead of all 45 up front. `execute` also runs `burp_up` / `burp_down` / `burp_status` and the history tools; results over `[mcp] inline_limit_kb` are saved to `.raijin/tool-results/` and returned as `{saved_to, preview}`. `--surface full` also lists every Raijin tool; `--remote <url>` drives an already-running Raijin.
- `theme = "dark" | "light"` in `raijin.toml` (default `dark`) sets Burp's look and feel on every `raijin up`.
- `task_engine = "running" | "paused"` (default `running`): Burp pauses every task when it reopens a project, so proxy traffic stopped reaching the site map; `raijin up` now passes `--unpause-spider-and-scanner` unless set to `paused` (unfinished scans in the project resume too).
- A headless launch on macOS no longer leaves Burp's splash screen on screen.
- `install.sh`, attached to each release: `curl -LsSf https://github.com/bitbytelabio/raijin/releases/latest/download/install.sh | sh` installs the CLI for the current platform and the extension as `raijin.jar` into `~/.local/bin` after checking their `.sha256` (`RAIJIN_VERSION`, `RAIJIN_INSTALL_DIR` override).
- `raijin history list|show|search|endpoints|diff|export` (and the matching `history_*` tools) read every `.burp` project of a target in parallel without Burp, through a vendored copy of amber (see NOTICE), together with Raijin's archive of tool-sent traffic and scanner issues.

### CLI support in the extension
- Headless Burp (`-Djava.awt.headless=true`): no Raijin tab; the startup lines go to Burp's output log.
- `POST /api/shutdown` on the dashboard, only when `-Draijin.controlToken` is set and the `X-Raijin-Control-Token` header matches.
- With `-Draijin.archiveDir`, the requests `http_send_request`, `http_send_requests_parallel`, `http_send_raw_bytes`, `http_send_request_chain`, `http_race` and `http_send_pipeline` send, and the scanner issues Burp reports, are appended to `exchanges.jsonl` / `issues.jsonl` there.
- The jar ships `catalog/tools.json`: every published tool's schema, grouped into domains (`tools/ToolDomains.kt`).

### Scope
- One scope gate for every send path. `mcp_scope_mode=warn` (default) sends and puts `scope_warning` first in the result; `enforce` refuses with one error shape (`out_of_scope: true`, `scope_mode`, a pointer to `scope(action=include)`); `off` checks nothing. The URL checked is always where the bytes go: the connection's host and port plus the request path, never the host of an absolute-form request line or a Host header. Fuzz, race and pipeline check every distinct request they will send, and a `host` that cannot be put into a URL is refused under enforce.
- Batch tools (`http_send_requests_parallel`, `http_send_request_chain`, `api_import_openapi`, content discovery) check every item: a refused item is skipped, the rest go out, and the result counts `skipped_out_of_scope` / `sent_out_of_scope`. Before, one out-of-scope item refused the whole parallel batch.
- Turbo runs, Scanner tasks, WebSocket opens and followed redirects are advisory: flagged (`scope_warning`, `scope_warnings`), never refused. Turbo flags every origin a script queues to.
- Scope decisions show in the MCP Activity tab (warning-coloured rows, an Out-of-scope count, the warning in Info), in the `tool.called` event and in the audit log (`out_of_scope: true`, and the call is always audited). The Rules ▸ Scope tab shows the current mode.
- `preference_store` accepts only `off`, `warn` or `enforce` for `mcp_scope_mode`, and every change or delete is announced (`scope.mode_changed` event, a line in Burp's output). The Server tab follows a change made by a client.

### Sending
- Structured inputs lose raw CR/LF only (reported in `warnings`); NUL, VT and other bytes reach the wire. The WebSocket and GraphQL subscription handshakes send headers exactly as given.
- `url` is split leniently: the request target goes out as written (no re-encoding), hosts with `_` work, and the Host header is the URL's authority while `host`/`port` only move the connection. `url` with `raw_request` sends the raw request to the url's target. `use_tls=false` without a port means port 80.
- `http_send_raw_bytes` defaults to HTTP/1 and notes an HTTP/2 response.
- `http_fuzz` and `http_race` count Content-Length in the bytes they send (ISO-8859-1 unless a char needs UTF-8), keep a fuzzed Content-Length as rendered, and take `auto_fix_content_length`.
- Raw header blocks keep names as written; duplicate headers and lines without `:` are reported. A list argument like `"[admin]"` stays one value.
- Batch items honour `auto_fix_content_length` and `preserve_headers`, report their own fix and header warnings, and refuse fields only `http_send_request` supports.
- Parallel sends keep the responses a slow group did not time out; a chain step needs a response to succeed and reports `extract_missed` and `unresolved_placeholders`.
- `report=all` fuzz runs cap listed bodies at 20,000 characters unless `max_response_length` is given.
- Exchanges the `http_send_*` tools add to the site map carry their `[MCP]` note, so `sitemap(note_contains="[MCP]")` finds them; the note used to be set after Burp had stored its copy.

### Turbo
- A run reads `completed` only after its responses are ranked and the script has finished; callback exceptions are counted in `callback_errors` / `last_callback_error` instead of as connection failures.
- Each run gets its own Python state; a stop no longer reports a "User Python error"; a cancel from a callback no longer waits for itself; every engine of a multi-engine run is stopped and counted, with unique request ids.
- HEAD, 204, 304 and 1xx responses end at their head; `Connection: close` and HTTP/1.0 responses close the connection. HTTP/2 and HTTP/3 bodies are capped at 10 MB like HTTP/1.
- A payload containing `%s` is not substituted again. `timeout_ms` and `limit` are clamped; a cancelled wait answers with the current state. Organizer saves report failures; exports write the exact bytes.

### Other fixes
- Proxy history items carry Burp's `id` and their list `index`; `proxy_annotate` takes that `id` (the parameter was `index`); searches take `start_index`, return `next_start_index` and count `skipped_oversize`. The Proxy Explorer shows the newest entries first and sends Burp's own request to Repeater and Intruder.
- GraphQL POI scan matches camelCase and plural field names; `auto_headers` takes the newest request that carried credentials and never sends a header twice.
- Limits of injection, GraphQL, recon, cache probe and events tools are clamped and reported instead of refused.
- JWT `psychic` also returns `token_raw_rs`; HMAC `alg` is case-insensitive. `scope(action=include)` reports when an exclude rule still wins.
- Stores replace lone surrogates, repair a cut-off last line and create owner-only files; the audit log keeps arguments as JSON and records the project.
- Listener restarts cannot leave a stale listener behind; Streamable HTTP sessions idle out after 24 hours (256 at most), and legacy SSE accepts requests up to 64 MiB.

## 2.2.1

### Logging
- The startup log lists only the Streamable HTTP `/mcp` URLs; the legacy SSE URL is no longer printed (the endpoint is still served at `/`).
- The Turbo load message reports the Raijin version instead of a fixed `2.1.0`.

## 2.2.0

### Skills
- Skill prompts use the plain kebab-case skill name, without the `_skill` suffix: `/mcp__burpsuite__http-testing` in Claude Code, `burpsuite:http-testing` in omp.
- Renamed skills: `burpsuite-overview` is now `overview`, `recon-and-probes` is now `recon-probes` (prompts, `skill://<name>/SKILL.md` resources and tools alike).
- `load_skill` takes a skill `name` (e.g. `overview`) or a `skill://<name>/SKILL.md` `uri`. `read_skill_file` is gone; `search_skills` and `load_skill` cover clients that only call tools.

### Logging
- The MCP SDK's kotlin-logging startup banner and INFO/WARN connection messages are silenced; SDK errors still reach Burp's error log.
- Listener and dashboard startup messages are no longer written to the extension output.

## 2.1.0

### Build and dependencies
- Java 25 bytecode: the jar needs Burp running on Java 25 or newer. Built with Gradle 9.9.1 (Shadow 9) on a JDK 25 toolchain and daemon; CI on JDK 25.
- Ktor 3.6.1, kotlinx-serialization 1.13.0, graphql-java 26.2, Jython 2.7.4, RSyntaxTextArea 4.0.1 / RSTAUI 4.0.0, Kwik 0.12.3, Nimbus JOSE+JWT 10.10, BouncyCastle 1.87, Tink 1.24.0, SnakeYAML 2.7; tests on JUnit 6.1.3.
- Turbo HTTP/3 always carries requests and Kwik reads on virtual threads; the platform-thread fallback for JDKs before 24 and its 4,096-request cap are gone.
- Turbo HTTP/3 refuses a stream frame too large for one QUIC datagram instead of letting Kwik 0.12's 16-bit frame length wrap.
- XPath value extraction parses XML up to its documented depth of 256 on Java 25; JDK 24 lowered the parser's own limit to 100.

## 2.0.0

### Remote access and transport
- Remote/VM mode: a non-loopback bind (operator opt-in `mcp_allow_remote_bind`) or `mcp_require_auth` makes every listener, MCP and dashboard, require `Authorization: Bearer <token>`. The token is generated with `SecureRandom`, kept in `mcp_auth_token`, compared in constant time and never logged. Optional source IP/CIDR allowlist (`mcp_allowed_ips`, the TCP peer only, never `X-Forwarded-For`) and extra allowed host names (`mcp_allowed_hosts`); every setting also has a `-Draijin.*` property. Loopback stays token-free. See [SECURITY.md](docs/dev/ultra/SECURITY.md#remote--vm-mode).
- Browsers log in once with `?token=`: the `HttpOnly; SameSite=Strict` cookie holds a digest of the token and of the listener's ports, so it opens only the listener that set it, and it expires after 12 hours. A CORS preflight skips the token only with exactly one well-formed allowed `Origin`; any other `OPTIONS` needs it.
- A rebind keeps the stricter of the old and new remote settings until every listener has moved, so leaving an exposed bind never serves it without a token.
- Server tab: bind-host picker, Require Auth Token, token Show/Hide/Regenerate/Copy, allowed IPs and hosts, Save & Rebind Now, and Copy MCP Config / Copy Command with the token when it is required; toggles for `mcp_scope_mode` and `mcp_allow_destructive`.
- IPv6 hosts are accepted (`Host: [::1]:9876`) and bracketed in dashboard URLs; Host and Origin compare case-insensitively. A listener configured on another's port moves for the session, never onto a port another listener is configured for, and the log names the preference to fix.
- Both MCP listeners share one server; legacy SSE sessions are capped and released when a client disconnects. Tool handlers run off the CPU dispatcher.
- `configs/Caddyfile`: Profile A (local proxy on `127.0.0.1:9900`–`9902`) names its hosts and refuses any other Host, because its `Host` rewrite hides the original from Raijin's DNS-rebinding check; Profile B is a remote-VM setup with `tls internal`, a bearer check and dashboard basic auth. `mcp-claude-desktop.json` uses Streamable HTTP `/mcp`; `setup.sh` runs `./gradlew build`.
- Activity, audit and findings files: one lock per file, atomic rewrites, rotation (the audit log at 20,000 lines or 16 MiB), write failures reported to Burp's error log. The audit log also records failed and cancelled calls and every state-changing tool family, without the read-only members.
- Unload no longer erases saved data: removing a finding deletes it from disk by id, and the Raijin tab's queued saves write the state from before the unload cleared it.
- `events(action=subscribe)` opens a poll subscription read with `events(action=get, subscription_id=...)` (at most 64, least recently used dropped); `events(action=clear)` keeps the dashboard and tab feeds.
- Dashboard: static page served from resources with ETags, recent history loaded on open, the real ports from the new `/api/info`, copy-paste commands with current tool and action names, autorize and intercept events; `/api/proxy/recent` returns metadata, newest first, unless `include_request` / `include_response` are set.

### Tools and schemas
- Grouped tools merge a parameter several actions share: enums are united, every action keeps its own description and constraints, and a type conflict accepts any JSON value ([details](docs/dev/tool-consolidation.md#parameters-shared-by-several-actions)). A member parameter colliding with `action` now fails at startup.
- `http_rule(action=traffic_rule_set)` publishes the member's `action` as `rule_action` (`modify`, `drop`, `spoof_response`), so drop and spoof rules work.
- Tool errors set `isError` everywhere and stay valid JSON whatever the message holds (quotes, backslashes, newlines). Closed parameters declare an `enum`; numbers are bounds-checked.
- Oversized `max_results`, `max_response_length` and `max_depth` (`sitemap`, `organizer`, `util(action=decode_smart)`) and paging counts (`proxy_history`, `autorize(action=list_matches)`) are clamped and reported (`<param>_clamped_to` or a note) instead of failing, as are `analyze(action=response_body_search)`'s `max_results`, `recon(action=js_endpoints)`'s `max_items`, `recon(action=param_mine)`'s `offset`, `probe(action=idor)`'s `enumerate`, and a `max_results` or `max_depth` below its minimum in `scanner(action=get_all_issues)` and `scanner(action=start_crawl)`. Integer arguments accept whole-number decimals such as `50.0` or `5e1`, read exactly.
- `sitemap(action=query)` searches only the URL unless `search_in` says otherwise, as documented; `sitemap(action=get_issues)` filters on `FALSE_POSITIVE`; `log(action=message)` accepts every level again.
- `organizer(action=get_items)` returns `id`, `notes` and `highlight`; `util(action=decode_smart)` reports `fully_decoded` correctly; `ai(action=prompt)` sends its `context`; findings reject a NaN `cvss_score` and take `critical`, `high`, `medium`, `low` or `info`.
- User regexes in checks, rules, searches and Intruder processors run through a bounded regex engine; bad patterns and replacement references are rejected when set.

### HTTP
- New `http_send_pipeline`: several raw HTTP/1.1 requests over one socket, every response read back in order, for desync and 0.CL research. Strict framing (a bad Content-Length, chunk size or chunk CRLF stops with `close_reason: "error"`), chunk trailers per response, `switching_protocols` after a 101, no body for `HEAD`; `keep_open` / `connection_id` reuse a socket only when the server keeps it.
- `http_send_pipeline` reads while it writes, and each response carries its raw bytes (`raw_response_hex`, capped by `raw_hex_max_bytes`) and `ttfb_ms`/`ttlb_ms` from when its request was completely written (negative: the response began first). Requests pause mid-write as in Turbo (`pause_before`, `pause_markers`, `pause_ms`); `sni` sets the TLS server name; `decode_content` undoes gzip and deflate; bodies show as UTF-8 when they are valid UTF-8. The new `http_state(action=pipeline_connections)` lists the kept connections and closes them (`close`, `close_all`, `force`).
- Raw requests keep their body: only the header block's bare LF becomes CRLF, and Content-Length is fixed in place, counted in the bytes sent. In `http_send_raw_bytes` and `http_send_pipeline`, literal `\r\n` escapes are decoded only when the text has no real line break, and a character above U+00FF sends UTF-8 instead of `?`.
- `http_send_request`: `http2_headers` sends a native HTTP/2 request whose header list goes out as given, pseudo-headers included (repeated, reordered, missing, CR/LF, uppercase); a list without pseudo-headers gets the four derived from the URL. Burp's request options `follow_redirects`, `sni`, `response_timeout_ms` and `verify_tls`.
- `http_fuzz` runs Intruder's attack types: `attack_mode` `sniper` (default), `battering_ram`, `pitchfork` and `cluster_bomb`, with one payload set per position in `payload_sets`. A sniper run over several positions now goes position by position, in Intruder's order. `encoders` (`url`, `url_all`, `double_url`, `json`, `base64`, `base64url`, `html`, `hex`, `raw`), `concurrency`, `rate_limit` and `max_requests` shape the run; every response is clustered by status and body similarity with timing outliers; `hide_status`, `filter_length`, `grep_regex` and `hide_regex` shorten the list, and `report` (`all`, `clusters`, `summary`) sets how much of it is returned.
- `http_race` releases its requests behind a real synchronisation barrier instead of a sleep. `sync=single_packet` (default) is the HTTP/2 single-packet attack through Burp's parallel sender, the route of Repeater's group send and Turbo's gated `BURP2` engine. `sync=last_byte` writes HTTP/1.1 requests on Raijin's own connections except for their last bytes and releases those together (at most 256 connections; `sni`; per-request `ttfb_ms`/`ttlb_ms`; `release_spread_us`), bypassing Burp: no session rules, nothing in the site map. Responses are clustered with timing outliers and `race_condition_likely`, which replace `status_variation` and `length_variation`; `gate_delay` is gone (passing it adds a note).
- `timeout_ms` on `http_send_request_chain` (per step), `http_fuzz` (per request) and `http_race` (whole batch), default 25 s; `timeout_ms: 0` means no hard timeout; a failed fuzz request is recorded and the run goes on. `http_send_request_chain` takes `connection_id`, `http_fuzz` takes `stop_on_match` and recomputes Content-Length after each substitution, as does `http_race`; inactive `§` markers are stripped, odd markers and overlapping positions rejected. Out-of-range counts and limits (`count`, `concurrency`, `max_responses`, ...) are clamped and reported in `notes` instead of refused.
- Payload libraries `ssrf`, `xxe`, `crlf`, `nosqli`, `open_redirect`, `prototype_pollution`, and unquoted numeric `sqli` entries.
- `tool_filter` on `http_rule(action=traffic_rule_set)`. Raijin's internal unauthenticated probes (`auth_diff`, `autorize`, `probe(action=idor)`) no longer receive session tokens or traffic-rule headers unless a rule's `tool_filter` names `EXTENSIONS`, which removes false "bypass" findings. Traffic-rule header lines are stored and sent exactly as given, CR/LF and a missing colon included.
- Session token rules (`http_rule(action=token_rule_create)`) select the value by `extract_json_path` or `extract_xpath` as well as `extract_regex`, and a header rule reads every line of its header (each `Set-Cookie`). `inject_into` adds `query` and `json` (a JSONPath naming one value, replaced in place, numbers kept numbers), templates take encoders (`{value|url}`, `{value|base64|url}`), and `inject_if_missing=false` only updates what a request already carries; a value with CR/LF is never injected. `http_send_request_chain` extract rules take `json_path` and `xpath` too.
- New login macros: `http_rule(action=macro_set)`, `macro_list`, `macro_remove` and `macro_run`. When a covered response shows an expired session (`trigger_status`, default 401, or `trigger_regex`), the macro replays its login steps and sends the original request once more; that response replaces the expired one and the tool result carries `reauthenticated`. One run at a time per macro, `min_interval_ms` between automatic runs, `step_timeout_ms` per step and for the retry, at most 20 steps and 60 s per run, and suspension after `max_failures` runs that did not help. Proxy traffic (`tool_filter`) and requests without credentials (`require_credentials`) are left alone by default; steps, retries and Raijin's internal probes never trigger a macro.

### Proxy and WebSockets
- New hold queue in `proxy_intercept`: `hold` parks matching proxied requests and/or responses just before they are sent, `list_held` shows them (optionally waiting), `forward` sends one as it is or edited (method, path, status, headers with CR/LF allowed, body, or a raw replacement), `drop` discards one or all, `release` stops holding. An unanswered hold is forwarded after `timeout_seconds` (default 60), at most `max_held` (default 20) are held, and after 3 timeouts in a row holding stops by itself.
- Proxy rules can modify the method, the path (`modify_path_regex` with `$1` groups) and the response status, and `modify_set_header` replaces every occurrence of a header or adds it; header lines are accepted with CR/LF again. `proxy_auto_auth` replaces an existing auth header instead of adding a second one.
- Proxy history no longer fails on a malformed request (`malformed_request: true`); status filters never match items without a response. WebSocket history filters by `websocket_id` and `url`.
- New WebSocket actions: `wait_message` blocks until a matching frame arrives after `since_index` (pass the `message_index` a send returns; continue with `next_since_index`), `fuzz` sends payloads over an open or a fresh connection per payload and clusters the responses, `list_intercept_rules` and `remove_intercept_rule`. Intercept rules take `message_type` and also match and rewrite binary frames (`\xNN` matches a byte), including rules set before without one. Binary data accepts standard or URL-safe base64 and round-trips byte for byte.
- `websocket(action=get_messages)` never skips a frame and reports `oldest_index`, `next_index`, `has_more` and `missed_messages`; frames right after the handshake are recorded; a frame whose send fails stays as `TEXT_UNSENT` / `BINARY_UNSENT`; unload closes every connection Raijin opened.

### Access control
- `auth_diff`, `probe(action=access_control)`, `probe(action=idor)` and live `autorize` share one identity applier: a level's headers (`headers`, `remove_headers` for several) replace the request's own, `none`/`unauth`/`anonymous` strips every credential header, Content-Length is fixed, and each level reports `headers_set`, `headers_removed`, `credential_headers_kept`.
- Fewer false positives: alike refusals (same 401/403/404/5xx, a login redirect, a 200 login or denial page, `denied_regex`) are informational, never high or critical; every level must be granted for `all_identical`; a level with no response goes to `errors`. New ids `all_identical_soft_denial`, `unauth_soft_denial`, `unauth_redirected`, `static_asset_accessible`. A JSON body counts as a refusal only by its top-level code, error or message field, not by words in its data.
- `probe(action=idor)` swaps ids at their parameter boundary (path segment, query/form/cookie/header value, JSON value by position), takes `id_name`, prefers an identity's own `object_id`, and confirms transformed ids by canary. A pinned `id_value` may begin a path segment (`42` of `/users/42-alice`); auto-detection never picks a header just because its value equals an `object_id` (a lone `1` there is a flag such as `DNT`); without the reader's own view (`own_view: false`) only a canary grades a transformed id above info.
- `autorize`: `POST`, `PUT`, `DELETE` and `PATCH` are replayed only with `include_mutating`; originals without credentials or answered 401 or 404 are skipped; each endpoint is tested once per query string (at most 50 variants). Matches persist per project (`~/.raijin-autorize.jsonl`) with every identity's replay, are emitted as `autorize.match` events, and are paged by `list_matches` (`include_replays`, `match_id`); soft denials are kept and marked. Replays are bounded and never block the proxy. New Autorize tab with rules, live matches and original-vs-replay viewers.

### Injection, recon and probes
- `probe(action=injection)`: ten classes (`sqli`, `nosqli`, `cmdi`, `ssti`, `lfi`, `xxe`, `ssrf`, `xss`, `open_redirect`, `crlf`), `FUZZ` anywhere with the encoding that position needs (`encoding`, `base_value`), out-of-band confirmation through a Collaborator client it manages itself (`oob`, `oob_wait_seconds`), and `time_budget_seconds`. Each finding carries `payload`, `confidence` and `evidence` (baseline next to probe); a timeout is never evidence, delays and TRUE/FALSE differences must repeat under controls; late out-of-band hits arrive as `late_oob_interactions`. Boolean and operator checks only narrow the query (no `OR`, no range or regex that matches other rows or documents), so a `FUZZ` in a `DELETE` or `UPDATE` reaches nothing the baseline request does not; `base_value` must match a real row or document.
- New `probe(action=cache)`: web cache poisoning (unkeyed headers and cookies under their own cache buster, confirmed by an anonymous request) and web cache deception. An input that changes the status, a redirect or the path waits until a new cache buster is seen to get a cache entry of its own; unproven isolation or a changed visitor baseline gives `inconclusive`, never a confirmation, and a run can stop with `rate_limited`, `baseline_changed` or `cache_buster_ignored`.
- `recon(action=param_mine)`: many names per request with a binary search in buckets, so the bundled list costs a few hundred requests; `headers`, `cookies`, `body`, `cache_buster`, `offset`/`limit`, `bucket_size`, `max_requests`, `name~value` candidates; `diff` uses repeated baselines and `Location`/`Set-Cookie`/`X-Cache`; a cache buster the target rejects is dropped and reported (`cache_buster_dropped`).
- `recon(action=content_discovery)` learns not-found behaviour from several made-up paths first and stops with `stopped_at` when blocked; `recon(action=js_endpoints)` reads `.mjs`/`.cjs`, template literals and source maps (`fetch_source_maps`).
- `probe(action=cors)` sends origins derived from the target as GET and preflight and checks `Vary: Origin`. `analyze(action=passive_intel)` adds GitHub, GitLab, OpenAI and Anthropic token and source-map patterns, drops noisy ones, skips binary bodies, bounds scans and reports each distinct value once with its `occurrences` and up to four more places (`also_seen`), so a token sent on every page takes one slot of its category; `categories` takes partial names (`aws`).
- GraphQL: new `subscription_probe` mode (both WebSocket protocols, `init_requires_auth`, `subscription_requires_auth`; the anonymous session keeps only `Host`, `Origin` and `User-Agent` of the caller's headers, and Docker-style host names with `_` work); `cycles_scan` lists every cycle with `cyclic_types`; `poi_scan` follows interfaces and unions; `bruteforce_schema` batches guesses, never sends an executable document and stops at `max_requests`; `batch_attack` is capped at 10,000 operations; an unreachable target is one error.
- `api_import_openapi`: YAML, OpenAPI 3.1, `oneOf`/`anyOf`/`allOf`, every `$ref` target, cookie/form/multipart/XML/`+json` bodies, percent-encoded parameters, relative and templated servers (`spec_url`), and `security_schemes` in the result. YAML expansion and the whole import are size-capped against hostile documents. A server URL that names an unusable host is an error, never a silent switch to the `spec_url` host.

### Scanner, Collaborator and JWT
- New `custom_check(action=bcheck_dry_run)` and `custom_check(action=scancheck_dry_run)` (try a definition on recorded proxy history, nothing sent) and the `bambda_templates` tool. Active checks report only when the unmodified request would not match too; that request is sent before the first payload, so a payload the application stores cannot hide its own match, and a step without response conditions only primes the target. `match_mode` per check and step; creating a check under an existing name replaces it; generated BChecks escape all input and follow PortSwigger's grammar. `scanner(action=start_audit)`'s auth header applies to Scanner traffic to the audited hosts only, until the audit ends; a `Cookie` one sets only the cookies it names.
- Collaborator clients survive a reload (`collaborator(action=list_clients)`); `poll` reads a history with a `since` cursor, `limit` and `payload_id` (now returned by `generate_payload`), returns full HTTP exchanges, and decodes DNS names strictly. The tab shows every interaction of a payload.
- JWT: `header_url` with `key_id` signs the token and returns the JWK set or certificate chain to host; signing keeps the payload byte for byte; `verify` explains failures and requires an `alg` that fits the key; every key lists its `modes`; OKP keys export to PEM; `decrypt` refuses a PBES2 `p2c` above 1,000,000 (CVE-2023-52428). JWT tab: JWE, `alg` pickers, buttons enabled by key modes, the `header_url` document pane.

### Turbo
- `idleTimeout` is milliseconds without activity on every engine (THREADED read seconds, BURP and HTTP/2 ignored it); `req.time` is microseconds everywhere; `engine.queue(delay=...)` is accepted and ignored.
- A stop during `start()` stands; overflow before `start()` waits in order, `queue()` does not block while that backlog holds requests, and `openGate()` / `complete()` drain it in order within their timeouts.
- `table.setSortOrder(column, descending)` sorts the GUI table (replacing the anomaly-rank auto-sort) and sets the default order of `turbo_run(action=results)`, which accepts every sort field and reports the order it used.
- BURP gated requests are ranked `req.order` 0, 1, ... by time to first byte; unanswered ones get `-1` and are called back after the ranked ones. `@MatchRegex`/`@FilterRegex` search anywhere in the response; `Unique*` decorators count per engine under a lock.
- HTTP/1 framing from raw bytes (case-insensitive Content-Length, 1xx skipped, trailers, per-request timing), SNI and connect timeouts; HTTP/2 completes reliably and honours the header table size; HTTP/3 skips 1xx responses, follows RFC 9204 QPACK capacity rules and closes every QUIC connection on failure.
- Desync: `http2case` works, shared techniques also apply to Content-Length, transfer-coding techniques moved to `TE_TECHNIQUES`, kettled requests decode escapes in the method, path and names, and a backtick in a name is a colon.
- MCP: `turbo_run(action=start_async)` and `turbo_run(action=list)`; `result` cuts the body to `body_limit` lines and 200,000 characters (`0` = whole); `turbo_docs` serves all 12 topics; run errors set `isError`.
- Runs tab with sortable columns and a detail pane; the script dialog is themed and closed on unload; memory pressure is judged against the heap, and result bodies past an eighth of it are dropped oldest first.
- Examples: `desync-h2-downgrade` queues with `kettled=True`; `desync-smuggler` uses `Engine.BURP` so `connectionId` keeps each attack and victim on one connection; `0cl-exploit` and `0cl-poc` write requests with explicit CRLF and work when started over MCP; `customSortOrder` sorts by status.

## 1.1.0

- GraphQL: `fingerprint_engine` mode detects the backend engine (Apollo, Hasura, graphql-java, and 25+ others) from malformed-query error signatures.
- GraphQL: `bruteforce_schema` mode reconstructs the schema from "did you mean"/type-mismatch error messages when introspection is disabled, via wordlist-driven probing (`bucket_size`, `depth_limit`, `bruteforce_arguments`).
- GraphQL: every mode accepts `headers` and `auto_headers` (reuse identity headers from the most recent Proxy-history request to the target host).
- GraphQL: `query_templates`/`poi_scan`/`cycles_scan` cache the fetched schema for 10 minutes, bypassable with `refresh_schema`.

## 1.0.0

First release of Raijin: BurpMCP-Ultra 2.3.2 and Turbo Intruder 2.0.1 merged into one extension.

- One MCP server named `burpsuite`: Streamable HTTP at `http://127.0.0.1:9876/mcp` (also 9877), legacy SSE at `/`, dashboard on 9878.
- About 40 tools covering 160+ operations; families of operations are one tool with an `action` parameter ([mapping](docs/dev/tool-consolidation.md)).
- Turbo exposed as `turbo_run` and `turbo_docs`; runs from the script dialog and from agents share one run list (Turbo sub-tab).
- Eight built-in skills, served as MCP prompts (`*_skill`), `skill://<name>/SKILL.md` resources and the `search_skills` / `load_skill` tools.
- JWT key ring (`jwt_keys`, JWT sub-tab) and extended JWT probe modes: sign/verify with ring keys, JWE, embedded JWK, empty HMAC, psychic signatures, `jku`/`x5u`.
- Decoder accepts several data items at once; Montoya API 2026.7.
- UI follows Burp's theme (dark and light); dashboard syncs to Burp's colours.
- Removed: MCP bearer token, Turbo's Jetty MCP server and standalone mode, `albinowaxUtils-all.jar`, the legacy Burp extender API, Jython `callbacks`/`helpers`.
- Namespace `io.bitbytelab.raijin`; Java 21 bytecode; requires Burp Suite 2026.2 or newer.

Earlier history: [BurpMCP-Ultra](docs/dev/ultra/CHANGELOG-burpmcp-ultra.md).
