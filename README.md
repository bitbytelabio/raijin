<div align="center">

# ⚡ Raijin

**One Burp Suite extension that gives AI agents hands.**

An [MCP](https://modelcontextprotocol.io) server that runs inside Burp Suite, merged with the **Turbo** scripting engine
for high-speed work: single-packet race conditions, HTTP/2 and HTTP/3 gates, request-smuggling probes.

[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
![Burp Suite 2026.2+](https://img.shields.io/badge/Burp%20Suite-2026.2%2B-orange.svg)
![Java 25](https://img.shields.io/badge/Java-25-red.svg)
![Kotlin](https://img.shields.io/badge/Kotlin-2.4-7F52FF.svg)
![MCP](https://img.shields.io/badge/MCP-Streamable%20HTTP-black.svg)

[Quick start](#-quick-start) ·
[Tools](#-tools) ·
[Skills](#-skills) ·
[Turbo](#-turbo) ·
[JWT](#-jwt-toolkit) ·
[Credits](#-credits) ·
[Security](#-security-model) ·
[Configuration](#%EF%B8%8F-configuration) ·
[Development](#-development)

</div>

---

## ✨ Highlights

| | |
|---|---|
| 🧰 **200+ operations, ~45 tools** | Proxy, Scanner, Repeater, Intruder, Collaborator, Organizer, site map, scope, WebSockets, cookies, config, Burp AI. Families of operations are grouped behind an `action` parameter so the client's tool list stays small. |
| 🏎️ **Turbo engine** | Python (Jython) scripts on a custom request engine: single-packet attack, HTTP/2 and HTTP/3, pipelining, timing analysis. Runs from Burp's UI or from an agent. |
| 🔎 **Recon and guided probes** | JS endpoints and source maps, calibrated content discovery, Param Miner-style parameter mining with its wordlists, fingerprinting; CORS, web cache poisoning and deception, GraphQL, injection (ten classes, out-of-band confirmation through Collaborator), access control, IDOR and JWT probes. Findings carry the evidence to re-check them. |
| 🛂 **Live access-control checks** | Autorize-style proxy tap: matching traffic is replayed in the background under lower-privilege identities; mismatches, with what each identity received, land in findings and on the Autorize tab and survive a reload. |
| 🕸️ **GraphQL toolkit** | Ported from InQL: query templates per field, points-of-interest and cycle scans, batched alias queries for brute force and rate-limit testing; plus engine fingerprinting, schema brute force without introspection and a subscription probe over WebSocket. |
| 🧬 **Request smuggling** | HTTP Request Smuggler's desync technique catalog, probe payloads and canaries for Turbo scripts, and `http_send_pipeline` for raw requests over one socket (mid-request pauses, the raw response bytes, timing per response). |
| 🔑 **JWT toolkit** | Key ring (RSA, EC, OKP, oct, password), sign, verify, JWE encrypt/decrypt, and the usual JWT test cases (`alg:none`, algorithm confusion, embedded JWK, psychic signatures, `jku`/`x5u` with the document to host, secret cracking). |
| 📚 **Built-in skills** | Eight usage guides served as MCP prompts and resources, so an agent learns the tools and workflows on its own. |
| 🖥️ **Native UI** | A **Raijin** tab that follows Burp's theme (dark or light): MCP activity, proxy explorer, scanner, findings, Autorize, Collaborator, rules (traffic, WebSocket, scope), JWT, Turbo runs, server settings with remote access. |
| 🔒 **No token on loopback** | Loopback bind plus Host and Origin checks. Remote/VM mode adds a bearer token and source-IP and host allowlists. |

> Raijin merges [BurpMCP-Ultra](docs/dev/ultra/README-burpmcp-ultra.md) and [Turbo Intruder](docs/dev/turbo/readme-turbo-intruder.md),
> and ports parts of [InQL](https://github.com/doyensec/inql), [HTTP Request Smuggler](https://github.com/PortSwigger/http-request-smuggler)
> and [Param Miner](https://github.com/PortSwigger/param-miner). See [Credits](#-credits) and [NOTICE](NOTICE).

---

## 🚀 Quick start

### 1. Requirements

- **Burp Suite 2026.2 or newer** (Montoya API), Community or Professional.
  The Turbo HTTP/3 engine and the `AUTO` engine need **Professional**.
- **JDK 25** to build. Another default JDK on `PATH` is fine: `gradle/gradle-daemon-jvm.properties` pins Gradle to 25. The jar needs Burp running on **Java 25 or newer**.

### 2. Build and load

```bash
git clone git@github.com:bitbytelabio/raijin.git
cd raijin
./gradlew build          # -> build/libs/raijin.jar
```

In Burp: **Extensions → Installed → Add → Extension type: Java →** select `build/libs/raijin.jar`.
A **Raijin** tab appears, and the extension output prints the endpoints and counts (`MCP Prompts: 8`, ...).

### 3. Connect your MCP client

**Claude Code**

```bash
claude mcp add --transport http burpsuite http://127.0.0.1:9876/mcp
```

**Any client with a JSON config** (`.mcp.json`, omp's `.omp/mcp.json`, ...)

```json
{
  "mcpServers": {
    "burpsuite": { "type": "http", "url": "http://127.0.0.1:9876/mcp" }
  }
}
```

**Clients that only speak stdio** (Claude Desktop): bridge to the Streamable HTTP endpoint with [supergateway](https://github.com/supercorp-ai/supergateway), see [`configs/mcp-claude-desktop.json`](configs/mcp-claude-desktop.json).

Then ask your agent something like *"Load the overview skill, check the scope, and summarise the proxy history for example.com"*.

> [!TIP]
> The **Raijin → Server** sub-tab shows the exact client config for your current bind address and ports; **Copy MCP Config** includes the bearer token when the listeners require one.

### CLI (optional)

The `raijin` CLI launches Burp with Raijin per target folder and serves the `raijin mcp` stdio gateway (macOS and Linux, x86_64 and arm64):

```bash
curl -LsSf https://github.com/bitbytelabio/raijin/releases/latest/download/install.sh | sh
raijin init              # in your target folder
```

`RAIJIN_VERSION` (e.g. `2.3.0`; default latest) picks the release and `RAIJIN_INSTALL_DIR` the destination (default `~/.local/bin`). The script installs `raijin` and the matching extension `raijin.jar` there (load it in Burp as in step 2), checks both against their `.sha256`, and does not edit your shell profile.

### Endpoints

| Endpoint | Default URL | Notes |
|---|---|---|
| MCP, Streamable HTTP | `http://127.0.0.1:9876/mcp` | **Use this.** Also served on `9877`. |
| MCP, legacy SSE | `http://127.0.0.1:9876/` | Root path, not `/sse`. Deprecated by the MCP spec; kept for old `"type": "sse"` configs. |
| Dashboard | `http://127.0.0.1:9878/` | Live web view of activity, stats, proxy traffic and rules. |

With remote access on, every endpoint needs the bearer token; see [Security model](#-security-model).

### Ready-made configs

| File | Purpose |
|---|---|
| [`configs/mcp-claude-code-direct.json`](configs/mcp-claude-code-direct.json) | Claude Code, direct to Burp. |
| [`configs/mcp-claude-code-caddy.json`](configs/mcp-claude-code-caddy.json) | Claude Code through the Caddy proxy on `:9900`. |
| [`configs/mcp-claude-desktop.json`](configs/mcp-claude-desktop.json) | Claude Desktop via supergateway (Streamable HTTP `/mcp`). |
| [`configs/Caddyfile`](configs/Caddyfile) | Caddy profiles: a local streaming proxy on `127.0.0.1:9900`–`9902` that checks the Host itself, and a remote-VM profile with TLS and a bearer check. |
| [`configs/setup.sh`](configs/setup.sh) | Builds the jar (`./gradlew build`), optionally installs the Caddyfile, prints the client config. |

---

## 🧰 Tools

Raijin exposes about **45 MCP tools** over 200+ operations. Frequently used tools stay individual; families of operations are one tool with a required `action` parameter, for example `scope(action=include)` or `scanner(action=start_audit)`. Each tool's description lists its actions and the parameters each one needs (required ones are marked `*`); a parameter several actions share keeps every action's description and allowed values. The member tools behind each action are mapped in [docs/dev/tool-consolidation.md](docs/dev/tool-consolidation.md).

<details open>
<summary><b>HTTP and proxy</b></summary>

| Tool | What it does |
|---|---|
| `http_send_request` | Send one HTTP request through Burp, from a URL or raw text; HTTP/1.1 or HTTP/2, including a native HTTP/2 header list sent as given (pseudo-headers too); Burp's redirect, SNI, response-timeout and TLS-verification options. |
| `http_send_requests_parallel` | Send many requests concurrently, across hosts. |
| `http_send_request_chain` | Send a sequence, extracting values from each response (regex, JSONPath or XPath) into the next request. |
| `http_send_raw_bytes` | Send exact bytes (hex or text) for smuggling and CRLF cases; one request, one response. |
| `http_send_pipeline` | Several raw HTTP/1.1 requests over one socket; every response read back in order with its framing, trailers, close reason, raw bytes and timing (desync and 0.CL work). Requests can pause mid-write; bodies can be shown decompressed. |
| `http_fuzz` | Intruder's attack types (sniper, battering ram, pitchfork, cluster bomb) on `FUZZ` or `§` positions: payload sets and built-in libraries, encoders, concurrency and rate limit, filters; every response clustered. |
| `http_race` | Release requests together behind a real barrier to test race conditions: HTTP/2 single-packet through Burp, or HTTP/1.1 last-byte on Raijin's own connections; responses clustered. |
| `http_rule` | Outgoing traffic rules (`rule_action`: modify, drop, spoof a response; `tool_filter` by Burp tool), session token rules (regex, JSONPath or XPath; injected into a header, cookie, form, query or JSON value) and login macros that log in again when a session expires. |
| `http_state` | Burp cookie jar: get, set, delete; the connections `http_send_pipeline` keeps open: list, close. |
| `proxy_history`, `proxy_history_search` | Read and search Proxy HTTP history (sensitive request headers masked unless the full request is asked for). |
| `proxy_annotate` | Highlight and comment history items. |
| `proxy_auto_auth` | Set an auth header (replacing any existing one) on every proxied request for a host pattern. |
| `proxy_rule` | Proxy request/response rules: modify (headers, body, method, path, status), drop, tag. |
| `proxy_intercept` | Burp's Intercept switch, plus a hold queue: park matching proxied messages, list them, forward them edited or as they are, drop them (unanswered holds are forwarded by themselves). |
| `websocket` | Open connections, send text or binary, wait for a reply, fuzz an endpoint, read messages, intercept rules (set, list, remove), WebSocket history. |

</details>

<details>
<summary><b>Scanning, recon and probes</b></summary>

| Tool | What it does |
|---|---|
| `scanner` | Start crawls and audits (an optional auth header applies to the audited hosts only, until the audit ends), read issues, generate reports, register checks. |
| `scanner_task` | Status, list, delete running scan tasks; add requests; read their issues. |
| `custom_check` | BChecks and passive/active scan checks: create from a template, import, dry-run against proxy history, list, remove. |
| `recon` | JS endpoints and source maps, calibrated content discovery, fingerprinting, parameter mining. `param_mine` checks reflection or behaviour changes (`mode=diff`) in the query, body, JSON body, cookies or headers, many names per request, with Param Miner's wordlists when no candidates are given. |
| `probe` | Guided probes: `cors`, `cache` (web cache poisoning and deception), `graphql`, `injection`, `access_control`, `idor`, `jwt`. See [GraphQL](#graphql) for the GraphQL modes. |
| `auth_diff` | Send the same request at different auth levels (admin, user, none) and compare responses; each level reports the headers it sent. |
| `autorize` | Live access-control tap: replay matching proxied requests under other identities and flag mismatches (`set_rule`, `list_rules`, `remove_rule`, `list_matches`, `clear_matches`). |
| `analyze` | Offline analysis: parse requests/responses, reflections, parameters, insertion points, diffs, keywords, passive intel. |
| `api_import_openapi` | Import an OpenAPI 3.0/3.1 or Swagger 2.0 document (JSON or YAML): build example requests (parameters, JSON/form/multipart/XML bodies), optionally send them and add them to scope and the site map; reports the security schemes each operation expects. |
| `bambda_import`, `bambda_templates` | Import a `.bambda` file into Burp; the envelope format, known functions and starting templates. |
| `collaborator` | Collaborator clients (kept across reloads), payloads, polling with a `since` cursor. |

</details>

<details>
<summary><b>Burp workspace</b></summary>

| Tool | What it does |
|---|---|
| `scope` | Check a URL, include/exclude, list and remove rules. |
| `sitemap` | Query the site map, read issues, add requests or issues, annotate. |
| `send_to_tool` | Send a request to Repeater, Intruder (with positions), Comparer or Decoder. |
| `organizer` | Send items to Organizer, read them back, annotate. |
| `findings` | Record, list and remove findings during testing (kept per Burp project). |
| `config` | Proxy listeners, match/replace rules, upstream proxy, Intruder payload processors. |
| `persistence` | Key/value storage in the Burp project, plus string user preferences. |
| `events` | Subscribe to and read the event feed. |
| `burp` | Version, project and extension info, config import/export, task engine, shutdown. |
| `ai` | Burp AI status and prompts. |
| `log` | Write to the Raijin log and activity feed. |
| `util` | URL/Base64/HTML encoding, hashing, compression, random data, JWT decode, smart decode. |

</details>

<details>
<summary><b>Turbo, JWT and skills</b></summary>

| Tool | What it does |
|---|---|
| `turbo_run` | Start (blocking or `start_async`), list, poll, read, stop and delete Turbo runs; search responses; save to Organizer. |
| `turbo_docs` | Turbo documentation (12 topics) and example scripts. Read before `turbo_run`. |
| `jwt_keys` | JWK key ring: generate, import, list, export, delete. |
| `search_skills`, `load_skill` | Find and read the built-in skills from a tool call. |

</details>

### Resources

Read-only snapshots for clients that browse MCP resources:

| URI | Content |
|---|---|
| `burp://proxy/history` | Proxy HTTP history |
| `burp://proxy/websocket/history` | Proxy WebSocket history |
| `burp://scanner/issues` | Scanner issues |
| `burp://sitemap` | Site map |
| `burp://scope` | Target scope |
| `burp://config/project`, `burp://config/user` | Burp configuration |
| `burp://organizer/items` | Organizer items |
| `burp://skills/manifest` | Skill names, descriptions, URIs and hashes |
| `skill://<name>/SKILL.md` | One skill as markdown |

---

## 📚 Skills

The server ships short usage guides so an agent can learn the tool groups and workflows by itself.

| Skill | Covers |
|---|---|
| `overview` | **Start here.** Tool map, scope rules, standard Burp testing workflow. |
| `http-testing` | Send, chain, pipeline, fuzz, and race HTTP requests; rules and macros. |
| `proxy-traffic` | Proxy history, intercept/hold, rewrite rules, Autorize, and WebSockets. |
| `scanner-audit` | Crawls, audits, scan tasks, BChecks, custom scan checks, and Bambdas. |
| `recon-probes` | Recon, param mining, OpenAPI, and CORS/cache/GraphQL/SQLi/IDOR/JWT probes. |
| `findings-reporting` | Record findings, create Burp issues, export reports, and Organizer notes. |
| `collaborator-oob` | Out-of-band DNS/HTTP/SMTP payloads and polling with Burp Collaborator. |
| `turbo-scripting` | High-volume, race, and smuggling runs with Python Turbo scripts. |

Each skill is served three ways:

- **MCP prompts** (no arguments). Clients list them as slash commands: `/mcp__burpsuite__http-testing` in Claude Code, `/burpsuite:http-testing` in omp (type `/burpsuite` to filter them).
- **MCP resources** at `skill://<name>/SKILL.md` (`text/markdown`), readable through the client's resource reader (`ReadMcpResourceTool` in Claude Code).
- **Tools**: `search_skills` and `load_skill` (accepts `name` or `uri`), for clients that only call tools.

The server `instructions` sent on connect point the agent at `overview` and list every skill.

<details>
<summary><b>No skills show up?</b></summary>

- Clients read prompts when they connect. After reloading the extension, reconnect the server (`/mcp` in Claude Code; omp reconnects by itself).
- Check that Burp runs the new jar: the extension output prints `MCP Prompts: 8`.
- In Claude Code's MCP log for `burpsuite`, look for `"hasPrompts":true`.
- omp's `/skill:<name>` entries are its own local skills, not MCP prompts. Type `/burpsuite` to narrow the list.

</details>

---

## 🏎️ Turbo

Turbo runs a Python (Jython) script over its own request engine. Use it when you need volume or timing precision; prefer the `http_*` tools for ordinary requests.

**From Burp**

1. Right-click a request → **Send to Raijin Turbo** (or <kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>T</kbd> in a message editor).
2. Select text first to turn it into the `%s` injection point.
3. Pick an example script, edit, start.

**From an agent**

```text
turbo_docs(action=get_docs)          # topics; start with api-quickstart
turbo_docs(action=list_examples)     # then pick an example
turbo_run(action=start, ...)         # waits up to timeout_ms (55 s), or start_async to return at once
turbo_run(action=status | results | result | search_responses | list)
turbo_run(action=stop | delete | save_to_organizer)
```

Runs started from the dialog and from agents are listed together on the **Raijin → Turbo** sub-tab.

**Scripting API.** Scripts get the Montoya API as `api`, for example `api.siteMap().add(req.getMontoyaRequest())` or `api.collaborator().createClient()`. Engine classes are reached through the injected `turbo` object (`import io...` does not work in Jython). The legacy `callbacks`, `helpers` and `req.getBurpRequest()` from Turbo Intruder are gone.

| | |
|---|---|
| Docs | [`src/main/resources/turbo-docs/`](src/main/resources/turbo-docs/), also served by `turbo_docs(action=get_docs, topic=...)`: quick start, engines, settings, race conditions, response processing, decorators, performance, desync techniques, wordlists and utilities, Montoya API patterns |
| Examples | [`src/main/resources/examples/`](src/main/resources/examples/): single-packet races (H1, H2, H3), multi-endpoint races, 0.CL desync, desync technique sweeps (`desync-smuggler`, `desync-h2-downgrade`), rate limits, timing, crawling and more |

**Request smuggling.** `turbo.DesyncTechniques` (obfuscated `Content-Length`/`Transfer-Encoding` variants, H1 and H2), `turbo.DesyncProbePayloads` and `turbo.DesyncCanary` are ported from [HTTP Request Smuggler](https://github.com/PortSwigger/http-request-smuggler). They only build and match bytes; Turbo's engine does the timing and connection pinning. Read `turbo_docs(action=get_docs, topic=desync-techniques)` first. To send a few raw requests over one socket without a script, use `http_send_pipeline`.

> [!WARNING]
> A Turbo run executes Python inside Burp's JVM. Only connect MCP clients you trust.

---

## 🛂 Access control and GraphQL

### Autorize-style tap

`autorize(action=set_rule, identities=[...])` starts a background tap on Proxy traffic, the idea behind the [Autorize](https://github.com/PortSwigger/autorize) extension. Every proxied request that matches the rule (scope, host glob or regex, methods, URL exclusions, static assets skipped) is replayed under each identity, for example `{"name":"none"}` for unauthenticated or `{"name":"low_priv","header_name":"Cookie","header_value":"session=..."}`; identities take `headers` and `remove_headers` as in `auth_diff`. Only authenticated originals are replayed: requests without credentials or answered 401 or 404 are skipped, and `POST`, `PUT`, `DELETE` and `PATCH` are replayed only with `include_mutating=true`, since each replay repeats the action. Each endpoint is tested once per query string (`?id=1` and `?id=2` separately, at most 50 variants per endpoint). Responses are compared with the original by status and body similarity (`similarity_threshold`, default 90); refusals that look alike (the same 401/403/404, a redirect to a login page) stay informational, and a match the denial-wording check turned informational is kept with `soft_denial: true`. Matches are saved per Burp project (`~/.raijin-autorize.jsonl`) with what every identity sent and received: `autorize(action=list_matches)` pages through them (`start_index`, `count`, `include_replays`, or `match_id` for one in full), the **Raijin → Autorize** tab shows the original next to each replay, each match is an `autorize.match` event, and critical or high ones are recorded as findings. Replays never block the proxy: at most 10 are sent at once and 100 wait, and an endpoint skipped while the queue is full is tried again later. Setting a rule re-tests the endpoints it already replayed.

### One-off checks

`auth_diff` sends one request per auth level; `probe(action=access_control)` does the same for many requests and identities. A level's headers (`header_name`/`header_value`, or `headers` for several, `remove_headers` to drop some) replace the request's own instead of adding a second `Cookie` or `Authorization`; a level named `none`, `unauth` or `anonymous` is sent without any credential header; Content-Length is fixed for every level. Each level reports what it sent (`headers_set`, `headers_removed`, `credential_headers_kept`), and findings carry an id and severity (`all_identical`, `unauth_accessible`, `unauth_reads_protected`, ...). Uniform refusals, a 200 login or denial page, or a body matching `denied_regex` are informational, never high or critical; a level that gets no response is listed under `errors`.

`probe(action=idor)` swaps the object id at its parameter boundary (one path segment, one query/form/cookie/header value, one JSON value, so `/v1/users/1` never becomes `/v2/users/2`), replays it under every other identity, and confirms a cross-user read only when the owner's `canary` appears in the reader's response. Pin the id with `id_value`, `id_location` and `id_name` when auto-detection picks the wrong one.

### GraphQL

`probe(action=graphql, url=..., mode=...)`, ported from [InQL](https://github.com/doyensec/inql):

| Mode | Purpose |
|---|---|
| `probe` (default) | Introspection enabled, disabled (falls back to "Did you mean" suggestions), or not GraphQL. |
| `query_templates` | A runnable example query, mutation or subscription for each schema field (`max_depth`, default 6). Needs introspection. |
| `poi_scan` | Fields that look security-relevant by name (auth, privileged, PII, payment, database, debugging, files), deprecated fields, custom scalars; each at its shortest path, through interfaces and unions. `custom_keywords` are matched literally. |
| `cycles_scan` | Every cycle in the type graph (deep nesting, denial of service), shortest first, plus `cyclic_types`; `truncated` when the search hits its cap. |
| `batch_attack` | Expand `$[INT:first:last]` or `$[LIST]` in `template` into aliased operations in one request (2FA brute force, IDOR enumeration, rate limits); at most 10,000. Generates only unless `send=true`. |
| `fingerprint_engine` | Detect the backend engine (Apollo, Hasura, graphql-java, ...) from malformed-query error signatures. |
| `bruteforce_schema` | Reconstruct the schema from "did you mean"/type-mismatch error messages when introspection is disabled. Request-heavy: guesses go out in buckets (`bucket_size`, `depth_limit`, `bruteforce_arguments`), every document built to fail validation so a compliant server executes none, and the run stops at `max_requests` (default 2000) with the partial schema. |
| `subscription_probe` | Subscriptions over WebSocket (`ws(s)://` or the HTTP endpoint), with both the `graphql-transport-ws` and the legacy `subscriptions-transport-ws` protocols: per protocol `handshake_accepted`, `init_requires_auth`, `subscription_accepted` and `subscription_requires_auth`, comparing an anonymous session with one carrying your `headers` and `connection_payload` (`subscription_query`, `wait_ms`). |

Every mode accepts `headers` and `auto_headers` (reuse the most recent Proxy-history request's `Authorization`/`Cookie`/`X-Api-Key`/`X-Auth-Token` for this host); `query_templates`/`poi_scan`/`cycles_scan` also cache the fetched schema for 10 minutes, bypassable with `refresh_schema`. An unreachable target is reported as one error instead of a verdict.

---

## 🔑 JWT toolkit

- **Key ring** (`jwt_keys` tool, **Raijin → JWT** tab): generate RSA, EC, OKP (Ed25519, Ed448, X25519, X448), symmetric (`oct`) and password keys; import PEM or JWK; export as JWK or PEM. Private material is never listed, and is exported only when asked. Every key lists the modes it can serve (X25519 and X448 keys encrypt and decrypt; they do not sign).
- **Token operations** (`probe(action=jwt, mode=...)`). Signing modes keep the token's payload byte for byte unless `payload_overrides` names claims, and keep its header apart from `alg`, `kid` and the key they embed or point to:

| Mode | Purpose |
|---|---|
| `analyze` | Flag `alg:none`, HMAC, asymmetric algorithms, `kid`/`jku`, missing or malformed `exp`, repeated claims. |
| `sign`, `sign_key`, `verify` | Sign with a secret or ring key; verify against one key or all of them, with the reason a key does not verify. |
| `encrypt`, `decrypt` | JWE with a ring key. |
| `forge_none` | Unsigned tokens, with case variants of `none`. |
| `alg_confusion` | RS→HS confusion using the server's public key (PEM, JWK or a ring key). |
| `embed_jwk` | Sign and embed the public key in the header. |
| `empty_hmac`, `psychic` | Empty HMAC key; ECDSA psychic signatures (ES256/384/512). |
| `header_url` | Point `jku` or `x5u` at a URL you control; with `key_id` the token is signed with that ring key and the result holds the JWK set or certificate chain to host there. |
| `crack` | Recover an HMAC secret from a wordlist or the built-in list. |

---

## 🔒 Security model

On loopback (the default) there is **no token to manage**. Protection is:

- **Loopback bind.** The servers bind to `127.0.0.1`.
- **Host-header allowlist** against DNS rebinding.
- **Origin lockdown** so web pages in your browser cannot call localhost.

**Remote / VM mode.** Another bind address (`mcp_bind_host`) needs the operator opt-in `mcp_allow_remote_bind`. Every listener then requires `Authorization: Bearer <token>` (generated and shown on the **Server** tab; **Copy MCP Config** includes it), optionally narrowed by a source IP/CIDR allowlist (`mcp_allowed_ips`) and extra allowed host names (`mcp_allowed_hosts`). `mcp_require_auth` turns the token on for loopback too. SSH port forwarding, a VPN address or the Caddy profile keep Raijin itself on loopback. Details, including the browser cookie and the Caddy setup: [SECURITY.md](docs/dev/ultra/SECURITY.md).

> [!CAUTION]
> On loopback any local process can call the tools, and the tools drive your Burp (including running Python through Turbo). Do not run Raijin on a shared machine.

Outbound requests from the `http_*`, recon and probe tools are checked against Burp's target scope by `mcp_scope_mode`: `warn` (default) sends them and adds `scope_warning` to the result, `enforce` refuses them (`out_of_scope: true`, nothing sent), `off` skips the check. Turbo runs, Scanner tasks, WebSocket opens and followed redirects are advisory only: flagged under `warn` and `enforce`, never refused. Every scope decision shows in the tool result, in the MCP Activity tab (warning-coloured rows, an Out-of-scope count) and in the audit log (`out_of_scope: true`). Set the scope with `scope(action=include)` first. An MCP client can change the mode with `persistence(action=preference_store)`: only `off`, `warn` or `enforce` is accepted, and every change is announced (a `scope.mode_changed` event and a line in Burp's output) and shown on the Server tab.

---

## ⚙️ Configuration

| Setting | JVM property | Burp preference | Default |
|---|---|---|---|
| MCP port (SSE + Streamable HTTP) | `raijin.ssePort` | `mcp_sse_port` | `9876` |
| Second MCP port | `raijin.httpPort` | `mcp_http_port` | `9877` |
| Dashboard port | `raijin.dashboardPort` | `mcp_dashboard_port` | `9878` |
| Bind address | `raijin.bindHost` | `mcp_bind_host` | `127.0.0.1` |
| Allow a non-loopback bind | `raijin.allowRemoteBind` | `mcp_allow_remote_bind` | `false` |
| Require the token on loopback too | `raijin.requireAuth` | `mcp_require_auth` | `false` |
| Bearer token | `raijin.authToken` | `mcp_auth_token` | generated when needed |
| Source IP/CIDR allowlist | `raijin.allowedIps` | `mcp_allowed_ips` | empty: any source |
| Extra allowed host names | `raijin.allowedHosts` | `mcp_allowed_hosts` | none |
| Scope policy for outbound requests | | `mcp_scope_mode` | `warn` |
| Allow shutdown and config import | | `mcp_allow_destructive` | `false` |
| Save the MCP activity log | | `mcp_persist_activity` | `true` |

PortSwigger's own MCP Server extension also defaults to `9876`; change one of them if you run both. When two listeners are configured on one port, the later one moves for the session (to its default or the next free port, never one another listener is configured for) and the log names the preference to fix.

JVM properties go in Burp's launcher, e.g. `java -Draijin.ssePort=9976 -jar burpsuite_pro.jar`, and win over the preference. The **Server** tab edits the bind and remote-access settings and rebinds without a reload. Activity, audit log, findings and Autorize matches are stored in `~/.raijin-{activity,audit,findings,autorize}.jsonl`.

---

## 🔄 Coming from BurpMCP-Ultra or Turbo Intruder

- **One extension, one server** named `burpsuite`. Turbo's own MCP server (ports 31337/31338) and its standalone `java -jar … --mcp` mode are gone; use `turbo_run` and `turbo_docs`.
- **No bearer token on loopback** (BurpMCP-Ultra always required one); a remote bind requires one.
- **Montoya API only.** Turbo no longer bundles `albinowaxUtils-all.jar` or the legacy extender API.
- **Settings.** Turbo's old settings menu is now in Burp's Settings window; previously saved Turbo settings are not migrated.
- **Renames.** System properties moved from `burpmcp.*` to `raijin.*`. Per-operation tool names were folded into `action` tools ([mapping](docs/dev/tool-consolidation.md)).

---

## 🛠️ Development

```bash
./gradlew test           # unit tests
./gradlew build          # tests + fat jar (build/libs/raijin.jar)
```

All source is Kotlin, Montoya API only (`compileOnly`), namespace `io.bitbytelab.raijin`.

```text
src/main/kotlin/io/bitbytelab/raijin/
├── core/        shared helpers (JSON arguments and truncation, payload libraries, wordlists, similarity)
├── transport/   MCP server, Streamable HTTP + SSE, security and remote access, prompts, resources, dashboard, JSONL stores
├── safety/      scope gate, request hygiene (wire encoding, Content-Length), regex and send time limits
├── bridge/      *Bridge.kt wrappers over Burp APIs
├── recon/       param mining, content discovery, JS endpoints and source maps
├── webprobe/    CORS, web cache poisoning/deception, fingerprinting
├── injection/   injection probe: payloads, oracles, Collaborator confirmation
├── openapi/     OpenAPI/Swagger parsing (JSON and YAML) and request building
├── graphql/     schema model, query printer, scanners, batch queries (ported from InQL), subscriptions
├── events/      event bus behind the event feed and the dashboard
├── state/       shared state (rules, Autorize matches, WebSocket connections)
├── tools/       <area>/*Tools.kt MCP tools; ToolConsolidation.kt groups them into action tools
├── skills/      SkillCatalog (skill markdown lives in src/main/resources/skills/)
├── jwt/         JOSE operations and the key ring
├── ui/          the Raijin tab (colours from RaijinTheme, never hardcoded)
└── turbo/       the Turbo engine and Jython bridge
```

<details>
<summary><b>Adding things</b></summary>

- **A tool:** register it in `tools/<area>/*Tools.kt`, then add it to `ToolConsolidation.GROUPS` (as an action) or `KEEP` (as its own tool). A test fails if you forget.
- **A skill:** add `src/main/resources/skills/<name>.md` with `name` and `description` frontmatter and list it in `SkillCatalog.NAMES`.
- **Turbo docs or examples:** add the file under `src/main/resources/turbo-docs/` or `src/main/resources/examples/`, and list it in `McpResourceHandlers` (`docTopics`, or the example set the MCP tools serve). A test fails when a doc file and the topic list differ.

MCP SDK: `io.modelcontextprotocol:kotlin-sdk-server` 0.16, which pins Kotlin 2.4 and Ktor 3.5; bump them together. Developer notes are in [`docs/dev/`](docs/dev/).

</details>

---

## 🙏 Credits

| Project | License | Used for |
|---|---|---|
| [Turbo Intruder](https://github.com/PortSwigger/turbo-intruder) (PortSwigger) | AGPL-3.0 (Apache-2.0 up to 1.62) | The Turbo engine. |
| [BurpMCP-Ultra](docs/dev/ultra/README-burpmcp-ultra.md) (Cy-S3c) | MIT | The MCP server and tools. |
| [InQL](https://github.com/doyensec/inql) (Doyensec) | Apache-2.0 | GraphQL schema model, query templates, scanners, batch queries, POI keywords. |
| [HTTP Request Smuggler](https://github.com/PortSwigger/http-request-smuggler) (PortSwigger, James Kettle) | Apache-2.0 | Desync techniques, probe payloads, canaries. |
| [Param Miner](https://github.com/PortSwigger/param-miner) (PortSwigger, James Kettle) | Apache-2.0 | Parameter and header wordlists. |
| [Autorize](https://github.com/PortSwigger/autorize) (Barak Tawily) | | The idea behind the `autorize` tool; no code copied. |

---

## 📄 License

[GNU AGPL-3.0](LICENSE). Contains MIT-licensed code from BurpMCP-Ultra ([LICENSE-MIT](LICENSE-MIT)), and Apache-2.0 code from Turbo Intruder contributions, InQL, HTTP Request Smuggler and Param Miner ([LICENSE-APACHE-2.0](LICENSE-APACHE-2.0)). See [NOTICE](NOTICE).

<div align="center">
<sub>Made by <a href="https://github.com/bitbytelabio">bitbytelab</a></sub>
</div>
