<div align="center">

# ⚡ Raijin

**One Burp Suite extension that gives AI agents hands.**

An [MCP](https://modelcontextprotocol.io) server that runs inside Burp Suite, merged with the **Turbo** scripting engine
for high-speed work: single-packet race conditions, HTTP/2 and HTTP/3 gates, desync probes.

[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
![Burp Suite 2026.2+](https://img.shields.io/badge/Burp%20Suite-2026.2%2B-orange.svg)
![Java 21](https://img.shields.io/badge/Java-21-red.svg)
![Kotlin](https://img.shields.io/badge/Kotlin-2.4-7F52FF.svg)
![MCP](https://img.shields.io/badge/MCP-Streamable%20HTTP-black.svg)

[Quick start](#-quick-start) ·
[Tools](#-tools) ·
[Skills](#-skills) ·
[Turbo](#-turbo) ·
[JWT](#-jwt-toolkit) ·
[Security](#-security-model) ·
[Configuration](#%EF%B8%8F-configuration) ·
[Development](#-development)

</div>

---

## ✨ Highlights

| | |
|---|---|
| 🧰 **160+ operations, ~40 tools** | Proxy, Scanner, Repeater, Intruder, Collaborator, Organizer, site map, scope, WebSockets, cookies, config, Burp AI. Families of operations are grouped behind an `action` parameter so the client's tool list stays small. |
| 🏎️ **Turbo engine** | Python (Jython) scripts on a custom request engine: single-packet attack, HTTP/2 and HTTP/3, pipelining, timing analysis. Runs from Burp's UI or from an agent. |
| 🔎 **Recon and guided probes** | JS endpoint extraction, content discovery, parameter mining, fingerprinting; CORS, GraphQL, injection, access control, IDOR and JWT probes, all limited to in-scope targets. |
| 🔑 **JWT toolkit** | Key ring (RSA, EC, OKP, oct, password), sign, verify, JWE encrypt/decrypt, and the usual JWT test cases (`alg:none`, algorithm confusion, embedded JWK, psychic signatures, `jku`/`x5u`, secret cracking). |
| 📚 **Built-in skills** | Eight usage guides served as MCP prompts and resources, so an agent learns the tools and workflows on its own. |
| 🖥️ **Native UI** | A **Raijin** tab that follows Burp's theme (dark or light): MCP activity, proxy explorer, scanner, findings, Collaborator, rules, JWT, Turbo runs, server info. |
| 🔒 **No token to manage** | Loopback bind plus Host and Origin checks. Point your client at a URL and go. |

> Raijin merges [BurpMCP-Ultra](docs/dev/ultra/README-burpmcp-ultra.md) and [Turbo Intruder](docs/dev/turbo/readme-turbo-intruder.md).
> See [NOTICE](NOTICE) for attribution and licensing.

---

## 🚀 Quick start

### 1. Requirements

- **Burp Suite 2026.2 or newer** (Montoya API), Community or Professional.
  The Turbo HTTP/3 engine and the `AUTO` engine need **Professional**.
- **JDK 21** to build. A newer JDK on `PATH` is fine: `gradle/gradle-daemon-jvm.properties` pins Gradle to 21.

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

**Clients that only speak stdio** (Claude Desktop): bridge with [supergateway](https://github.com/supercorp-ai/supergateway), see [`configs/mcp-claude-desktop.json`](configs/mcp-claude-desktop.json).

Then ask your agent something like *"Use the burpsuite_overview_skill, check the scope, and summarise the proxy history for example.com"*.

> [!TIP]
> The **Raijin → Server** sub-tab shows the exact client config for your current bind address and ports.

### Endpoints

| Endpoint | Default URL | Notes |
|---|---|---|
| MCP, Streamable HTTP | `http://127.0.0.1:9876/mcp` | **Use this.** Also served on `9877`. |
| MCP, legacy SSE | `http://127.0.0.1:9876/` | Root path, not `/sse`. Deprecated by the MCP spec; kept for old `"type": "sse"` configs. |
| Dashboard | `http://127.0.0.1:9878/` | Live web view of activity, stats, proxy traffic and rules. |

### Ready-made configs

| File | Purpose |
|---|---|
| [`configs/mcp-claude-code-direct.json`](configs/mcp-claude-code-direct.json) | Claude Code, direct to Burp. |
| [`configs/mcp-claude-code-caddy.json`](configs/mcp-claude-code-caddy.json) | Claude Code through the Caddy proxy on `:9900`. |
| [`configs/mcp-claude-desktop.json`](configs/mcp-claude-desktop.json) | Claude Desktop via supergateway. |
| [`configs/Caddyfile`](configs/Caddyfile) | Optional Caddy reverse proxy with unbuffered, no-timeout streaming. |
| [`configs/setup.sh`](configs/setup.sh) | Builds the jar, optionally installs the Caddyfile, prints the client config. |

---

## 🧰 Tools

Raijin exposes about **40 MCP tools**. Frequently used tools stay individual; families of operations are one tool with a required `action` parameter, for example `scope(action=include)` or `scanner(action=start_audit)`. Each tool's description lists its actions and the parameters each one needs (required ones are marked `*`). The old per-operation names are mapped in [docs/dev/tool-consolidation.md](docs/dev/tool-consolidation.md).

<details open>
<summary><b>HTTP and proxy</b></summary>

| Tool | What it does |
|---|---|
| `http_send_request` | Send one HTTP request through Burp. |
| `http_send_requests_parallel` | Send many requests concurrently. |
| `http_send_request_chain` | Send a sequence, extracting values from each response (regex) into the next request. |
| `http_send_raw_bytes` | Send exact bytes (malformed or smuggling-style requests). |
| `http_fuzz` | Inject payloads at marked positions (sniper mode). |
| `http_race` | Fire requests together to test race conditions. |
| `http_rule` | Outgoing traffic rules and session token rules. |
| `http_state` | Burp cookie jar: get, set, delete. |
| `proxy_history`, `proxy_history_search` | Read and search Proxy HTTP history. |
| `proxy_annotate` | Highlight and comment history items. |
| `proxy_auto_auth` | Add an auth header to every proxied request for a host pattern. |
| `proxy_rule` | Proxy request/response rules (modify, drop, tag). |
| `proxy_intercept` | Turn interception on or off, read its state. |
| `websocket` | Open connections, send, read messages, intercept rules, WebSocket history. |

</details>

<details>
<summary><b>Scanning, recon and probes</b></summary>

| Tool | What it does |
|---|---|
| `scanner` | Start crawls and audits, read issues, generate reports, register checks. |
| `scanner_task` | Status, list, delete running scan tasks; add requests; read their issues. |
| `custom_check` | BChecks and passive/active scan checks: create from a template, import, list, remove. |
| `recon` | JS endpoints, content discovery, parameter mining, fingerprinting (in scope only). |
| `probe` | Guided probes: `cors`, `graphql`, `injection`, `access_control`, `idor`, `jwt` (in scope only). |
| `auth_diff` | Send the same request at different auth levels (admin, user, none) and compare responses. |
| `analyze` | Offline analysis: parse requests/responses, reflections, parameters, insertion points, diffs, keywords, passive intel. |
| `api_import_openapi` | Import an OpenAPI 3 / Swagger 2 spec: build sample requests, optionally send them and add them to scope and the site map. |
| `bambda_import` | Import a `.bambda` file into Burp. |
| `collaborator` | Collaborator clients, payloads, polling. |

</details>

<details>
<summary><b>Burp workspace</b></summary>

| Tool | What it does |
|---|---|
| `scope` | Check a URL, include/exclude, list and remove rules. |
| `sitemap` | Query the site map, read issues, add requests or issues, annotate. |
| `send_to_tool` | Send a request to Repeater, Intruder (with positions), Comparer or Decoder. |
| `organizer` | Send items to Organizer, read them back, annotate. |
| `findings` | Record, list and remove findings during testing. |
| `config` | Proxy listeners, match/replace rules, upstream proxy, Intruder payload processors. |
| `persistence` | Key/value storage in the Burp project and user preferences. |
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
| `turbo_run` | Start, poll, read, stop and delete Turbo runs; search responses; save to Organizer. |
| `turbo_docs` | Turbo documentation and example scripts. Read before `turbo_run`. |
| `jwt_keys` | JWK key ring: generate, import, list, export, delete. |
| `search_skills`, `load_skill`, `read_skill_file` | Find and read the built-in skills from a tool call. |

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

| Skill | Prompt name | Covers |
|---|---|---|
| `burpsuite-overview` | `burpsuite_overview_skill` | **Start here.** Tool map, scope rules, typical workflow. |
| `http-testing` | `http_testing_skill` | Sending, chaining, fuzzing and racing requests. |
| `proxy-traffic` | `proxy_traffic_skill` | History, search, annotations, proxy rules, interception. |
| `scanner-audit` | `scanner_audit_skill` | Crawls, audits, tasks, BChecks and custom checks. |
| `recon-and-probes` | `recon_and_probes_skill` | Recon and guided probes on in-scope targets. |
| `findings-reporting` | `findings_reporting_skill` | Recording findings and producing reports. |
| `collaborator-oob` | `collaborator_oob_skill` | Out-of-band testing with Collaborator. |
| `turbo-scripting` | `turbo_scripting_skill` | Writing and running Turbo scripts. |

Each skill is served three ways:

- **MCP prompts** (no arguments). Clients list them as slash commands: `/mcp__burpsuite__http_testing_skill` in Claude Code, `/burpsuite:http_testing_skill` in omp. **Type `/skill`** to list them all; pickers filter on the name, which is why every prompt ends in `_skill`.
- **MCP resources** at `skill://<name>/SKILL.md` (`text/markdown`), readable through the client's resource reader (`ReadMcpResourceTool` in Claude Code).
- **Tools**: `search_skills`, `load_skill` and `read_skill_file`, for clients that only call tools.

The server `instructions` sent on connect point the agent at `burpsuite-overview` and list every skill.

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
turbo_docs(action=get_docs)          # read the docs first
turbo_docs(action=list_examples)     # then pick an example
turbo_run(action=start, ...)         # start a run
turbo_run(action=status | results | result | search_responses)
turbo_run(action=stop | delete | save_to_organizer)
```

Runs started from the dialog and from agents are listed together on the **Raijin → Turbo** sub-tab.

**Scripting API.** Scripts get the Montoya API as `api`, for example `api.siteMap().add(req.getMontoyaRequest())` or `api.collaborator().createClient()`. Engine classes are reached through the injected `turbo` object (`import io...` does not work in Jython). The legacy `callbacks`, `helpers` and `req.getBurpRequest()` from Turbo Intruder are gone.

| | |
|---|---|
| Docs | [`src/main/resources/turbo-docs/`](src/main/resources/turbo-docs/): quick start, engines, decorators, race conditions, performance, settings |
| Examples | [`src/main/resources/examples/`](src/main/resources/examples/): single-packet races (H1, H2, H3), multi-endpoint races, 0.CL desync, rate limits, timing, crawling and more |

> [!WARNING]
> A Turbo run executes Python inside Burp's JVM. Only connect MCP clients you trust.

---

## 🔑 JWT toolkit

- **Key ring** (`jwt_keys` tool, **Raijin → JWT** tab): generate RSA, EC, OKP (Ed25519/X25519), symmetric (`oct`) and password keys; import PEM or JWK; export as JWK or PEM. Private material is never listed, and is exported only when asked.
- **Token operations** (`probe(action=jwt, mode=...)`):

| Mode | Purpose |
|---|---|
| `analyze` | Flag `alg:none`, HMAC, asymmetric algorithms, `kid`/`jku`, missing `exp`. |
| `sign`, `sign_key`, `verify` | Sign with a secret or ring key; verify against one key or all of them. |
| `encrypt`, `decrypt` | JWE with a ring key. |
| `forge_none` | Unsigned tokens, with case variants of `none`. |
| `alg_confusion` | RS→HS confusion using the server's public key (PEM, JWK or a ring key). |
| `embed_jwk` | Sign and embed the public key in the header. |
| `empty_hmac`, `psychic` | Empty HMAC key; ECDSA psychic signatures (ES256/384/512). |
| `header_url` | Point `jku` or `x5u` at a URL you control. |
| `crack` | Recover an HMAC secret from a wordlist or the built-in list. |

---

## 🔒 Security model

There is **no authentication token**. Protection is:

- **Loopback only.** The servers bind to `127.0.0.1`. Remote binding needs `-Draijin.allowRemoteBind=true`, and then nothing protects them but your network.
- **Host-header allowlist** against DNS rebinding.
- **Origin lockdown** so web pages in your browser cannot call localhost.

> [!CAUTION]
> Any local process can call the tools, and the tools drive your Burp (including running Python through Turbo). Do not run Raijin on a shared machine.

The recon and probe tools refuse targets that are not in Burp's scope; set it with `scope(action=include)` first.

---

## ⚙️ Configuration

| Setting | JVM property | Burp preference | Default |
|---|---|---|---|
| MCP port (SSE + Streamable HTTP) | `raijin.ssePort` | `mcp_sse_port` | `9876` |
| Second MCP port | `raijin.httpPort` | `mcp_http_port` | `9877` |
| Dashboard port | `raijin.dashboardPort` | `mcp_dashboard_port` | `9878` |
| Allow non-loopback bind | `raijin.allowRemoteBind` | | `false` |

PortSwigger's own MCP Server extension also defaults to `9876`; change one of them if you run both.

JVM properties go in Burp's launcher, e.g. `java -Draijin.ssePort=9976 -jar burpsuite_pro.jar`. Activity, audit log and findings are stored in `~/.raijin-{activity,audit,findings}.jsonl`.

---

## 🔄 Coming from BurpMCP-Ultra or Turbo Intruder

- **One extension, one server** named `burpsuite`. Turbo's own MCP server (ports 31337/31338) and its standalone `java -jar … --mcp` mode are gone; use `turbo_run` and `turbo_docs`.
- **No bearer token** (BurpMCP-Ultra required one).
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
├── core/        shared helpers (JSON truncation, payload libraries, similarity)
├── transport/   MCP server, Streamable HTTP + SSE, security checks, prompts, resources, dashboard
├── bridge/      *Bridge.kt wrappers over Burp APIs
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
- **Turbo docs or examples:** drop files in `src/main/resources/turbo-docs/` or `src/main/resources/examples/`.

MCP SDK: `io.modelcontextprotocol:kotlin-sdk-server` 0.16, which pins Kotlin 2.4 and Ktor 3.5; bump them together. Developer notes are in [`docs/dev/`](docs/dev/).

</details>

---

## 📄 License

[GNU AGPL-3.0](LICENSE). Contains MIT-licensed code from BurpMCP-Ultra ([LICENSE-MIT](LICENSE-MIT)) and Apache-2.0 contributions to Turbo Intruder ([LICENSE-APACHE-2.0](LICENSE-APACHE-2.0)). See [NOTICE](NOTICE).

<div align="center">
<sub>Made by <a href="https://github.com/bitbytelabio">bitbytelab</a></sub>
</div>
