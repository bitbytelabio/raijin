# Raijin

**One Burp Suite extension that gives AI agents hands.** Raijin is an [MCP](https://modelcontextprotocol.io) server for Burp Suite (160+ tools across proxy, scanner, repeater, collaborator, organizer, sitemap and more) merged with the **Turbo** scripting engine for high-speed work: single-packet race conditions, HTTP/2 and HTTP/3 gates and desync probes.

It runs inside Burp, follows Burp's theme (dark or light), and needs no token: point your MCP client at a URL.

> Raijin merges [BurpMCP-Ultra](docs/dev/ultra/README-burpmcp-ultra.md) and [Turbo Intruder](docs/dev/turbo/readme-turbo-intruder.md). See [NOTICE](NOTICE) for attribution and licensing.

## Install

Requires Burp Suite 2026.2 or newer (Montoya API) on Java 21+. The Turbo HTTP/3 engine and the AUTO engine need Burp Professional.

```bash
./gradlew build          # builds build/libs/raijin.jar
```

In Burp: **Extensions → Add → Java →** `raijin.jar`. A **Raijin** tab appears.

Building needs a JDK 21 (a newer JDK on `PATH` is fine; `gradle/gradle-daemon-jvm.properties` pins Gradle to 21).

## Connect an MCP client

| Endpoint | URL |
|---|---|
| MCP (SSE) | `http://127.0.0.1:9876/` (also `9877`) |
| Dashboard | `http://127.0.0.1:9878/` |

```bash
claude mcp add --transport sse raijin http://127.0.0.1:9876/
```

or in a client config (`configs/` has ready-made files):

```json
{ "mcpServers": { "raijin": { "type": "sse", "url": "http://127.0.0.1:9876/" } } }
```

The endpoint is the root path `/`, not `/sse`. The **Server** sub-tab shows the exact config for your bind address.

### Security model

There is **no authentication token**. Protection is:

- the servers bind to `127.0.0.1` only (remote binding must be enabled explicitly with `-Draijin.allowRemoteBind=true`, and then nothing protects them but your network);
- a Host-header allowlist (defeats DNS rebinding) and an Origin lockdown (defeats web pages calling localhost).

Any local process can call the tools, and the tools drive your Burp. Do not run Raijin on a shared machine.

Ports can be changed with the JVM properties `raijin.ssePort`, `raijin.httpPort`, `raijin.dashboardPort`, or the Burp preferences `mcp_sse_port`, `mcp_http_port`, `mcp_dashboard_port`. PortSwigger's own MCP Server extension also defaults to 9876.

## Turbo

Turbo drives a Python (Jython) script over its own request engine.

- **From Burp:** right-click a request → **Send to Raijin Turbo** (or `Ctrl+Alt+T` in an editor). Select text first to turn it into the `%s` injection point.
- **From an agent:** `turbo_start_run`, then `turbo_run_status`, `turbo_run_results`, `turbo_run_result`, `turbo_stop_run`, `turbo_search_responses`, `turbo_save_to_organizer`. Read `turbo_get_docs` and `turbo_list_examples` first.
- **Runs** from the dialog and from agents are listed together on the **Turbo** sub-tab.

Because a run executes Python inside Burp's JVM, agents cannot start one until you enable
**Burp → Settings → Raijin Turbo → "Allow MCP clients to run Turbo scripts"** (off by default).

Prefer the `http_*` tools for ordinary requests; use Turbo when you need volume or timing precision.

### Scripting API

Scripts get the Montoya API as `api` (e.g. `api.siteMap().add(req.getMontoyaRequest())`, `api.collaborator().createClient()`). The legacy `callbacks`, `helpers` and `req.getBurpRequest()` from Turbo Intruder are gone. See `src/main/resources/turbo-docs/` and `src/main/resources/examples/`.

## Differences from the two projects it replaces

- One extension, one server named `raijin`. Turbo's own MCP server (port 31337/31338) and its standalone `java -jar … --mcp` mode are gone; use the `turbo_*` tools.
- No bearer token (BurpMCP-Ultra required one).
- Turbo no longer bundles `albinowaxUtils-all.jar` or the legacy Burp extender API; it uses only the Montoya API. Turbo's old settings menu is now in Burp's Settings window, and previously saved Turbo settings are not migrated.
- System properties renamed from `burpmcp.*` to `raijin.*`; the on-disk stores are `~/.raijin-*.jsonl`.

## Development

```bash
./gradlew test           # unit tests
./gradlew build          # tests + fat jar
```

Source layout: `io.bitbytelab.raijin.{core,transport,bridge,tools,ui}` is the MCP server and UI; `io.bitbytelab.raijin.turbo` is the Turbo engine. All source is Kotlin.

## License

GNU AGPL-3.0 ([LICENSE](LICENSE)). Contains MIT-licensed code from BurpMCP-Ultra ([LICENSE-MIT](LICENSE-MIT)) and Apache-2.0 contributions to Turbo Intruder ([LICENSE-APACHE-2.0](LICENSE-APACHE-2.0)).
