# Security model

Raijin exposes an MCP server that **drives your Burp Suite**: it sends arbitrary HTTP requests, runs
scans, reads captured proxy history (real requests, cookies and tokens), manages Collaborator and
more. Treat access to it as control of your Burp.

For the full capability audit see `security-and-capability-review.md`. This document covers the
trust boundary and the operator controls.

## Listeners

| Listener | Default port | Serves | Port setting |
|---|---|---|---|
| MCP primary | `9876` | Streamable HTTP at `/mcp`; legacy SSE at `/` (GET) with its back-channel `POST /?sessionId=…` | `mcp_sse_port` / `-Draijin.ssePort` |
| MCP secondary | `9877` | the same as primary | `mcp_http_port` / `-Draijin.httpPort` |
| Dashboard | `9878` | `/`, `/events` (SSE), `/api/*` | `mcp_dashboard_port` / `-Draijin.dashboardPort` |

All three install the same checks (`transport/SecurityConfig.kt`, `installLocalhostSecurity`), so
everything below applies to every route of every listener. If two listeners are configured on
the same port, the later one moves to a free port for the session and the clash is logged.

## Default: loopback, no token

Out of the box the listeners bind `127.0.0.1` and need **no token**: an MCP client connects with
the URL alone (`http://127.0.0.1:9876/mcp`). Loopback is not a trust boundary against a web page (a
page you visit can send requests to localhost, and DNS rebinding can make the answers readable
cross-origin), so two controls always apply:

1. **Host-header allowlist**: only the bind host, loopback names (`127.0.0.1`, `localhost`,
   `[::1]`), and when exposed this machine's own interface addresses, on the listener's port.
   A rebound request carries `Host: attacker.example` and gets `403` before any handler runs.
   Comparison ignores case, and IPv6 literals are normalized (`[0:0:0:0:0:0:0:1]` is `[::1]`).
2. **Origin lockdown**: a browser request whose `Origin` is not one of those hosts gets `403`;
   CORS only ever answers allowed origins, never `*`.

Any local process can still call the server. That is the loopback threat model: it is your machine.

## Remote / VM mode

Use this when Burp runs in a VM, on a VPS or on another LAN host and the MCP client runs
elsewhere. Remote mode adds three controls, all read on every request (a change applies to the
next request, without restarting the listeners):

| Setting | Burp preference | JVM property | Default |
|---|---|---|---|
| Bind address | `mcp_bind_host` (string) | `-Draijin.bindHost` | `127.0.0.1` |
| Allow a non-loopback bind | `mcp_allow_remote_bind` (boolean) | `-Draijin.allowRemoteBind` | `false` |
| Require the token on loopback too | `mcp_require_auth` (boolean) | `-Draijin.requireAuth` | `false` |
| Bearer token | `mcp_auth_token` (string) | `-Draijin.authToken` | generated when needed |
| Source IP / CIDR allowlist | `mcp_allowed_ips` (string) | `-Draijin.allowedIps` | empty: any source |
| Extra allowed host names | `mcp_allowed_hosts` (string) | `-Draijin.allowedHosts` | empty |

A JVM property wins over the preference. Lists are separated by commas, spaces or semicolons.

The Server tab's remote-access controls edit these preferences: a bind-host picker filled from this
machine's interfaces, **Require Auth Token** (forced on for a non-loopback host), the token with
Show/Hide, Regenerate and Copy Token, and the Allowed IPs/CIDR and Allowed Hosts fields. Fields a
`-Draijin.*` property overrides are greyed out. **Save & Rebind Now** saves them and applies them
without reloading the extension; **Copy MCP Config**, **Copy Command** and the dashboard
**Copy Link** include the token only while the listeners require it.

### Binding to a network interface

A non-loopback bind (a concrete address, or `0.0.0.0` / `::`) is honored **only** with the operator
opt-in `mcp_allow_remote_bind=true`; without it the request is refused and the listeners stay on
`127.0.0.1`, with a warning. When the exposure is honored:

- the Output tab shows a `⚠ SECURITY` warning and the audit log gets a `server.remote_bind` entry;
- the bearer token becomes **mandatory** (`mcp_require_auth` cannot turn it off);
- the Host/Origin allowlist gains this machine's own interface addresses, never `anyHost()`;
- if no source allowlist is set, Burp's output says so: anyone who can reach the port may try the token.

### Bearer token

- Required when a listener is exposed, or on loopback when `mcp_require_auth=true`.
- Generated with `SecureRandom` (256 bits, URL-safe Base64) the first time it is needed and saved
  to the `mcp_auth_token` preference so it survives reloads. `-Draijin.authToken` overrides it and
  is never written to the preferences. The Server tab shows, copies and regenerates it. Raijin
  never prints the token in its logs; the startup log says where to find it.
- Clients send `Authorization: Bearer <token>` on every request (Claude Code, Cursor, Codex and omp
  accept a `headers` entry; the Server tab's **Copy MCP Config** includes it). The comparison is
  constant-time over SHA-256 digests.
- A missing or wrong token gets `401` with `WWW-Authenticate: Bearer`. CORS preflights
  (`OPTIONS` with `Origin` and `Access-Control-Request-Method`) pass without it, because browsers
  never attach credentials to them; any other `OPTIONS` needs the token.
- **Browsers**: open the dashboard once as `http://<host>:9878/?token=<token>`. Raijin sets an
  `HttpOnly; SameSite=Strict` cookie `raijin_auth` (a digest of the token, not the token) and
  redirects to the same page without the token, so it leaves the address bar. The page's
  `EventSource` and `fetch` calls then authenticate with the cookie. Cookies are per host, so the
  cookie also works on the MCP ports of the same host.
- **URL-only MCP clients**: a Streamable HTTP client can use `http://<host>:9876/mcp?token=<token>`,
  because every request goes to that URL. The legacy SSE transport cannot: its back-channel is the
  relative reference `?sessionId=…`, which drops the query, so legacy SSE clients must send the header.
- Regenerating the token (or changing `mcp_auth_token`) invalidates the old token and every cookie
  derived from it on the next request.

### Source IP / CIDR allowlist

- `mcp_allowed_ips` takes single addresses and CIDR ranges, IPv4 and IPv6, for example
  `192.168.56.1, 10.0.2.2, 100.64.0.0/10, fd7a:115c:a1e0::/48`.
- Only the TCP peer address counts. `X-Forwarded-For` / `Forwarded` are never consulted, so a
  reverse proxy in front appears as its own address (usually loopback).
- Loopback (`127.0.0.0/8`, `::1`) is always allowed. Anything else outside the list gets `403`
  before the token is checked.
- Entries that are not an IP or CIDR are ignored with a warning; the list stays active, so a list
  of only invalid entries admits loopback alone.

### Extra allowed host names

`mcp_allowed_hosts` adds names to the Host and Origin allowlists: Tailscale MagicDNS names,
`/etc/hosts` entries, or the name a reverse proxy forwards. A bare name (`burp-vm.tailnet.ts.net`)
is accepted without a port (a proxy on 443 forwards `Host: name`) and on every listener port; a
`name:port` entry only on that port; IPv6 literals as `[fd7a::5]`. Origins are accepted over both
`http` and `https`. Wildcards are not supported.

### Order of checks

1. Source address not allowed: `403`.
2. Host not allowed: `403`.
3. Origin present and not allowed: `403`.
4. Token required and missing or wrong (CORS preflights excepted): `401`.

## Recommended setups

Prefer the options that keep Raijin on loopback.

### SSH local port forwarding (nothing exposed)

```bash
ssh -N -L 9877:127.0.0.1:9877 -L 9878:127.0.0.1:9878 user@burp-vm
```

The client on your machine uses `http://127.0.0.1:9877/mcp` and the dashboard at
`http://127.0.0.1:9878`. Raijin stays on loopback without a token; SSH authenticates you. Keep the
same port number on both ends: the `Host` header carries the local port, and Raijin only knows its
own. If you must forward to another local port (`-L 19877:127.0.0.1:9877`), add
`127.0.0.1:19877` to `mcp_allowed_hosts`.

### Tailscale / WireGuard

Bind to the VPN address only, never `0.0.0.0`:

- `mcp_bind_host=100.101.102.103` (the VM's tailnet IP) and `mcp_allow_remote_bind=true`;
- `mcp_allowed_ips=100.64.0.0/10` (the tailnet range), or just your client's tailnet IP;
- `mcp_allowed_hosts=burp-vm.tailnet.ts.net` if the client uses the MagicDNS name;
- the client sends the bearer token from the Server tab.

The same applies to a host-only VM network: bind the VM's host-only address (VirtualBox default
`192.168.56.x`) and allow only the host (`192.168.56.1`).

### Caddy with TLS (`configs/Caddyfile`)

Profile B of `configs/Caddyfile` keeps Raijin on loopback and puts Caddy on the VM address with
HTTPS from Caddy's internal CA (`tls internal`), a bearer check at Caddy for MCP and basic auth for
the dashboard. Caddy rewrites `Host` to `127.0.0.1:<port>` (`header_up Host`), which Raijin's Host
allowlist requires. Raijin sees Caddy as a loopback peer, so source allowlisting belongs in Caddy or
the firewall. Using Raijin's token as Caddy's `RAIJIN_TOKEN` lets you also enable
`mcp_require_auth`, so both layers check the same header.

## Operator controls and what an agent can change

| Preference | Type | Default | Effect |
|---|---|---|---|
| `mcp_scope_mode` | string | `warn` | Gates outbound HTTP against Burp's target scope (`off` / `warn` / `enforce`). |
| `mcp_allow_destructive` | boolean | `false` | Blocks `burp_shutdown` and project/user config import until enabled. |
| `mcp_allow_remote_bind` | boolean | `false` | Required for any non-loopback bind. |
| `mcp_require_auth` | boolean | `false` | Requires the bearer token on loopback too. |
| `mcp_persist_activity` | boolean | `true` | Saves the MCP activity log to disk. |

The `persistence` tool (`preference_get` / `preference_store`) reads and writes **string**
preferences only. The boolean gates above can be changed only by the operator (Server tab, Burp
preferences, `-D` properties). A connected agent can read and change the string settings
(`mcp_scope_mode`, `mcp_bind_host`, `mcp_auth_token`, `mcp_allowed_ips`, `mcp_allowed_hosts`, the
ports): a connected agent already drives Burp. A changed bind host still needs the boolean opt-in,
and network settings apply on the next rebind or reload.

## Files on disk

| File | Content |
|---|---|
| `~/.raijin-audit.jsonl` | Audit trail of security-relevant calls: outbound requests, destructive and mutating tools (Turbo runs, `http_send_requests_parallel`, `config_*`, `websocket_*`, `persistence_*`, ...), errors, and `server.remote_bind`. Arguments are kept up to 8000 characters each. Rotated at 20,000 lines or 16 MiB. |
| `~/.raijin-activity.jsonl` | The dashboard's MCP activity log, per Burp project (toggle: `mcp_persist_activity`). |
| `~/.raijin-findings.jsonl` | The agent's findings, per Burp project. |

Write failures go to Burp's error log. Raijin itself never writes the token to these files or to
its logs, but tool arguments and result summaries are recorded: a call that passes or reads a
secret (for example `preference_get` on `mcp_auth_token`) leaves it on disk.

## Reporting a vulnerability

Please report security issues privately to the maintainer (see the repo README / profile:
GitHub `Cy-S3c`, Telegram `@D4RK_V0RT3X`) rather than opening a public issue.
