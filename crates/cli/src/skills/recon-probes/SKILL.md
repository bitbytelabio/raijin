---
name: recon-probes
description: Use when mapping a target or testing one vulnerability class. Recon, param mining, OpenAPI, CORS/cache/GraphQL/injection/IDOR/JWT probes.
---
# Recon and probes

Map a target (fingerprint, content discovery, parameter mining, JavaScript endpoints, OpenAPI) and test one
vulnerability class at a time with a guided probe, or compare identities (authorization). A full Burp Scanner
crawl and audit is `scanner-audit`; sending and varying requests by hand is `http-testing`.

## Pick the call

| Goal | Call |
|---|---|
| Technology and WAF | `run {"do":"recon.fingerprint","url":"https://example.com/"}` |
| Hidden paths | `run {"do":"recon.content_discovery","base_url":"https://example.com/","paths":["<...>"]}` |
| Hidden parameters | `run {"do":"recon.param_mine","url":"https://example.com/search"}` |
| Endpoints in JavaScript already in history | `run {"do":"recon.js_endpoints"}` |
| Requests from an OpenAPI/Swagger document | `run {"do":"api_import_openapi","spec_json":"<document>"}` |

| Probe | Class | Call |
|---|---|---|
| `probe.cors` | CORS misconfiguration | `run {"do":"probe.cors","url":"<url>"}` |
| `probe.cache` | Cache poisoning and deception | `run {"do":"probe.cache","url":"<url>"}` |
| `probe.graphql` | GraphQL introspection, schema, batching | `run {"do":"probe.graphql","url":"<url>"}` |
| `probe.injection` | SQLi, NoSQLi, cmdi, SSTI, LFI, XXE, SSRF, XSS, redirect, CRLF | `run {"do":"probe.injection","request":"<raw>","host":"<host>"}` |
| `auth_diff` | One request across identities | `run {"do":"auth_diff","request":"<raw>","host":"<host>","auth_levels":["<...>"]}` |
| `probe.access_control` | Many requests across identities | `run {"do":"probe.access_control","requests":["<...>"],"identities":["<...>"]}` |
| `probe.idor` | Horizontal IDOR, canary-confirmed | `run {"do":"probe.idor","request":"<raw>","host":"<host>","identities":["<...>"]}` |
| `probe.jwt` | JWT attacks | `run {"do":"probe.jwt","mode":"analyze","token":"<jwt>"}` |

## Workflow
1. Scope first: `run {"do":"scope.include","url":"https://example.com"}`.
2. Fingerprint: `recon.fingerprint`.
3. Discover: `recon.content_discovery`, `recon.js_endpoints` (browse the target first), `api_import_openapi`.
4. Mine parameters: `recon.param_mine`.
5. Probe the class the target suggests (table above).
6. Confirm a hit with `http_send_request`, then record it.

## Pitfalls
- Every request these tools send is checked against Burp's scope by the operator's `mcp_scope_mode`: `warn`
  (default) sends it and adds `scope_warning` to the result, `enforce` refuses it (`out_of_scope: true`).
  Content discovery checks every path and reports `skipped_out_of_scope` / `sent_out_of_scope`.
- Probes resend a request many times, so do not point them at requests that change data (a delete, a
  payment) unless you mean to.
- A probe hit is a lead, not a finding. Refusals that look alike are informational in the authorization
  probes; a timeout is never evidence in `probe.injection`.
- Decode a token with `run {"do":"util.jwt_decode","token":"<jwt>"}` before `probe.jwt`.

## Done when
The probe's lead reproduces with one `http_send_request`, and it is recorded:
`run {"do":"findings.add","type":"<type>","url":"<url>","severity":"high","evidence":"<what you saw>"}`.

## References
- `guide {"topic":"recon-probes/references/recon.md"}`: fingerprint, content discovery, parameter mining,
  JavaScript endpoints and source maps, OpenAPI import.
- `guide {"topic":"recon-probes/references/probes.md"}`: the CORS, cache, GraphQL and injection probes.
- `guide {"topic":"recon-probes/references/authz.md"}`: `auth_diff`, `probe.access_control`, `probe.idor`.
- `guide {"topic":"recon-probes/references/jwt.md"}`: `probe.jwt` modes, `jwt_keys`, `util.jwt_decode`.
