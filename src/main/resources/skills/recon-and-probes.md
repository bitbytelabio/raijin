---
name: recon-and-probes
description: Guided recon and probe tools (scope-gated): what each does and how to use them safely.
---
# Recon and probes

All of these refuse targets outside Burp's scope. Add the target with `scope(action=include)` first.

- `recon(action=fingerprint)`: technology and WAF fingerprinting.
- `recon(action=content_discovery)`: find paths and files.
- `recon(action=param_mine)`: discover hidden parameters. `mode=reflection` (default) flags names whose value is echoed back; `mode=diff` flags names that change server status/body WITHOUT reflecting (auth/cache/feature-flag params reflection alone misses); `mode=both` reports both. `inject_in` picks where the name goes: query (default), body, json_body, cookie, header. Omit `candidates` to use a bundled dictionary.
- `recon(action=js_endpoints)`: pull endpoints out of JavaScript.
- `probe(action=cors)`: CORS misconfiguration checks.
- `probe(action=graphql)`: introspection and schema checks. `mode=probe` (default) is the introspection/suggestion verdict; `mode=query_templates` generates a runnable example query/mutation/subscription per schema field; `mode=poi_scan` flags security-interesting fields by name (auth/privileged/pii/payment/database/debugging/files) plus deprecated fields and custom scalars; `mode=cycles_scan` flags types that recurse into themselves (deep-nesting/DoS risk); `mode=batch_attack` expands a `$[INT:first:last]`/`$[LIST]` placeholder in a query template into N aliased sub-operations in one request (2FA brute force, IDOR enumeration, rate-limit bypass) — generates only unless `send` is set. The schema-aware modes need introspection enabled.
- `probe(action=injection)`: guided SQLi / SSTI / LFI detection with confirmation oracles.
- `probe(action=access_control)`: run the same requests as several identities and compare. `autorize(action=set_rule)` is the live/continuous counterpart — it taps proxy traffic instead of needing a fixed request list, replaying matching requests under a second identity in the background.
- `probe(action=idor)`: swap object ids horizontally with canary confirmation.
- `probe(action=jwt)`: JWT checks and token operations. Decode first with `util(action=jwt_decode)`. Modes: analyze, forge_none, alg_confusion, crack, sign (HMAC secret), sign_key, verify, encrypt, decrypt, embed_jwk, empty_hmac, psychic, header_url. Keys come from `jwt_keys`.
- `jwt_keys`: generate, import, list, export, or delete a key (RSA, EC, OKP, oct, password). `list` and `export` omit private material unless `include_private` is true.
- `auth_diff`, `api_import_openapi`: compare identities; import an OpenAPI spec as test requests.

Workflow: fingerprint, discover, mine parameters, then probe. Treat a probe hit as a lead; confirm it manually with `http_send_request`, then record it with `findings(action=add)`.
