---
name: recon-and-probes
description: Guided recon and probe tools (scope-gated): what each does and how to use them safely.
---
# Recon and probes

All of these refuse targets outside Burp's scope. Add the target with `scope(action=include)` first.

- `recon(action=fingerprint)`: technology and WAF fingerprinting.
- `recon(action=content_discovery)`: find paths and files.
- `recon(action=param_mine)`: discover hidden parameters.
- `recon(action=js_endpoints)`: pull endpoints out of JavaScript.
- `probe(action=cors)`: CORS misconfiguration checks.
- `probe(action=graphql)`: introspection and schema checks.
- `probe(action=injection)`: guided SQLi / SSTI / LFI detection with confirmation oracles.
- `probe(action=access_control)`: run the same requests as several identities and compare.
- `probe(action=idor)`: swap object ids horizontally with canary confirmation.
- `probe(action=jwt)`: JWT checks and token operations. Decode first with `util(action=jwt_decode)`. Modes: analyze, forge_none, alg_confusion, crack, sign (HMAC secret), sign_key, verify, encrypt, decrypt, embed_jwk, empty_hmac, psychic, header_url. Keys come from `jwt_keys`.
- `jwt_keys`: generate, import, list, export, or delete a key (RSA, EC, OKP, oct, password). `list` and `export` omit private material unless `include_private` is true.
- `auth_diff`, `api_import_openapi`: compare identities; import an OpenAPI spec as test requests.

Workflow: fingerprint, discover, mine parameters, then probe. Treat a probe hit as a lead; confirm it manually with `http_send_request`, then record it with `findings(action=add)`.
