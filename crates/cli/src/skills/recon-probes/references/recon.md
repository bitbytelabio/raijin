# Recon

## Fingerprint
`run {"do":"recon.fingerprint","url":"https://example.com/"}`: technology and WAF fingerprinting from one GET.

## Content discovery
`run {"do":"recon.content_discovery","base_url":"https://example.com/","paths":["<...>"]}`: up to 2000 paths
per call.

- Not-found behaviour is learned first from made-up paths of several shapes (plain, directory, `.json`,
  `.php`, your extensions), so a site that answers 200 to everything, echoes the path or redirects every
  unknown path gives no false hits.
- A 429 is waited out and the pace slowed; if blocking persists the scan stops with `stopped_at` so you can
  continue later.
- Every path is checked against scope; the result reports `skipped_out_of_scope` / `sent_out_of_scope`.

## Parameter mining
`run {"do":"recon.param_mine","url":"https://example.com/search"}`: hidden parameters, Param Miner style: many
names per request, each with its own canary, and a binary search inside a bucket only when its response
stands out, so the whole bundled list costs a few hundred requests.

- `mode` `reflection` (default) reports names whose value is echoed back; `diff` reports names that change the
  status, body, `Location`, `Set-Cookie` or `X-Cache` without reflecting, judged against repeated baselines;
  `both` reports both: `run {"do":"recon.param_mine","url":"<url>","mode":"both"}`.
- `inject_in` is `query` (default), `body`, `json_body`, `cookie` or `header`:
  `run {"do":"recon.param_mine","url":"<url>","inject_in":"header"}`.
- Omit `candidates` to use the bundled list (`param-miner-params`; `param-miner-headers` for `header`); a
  candidate may be `name~value` (`%s` = canary, `%h` = target host).
- `headers`, `cookies` and `body` shape the base request.
- `cache_buster` (default on) keeps responses out of caches; it is left off, with `cache_buster_dropped`, when
  the target rejects unknown query parameters.
- `offset`/`limit` page through the list (continue from `next_offset`); `bucket_size` and `max_requests`
  (default 500) bound the run.

## JavaScript endpoints
`run {"do":"recon.js_endpoints"}`: endpoints from JavaScript already in proxy history (`.js`, `.mjs`, `.cjs`):
quoted paths, full URLs and template literals (`/users/${id}` comes back as `/users/{id}`). Browse the target
first.

- Source maps are read when they are in history (original file names, endpoints in embedded sources).
- Maps a script only points to (`sourceMappingURL`, `SourceMap` header) are listed, and requested with
  `run {"do":"recon.js_endpoints","fetch_source_maps":true}`.
- `run {"do":"analyze.passive_intel"}` summarises what traffic already revealed.

## OpenAPI import
`run {"do":"api_import_openapi","spec_json":"<document>","send_requests":false}` imports an OpenAPI 3.0/3.1
or Swagger 2.0 document (JSON or YAML text in `spec_json`; `spec_url` when its server URL is relative) as test
requests, added to the site map and optionally sent (`send_requests`).

- A server URL naming a host that cannot be used is an error, never a fallback to the `spec_url` host.
- The result lists `security_schemes` and each endpoint's `security`.
