# Fuzzing and races

## `http_fuzz`
Burp Intruder's attack types:
`run {"do":"http_fuzz","request":"<raw>","host":"<h>","attack_mode":"pitchfork","payload_sets":["<...>"],"encoders":["url"]}`.

- Positions: mark them with `FUZZ` or `§value§` pairs (the pair not being fuzzed keeps its value), or give
  `positions` offsets.
- `attack_mode`: `sniper` (default) fuzzes one position at a time while the others keep their value (every
  `FUZZ` takes the payload at once); `battering_ram` puts the same payload in every position; `pitchfork`
  walks one payload set per position in step; `cluster_bomb` sends every combination.
- Payloads come from `payloads` and/or a built-in `payload_library` (`xss`, `sqli`, `traversal`, `ssti`,
  `cmdi`, `ssrf`, `xxe`, `crlf`, `nosqli`, `open_redirect`, `prototype_pollution`), or one set per position
  from `payload_sets` (each an array, a library name or `{payloads, library}`).
- `encoders` (`url`, `url_all`, `double_url`, `json`, `base64`, `base64url`, `html`, `hex`, `raw`) run on
  each payload in order.

### Pace and output
- A run sends one request at a time unless `concurrency` (at most 50) says otherwise; `rate_limit` caps the
  requests started per second and `max_requests` (default 10000) the run.
- `stop_on_match` stops at the first matching response; a failed request is recorded without stopping the
  run.
- Every response is clustered by status and body similarity (`cluster_similarity`, default 90) with timing
  outliers: the small clusters are the anomalies.
- `hide_status`, `filter_length`, `grep_regex` and `hide_regex` only shorten the list (hidden responses still
  count in the summary).
- `report` `clusters` lists one line per request plus one full exchange per cluster; `summary` gives the
  summary alone: `run {"do":"http_fuzz","request":"<raw>","host":"<host>","payloads":["<...>"],"report":"summary"}`.

## `http_race`
Simultaneous requests for race conditions (`count`, or `FUZZ` with `payloads`), released together behind a
real synchronisation barrier: `run {"do":"http_race","request":"<raw>","host":"<host>","count":20}`.

- `sync` `single_packet` (default) is the HTTP/2 single-packet attack through Burp's parallel sender: the
  final frames of every request leave in one TCP packet, so the target must speak HTTP/2 (`http_mode`
  `HTTP_2_IGNORE_ALPN` forces it without ALPN).
- `sync` `last_byte` (the default with `http_mode` `HTTP_1`) is for HTTP/1.1: every request is written on a
  connection of its own except for its last byte, and the last bytes go out back to back once every
  connection is ready (at most 256 connections; `sni` sets the TLS server name). It reports
  `ttfb_ms`/`ttlb_ms` per request and the `release_spread_us`, and bypasses Burp:
  `run {"do":"http_race","request":"<raw>","host":"<host>","count":20,"sync":"last_byte"}`.
- Results are clustered by status and body similarity with timing outliers; `race_condition_likely` is true
  when identical requests were answered in more than one way. Alike responses do not rule a race out: check
  the application state too.
- For HTTP/3, several endpoints at once or a scripted sequence, use `turbo_run`
  (`guide {"topic":"turbo-scripting"}`).

## Content-Length and encoding
- After a substitution (`http_fuzz`, `http_race`) Content-Length is recomputed in the bytes actually sent,
  unless `"auto_fix_content_length":false`. A fuzz position on the Content-Length line turns the fix off for
  that run.
- Request text goes out as ISO-8859-1 (one byte per char), or as UTF-8 when it holds a char above U+00FF.
  Only the header block's bare line feeds become CRLF; the body is sent as typed.

## Comparing responses
- `run {"do":"analyze.http_variations","responses":["<...>"]}`: which attributes differ between responses.
- `run {"do":"analyze.http_keywords","response":"<raw>","keywords":["<...>"]}`: keyword counts in one
  response; run it per response to compare them.
- `run {"do":"analyze.diff","item1":"<response>","item2":"<response>","type":"response"}`: a diff of two messages.
