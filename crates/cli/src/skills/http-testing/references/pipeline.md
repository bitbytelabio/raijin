# Pipelines: several requests over one socket

`http_send_pipeline` writes several raw HTTP/1.1 requests over ONE socket and reads every response back in
order, for 0.CL and CL.TE probes where one request can draw two responses:
`run {"do":"http_send_pipeline","requests":["<...>"],"host":"<host>","port":443,"use_tls":true}`.

It writes to a socket of its own: nothing it sends passes through Burp (no site map entry, no traffic rule,
token rule or login macro).

## Framing
- Content-Length is never fixed.
- Framing is strict: a bad length or chunk stops reading with `close_reason: "error"` instead of guessing.
- Each response carries `framing`, `trailers` and `warnings`.
- `close_reason` says why reading stopped: `max_responses`, `idle`, `total_timeout`, `fin`, `rst`, `error`,
  or `switching_protocols` after a 101.
- Set `max_responses` when a probe may draw more or fewer responses than requests:
  `run {"do":"http_send_pipeline","requests":["<...>"],"host":"<host>","max_responses":3}`.

## Writing
- `write_mode` `single_write` with `write_pause_ms` writes request by request:
  `run {"do":"http_send_pipeline","requests":["<...>"],"host":"<h>","write_mode":"single_write","write_pause_ms":500}`.
- A request item can pause mid-write, as in Turbo: `pause_before` (n > 0 sends the first n-1 bytes, n < 0
  holds the last |n| back), `pause_markers` (after each occurrence of a string) and `pause_ms` (default 1000;
  a pause ends early once response bytes arrive).

## Bytes and timing
- Responses are read while the requests are still being written.
- Each response carries `raw_response_hex`: the bytes as received, any 1xx and the chunk framing included
  (`raw_hex_max_bytes`, default 65536; 0 leaves it out).
- `ttfb_ms`/`ttlb_ms` count from when the request with the same index was completely written: a negative
  value means the response began before its request was complete, a desync signal.
- `decode_content` `true` shows bodies with gzip or deflate undone; `sni` sets the TLS server name.
- The bytes of an unfinished response come back as `partial_response`, bytes past the last response as
  `unparsed`.

## Kept connections
- `keep_open` plus `connection_id` continue on the same socket in a later call, only when the server kept it
  open: `run {"do":"http_send_pipeline","requests":["<...>"],"host":"<host>","keep_open":true}`, then
  `run {"do":"http_send_pipeline","requests":["<...>"],"host":"<host>","connection_id":"<id>"}`.
- `run {"do":"http_state.pipeline_connections"}` lists the sockets `keep_open` kept and closes them:
  `run {"do":"http_state.pipeline_connections","close":["<id>"]}`,
  `run {"do":"http_state.pipeline_connections","close_all":true}`, plus `"force":true` for one a call is
  using.
- A kept socket nobody uses for 120 s is closed by itself.

For a scripted desync sweep, use Turbo (`guide {"topic":"turbo-scripting"}`).
