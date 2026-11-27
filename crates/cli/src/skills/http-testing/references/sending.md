# Sending requests

## `http_send_request`
One request, from `url` + `method` + `headers` + `body` or from `raw_request`. Start here:
`run {"do":"http_send_request","url":"https://example.com/api","method":"POST","body":"{}"}`.

- `http_mode` picks `AUTO`, `HTTP_1`, `HTTP_2` or `HTTP_2_IGNORE_ALPN`.
- `connection_id` reuses one Burp connection; the request still completes before the call returns.
- Burp's request options: `follow_redirects` (`never`, `always`, `same_host` or `in_scope`; Burp does not
  follow redirects by default), `sni` (a TLS server name other than the host), `response_timeout_ms` (Burp's
  own read timeout), `verify_tls`:
  `run {"do":"http_send_request","url":"<url>","follow_redirects":"same_host","sni":"<name>"}`.
- With `url` and `raw_request` together the url names the target and the raw request is sent as written.

### Native HTTP/2
`run {"do":"http_send_request","url":"<url>","http2_headers":[{"name":":path","value":"/x"}]}` sends the
header list exactly as given, pseudo-headers included, so they can be repeated, reordered, left out or
malformed (CR/LF and uppercase names reach the wire).

- Items are `{"name": ":path", "value": "/x"}` or `[":path", "/x"]`.
- A list without any pseudo-header gets the four derived from `url` and `method`, first.
- No Content-Length is added: put a `content-length` field in the list to send one.
- It goes out as HTTP/2 (`http_mode` `HTTP_2`, the default here, or `HTTP_2_IGNORE_ALPN`) and does not combine
  with `raw_request` or `headers`.

## `http_send_request_chain`
Dependent requests (login, then use the token): `run {"do":"http_send_request_chain","steps":["<...>"]}`.

- A step's `extract` is an array of `{name, pattern | json_path | xpath, from}`; `from` is `body` or
  `header`. The pattern's first group is the value, and a header pattern runs over the `Name: value` lines,
  every `Set-Cookie` included.
- An extracted value fills `{{name}}` in later steps. Extract rules are checked before the step is sent.

## `http_send_requests_parallel`
Independent requests at once, across hosts: `run {"do":"http_send_requests_parallel","requests":["<...>"]}`.

## `http_send_raw_bytes`
Exact bytes, one request and one response, when the request must not be normalised (smuggling, CRLF
injection): `run {"do":"http_send_raw_bytes","raw_request":"<raw>","host":"<host>","port":443,"use_tls":true}`.

- `raw_request_hex` is byte-exact.
- In `raw_request`, literal `\r\n` escapes are decoded only when the text has no real line break, and a
  character above U+00FF sends the whole text as UTF-8.
- It goes out as HTTP/1 unless `http_mode` says otherwise (`notes` say when the response still came back over
  HTTP/2).

Several raw requests over one socket are `http_send_pipeline`
(`guide {"topic":"http-testing/references/pipeline.md"}`).

## Encoding and structured inputs
- After a substitution (`http_fuzz`, `http_race`) or when a raw request's Content-Length does not match its
  body (`http_send_request`), Content-Length is recomputed in the bytes actually sent, unless
  `auto_fix_content_length` is `false` (all three tools take it).
- Request text goes out as ISO-8859-1 (one byte per char), or as UTF-8 when it holds a char above U+00FF.
  Only the header block's bare line feeds become CRLF; the body is sent as typed. `http_send_raw_bytes` and
  `http_send_pipeline` change nothing.
- Structured inputs (`url`, `method`, `headers`) lose raw CR/LF only, always reported in `warnings`; every
  other byte (NUL, VT, odd header names) is sent.
- The `url` target goes out exactly as written, and the Host header is the URL's authority: `host`/`port`
  only move the connection.

## Timeouts and limits
- `timeout_ms` (0 = default, -1 = no hard timeout, at most 600000, default 25000) bounds one request, each chain step or
  fuzz request, a whole parallel batch or race. A timed-out send returns `is_timeout: true`.
- A number out of range (`count`, `concurrency`, `max_responses`, ...) is clamped and reported in `notes`
  instead of being refused.
