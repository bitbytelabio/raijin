# Intercept, hold, rules and Autorize

## Burp's Intercept switch
`run {"do":"proxy_intercept.status"}`, `run {"do":"proxy_intercept.enable"}` and
`run {"do":"proxy_intercept.disable"}` drive Burp's own Intercept tab. Turn it back off when finished or the
browser hangs.

## Hold and edit live traffic
`run {"do":"proxy_intercept.hold","target":"both","match_host":"<host>","in_scope_only":true}` parks proxied
requests and/or responses (`target` is `request`, `response` or `both`; filters `match_host`, `match_url`,
`match_method`, `in_scope_only`) just before they are sent, after Burp's Intercept tab and the proxy rules,
so what you edit is what goes on the wire.

- `run {"do":"proxy_intercept.list_held","wait_seconds":10}` lists them with an `id` and `expires_in_ms`.
- `run {"do":"proxy_intercept.forward","id":"<id>"}` sends one as it is, or edited: `raw` replacement,
  `method`, `path`, `status_code`, `set_headers`, `remove_headers`, `body`; CR/LF allowed in headers.
  `run {"do":"proxy_intercept.forward","id":"<id>","set_headers":{"X-Test":"1"},"body":"<body>"}`.
- `run {"do":"proxy_intercept.drop","id":"<id>"}` discards it. `"all":true` forwards or drops every held
  message.
- `run {"do":"proxy_intercept.release"}` stops holding and forwards everything.
- Safety: a message nobody decides on within `timeout_seconds` (default 60) is forwarded unchanged, at most
  `max_held` (default 20) are held at once, and after 3 timeouts in a row holding stops by itself, so the
  browser is never stuck.

## Proxy rules
`run {"do":"proxy_rule.set_request_rule","rule_action":"modify","match_host":"<glob>","modify_set_header":"<h>"}`
and `proxy_rule.set_response_rule` take `rule_action` `modify`, `drop` or `tag`.
`run {"do":"proxy_rule.list"}` and `run {"do":"proxy_rule.remove","rule_id":"<id>"}` manage them.

- Match on `match_host` (a glob such as `*.example.com`, or a regex), `match_url`, `match_method`,
  `match_header`, `match_body`, `match_status`.
- `modify` can add, remove, replace or set headers (`modify_set_header` replaces every occurrence or adds the
  header; header lines are sent as written, CR/LF included), rewrite the body (`modify_body_regex`), the
  method and path of a request (`modify_method`, `modify_path`, `modify_path_regex` with `$1` groups) or the
  status of a response (`modify_status`).
- Config-level equivalents:
  `run {"do":"config.match_replace_add","type":"<type>","match":"<regex>","replace":"<text>"}`,
  `run {"do":"config.match_replace_list"}`, `run {"do":"config.match_replace_remove","rule_index":0}`.

## Auth header on every request
`run {"do":"proxy_auto_auth","host_pattern":"<host>","header_name":"Authorization","header_value":"<value>"}`
sets an auth header (replacing an existing one) on every proxied request to a host pattern.

## Autorize: live broken-access-control detection
`run {"do":"autorize.set_rule","identities":["<...>"]}` replays matching proxied requests under other
identities in the background and diffs the responses; browse the app as normal afterwards.

- Only authenticated originals are replayed (no credentials, 401 or 404 are skipped), `POST`/`PUT`/`DELETE`/
  `PATCH` only with `"include_mutating":true`, and each endpoint once per query string.
- Matches persist per Burp project with each identity's replay: read them with
  `run {"do":"autorize.list_matches"}` (`include_replays`, or `match_id` for one in full). Critical/high ones
  also go to `findings`.
- `autorize.list_rules`, `autorize.remove_rule` and `autorize.clear_matches` manage rules and matches.
- For a one-off check of requests you already have, use `auth_diff` or `probe.access_control` instead.
