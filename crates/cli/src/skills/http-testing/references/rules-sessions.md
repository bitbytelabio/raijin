# Rules and sessions

## Cookie jar
Inspect, seed or remove Burp's cookies: `run {"do":"http_state.cookie_jar_get"}`,
`run {"do":"http_state.cookie_jar_set","name":"<name>","value":"<value>","domain":"<domain>"}` and
`run {"do":"http_state.cookie_jar_delete","name":"<name>","domain":"<domain>"}`.

## Traffic rules
`run {"do":"http_rule.traffic_rule_set","direction":"request","rule_action":"modify","modify_add_header":"<header>"}`
rewrites outgoing traffic (`direction` is `request` or `response`).

- `rule_action` `modify` (default) adds, removes or replaces headers, written exactly as given (CR/LF, odd
  spacing or a missing colon included).
- `drop` suppresses the request, and `spoof_response` answers it with the `spoof_response` text without
  sending it (both `direction` `request` only).
- `tool_filter` limits a rule to traffic from some Burp tools. Raijin's own unauthenticated probes
  (`auth_diff`, `autorize`, `probe.idor`) only get rules whose `tool_filter` names `EXTENSIONS`.
- List and remove: `run {"do":"http_rule.traffic_rule_list"}`,
  `run {"do":"http_rule.traffic_rule_remove","rule_id":"<id>"}`.

## Token rules
`http_rule.token_rule_create`, `http_rule.token_rule_list` and `http_rule.token_rule_remove` extract a value
from responses and inject it into later requests to keep CSRF or session tokens fresh. For example, a rule
named `jwt` that reads `$.data.token` from response bodies and sends it as `Authorization: Bearer <token>`
(one call, on one line):

`run {"do":"http_rule.token_rule_create","rule_name":"jwt","scope":"suite","extract_from":"body","extract_json_path":"$.data.token","inject_into":"header","inject_name":"Authorization","inject_value_template":"Bearer {value}"}`

- `extract_json_path` (`$.data.token`) or `extract_xpath` (`//input[@name='csrf']/@value`) selects the value;
  `extract_regex` takes its first group (else the whole match), after a path from the selected value.
- `extract_from` `header` reads every line of `extract_header_name`, each `Set-Cookie` included.
- The value goes into a `header`, `cookie`, `body` (form parameter), `query` (URL parameter) or `json` value
  (`inject_name` is then a JSONPath naming one value, replaced in place); a value with CR/LF is never written.
- `inject_value_template` renders `{value}`, or an encoded `{value|url}`, `{value|base64|url}`, ... (the
  `http_fuzz` encoders); `inject_if_missing` `false` only updates requests that already carry it.
- Internal unauthenticated probes never receive it.

## Login macros
Macros re-establish an expired session on their own:
`run {"do":"http_rule.macro_set","name":"<name>","steps":["<...>"],"scope":"suite"}` stores login requests
(`http_send_request_chain` steps, at most 20, whose `extract` feeds `{{name}}` in later steps).

- When a covered response shows an expired session (its status is in `trigger_status`, default `[401]`, or
  `trigger_regex` matches the status line, headers and body), the steps are replayed and the original request
  is sent once more; that response replaces the expired one, and the tool result reports `reauthenticated`
  with the macro's name.
- Cookies the steps set replace same-named cookies in covered requests (they are never added), and token rules
  extract from the step responses.
- `run {"do":"http_rule.macro_run","name":"<name>"}` runs it now, to prime the session or debug the steps (a
  run whose steps all succeed resumes a suspended macro); `run {"do":"http_rule.macro_list"}` shows runs,
  failures and suspension; `run {"do":"http_rule.macro_remove","name":"<name>"}` deletes it.

### Safeguards
- Proxy traffic is left alone by default (`tool_filter`), and only a request that carried credentials
  triggers a macro (`require_credentials`). Neither the steps, the retry nor Raijin's internal probes ever
  trigger one.
- A macro has one run at a time and runs by itself at most every `min_interval_ms` (default 5000), with
  `step_timeout_ms` (default 15000) per step and for the retry, and 60 s per run.
- After `max_failures` (default 3) runs in a row that did not help, it suspends itself.
- While a macro is enabled it also replaces a deliberately stale session cookie: set `"enabled":false` to
  send one.

## Handing requests on
- To the Burp UI: `run {"do":"send_to_tool.repeater","request":"<raw>","host":"<host>","port":443}`, or
  `send_to_tool.intruder`, or `run {"do":"organizer.send","request":"<raw>","host":"<host>","port":443}`.
  `run {"do":"send_to_tool.comparer","data":"<text>"}` and `send_to_tool.decoder` take `data` instead.
- Inspect parameters first: `run {"do":"analyze.extract_params","request":"<raw>"}` and
  `run {"do":"analyze.insertion_points","request":"<raw>","host":"<host>","port":443}`.
