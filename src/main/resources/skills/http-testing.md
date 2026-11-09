---
name: http-testing
description: Sending and varying HTTP requests with the http_* tools; when to use each.
---
# HTTP testing

- `http_send_request`: one request. Start here.
- `http_send_request_chain`: dependent requests (login, then use the token).
- `http_send_requests_parallel`: independent requests at once.
- `http_send_raw_bytes`: exact bytes when the request must not be normalised (smuggling-style cases).
- `http_fuzz`: replace marked positions from a payload list.
- `http_race`: simultaneous requests for race conditions. For sub-millisecond precision (single-packet), use `turbo_*`.
- `analyze(action=http_variations)`, `analyze(action=http_keywords)`, `analyze(action=diff)`: compare responses.
- `http_state(action=cookie_jar_get)` / `http_state(action=cookie_jar_set)`: inspect or seed cookies.
- `http_rule(action=traffic_rule_set)`, `http_rule(action=traffic_rule_list)`, `http_rule(action=traffic_rule_remove)`: rewrite outgoing traffic.
- `http_rule(action=token_rule_create)`, `http_rule(action=token_rule_list)`, `http_rule(action=token_rule_remove)`: keep tokens fresh across requests.

Hand a request to the Burp UI with `send_to_tool(action=repeater)`, `send_to_tool(action=intruder)`, `send_to_tool(action=comparer)`, `send_to_tool(action=decoder)` or `organizer(action=send)`.
Inspect parameters first with `analyze(action=extract_params)` and `analyze(action=insertion_points)`.
