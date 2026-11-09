---
name: proxy-traffic
description: Reading and shaping proxy traffic: history, search, intercept, rules, WebSockets.
---
# Proxy traffic

- Read: `proxy_history` (paged, filter by host/method/status), `proxy_history_search` (text or regex), `websocket(action=history)`, `websocket(action=history_search)`.
- Annotate: `proxy_annotate` to mark items worth returning to.
- Intercept: `proxy_intercept(action=status)`, `proxy_intercept(action=enable)`, `proxy_intercept(action=disable)`. Turn it back off when finished or the browser hangs.
- Rules: `proxy_rule(action=set_request_rule)`, `proxy_rule(action=set_response_rule)`, `proxy_rule(action=list)`, `proxy_rule(action=remove)`. Config-level equivalents: `config_match_replace_*`.
- Auth: `proxy_auto_auth` for automatic auth handling.
- Mining: `recon(action=js_endpoints)` (scope-gated) and `analyze(action=passive_intel)` summarise what traffic already revealed.
- WebSockets: `websocket(action=create)`, `websocket(action=send_text)`, `websocket(action=send_binary)`, `websocket(action=get_messages)`, `websocket(action=close)`.

Use `includeRequest` / `includeResponse` options sparingly; metadata-only history is much cheaper.
