# WebSockets

## Connections
- `run {"do":"websocket.create","url":"wss://example.com/ws","headers":{},"subprotocol":"<name>"}`
  opens a connection.
- `run {"do":"websocket.list"}` shows tracked connections, including those Burp's Proxy saw. Connections
  opened by Burp tools can be read but not written to.

## Sending
`run {"do":"websocket.send_text","connection_id":"<id>","message":"<text>"}` or
`run {"do":"websocket.send_binary","connection_id":"<id>","data":"<base64>"}` (base64, standard or URL-safe,
padding optional). Each send returns the `message_index` of the sent frame.

## Waiting instead of polling
`run {"do":"websocket.wait_message","connection_id":"<id>","since_index":"<message_index>"}` blocks until a
frame recorded after that index matches `direction` (default `server_to_client`), `message_type`
(`TEXT`/`BINARY`) and `pattern`, the connection closes, or `timeout_ms` passes (default 10000, at most
300000).

- A reply that arrived before the call is found at once.
- It returns `matched`, the message or a `reason` (`timeout`, `connection_closed`), and `next_since_index` to
  pass as `since_index` for the next wait.
- Without `since_index` only frames arriving after the call count.

## Reading the buffer
`run {"do":"websocket.get_messages","connection_id":"<id>","since_index":0}` reads from `since_index`: no
frame is skipped, and the result reports `oldest_index`, `next_index`, `has_more` and `missed_messages`
(frames evicted before you read them). A binary frame's payload is base64 and its `length` the size in bytes.

## History
`run {"do":"websocket.history","host":"<host>"}` and
`run {"do":"websocket.history_search","pattern":"<regex>"}` read the Proxy's WebSocket history, filtered by
`websocket_id`, `url`, `direction`, and `host` for the history.

## Fuzzing
`run {"do":"websocket.fuzz","connection_id":"<id>","payload_library":"xss","template":"<text>","marker":"FUZZ"}`
sends each payload (`payloads` and/or `payload_library`, optionally placed in a `template` at its `marker`,
`payload_encoding` `json` to escape it for a JSON string) as one message over an open `connection_id`, or
over a fresh connection per payload with `url` for servers that close on bad input.

- `setup_messages` go first on each connection.
- Per payload it returns the frames it triggered, `response_ms` and a cluster; small `clusters` are the
  anomalies.
- `delay_ms`, `window_ms`, `idle_ms` and `timeout_ms` shape the timing; a stopped run gives `next_index` to
  pass back as `start_index`.

## Intercept rules
`run {"do":"websocket.set_intercept_rule","rule_action":"modify","match_url":"<regex>","match_message":"<regex>"}`
(`rule_action` `modify`, `drop` or `tag`; also `direction` and `message_type`).
`run {"do":"websocket.list_intercept_rules"}` lists them in evaluation order,
`run {"do":"websocket.remove_intercept_rule","rule_id":"<id>"}` removes one.

- Binary frames are matched and rewritten as ISO-8859-1 text, so `\xNN` matches one byte.
- A rule without `message_type` applies to both kinds.

## Regexes
Regexes in `wait_message`, `fuzz` and the history search ignore case; start the pattern with `(?-i)` for an
exact match.
