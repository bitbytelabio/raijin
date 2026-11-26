# Authorization: compare identities

## `auth_diff` and `probe.access_control`
`run {"do":"auth_diff","request":"<raw>","host":"<host>","auth_levels":["<...>"]}` compares one request across
identities; `run {"do":"probe.access_control","requests":["<...>"],"identities":["<...>"]}` does it for many.

- A level is `{name, header_name, header_value}`, or `headers` for several (session cookie plus CSRF header)
  and `remove_headers`. Its headers replace the request's own, and a level named `none`, `unauth` or
  `anonymous` is sent without any credential header.
- Each level reports `headers_set`, `headers_removed` and `credential_headers_kept`.
- Findings have an `id` and `severity` (`all_identical`, `unauth_accessible`, `unauth_reads_protected`, ...).
- Refusals that look alike (same 401/403/404, a login redirect, a 200 login or denial page) are
  informational, never high or critical. A JSON body counts as a refusal only by its top-level error, message
  or 401/403 code, not by words in its data.
- Pass `denied_regex` when the application refuses with a 200 the built-in check does not recognise:
  `run {"do":"auth_diff","request":"<raw>","host":"<host>","auth_levels":["<...>"],"denied_regex":"<regex>"}`.
- A level without a response is listed under `errors`.
- `autorize.set_rule` is the live counterpart on proxy traffic (`guide {"topic":"proxy-traffic"}`).

## `probe.idor`
Horizontal IDOR with canary confirmation:
`run {"do":"probe.idor","request":"<raw>","host":"<host>","identities":["<...>"]}`.

- Give the request identity A makes to its own object, and `identities` that each declare `object_id` (a
  resource it owns) and `canary` (a string only in its own data).
- The id is swapped at its parameter boundary only (one path segment, one query/form/cookie/header value, one
  JSON value), replayed under every other identity, and a cross-user read is CONFIRMED only when the owner's
  canary appears in the reader's response.
- Pin the id with `id_value`, `id_location` and `id_name` (parameter name, JSON path, or path segment index)
  when auto-detection picks the wrong one; a pinned `id_value` may also begin a path segment (`42` of
  `/users/42-alice`).
- `transforms` and `enumerate` (at most 25; a larger value is clamped) add encoded and neighbouring ids,
  reported only when the answer is neither the reader's own view nor a not-found.
- When the unmodified request does not give the reader its own object (`own_view: false`, a login or denial
  page included), only a canary can grade a transformed id above info.
