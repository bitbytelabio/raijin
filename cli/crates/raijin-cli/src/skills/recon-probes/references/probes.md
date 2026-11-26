# Probes: CORS, cache, GraphQL, injection

Probes resend a request many times: do not point them at requests that change data unless you mean to.
Treat a hit as a lead; confirm it with `http_send_request`, then record it with `findings.add`.

## CORS
`run {"do":"probe.cors","url":"<url>"}` sends an unrelated origin, `null`, and origins built from the target's
own host (prefix and suffix matches, an unescaped dot, `_` and subdomain tricks, the `http://` origin), each
as a GET and as an `OPTIONS` preflight. It flags a reflected origin, credentials, and a missing
`Vary: Origin`.

## Cache poisoning and deception
`run {"do":"probe.cache","url":"<url>","headers":{"Cookie":"<session>"}}` tests web cache poisoning and web cache
deception. It reads the cache state from the response headers first.

- Poisoning sends headers and cookies a cache often leaves out of its key, each under its own throwaway
  cache-buster, then asks for the same URL without the input and without a session: the changed response
  coming back confirms it. Nothing is sent if the cache ignores the query string.
- An input that works by changing the status, a redirect or the path is sent only once a new cache-buster
  value is seen to get a cache entry of its own (the others are listed under `skipped`). A changed status or
  redirect whose storage cannot be checked without risk to other visitors, or that a visitor without the
  input then gets too, is `inconclusive`, never confirmed.
- `stopped` says why a run ended early: `request_budget`, `rate_limited`, `baseline_changed` (the page now
  answers everyone differently) or `cache_buster_ignored` (a planted response reached every visitor: have the
  page purged).
- Deception requests static-looking variants of a page (`/page/x.css`, `/page;x.css`, ...) as the user, then
  without a session. Pass the logged-in user's `headers` to prove a private page gets stored.
- `checks` (`poisoning`, `deception`), `probe_headers`/`probe_cookies` (`name` or `name~value`) and
  `max_requests` (default 150) tune it: `run {"do":"probe.cache","url":"<url>","checks":["deception"]}`.

## GraphQL
`run {"do":"probe.graphql","url":"<url>","mode":"probe"}`. Modes:

- `probe` (default): the introspection/suggestion verdict.
- `query_templates`: a runnable query/mutation/subscription per field.
- `poi_scan`: security-interesting fields (auth, privileged, PII, payment, database, debugging, files;
  `custom_keywords` match literally), deprecated fields and custom scalars at their shortest path, through
  interfaces and unions.
- `cycles_scan`: every cycle (deep-nesting/DoS risk) with `cyclic_types`.
- `batch_attack`: expands `$[INT:first:last]`/`$[LIST]` into aliased operations in one request (2FA brute
  force, IDOR enumeration, rate limits); it only generates unless `send`.
- `fingerprint_engine`: names the backend.
- `bruteforce_schema`: rebuilds the schema from error messages when introspection is off (stops at
  `max_requests`, never sends an executable document).
- `subscription_probe`: checks subscriptions over WebSocket for both protocols (`graphql-transport-ws` and the
  legacy one) and reports `handshake_accepted`, `init_requires_auth`, `subscription_accepted`,
  `subscription_requires_auth`. Credentials go in `headers` and `connection_payload`; the anonymous session
  keeps only `Host`, `Origin` and `User-Agent` of your headers.

Every mode takes `headers` / `auto_headers`; an unreachable target is one error.

## Injection
`run {"do":"probe.injection","request":"<raw>","host":"<host>","classes":["sqli","ssti"]}`: put `FUZZ` anywhere
in the raw request (request line, any header such as `Cookie: id=FUZZ`, or the body).

- Each payload is written in the encoding that position needs (`encoding` overrides it) and Content-Length is
  recomputed.
- Classes: `sqli`, `nosqli`, `cmdi`, `ssti`, `lfi` (or `traversal`), `xxe`, `ssrf`, `xss`, `open_redirect`,
  `crlf`; all ten (about 130 requests) unless `classes` narrows them.
- `base_value` (default `1`) is the value the baseline sends at `FUZZ`; the boolean and operator checks only
  narrow the query, so it must match a real row or document.
- `ssrf`, `xxe` and `cmdi` also confirm out of band through Collaborator (`oob`, `oob_wait_seconds`; skipped
  with a reason on Community). Late out-of-band hits come back in the next call as `late_oob_interactions`.
- A finding needs a difference from the baseline that the payload explains: a timeout is never evidence, a
  delay must repeat while a zero-delay control stays fast, a TRUE/FALSE difference must hold over three
  rounds.
- Each finding carries `payload`, `confidence` (`certain`, `firm`, `tentative`) and `evidence` (what was sent,
  the baseline next to the probe).
- `time_budget_seconds` (default 300) stops new probes and lists `classes_not_completed`.
