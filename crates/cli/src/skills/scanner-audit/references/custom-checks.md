# Custom checks and Bambdas

## BChecks
Read `run {"do":"custom_check.bcheck_templates"}` first, then create one:
`run {"do":"custom_check.bcheck_create","name":"<name>","description":"<what it finds>","type":"passive_response","match_pattern":"<regex>","severity":"medium","confidence":"firm"}`.

- Types: `passive_response`, `passive_request`, `insertion_point`, `host_level` (with its own `path`),
  `path_level`, `collaborator`.
- Any text is written into the script as a string, never as DSL; an empty pattern is rejected.
- `run {"do":"custom_check.bcheck_import","script":"<bcheck>"}` imports a hand-written script;
  `run {"do":"custom_check.bcheck_list"}` and `run {"do":"custom_check.bcheck_remove","id":"<id>"}`
  manage them.

## Script-mode scan checks
Read `run {"do":"custom_check.scancheck_templates"}` first.

- Passive, conditions joined by `match_mode` `all` or `any`:
  `run {"do":"custom_check.scancheck_create_passive","name":"<n>","description":"<d>","severity":"low","confidence":"firm","issue_detail":"<d>","conditions":["<...>"],"match_mode":"any"}`.
- Active, with payload steps:
  `run {"do":"custom_check.scancheck_create_active","name":"<n>","description":"<d>","severity":"high","confidence":"firm","issue_detail":"<d>","steps":["<...>"]}`.
  Payload steps each have their own `match_mode`; `stop_if_no_match` `false` makes a step optional; a step
  without response conditions only primes the target, so it counts once answered but is never evidence.
- An active check reports only when a step matches and the unmodified request would not have matched the
  same conditions. That unmodified request is sent before the first payload, so a payload the application
  stores cannot hide its own match.
- `run {"do":"custom_check.scancheck_list"}` and `run {"do":"custom_check.scancheck_remove","id":"<id or name>"}`
  manage them.

## Dry runs before deploying
`run {"do":"custom_check.bcheck_dry_run","type":"passive_response","match_pattern":"<regex>"}` and
`custom_check.scancheck_dry_run` take the same definition and evaluate it against the proxy history already
recorded (`url_pattern`, `in_scope_only`, `max_items`, `max_matches`).

- Nothing is imported or sent.
- A passive check lists what it would report; an active one shows how many recorded responses already satisfy
  its conditions without a payload (a high count means the conditions are too broad).

## Lower-level routes
`scanner.register_check`, `run {"do":"scanner.unregister_check","check_name":"<id or name>"}` and
`run {"do":"scanner.import_bcheck","script":"<bcheck>"}`. Creating a check under an existing name replaces it.

## Bambdas
`run {"do":"bambda_templates"}` gives the envelope format, known functions and locations, and starting
templates. Then `run {"do":"bambda_import","script":"<bambda>"}` imports an envelope or a bare lambda body;
the result carries its `id`, and importing that id again replaces it.
