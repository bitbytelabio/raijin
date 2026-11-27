---
name: scanner-audit
description: Use when running Burp Scanner. Crawls, audits, scan tasks, issues and reports, BChecks, scan checks, Bambdas.
---
# Scanner and audits

Run Burp Scanner crawls and audits, track their tasks, read and create issues, and extend the Scanner with
custom checks and Bambdas. One targeted vulnerability class is a probe (`recon-probes`), not a full audit.

## Pick the call

| Goal | Call |
|---|---|
| Is the target in scope | `run {"do":"scope.check","url":"https://example.com/"}` |
| Crawl | `run {"do":"scanner.start_crawl","urls":["https://example.com/"],"in_scope_only":true}` |
| Audit given URLs | `run {"do":"scanner.start_audit","urls":["https://example.com/app"]}` |
| Task progress | `run {"do":"scanner_task.status","task_id":"<id>"}` |
| Issues of one task | `run {"do":"scanner_task.issues","task_id":"<id>"}` |
| Every issue | `run {"do":"scanner.get_all_issues"}` |
| What a crawl found | `run {"do":"sitemap.query","only_with_response":true}` |
| Export a report | `run {"do":"scanner.generate_report","format":"HTML","output_path":"<path>"}` |

## Workflow
1. Confirm scope with `scope.check`. `scanner.start_crawl`'s `in_scope_only` is enforced by filtering seeds
   before crawling; its `max_depth` is NOT: Burp's Montoya API has no depth control, so it is always ignored
   (check the response's `ignored` field).
2. `scanner.start_crawl` and/or `scanner.start_audit`; each returns a task. `start_audit`'s `urls` are added
   directly. To audit with credentials:
   `run {"do":"scanner.start_audit","urls":["<url>"],"auth_header_name":"Cookie","auth_header_value":"<cookies>"}`.
3. Track with `run {"do":"scanner_task.list"}`, `scanner_task.status` and `scanner_task.issues`; add requests
   with `run {"do":"scanner_task.add_request","task_id":"<id>","request":"<raw>","host":"<host>"}`; stop
   with `run {"do":"scanner_task.delete","task_id":"<id>"}`.
4. Read results: `scanner.get_all_issues`, `run {"do":"sitemap.get_issues","severity":"FALSE_POSITIVE"}`
   (the severity filter includes `FALSE_POSITIVE`); export with `scanner.generate_report`. To see what a
   crawl actually found, `sitemap.query` with `only_with_response`: it excludes noise (`/cdn-cgi/`, favicon,
   etc.) by default and reports `with_response`/`without_response` counts and status/MIME histograms,
   unlike a raw site map dump.
5. Create issues yourself: `scanner.create_issue`, `sitemap.add_issue`. Mark entries worth returning to with
   `run {"do":"sitemap.annotate","url":"<url>","notes":"<note>"}`.
6. Pause or resume Burp's task engine: `run {"do":"burp.task_engine_set","state":"paused"}`,
   `run {"do":"burp.task_engine_state"}`.

## Pitfalls
- `audit_mode` `thorough` currently runs identically to `normal` (Montoya has only two built-in audit
  configurations); `insertion_point_types` is accepted but not enforced.
- `crawl_first` starts a real, separate crawl when `urls` is given, but its discoveries are NOT auto-added to
  this audit: poll the site map after and start a fresh audit with what you find. Read each response's
  `applied`/`ignored`/`crawl_note` fields rather than assuming every parameter took effect.
- `auth_header_name` + `auth_header_value` set one header (replacing the request's own value) on Scanner
  traffic to the audited hosts only, until the audit ends or is deleted. A `Cookie` value sets only the
  cookies it names and keeps the request's other cookies (the Scanner's cookie payloads, CSRF and load
  balancer cookies). An audit with an auth header and no resolvable host is refused.
- Burp's own `request_count`/status for a crawl can be unreliable (stuck at 0 on some Burp versions):
  `scanner_task.status` also reports `sitemap_new_entries`, a heuristic based on `sitemap.query` counts;
  prefer it for judging whether a crawl is still finding new pages.
- When Burp cannot list a task's issues, `scanner_task.issues` falls back to the site map's issues under the
  task's targets, marked `"source": "site_map"`.
- Scanner tasks are advisory under the scope check: flagged, never refused.

## Done when
Each issue worth reporting is confirmed with a request of your own (`http_send_request`) and recorded with
`run {"do":"findings.add","type":"<type>","url":"<url>"}`; the Burp report is exported if asked for.

## References
- `guide {"topic":"scanner-audit/references/custom-checks.md"}`: BChecks, script scan checks, dry runs,
  check registration, Bambdas.
