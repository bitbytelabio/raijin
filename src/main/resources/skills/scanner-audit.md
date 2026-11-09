---
name: scanner-audit
description: Running Burp audits and crawls, reading issues, and adding custom checks.
---
# Scanner and audits

1. Confirm scope (`scope(action=check)`). `scanner(action=start_crawl)`'s `in_scope_only` is enforced by filtering seeds before crawling; its `max_depth` is NOT — Burp's Montoya API has no depth control, so it's always ignored (check the response's `ignored` field).
2. `scanner(action=start_crawl)` and/or `scanner(action=start_audit)`; each returns a task. `start_audit`'s `urls` are added directly; `audit_mode=thorough` currently runs identically to `normal` (Montoya has only two built-in audit configurations); `insertion_point_types` is accepted but not enforced; `crawl_first` starts a real, separate crawl when `urls` is given, but its discoveries are NOT auto-added to this audit (poll the site map after and start a fresh audit with what you find) — read each response's `applied`/`ignored`/`crawl_note` fields rather than assuming every parameter took effect.
3. Track with `scanner_task(action=list)`, `scanner_task(action=status)`, `scanner_task(action=issues)`; add requests with `scanner_task(action=add_request)`; stop with `scanner_task(action=delete)`. Burp's own `request_count`/status for a crawl can be unreliable (stuck at 0 on some Burp versions) — `scanner_task(action=status)` also reports `sitemap_new_entries`, a heuristic based on `sitemap(action=query)` counts; prefer it for judging whether a crawl is still finding new pages.
4. Read results: `scanner(action=get_all_issues)`, `sitemap(action=get_issues)`; export with `scanner(action=generate_report)`. To see what a crawl actually found, `sitemap(action=query, only_with_response=true)` — it excludes noise (`/cdn-cgi/`, favicon, etc.) by default and reports `with_response`/`without_response` counts and status/MIME histograms, unlike a raw site map dump.
5. Create issues yourself: `scanner(action=create_issue)`, `sitemap(action=add_issue)`. Mark entries worth returning to with `sitemap(action=annotate)`.

Custom checks: `custom_check(action=bcheck_templates)`, `custom_check(action=bcheck_create)`, `custom_check(action=bcheck_import)`, `custom_check(action=bcheck_list)`, `custom_check(action=bcheck_remove)`; Kotlin-style scan checks via `custom_check(action=scancheck_templates)`, `custom_check(action=scancheck_create_passive)`, `custom_check(action=scancheck_create_active)`, `custom_check(action=scancheck_list)`, `custom_check(action=scancheck_remove)`; `scanner(action=import_bcheck)`, `scanner(action=register_check)`, `scanner(action=unregister_check)`.
Pause or resume Burp's task engine with `burp(action=task_engine_set)` / `burp(action=task_engine_state)`.
