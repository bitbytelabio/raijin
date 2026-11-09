---
name: scanner-audit
description: Running Burp audits and crawls, reading issues, and adding custom checks.
---
# Scanner and audits

1. Confirm scope (`scope(action=check)`).
2. `scanner(action=start_crawl)` and/or `scanner(action=start_audit)`; each returns a task.
3. Track with `scanner_task(action=list)`, `scanner_task(action=status)`, `scanner_task(action=issues)`; add requests with `scanner_task(action=add_request)`; stop with `scanner_task(action=delete)`.
4. Read results: `scanner(action=get_all_issues)`, `sitemap(action=get_issues)`; export with `scanner(action=generate_report)`.
5. Create issues yourself: `scanner(action=create_issue)`, `sitemap(action=add_issue)`.

Custom checks: `custom_check(action=bcheck_templates)`, `custom_check(action=bcheck_create)`, `custom_check(action=bcheck_import)`, `custom_check(action=bcheck_list)`, `custom_check(action=bcheck_remove)`; Kotlin-style scan checks via `custom_check(action=scancheck_templates)`, `custom_check(action=scancheck_create_passive)`, `custom_check(action=scancheck_create_active)`, `custom_check(action=scancheck_list)`, `custom_check(action=scancheck_remove)`; `scanner(action=import_bcheck)`, `scanner(action=register_check)`, `scanner(action=unregister_check)`.
Pause or resume Burp's task engine with `burp(action=task_engine_set)` / `burp(action=task_engine_state)`.
