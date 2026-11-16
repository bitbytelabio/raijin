---
name: findings-reporting
description: Recording findings and producing reports.
---
# Findings and reporting

- `findings(action=add, type=..., url=...)`: store a finding. `type` (xss, sqli, idor, ssrf, ...) and `url` are required; add `severity` (`critical`, `high`, `medium`, `low`, `info`), `location` (`param:name`, `header:name`, `body`, `path`), `detail`, `evidence`, `request` and `response`, `steps_to_reproduce`, `cvss_score` / `cvss_vector`, `owasp_category`. The same type, URL and location is stored once. Findings are kept per Burp project, survive reloads and fill the Raijin → Findings tab.
- `findings(action=list)` (filter by `severity` or `type`) and `findings(action=remove, id=...)`. A critical/high mismatch from a live `autorize` tap is added automatically; do not record it twice.
- `scanner(action=generate_report)`: export Burp's scanner issues as an HTML or XML report. `scanner(action=create_issue)` or `sitemap(action=add_issue)` puts an issue into Burp's own issue list.
- `organizer(action=send)`, `organizer(action=get_items)`, `organizer(action=annotate)`: park interesting requests in Organizer.
- `persistence(action=store)`, `persistence(action=get)`, `persistence(action=list)`, `persistence(action=delete)`: keep notes across calls in the Burp project.
- `log(action=message)`, `log(action=event)`: write to the extension log and Burp's event log.

Include a minimal reproduction request, the observed response evidence, and the impact. Keep wording neutral and factual.
