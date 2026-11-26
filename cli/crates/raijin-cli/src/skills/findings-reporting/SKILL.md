---
name: findings-reporting
description: Use when recording or reporting results. Findings, Burp issues, scanner reports, Organizer, notes, logs.
---
# Findings and reporting

Record what you confirmed, put issues into Burp, export reports and keep notes in the Burp project. Finding
and confirming the behaviour is in the domain playbooks (`guide {"topic":"overview"}` maps them).

## Pick the call

| Goal | Call |
|---|---|
| Store a finding | `run {"do":"findings.add","type":"xss","url":"<url>","severity":"medium"}` |
| List findings | `run {"do":"findings.list","severity":"high"}` |
| Remove one | `run {"do":"findings.remove","id":"<id>"}` |
| An issue in Burp's own list | `run {"do":"scanner.create_issue","name":"<name>","url":"<url>","severity":"high"}` |
| Export Burp's scanner issues | `run {"do":"scanner.generate_report","format":"HTML","output_path":"<path>"}` |
| Park a request in Organizer | `run {"do":"organizer.send","request":"<raw>","host":"<host>","port":443}` |
| A note across calls | `run {"do":"persistence.store","key":"<key>","value":"<text>"}` |
| A line in the extension log | `run {"do":"log.message","message":"<text>"}` |

## Workflow
1. `findings.add` stores a finding. `type` (xss, sqli, idor, ssrf, ...) and `url` are required; add
   `severity` (`critical`, `high`, `medium`, `low`, `info`), `location` (`param:name`, `header:name`, `body`,
   `path`), `detail`, `evidence`, `request` and `response`, `steps_to_reproduce`, `cvss_score` /
   `cvss_vector`, `owasp_category`.
2. Review with `findings.list` (filter by `severity` or `type`); drop a wrong one with `findings.remove`.
3. Put an issue into Burp's own issue list with `scanner.create_issue` or `sitemap.add_issue`; export Burp's
   scanner issues as an HTML or XML report with `scanner.generate_report`.
4. Park interesting requests in Organizer: `organizer.send`, `run {"do":"organizer.get_items"}`,
   `run {"do":"organizer.annotate","id":"<id>","notes":"<note>"}`.
5. Keep notes across calls in the Burp project: `persistence.store`, `run {"do":"persistence.get","key":"<key>"}`,
   `run {"do":"persistence.list"}`, `run {"do":"persistence.delete","key":"<key>"}`.
6. Write to the extension log and Burp's event log: `log.message`, `run {"do":"log.event","message":"<text>"}`.

## Pitfalls
- The same type, URL and location is stored once.
- Findings are kept per Burp project, survive reloads and fill the Raijin → Findings tab.
- A critical/high mismatch from a live `autorize` tap is added automatically; do not record it twice.

## Done when
Each finding has a minimal reproduction request, the observed response evidence, and the impact, worded
neutrally and factually, and `findings.list` shows it.
