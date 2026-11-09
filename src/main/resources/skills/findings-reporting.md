---
name: findings-reporting
description: Recording findings and producing reports.
---
# Findings and reporting

- `findings(action=add)`: store a finding (title, severity, evidence request/response, notes). Add each confirmed issue once.
- `findings(action=list)`: review everything recorded so far.
- `scanner(action=generate_report)`: export Burp scanner issues as a report.
- `organizer(action=send)` / `organizer(action=get_items)`: park interesting requests in Organizer.
- `persistence(action=store)`, `persistence(action=get)`, `persistence(action=list)`, `persistence(action=delete)`: keep notes across calls in the Burp project.
- `log(action=message)`, `log(action=event)`: write to the extension log and activity feed.

Include a minimal reproduction request, the observed response evidence, and the impact. Keep wording neutral and factual.
