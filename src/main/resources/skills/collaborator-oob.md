---
name: collaborator-oob
description: Out-of-band testing with Burp Collaborator.
---
# Collaborator (out-of-band)

1. `collaborator(action=create_client)` (keep the returned client id; `collaborator(action=get_secret)` and `collaborator(action=restore_client)` let you resume later).
2. `collaborator(action=generate_payload)` for a unique host, or `collaborator(action=default_payload)`.
3. Place the payload in the request (header, parameter, body) and send it.
4. `collaborator(action=poll)` to see DNS/HTTP/SMTP interactions. Wait a few seconds and poll again before concluding nothing happened.
5. `collaborator(action=server_info)` shows which Collaborator server is in use.

Use one payload per injection point so an interaction identifies its source.
