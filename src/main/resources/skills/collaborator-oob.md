---
name: collaborator-oob
description: Out-of-band DNS/HTTP/SMTP payloads and polling with Burp Collaborator.
---
# Collaborator (out-of-band)

Burp Professional only.

1. `collaborator(action=create_client)` and keep the client id. Clients are saved in the Burp project and come back after an extension reload; `collaborator(action=list_clients)` shows them. `collaborator(action=get_secret)` and `collaborator(action=restore_client)` move a client to another project.
2. `collaborator(action=generate_payload, client_id=...)` for a unique host; keep its `payload_id`. Payloads from `collaborator(action=default_payload)` show up in Burp's own Collaborator tab instead and cannot be polled here.
3. Place the payload in the request (header, parameter, body) and send it. Use one payload per injection point so an interaction identifies its source.
4. `collaborator(action=poll, client_id=..., payload_id=...)` returns DNS, HTTP (full request and response) and SMTP interactions, oldest first. Polling reads a history and discards nothing, so repeat it freely: pass `since=<next_since>` from the previous result to get only newer interactions, `type` (`dns`, `http`, `smtp`) to narrow, `limit` to page (`has_more` says more are waiting), `max_body_length` for long bodies. Wait a few seconds and poll again before concluding nothing happened.
5. `collaborator(action=server_info)` shows which Collaborator server is in use; `collaborator(action=remove_client)` drops a client together with its saved key and history.

`probe(action=injection)` runs its own out-of-band checks (`ssrf`, `xxe`, `cmdi`) with a client it creates and polls itself: no setup needed. Interactions that arrive after it returned are reported by its next call as `late_oob_interactions`.
