---
name: collaborator-oob
description: Use when a test needs out-of-band evidence. Burp Collaborator DNS/HTTP/SMTP payloads, polling, clients.
---
# Collaborator (out-of-band)

Generate Burp Collaborator payloads, place them in requests and poll for DNS, HTTP and SMTP interactions.
Burp Professional only. `probe.injection` runs its own out-of-band checks (`guide {"topic":"recon-probes"}`).

## Pick the call

| Goal | Call |
|---|---|
| A client to poll with | `run {"do":"collaborator.create_client"}` |
| A unique payload host | `run {"do":"collaborator.generate_payload","client_id":"<id>"}` |
| Interactions of a payload | `run {"do":"collaborator.poll","client_id":"<id>","payload_id":"<id>"}` |
| Only newer interactions | `run {"do":"collaborator.poll","client_id":"<id>","since":"<next_since>"}` |
| Saved clients | `run {"do":"collaborator.list_clients"}` |
| Which server is in use | `run {"do":"collaborator.server_info","client_id":"<id>"}` |

## Workflow
1. `collaborator.create_client` and keep the client id. Clients are saved in the Burp project and come back
   after an extension reload; `collaborator.list_clients` shows them. `collaborator.get_secret` and
   `run {"do":"collaborator.restore_client","secret_key":"<secret>"}` move a client to another project.
2. `collaborator.generate_payload` gives a unique host; keep its `payload_id`.
3. Place the payload in the request (header, parameter, body) and send it. Use one payload per injection point
   so an interaction identifies its source.
4. `collaborator.poll` returns DNS, HTTP (full request and response) and SMTP interactions, oldest first.
   Polling reads a history and discards nothing, so repeat it freely: pass `since` (the previous result's
   `next_since`) to get only newer interactions, `type` (`dns`, `http`, `smtp`) to narrow, `limit` to page
   (`has_more` says more are waiting), `max_body_length` for long bodies:
   `run {"do":"collaborator.poll","client_id":"<id>","type":"http","limit":20}`.
5. `collaborator.server_info` shows which Collaborator server is in use;
   `run {"do":"collaborator.remove_client","client_id":"<id>"}` drops a client together with its saved key
   and history.

## Pitfalls
- Payloads from `run {"do":"collaborator.default_payload"}` show up in Burp's own Collaborator tab instead and
  cannot be polled here.
- Wait a few seconds and poll again before concluding nothing happened.
- `probe.injection` runs its own out-of-band checks (`ssrf`, `xxe`, `cmdi`) with a client it creates and polls
  itself: no setup needed. Interactions that arrive after it returned are reported by its next call as
  `late_oob_interactions`.

## Done when
An interaction is tied to one payload and so to one injection point, and recorded with
`run {"do":"findings.add","type":"ssrf","url":"<url>","location":"param:<name>","evidence":"<interaction>"}`.
