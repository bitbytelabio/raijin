---
name: data-library
description: Use when you need known XSS vectors, URL-validation/SSRF bypasses, BChecks or Bambdas, or want to save what worked on this target.
---
# Data library

The `data` tools search PortSwigger's public data, downloaded once per machine into `~/.raijin/data/`,
plus this target's own payloads, BChecks and Bambdas in `data/` (tracked by git, `[data] dir` in
raijin.toml). Burp is not needed, except for `data_import`. The data is a map of known tricks, not the
limit of what to try.

## Pick the call

| Goal | Call |
|---|---|
| What is there, and how old | `run {"do":"data_list"}` |
| Event handlers that fire without a click | `run {"do":"data_search","query":"onfocus autofocus","source":"xss","no_interaction":true}` |
| XSS without parentheses | `run {"do":"data_search","source":"xss","category":"restricted_characters","query":"parentheses"}` |
| One entry whole (vector or script) | `run {"do":"data_get","id":"xss:events/onload/svg"}` |
| Allow-list bypasses ready for a fuzz | `run {"do":"data_payloads","source":"url","category":"domain_allow_list_bypass","attacker":"attacker.example","allowed":"target.example"}` |
| A BCheck for a technology | `run {"do":"data_search","source":"bchecks","query":"springboot actuator"}` |
| Load a BCheck or Bambda into Burp | `run {"do":"data_import","id":"<id>"}` |
| Save what worked here | `run {"do":"data_add","category":"<name>","payload":"<vector>","description":"<where it worked>"}` |
| Download or refresh now | `run {"do":"data_update"}` |

## Sources

| Source | What | Categories |
|---|---|---|
| `xss` | XSS cheat sheet: ~1,600 vectors | `events` (one per event and element), `classic`, `restricted_characters`, `waf_bypass_global_obj`, `angularjs`, `vuejs`, `prototype-pollution`, `dangling_markup`, `protocols`, `encodings`, `consuming_tags`, `useful_tags`, `special_tags`, `math_ml`, `hoisting`, `obfuscation`, `polyglot`, `content-types`, `response-content-types`, `file_uploads`, `frameworks`, `impossible` |
| `url` | URL validation bypass cheat sheet: ~300 payloads | `loopback`, `cloud_metadata_endpoints`, `domain_allow_list_bypass`, `fake_relative_urls`, `ipv6`, `url-spliting_unicode_characters` |
| `bchecks` | PortSwigger's BChecks repo | folders: `examples`, `other/...` (`springboot`, `tokens`, `fastjson`, `GraphQL`, `files`, ...), `vulnerabilities-CVEd`, `vulnerability-classes/injection` |
| `bambdas` | PortSwigger's Bambdas repo | `CustomAction`, `CustomColumn/...`, `CustomScanChecks`, `Filter/...`, `MatchAndReplace/...` |
| `custom` | this target's `data/` | `payloads/<category>.json`, `bchecks/**`, `bambdas/**` |

A category also matches its subfolders: `"category":"Filter"` finds `Filter/Proxy/HTTP`. `data_list`
gives the exact names and counts. Licenses: the two cheat sheets are © PortSwigger with no license (local
use only, never republish them); BChecks and Bambdas are LGPL-3.0.

## Workflow
1. Identify the context first: where the input is reflected (tag, attribute, script, URL), which
   characters and words the filter drops, the framework (AngularJS, Vue) and the browser that matters.
2. Search narrowly: `data_search` with `source`, `category` and a few `query` words; `tag`, `browser`,
   `context` and `no_interaction` filter further. Rows show the vector; `data_get` shows every field.
3. Adapt a vector to the context you observed and try a few with `http_send_request`.
4. For volume, `data_payloads` gives a deduplicated `payloads` array to paste into `http_fuzz`.
5. When nothing fits, combine techniques or write new vectors: the library holds known tricks only.
6. Save what worked with `data_add`. The target's `data/` folder is committed with the engagement and
   comes back in every later session; `data_search` lists it first.

## Pitfalls
- An xss entry with `hash` in `extra` needs that URL fragment; `interaction:true` needs a user action.
- url tags: `HOST` payloads go in the Host header, `URL` ones in URL parameters, `CORS` ones in Origin.
- `<attacker>` and `<allowed>` stay as written unless you pass `attacker` and `allowed`.
- BChecks and most Bambdas need Burp Professional; `data_import` reports Community Edition as unsupported.
- The first data call of a session downloads missing sources and refreshes ones older than 7 days;
  `RAIJIN_NO_DATA_UPDATE=1` turns that off for offline work.
- Results over the inline limit come back as `{saved_to, preview}`: parse the file with jq.

## Done when
The vector that worked is confirmed by a request and its response, recorded with `findings.add`, and saved
with `data_add`.
