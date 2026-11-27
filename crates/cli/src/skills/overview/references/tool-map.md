# Tool map

Every published Raijin tool, the actions of the grouped ones and what it is for. Run a grouped tool with
`"do"` set to `<tool>.<action>`, e.g. `run {"do":"scope.list"}`; `guide {"topic":"<tool>"}` gives its parameters.

## Sending (domain `http`)
| Tool | Actions | What it does |
|---|---|---|
| `http_send_request` | | One request, from `url` + `method` + `headers` + `body` or `raw_request`; native HTTP/2 |
| `http_send_requests_parallel` | | Independent requests at once, across hosts |
| `http_send_request_chain` | | Dependent requests; `extract` feeds `{{name}}` into later steps |
| `http_send_raw_bytes` | | Exact bytes, one request and one response |
| `http_send_pipeline` | | Several raw HTTP/1.1 requests over one socket, every response read back |
| `http_fuzz` | | Burp Intruder's attack types, clustered responses |
| `http_race` | | Single-packet or last-byte races |
| `http_rule` | `traffic_rule_set`, `traffic_rule_list`, `traffic_rule_remove`, `token_rule_create`, `token_rule_list`, `token_rule_remove`, `macro_set`, `macro_list`, `macro_remove`, `macro_run` | Outgoing traffic rules, session token rules, login macros |
| `http_state` | `cookie_jar_get`, `cookie_jar_set`, `cookie_jar_delete`, `pipeline_connections` | Cookie jar, kept `http_send_pipeline` connections |

## Proxy (domain `proxy`)
| Tool | Actions | What it does |
|---|---|---|
| `proxy_history` | | Read Proxy history, paged and filtered |
| `proxy_history_search` | | Regex over Proxy history |
| `proxy_annotate` | | Comment and highlight a Proxy history item |
| `proxy_auto_auth` | | Set an auth header on every proxied request to a host pattern |
| `proxy_intercept` | `enable`, `disable`, `status`, `hold`, `list_held`, `forward`, `drop`, `release` | Burp's Intercept switch; a hold queue to edit, forward or drop proxied messages |
| `proxy_rule` | `set_request_rule`, `set_response_rule`, `list`, `remove` | Proxy rules: modify, drop or tag |
| `sitemap` | `query`, `get_issues`, `add_request`, `add_issue`, `annotate` | Site map, where Raijin's own traffic lands |
| `organizer` | `send`, `get_items`, `annotate` | Burp Organizer |
| `send_to_tool` | `repeater`, `intruder`, `intruder_positions`, `comparer`, `decoder` | Hand a request to the Burp UI |
| `websocket` | `create`, `send_text`, `send_binary`, `close`, `list`, `get_messages`, `set_intercept_rule`, `wait_message`, `fuzz`, `list_intercept_rules`, `remove_intercept_rule`, `history`, `history_search` | WebSockets |

## Scanner (domain `scanner`)
| Tool | Actions | What it does |
|---|---|---|
| `scanner` | `start_crawl`, `start_audit`, `get_all_issues`, `generate_report`, `create_issue`, `import_bcheck`, `register_check`, `unregister_check` | Crawls, audits, issues, reports, check registration |
| `scanner_task` | `status`, `list`, `delete`, `add_request`, `issues` | Scan tasks |
| `custom_check` | `bcheck_create`, `bcheck_import`, `bcheck_list`, `bcheck_remove`, `bcheck_templates`, `bcheck_dry_run`, `scancheck_create_passive`, `scancheck_create_active`, `scancheck_list`, `scancheck_remove`, `scancheck_templates`, `scancheck_dry_run` | BChecks and script scan checks |
| `bambda_import` | | Import a Bambda |
| `bambda_templates` | | Bambda envelope format, functions, locations, templates |

## Recon and authorization (domains `recon`, `authz`)
| Tool | Actions | What it does |
|---|---|---|
| `recon` | `js_endpoints`, `content_discovery`, `param_mine`, `fingerprint` | Guided recon |
| `probe` | `cors`, `cache`, `graphql`, `injection`, `access_control`, `idor`, `jwt` | Guided probes, one vulnerability class each |
| `api_import_openapi` | | Turn an OpenAPI/Swagger document into requests |
| `auth_diff` | | One request compared across identities |
| `autorize` | `set_rule`, `list_rules`, `remove_rule`, `list_matches`, `clear_matches` | Live replay of proxied traffic under other identities |
| `jwt_keys` | `generate`, `import`, `list`, `export`, `delete` | Key ring for `probe.jwt` |

## Other domains
| Tool | Domain | Actions | What it does |
|---|---|---|---|
| `collaborator` | `oob` | `create_client`, `restore_client`, `get_secret`, `generate_payload`, `default_payload`, `poll`, `server_info`, `remove_client`, `list_clients` | Out-of-band payloads and polling |
| `turbo_run` | `turbo` | `start`, `stop`, `delete`, `status`, `results`, `result`, `script`, `search_responses`, `save_to_organizer`, `start_async`, `list` | Python-scripted high-volume or timing-critical runs |
| `turbo_docs` | `turbo` | `get_docs`, `list_examples`, `get_example` | Turbo documentation and example scripts |
| `analyze` | `analysis` | `request`, `response`, `find_reflected`, `extract_params`, `insertion_points`, `diff`, `response_body_search`, `http_keywords`, `http_variations`, `passive_intel` | Offline analysis of requests and responses |
| `util` | `analysis` | `url_encode`, `url_decode`, `base64_encode`, `base64_decode`, `html_encode`, `hash`, `compress`, `decompress`, `random_string`, `random_bytes`, `jwt_decode`, `decode_smart` | Encoding helpers |
| `findings` | `findings` | `add`, `list`, `remove` | Record and read results |
| `events` | `findings` | `subscribe`, `unsubscribe`, `get`, `get_by_type`, `clear` | Raijin's event stream |
| `log` | `findings` | `message`, `event` | Extension log and Burp's event log |
| `burp` | `settings` | `version`, `export_project_config`, `export_user_config`, `import_project_config`, `import_user_config`, `task_engine_state`, `task_engine_set`, `command_line_args`, `shutdown`, `project_info`, `extension_info` | Burp itself |
| `config` | `settings` | `proxy_listeners_list`, `proxy_listener_add`, `proxy_listener_remove`, `match_replace_add`, `match_replace_list`, `match_replace_remove`, `upstream_proxy_set`, `intruder_payload_processor_register` | Burp configuration |
| `scope` | `settings` | `check`, `include`, `exclude`, `get_config`, `list`, `remove` | Target scope |
| `persistence` | `settings` | `store`, `get`, `delete`, `list`, `preference_store`, `preference_get`, `preference_delete` | Notes kept in the Burp project |
| `ai` | `settings` | `status`, `prompt` | Burp AI |

## CLI tools
| Tool | Domain | What it does |
|---|---|---|
| `burp_up`, `burp_down`, `burp_status` | `lifecycle` | Start, stop and inspect this target's CLI-managed Burp instances |
| `history_list`, `history_show`, `history_search`, `history_endpoints`, `history_diff`, `history_export` | `history` | Offline review of the `.burp` projects (`guide {"topic":"offline-history"}`) |
| `data_list`, `data_search`, `data_get`, `data_payloads`, `data_add`, `data_import`, `data_update` | `data` | PortSwigger cheat sheets, BChecks, Bambdas and this target's own data (`guide {"topic":"data-library"}`) |
