# Tool consolidation

Raijin folds families of tools into one tool with an `action` parameter (`tools/ToolConsolidation.kt`): 27 grouped tools and 16 tools kept as they are, 43 in all, over 200 operations. The old per-operation names are not on the server any more, but the Activity tab and the audit log still record each call under its member name (the left column below), so this table also reads those records.

Tools kept as they are: `http_send_request`, `http_send_requests_parallel`, `http_send_request_chain`, `http_send_raw_bytes`, `http_send_pipeline`, `http_fuzz`, `http_race`, `proxy_history`, `proxy_history_search`, `proxy_annotate`, `proxy_auto_auth`, `auth_diff`, `api_import_openapi`, `bambda_import`, `bambda_templates`, `jwt_keys`.

Adding a tool: register it in its `tools/<area>/*Tools.kt`, then list it in a group of `ToolConsolidation.GROUPS` (as an action) or in `KEEP`. `ToolConsolidationTest` fails for a tool that is in neither.

## Calling a grouped tool

`tool(action=<action>, ...)` with the member's parameters. The tool description lists every action as `action(param*, param): first sentence of the member's description`, `*` marking the parameters that action requires. Dispatch checks those before calling the member: a missing one returns `missing_parameter`, an unknown or missing action returns `unknown_action` with the list of actions. The member then receives its own parameter names and validates exactly as it does on its own.

## Renamed parameters

A member parameter named `action` would collide with the dispatch parameter, so its group publishes it as `rule_action`:

| Tool | Action | `rule_action` values |
|---|---|---|
| `http_rule` | `traffic_rule_set` | `modify` (default), `drop`, `spoof_response` |
| `proxy_rule` | `set_request_rule`, `set_response_rule` | `modify`, `drop`, `tag` |
| `websocket` | `set_intercept_rule` | `modify`, `drop`, `tag` |

A group whose member declares `action` without a rename fails when the tools are published (and in `ToolConsolidationTest`), so a new collision cannot slip through. `jwt_keys` keeps its own `action` parameter (`generate`, `import`, `list`, `export`, `delete`): it is a kept tool, not a group.

## Parameters shared by several actions

When actions of one group declare the same parameter name, the group's schema merges their definitions instead of keeping the first:

- **Enums** are united, but only when every action declares one. If any action takes free text, the merged parameter has no enum, so that action's values still validate; the other actions' allowed values move into the description.
- **Structure**: `items` and `properties` merge recursively, and any other key (`minimum`, `default`, ...) stays only when every action agrees. When the actions disagree on the type, the parameter accepts any JSON value (`{}`) and its description starts with "Type depends on the action, so any JSON value is accepted here."
- **Descriptions**: a text every action shares reads `text [actions: a, b]` (no suffix when all actions use it). Different texts become one line per set of actions, `[a, b] text (one of: ...; type: ...; default: ...)`, so each action keeps its own wording plus the constraints the merged schema no longer states for it.

For example `probe.mode` unites the GraphQL and JWT modes into one enum, and its description has a `[graphql]` line and a `[jwt]` line, each listing that action's own modes.

## Mapping

| Member tool | Tool | `action` |
|---|---|---|
| `access_control_sweep` | `probe` | `access_control` |
| `ai_prompt` | `ai` | `prompt` |
| `ai_status` | `ai` | `status` |
| `analyze_diff` | `analyze` | `diff` |
| `analyze_extract_params` | `analyze` | `extract_params` |
| `analyze_find_reflected` | `analyze` | `find_reflected` |
| `analyze_insertion_points` | `analyze` | `insertion_points` |
| `analyze_request` | `analyze` | `request` |
| `analyze_response` | `analyze` | `response` |
| `analyze_response_body_search` | `analyze` | `response_body_search` |
| `autorize_clear_matches` | `autorize` | `clear_matches` |
| `autorize_list_matches` | `autorize` | `list_matches` |
| `autorize_list_rules` | `autorize` | `list_rules` |
| `autorize_remove_rule` | `autorize` | `remove_rule` |
| `autorize_set_rule` | `autorize` | `set_rule` |
| `bcheck_create` | `custom_check` | `bcheck_create` |
| `bcheck_dry_run` | `custom_check` | `bcheck_dry_run` |
| `bcheck_import` | `custom_check` | `bcheck_import` |
| `bcheck_list` | `custom_check` | `bcheck_list` |
| `bcheck_remove` | `custom_check` | `bcheck_remove` |
| `bcheck_templates` | `custom_check` | `bcheck_templates` |
| `burp_command_line_args` | `burp` | `command_line_args` |
| `burp_export_project_config` | `burp` | `export_project_config` |
| `burp_export_user_config` | `burp` | `export_user_config` |
| `burp_import_project_config` | `burp` | `import_project_config` |
| `burp_import_user_config` | `burp` | `import_user_config` |
| `burp_shutdown` | `burp` | `shutdown` |
| `burp_task_engine_set` | `burp` | `task_engine_set` |
| `burp_task_engine_state` | `burp` | `task_engine_state` |
| `burp_version` | `burp` | `version` |
| `cache_probe` | `probe` | `cache` |
| `collaborator_create_client` | `collaborator` | `create_client` |
| `collaborator_default_payload` | `collaborator` | `default_payload` |
| `collaborator_generate_payload` | `collaborator` | `generate_payload` |
| `collaborator_get_secret` | `collaborator` | `get_secret` |
| `collaborator_list_clients` | `collaborator` | `list_clients` |
| `collaborator_poll` | `collaborator` | `poll` |
| `collaborator_remove_client` | `collaborator` | `remove_client` |
| `collaborator_restore_client` | `collaborator` | `restore_client` |
| `collaborator_server_info` | `collaborator` | `server_info` |
| `comparer_send` | `send_to_tool` | `comparer` |
| `config_match_replace_add` | `config` | `match_replace_add` |
| `config_match_replace_list` | `config` | `match_replace_list` |
| `config_match_replace_remove` | `config` | `match_replace_remove` |
| `config_proxy_listener_add` | `config` | `proxy_listener_add` |
| `config_proxy_listener_remove` | `config` | `proxy_listener_remove` |
| `config_proxy_listeners_list` | `config` | `proxy_listeners_list` |
| `config_upstream_proxy_set` | `config` | `upstream_proxy_set` |
| `cors_probe` | `probe` | `cors` |
| `decoder_send` | `send_to_tool` | `decoder` |
| `events_clear` | `events` | `clear` |
| `events_get` | `events` | `get` |
| `events_get_by_type` | `events` | `get_by_type` |
| `events_subscribe` | `events` | `subscribe` |
| `events_unsubscribe` | `events` | `unsubscribe` |
| `extension_info` | `burp` | `extension_info` |
| `findings_add` | `findings` | `add` |
| `findings_list` | `findings` | `list` |
| `findings_remove` | `findings` | `remove` |
| `graphql_probe` | `probe` | `graphql` |
| `http_analyze_keywords` | `analyze` | `http_keywords` |
| `http_analyze_variations` | `analyze` | `http_variations` |
| `http_cookie_jar_delete` | `http_state` | `cookie_jar_delete` |
| `http_cookie_jar_get` | `http_state` | `cookie_jar_get` |
| `http_cookie_jar_set` | `http_state` | `cookie_jar_set` |
| `http_list_traffic_rules` | `http_rule` | `traffic_rule_list` |
| `http_pipeline_connections` | `http_state` | `pipeline_connections` |
| `http_remove_traffic_rule` | `http_rule` | `traffic_rule_remove` |
| `http_set_traffic_rule` | `http_rule` | `traffic_rule_set` |
| `idor_hunt` | `probe` | `idor` |
| `injection_probe` | `probe` | `injection` |
| `intruder_register_payload_processor` | `config` | `intruder_payload_processor_register` |
| `intruder_send` | `send_to_tool` | `intruder` |
| `intruder_send_with_positions` | `send_to_tool` | `intruder_positions` |
| `jwt_attack` | `probe` | `jwt` |
| `log_event` | `log` | `event` |
| `log_message` | `log` | `message` |
| `organizer_annotate` | `organizer` | `annotate` |
| `organizer_get_items` | `organizer` | `get_items` |
| `organizer_send` | `organizer` | `send` |
| `passive_intel` | `analyze` | `passive_intel` |
| `persistence_delete` | `persistence` | `delete` |
| `persistence_get` | `persistence` | `get` |
| `persistence_list` | `persistence` | `list` |
| `persistence_store` | `persistence` | `store` |
| `preference_delete` | `persistence` | `preference_delete` |
| `preference_get` | `persistence` | `preference_get` |
| `preference_store` | `persistence` | `preference_store` |
| `project_info` | `burp` | `project_info` |
| `proxy_intercept_disable` | `proxy_intercept` | `disable` |
| `proxy_intercept_drop` | `proxy_intercept` | `drop` |
| `proxy_intercept_enable` | `proxy_intercept` | `enable` |
| `proxy_intercept_forward` | `proxy_intercept` | `forward` |
| `proxy_intercept_hold` | `proxy_intercept` | `hold` |
| `proxy_intercept_list_held` | `proxy_intercept` | `list_held` |
| `proxy_intercept_release` | `proxy_intercept` | `release` |
| `proxy_intercept_status` | `proxy_intercept` | `status` |
| `proxy_list_rules` | `proxy_rule` | `list` |
| `proxy_remove_rule` | `proxy_rule` | `remove` |
| `proxy_set_request_rule` | `proxy_rule` | `set_request_rule` |
| `proxy_set_response_rule` | `proxy_rule` | `set_response_rule` |
| `proxy_websocket_history` | `websocket` | `history` |
| `proxy_websocket_history_search` | `websocket` | `history_search` |
| `recon_content_discovery` | `recon` | `content_discovery` |
| `recon_fingerprint` | `recon` | `fingerprint` |
| `recon_js_endpoints` | `recon` | `js_endpoints` |
| `recon_param_mine` | `recon` | `param_mine` |
| `repeater_send` | `send_to_tool` | `repeater` |
| `scancheck_create_active` | `custom_check` | `scancheck_create_active` |
| `scancheck_create_passive` | `custom_check` | `scancheck_create_passive` |
| `scancheck_dry_run` | `custom_check` | `scancheck_dry_run` |
| `scancheck_list` | `custom_check` | `scancheck_list` |
| `scancheck_remove` | `custom_check` | `scancheck_remove` |
| `scancheck_templates` | `custom_check` | `scancheck_templates` |
| `scanner_create_issue` | `scanner` | `create_issue` |
| `scanner_generate_report` | `scanner` | `generate_report` |
| `scanner_get_all_issues` | `scanner` | `get_all_issues` |
| `scanner_import_bcheck` | `scanner` | `import_bcheck` |
| `scanner_register_check` | `scanner` | `register_check` |
| `scanner_start_audit` | `scanner` | `start_audit` |
| `scanner_start_crawl` | `scanner` | `start_crawl` |
| `scanner_task_add_request` | `scanner_task` | `add_request` |
| `scanner_task_delete` | `scanner_task` | `delete` |
| `scanner_task_issues` | `scanner_task` | `issues` |
| `scanner_task_list` | `scanner_task` | `list` |
| `scanner_task_status` | `scanner_task` | `status` |
| `scanner_unregister_check` | `scanner` | `unregister_check` |
| `scope_check` | `scope` | `check` |
| `scope_exclude` | `scope` | `exclude` |
| `scope_get_config` | `scope` | `get_config` |
| `scope_include` | `scope` | `include` |
| `scope_list` | `scope` | `list` |
| `scope_remove` | `scope` | `remove` |
| `session_create_token_rule` | `http_rule` | `token_rule_create` |
| `session_list_rules` | `http_rule` | `token_rule_list` |
| `session_macro_list` | `http_rule` | `macro_list` |
| `session_macro_remove` | `http_rule` | `macro_remove` |
| `session_macro_run` | `http_rule` | `macro_run` |
| `session_macro_set` | `http_rule` | `macro_set` |
| `session_remove_rule` | `http_rule` | `token_rule_remove` |
| `sitemap_add_issue` | `sitemap` | `add_issue` |
| `sitemap_add_request` | `sitemap` | `add_request` |
| `sitemap_annotate` | `sitemap` | `annotate` |
| `sitemap_get_issues` | `sitemap` | `get_issues` |
| `sitemap_query` | `sitemap` | `query` |
| `turbo_delete_run` | `turbo_run` | `delete` |
| `turbo_get_docs` | `turbo_docs` | `get_docs` |
| `turbo_get_example` | `turbo_docs` | `get_example` |
| `turbo_list_examples` | `turbo_docs` | `list_examples` |
| `turbo_list_runs` | `turbo_run` | `list` |
| `turbo_run_result` | `turbo_run` | `result` |
| `turbo_run_results` | `turbo_run` | `results` |
| `turbo_run_script` | `turbo_run` | `script` |
| `turbo_run_status` | `turbo_run` | `status` |
| `turbo_save_to_organizer` | `turbo_run` | `save_to_organizer` |
| `turbo_search_responses` | `turbo_run` | `search_responses` |
| `turbo_start_run` | `turbo_run` | `start` |
| `turbo_start_run_async` | `turbo_run` | `start_async` |
| `turbo_stop_run` | `turbo_run` | `stop` |
| `util_base64_decode` | `util` | `base64_decode` |
| `util_base64_encode` | `util` | `base64_encode` |
| `util_compress` | `util` | `compress` |
| `util_decode_smart` | `util` | `decode_smart` |
| `util_decompress` | `util` | `decompress` |
| `util_hash` | `util` | `hash` |
| `util_html_encode` | `util` | `html_encode` |
| `util_jwt_decode` | `util` | `jwt_decode` |
| `util_random_bytes` | `util` | `random_bytes` |
| `util_random_string` | `util` | `random_string` |
| `util_url_decode` | `util` | `url_decode` |
| `util_url_encode` | `util` | `url_encode` |
| `websocket_close` | `websocket` | `close` |
| `websocket_create` | `websocket` | `create` |
| `websocket_fuzz` | `websocket` | `fuzz` |
| `websocket_get_messages` | `websocket` | `get_messages` |
| `websocket_list` | `websocket` | `list` |
| `websocket_list_intercept_rules` | `websocket` | `list_intercept_rules` |
| `websocket_remove_intercept_rule` | `websocket` | `remove_intercept_rule` |
| `websocket_send_binary` | `websocket` | `send_binary` |
| `websocket_send_text` | `websocket` | `send_text` |
| `websocket_set_intercept_rule` | `websocket` | `set_intercept_rule` |
| `websocket_wait_message` | `websocket` | `wait_message` |
