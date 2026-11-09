package io.bitbytelab.raijin.tools

import io.modelcontextprotocol.kotlin.sdk.server.ClientConnection
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequestParams
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.Tool
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.*

/**
 * Folds families of fine-grained tools (`bcheck_create`, `bcheck_list`, ...) into a single MCP tool
 * with an `action` parameter, so the client sees ~40 tools instead of ~165.
 *
 * Each `XxxTools.register` still registers its tools one by one, but onto a scratch server. [apply]
 * then publishes them on the real server: grouped tools are merged (schema = union of the member
 * schemas, handler = the member's original handler), every other tool is copied as is. Handlers,
 * bridges and their validation are untouched.
 *
 * Calls are reported to the Activity tab and audit log under the member's original name, so
 * [legacyName] maps `(tool, action)` back to it.
 */
object ToolConsolidation {

    /**
     * @param actions action name -> member tool name.
     * @param renames action -> (member parameter -> public parameter), for member parameters that
     *   would clash with the dispatch parameter `action`.
     */
    class Group(
        val tool: String,
        val intro: String,
        val actions: Map<String, String>,
        val renames: Map<String, Map<String, String>> = emptyMap(),
    )

    /** Members whose action is the member name minus [prefix]. */
    private fun prefixed(prefix: String, vararg members: String): Map<String, String> =
        members.associateBy { it.removePrefix(prefix) }

    private val RULE_ACTION = mapOf("action" to "rule_action")

    /** Tools that stay individual: frequent, or with a schema too specific to share. */
    val KEEP: Set<String> = setOf(
        "http_send_request", "http_send_requests_parallel", "http_send_request_chain",
        "http_send_raw_bytes", "http_fuzz", "http_race",
        "proxy_history", "proxy_history_search", "proxy_annotate", "proxy_auto_auth",
        "auth_diff", "api_import_openapi", "bambda_import",
    )

    val GROUPS: List<Group> = listOf(
        Group(
            "custom_check",
            "Custom Burp checks: BChecks and passive/active scan checks (create from a template, import, list, remove).",
            listOf(
                "bcheck_create", "bcheck_import", "bcheck_list", "bcheck_remove", "bcheck_templates",
                "scancheck_create_passive", "scancheck_create_active", "scancheck_list",
                "scancheck_remove", "scancheck_templates",
            ).associateWith { it },
        ),
        Group(
            "scanner", "Burp Scanner: start crawls and audits, read issues, report, register checks.",
            prefixed(
                "scanner_", "scanner_start_crawl", "scanner_start_audit", "scanner_get_all_issues",
                "scanner_generate_report", "scanner_create_issue", "scanner_import_bcheck",
                "scanner_register_check", "scanner_unregister_check",
            ),
        ),
        Group(
            "scanner_task", "Manage running Scanner tasks (status, list, delete, add requests, issues).",
            prefixed(
                "scanner_task_", "scanner_task_status", "scanner_task_list", "scanner_task_delete",
                "scanner_task_add_request", "scanner_task_issues",
            ),
        ),
        Group(
            "collaborator", "Burp Collaborator out-of-band testing: clients, payloads, polling.",
            prefixed(
                "collaborator_", "collaborator_create_client", "collaborator_restore_client",
                "collaborator_get_secret", "collaborator_generate_payload",
                "collaborator_default_payload", "collaborator_poll", "collaborator_server_info",
            ),
        ),
        Group(
            "config", "Burp configuration: proxy listeners, match/replace rules, upstream proxy, payload processors.",
            prefixed(
                "config_", "config_proxy_listeners_list", "config_proxy_listener_add",
                "config_proxy_listener_remove", "config_match_replace_add", "config_match_replace_list",
                "config_match_replace_remove", "config_upstream_proxy_set",
            ) + mapOf("intruder_payload_processor_register" to "intruder_register_payload_processor"),
        ),
        Group(
            "scope", "Burp target scope: check a URL, include, exclude, show the configuration.",
            prefixed("scope_", "scope_check", "scope_include", "scope_exclude", "scope_get_config"),
        ),
        Group(
            "persistence", "Key/value storage in the Burp project (persistence) and user preferences.",
            prefixed(
                "persistence_", "persistence_store", "persistence_get", "persistence_delete",
                "persistence_list", "preference_store", "preference_get",
            ),
        ),
        Group(
            "websocket", "WebSockets: open connections, send, read messages, intercept rules, proxy WebSocket history.",
            prefixed(
                "websocket_", "websocket_create", "websocket_send_text", "websocket_send_binary",
                "websocket_close", "websocket_list", "websocket_get_messages",
                "websocket_set_intercept_rule",
            ) + mapOf("history" to "proxy_websocket_history", "history_search" to "proxy_websocket_history_search"),
            renames = mapOf("set_intercept_rule" to RULE_ACTION),
        ),
        Group(
            "events", "Event feed: subscribe, read recent or typed events, clear.",
            prefixed(
                "events_", "events_subscribe", "events_unsubscribe", "events_get",
                "events_get_by_type", "events_clear",
            ),
        ),
        Group(
            "http_rule", "Rules applied to outgoing HTTP traffic and session token handling.",
            mapOf(
                "traffic_rule_set" to "http_set_traffic_rule",
                "traffic_rule_list" to "http_list_traffic_rules",
                "traffic_rule_remove" to "http_remove_traffic_rule",
                "token_rule_create" to "session_create_token_rule",
                "token_rule_list" to "session_list_rules",
                "token_rule_remove" to "session_remove_rule",
            ),
        ),
        Group(
            "http_state", "Burp cookie jar: read and set cookies.",
            mapOf("cookie_jar_get" to "http_cookie_jar_get", "cookie_jar_set" to "http_cookie_jar_set"),
        ),
        Group(
            "proxy_rule", "Proxy request/response rules (modify, drop, tag): set, list, remove.",
            mapOf(
                "set_request_rule" to "proxy_set_request_rule",
                "set_response_rule" to "proxy_set_response_rule",
                "list" to "proxy_list_rules",
                "remove" to "proxy_remove_rule",
            ),
            renames = mapOf("set_request_rule" to RULE_ACTION, "set_response_rule" to RULE_ACTION),
        ),
        Group(
            "proxy_intercept", "Proxy interception switch.",
            prefixed("proxy_intercept_", "proxy_intercept_enable", "proxy_intercept_disable", "proxy_intercept_status"),
        ),
        Group(
            "burp", "Burp Suite itself: version, project and extension info, config import/export, task engine, shutdown.",
            prefixed(
                "burp_", "burp_version", "burp_export_project_config", "burp_export_user_config",
                "burp_import_project_config", "burp_import_user_config", "burp_task_engine_state",
                "burp_task_engine_set", "burp_command_line_args", "burp_shutdown",
            ) + mapOf("project_info" to "project_info", "extension_info" to "extension_info"),
        ),
        Group(
            "turbo_run", "Turbo runs (Python scripts on the Turbo request engine): start, poll, read, stop, delete.",
            mapOf(
                "start" to "turbo_start_run", "stop" to "turbo_stop_run", "delete" to "turbo_delete_run",
                "status" to "turbo_run_status", "results" to "turbo_run_results", "result" to "turbo_run_result",
                "script" to "turbo_run_script", "search_responses" to "turbo_search_responses",
                "save_to_organizer" to "turbo_save_to_organizer",
            ),
        ),
        Group(
            "turbo_docs", "Turbo documentation and example scripts. Read these before turbo_run.",
            prefixed("turbo_", "turbo_get_docs", "turbo_list_examples", "turbo_get_example"),
        ),
        Group(
            "util", "Encoding, decoding, hashing, compression and random-data helpers.",
            prefixed(
                "util_", "util_url_encode", "util_url_decode", "util_base64_encode", "util_base64_decode",
                "util_html_encode", "util_hash", "util_compress", "util_decompress", "util_random_string",
                "util_random_bytes", "util_jwt_decode", "util_decode_smart",
            ),
        ),
        Group(
            "analyze", "Offline analysis of requests, responses and traffic (no new traffic is sent unless stated).",
            prefixed(
                "analyze_", "analyze_request", "analyze_response", "analyze_find_reflected",
                "analyze_extract_params", "analyze_insertion_points", "analyze_diff",
                "analyze_response_body_search",
            ) + mapOf(
                "http_keywords" to "http_analyze_keywords",
                "http_variations" to "http_analyze_variations",
                "passive_intel" to "passive_intel",
            ),
        ),
        Group(
            "sitemap", "Burp site map: query, issues, add requests or issues.",
            prefixed("sitemap_", "sitemap_query", "sitemap_get_issues", "sitemap_add_request", "sitemap_add_issue"),
        ),
        Group(
            "recon", "Recon on in-scope targets: JS endpoints, content discovery, parameter mining, fingerprinting.",
            prefixed(
                "recon_", "recon_js_endpoints", "recon_content_discovery", "recon_param_mine",
                "recon_fingerprint",
            ),
        ),
        Group(
            "probe", "Guided probes on in-scope targets: CORS, GraphQL, injection, access control, IDOR, JWT.",
            mapOf(
                "cors" to "cors_probe", "graphql" to "graphql_probe", "injection" to "injection_probe",
                "access_control" to "access_control_sweep", "idor" to "idor_hunt", "jwt" to "jwt_attack",
            ),
        ),
        Group(
            "findings", "Findings you record during testing: add and list.",
            prefixed("findings_", "findings_add", "findings_list"),
        ),
        Group(
            "organizer", "Burp Organizer: send items to it and read them back.",
            prefixed("organizer_", "organizer_send", "organizer_get_items"),
        ),
        Group(
            "send_to_tool", "Send a request to a Burp tool: Repeater, Intruder, Comparer or Decoder.",
            mapOf(
                "repeater" to "repeater_send", "intruder" to "intruder_send",
                "intruder_positions" to "intruder_send_with_positions",
                "comparer" to "comparer_send", "decoder" to "decoder_send",
            ),
        ),
        Group("log", "Write to the Raijin log and activity feed.", mapOf("message" to "log_message", "event" to "log_event")),
        Group("ai", "Burp AI: status and prompts.", prefixed("ai_", "ai_status", "ai_prompt")),
    )

    private val byTool = GROUPS.associateBy { it.tool }

    /** The member tool name behind a call of [tool] with [action], or null for an ungrouped tool. */
    fun legacyName(tool: String, action: String?): String? = byTool[tool]?.actions?.get(action)

    /**
     * Publishes the tools registered on [legacy] onto [target]: groups merged, the rest copied.
     * Fails if a group names a tool that was not registered.
     */
    fun apply(legacy: Server, target: Server) {
        val registered = legacy.tools
        val grouped = mutableSetOf<String>()
        for (g in GROUPS) {
            val members = g.actions.mapValues { (action, name) ->
                registered[name] ?: error("Tool group '${g.tool}': action '$action' needs unregistered tool '$name'")
            }
            grouped += g.actions.values
            val tool = Tool(name = g.tool, description = describe(g, members), inputSchema = schema(g, members))
            target.addTool(tool) { request -> dispatch(g, members, request) }
        }
        registered.filterKeys { it !in grouped }.values.forEach { target.addTool(it.tool, it.handler) }
    }

    private fun publicParam(g: Group, action: String, member: String) = g.renames[action]?.get(member) ?: member

    private fun schema(
        g: Group,
        members: Map<String, io.modelcontextprotocol.kotlin.sdk.server.RegisteredTool>,
    ): ToolSchema {
        // public param -> (definition of the first member that declares it, actions using it)
        val params = LinkedHashMap<String, Pair<JsonObject, MutableList<String>>>()
        members.forEach { (action, rt) ->
            rt.tool.inputSchema.properties?.forEach { (name, def) ->
                val pub = publicParam(g, action, name)
                params.getOrPut(pub) { (def as? JsonObject ?: JsonObject(emptyMap())) to mutableListOf() }.second += action
            }
        }
        val props = buildJsonObject {
            putJsonObject("action") {
                put("type", "string")
                putJsonArray("enum") { g.actions.keys.forEach { add(it) } }
                put("description", "Operation to run; see the tool description for each action's parameters.")
            }
            params.forEach { (name, v) ->
                val (def, actions) = v
                putJsonObject(name) {
                    def.forEach { (k, value) -> if (k != "description") put(k, value) }
                    val base = def["description"]?.jsonPrimitive?.contentOrNull.orEmpty()
                    val scope = if (actions.size == members.size) "" else " [actions: ${actions.joinToString(", ")}]"
                    put("description", (base + scope).trim())
                }
            }
        }
        return ToolSchema(properties = props, required = listOf("action"))
    }

    private fun describe(
        g: Group,
        members: Map<String, io.modelcontextprotocol.kotlin.sdk.server.RegisteredTool>,
    ): String = buildString {
        append(g.intro).append(" Pick one `action`; parameters marked * are required for that action.\n")
        members.forEach { (action, rt) ->
            val required = rt.tool.inputSchema.required.orEmpty().toSet()
            val params = rt.tool.inputSchema.properties?.keys.orEmpty().joinToString(", ") {
                publicParam(g, action, it) + if (it in required) "*" else ""
            }
            append("- ").append(action).append('(').append(params).append("): ")
                .append(summary(rt.tool.description)).append('\n')
        }
    }.trimEnd()

    /** First sentence of a member description, capped, so the merged description stays compact. */
    private fun summary(description: String?): String {
        val text = description.orEmpty().replace(Regex("\\s+"), " ").trim()
        val end = Regex("[.!?](\\s|$)").find(text)?.range?.first ?: text.length
        val sentence = text.substring(0, minOf(end + 1, text.length)).trim()
        return if (sentence.length <= 160) sentence else sentence.take(157).trimEnd() + "..."
    }

    private suspend fun ClientConnection.dispatch(
        g: Group,
        members: Map<String, io.modelcontextprotocol.kotlin.sdk.server.RegisteredTool>,
        request: CallToolRequest,
    ): CallToolResult {
        val args = request.params.arguments ?: JsonObject(emptyMap())
        val action = (args["action"] as? JsonPrimitive)?.contentOrNull
        val member = action?.let { members[it] }
        if (action == null || member == null) {
            return error(buildJsonObject {
                put("error", "unknown_action")
                put("message", if (action == null) "Missing required parameter: action" else "Unknown action '$action' for tool '${g.tool}'")
                putJsonArray("available") { g.actions.keys.forEach { add(it) } }
            })
        }

        val renames = g.renames[action].orEmpty()
        val missing = member.tool.inputSchema.required.orEmpty()
            .map { renames[it] ?: it }
            .filter { args[it] == null || args[it] is JsonNull }
        if (missing.isNotEmpty()) {
            return error(buildJsonObject {
                put("error", "missing_parameter")
                put("message", "action '$action' requires ${missing.joinToString(", ") { "'$it'" }}")
            })
        }

        val toMember = renames.entries.associate { (memberName, publicName) -> publicName to memberName }
        val forwarded = buildJsonObject {
            args.forEach { (k, v) -> if (k != "action") put(toMember[k] ?: k, v) }
        }
        return member.handler(
            this,
            CallToolRequest(CallToolRequestParams(name = member.tool.name, arguments = forwarded, meta = request.params.meta))
        )
    }

    private fun error(body: JsonObject) = CallToolResult(content = listOf(TextContent(body.toString())), isError = true)
}
