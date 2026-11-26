package io.bitbytelab.raijin.tools

import io.modelcontextprotocol.kotlin.sdk.server.ClientConnection
import io.modelcontextprotocol.kotlin.sdk.server.RegisteredTool
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequestParams
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
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
        "http_send_raw_bytes", "http_send_pipeline", "http_fuzz", "http_race",
        "proxy_history", "proxy_history_search", "proxy_annotate", "proxy_auto_auth",
        "auth_diff", "api_import_openapi", "bambda_import", "bambda_templates",
        "jwt_keys",
    )

    val GROUPS: List<Group> = listOf(
        Group(
            "custom_check",
            "Custom Burp checks: BChecks and passive/active scan checks (create from a template, import, dry-run against proxy history, list, remove).",
            listOf(
                "bcheck_create", "bcheck_import", "bcheck_list", "bcheck_remove", "bcheck_templates",
                "bcheck_dry_run",
                "scancheck_create_passive", "scancheck_create_active", "scancheck_list",
                "scancheck_remove", "scancheck_templates", "scancheck_dry_run",
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
                "collaborator_remove_client", "collaborator_list_clients",
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
            "scope", "Burp target scope: check a URL, include, exclude, list and remove rules, show the configuration.",
            prefixed(
                "scope_", "scope_check", "scope_include", "scope_exclude", "scope_get_config",
                "scope_list", "scope_remove",
            ),
        ),
        Group(
            "persistence", "Key/value storage in the Burp project (persistence) and user preferences.",
            prefixed(
                "persistence_", "persistence_store", "persistence_get", "persistence_delete",
                "persistence_list", "preference_store", "preference_get", "preference_delete",
            ),
        ),
        Group(
            "websocket", "WebSockets: open connections, send, read messages, intercept rules, proxy WebSocket history.",
            prefixed(
                "websocket_", "websocket_create", "websocket_send_text", "websocket_send_binary",
                "websocket_close", "websocket_list", "websocket_get_messages",
                "websocket_set_intercept_rule",
                "websocket_wait_message", "websocket_fuzz",
                "websocket_list_intercept_rules", "websocket_remove_intercept_rule",
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
            "http_rule", "Outgoing HTTP traffic rules, session tokens and bounded login macros.",
            mapOf(
                "traffic_rule_set" to "http_set_traffic_rule",
                "traffic_rule_list" to "http_list_traffic_rules",
                "traffic_rule_remove" to "http_remove_traffic_rule",
                "token_rule_create" to "session_create_token_rule",
                "token_rule_list" to "session_list_rules",
                "token_rule_remove" to "session_remove_rule",
                "macro_set" to "session_macro_set",
                "macro_list" to "session_macro_list",
                "macro_remove" to "session_macro_remove",
                "macro_run" to "session_macro_run",
            ),
            renames = mapOf("traffic_rule_set" to RULE_ACTION),
        ),
        Group(
            "http_state", "Burp cookie jar (read, set, delete) and raw pipeline connections (list, close).",
            mapOf(
                "cookie_jar_get" to "http_cookie_jar_get", "cookie_jar_set" to "http_cookie_jar_set",
                "cookie_jar_delete" to "http_cookie_jar_delete",
                "pipeline_connections" to "http_pipeline_connections",
            ),
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
            "proxy_intercept",
            "Proxy interception: Burp's Intercept switch and a bounded hold queue for inspecting, editing, " +
                "forwarding or dropping messages. An unanswered hold forwards itself.",
            prefixed(
                "proxy_intercept_", "proxy_intercept_enable", "proxy_intercept_disable", "proxy_intercept_status",
                "proxy_intercept_hold", "proxy_intercept_list_held", "proxy_intercept_forward",
                "proxy_intercept_drop", "proxy_intercept_release",
            ),
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
                "start_async" to "turbo_start_run_async", "list" to "turbo_list_runs",
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
            "analyze", "Local analysis of requests, responses and traffic in the running Burp (sends no traffic unless stated).",
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
            "sitemap", "Burp site map: query, issues, add requests or issues, annotate.",
            prefixed(
                "sitemap_", "sitemap_query", "sitemap_get_issues", "sitemap_add_request", "sitemap_add_issue",
                "sitemap_annotate",
            ),
        ),
        Group(
            "recon", "Recon: JS endpoints, content discovery, parameter mining, fingerprinting.",
            prefixed(
                "recon_", "recon_js_endpoints", "recon_content_discovery", "recon_param_mine",
                "recon_fingerprint",
            ),
        ),
        Group(
            "probe",
            "Guided probes: CORS, web cache poisoning/deception, GraphQL, injection, access control, IDOR, JWT.",
            mapOf(
                "cors" to "cors_probe", "cache" to "cache_probe", "graphql" to "graphql_probe",
                "injection" to "injection_probe",
                "access_control" to "access_control_sweep", "idor" to "idor_hunt", "jwt" to "jwt_attack",
            ),
        ),
        Group(
            "autorize",
            "Live broken-access-control detection: taps proxy traffic and replays matching requests " +
                "under lower-privilege identities in the background, flagging mismatches (the probe(action=access_control) " +
                "idea applied continuously instead of to a caller-supplied request list). Flagged mismatches are also " +
                "pushed to findings(action=add).",
            mapOf(
                "set_rule" to "autorize_set_rule",
                "list_rules" to "autorize_list_rules",
                "remove_rule" to "autorize_remove_rule",
                "list_matches" to "autorize_list_matches",
                "clear_matches" to "autorize_clear_matches",
            ),
        ),
        Group(
            "findings", "Findings you record during testing: add, list, remove.",
            prefixed("findings_", "findings_add", "findings_list", "findings_remove"),
        ),
        Group(
            "organizer", "Burp Organizer: send items to it, read them back, annotate.",
            prefixed("organizer_", "organizer_send", "organizer_get_items", "organizer_annotate"),
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
    fun legacyName(tool: String, action: String?): String? =
        byTool[tool]?.let { g -> resolveAction(tool, action)?.let { g.actions[it] } }

    /**
     * The action of group [tool] that [raw] means, forgiving case, `-` for `_`, the tool prefix
     * (`scope_list`), a dotted name (`scope.list`) and the member name (`proxy_websocket_history`).
     * Null for an ungrouped tool or no match.
     */
    fun resolveAction(tool: String, raw: String?): String? {
        val g = byTool[tool] ?: return null
        val a = raw?.trim()?.lowercase()?.replace('-', '_')?.takeIf { it.isNotEmpty() } ?: return null
        val candidates = listOfNotNull(a, a.removePrefix("${tool}_"), if ('.' in a) a.substringAfterLast('.') else null)
        return candidates.firstOrNull { it in g.actions } ?: g.actions.entries.firstOrNull { it.value == a }?.key
    }

    /** Group member names that are not published tools, mapped to how to call them now: `group(action=x)`. */
    private val LEGACY: Map<String, String> by lazy {
        val published = GROUPS.map { it.tool }.toSet() + KEEP
        GROUPS.flatMap { g -> g.actions.map { (action, member) -> member to "${g.tool}(action=$action)" } }
            .filter { it.first !in published }
            .toMap()
    }

    private val LEGACY_PATTERN: Regex by lazy {
        Regex("\\b(" + LEGACY.keys.sortedByDescending { it.length }.joinToString("|") { Regex.escape(it) } + ")\\b")
    }

    /** [text] with every unpublished member name replaced by the grouped call, e.g. `scope_list` -> `scope(action=list)`. */
    internal fun modernize(text: String): String = LEGACY_PATTERN.replace(text) { LEGACY.getValue(it.value) }

    private fun modernizeDescription(def: JsonObject): JsonObject {
        val d = (def["description"] as? JsonPrimitive)?.contentOrNull ?: return def
        val m = modernize(d)
        return if (m == d) def else JsonObject(def + ("description" to JsonPrimitive(m)))
    }

    private fun modernizeProps(props: JsonObject?): JsonObject? =
        props?.let { p -> JsonObject(p.mapValues { (_, v) -> (v as? JsonObject)?.let(::modernizeDescription) ?: v }) }

    /** What one action of a group accepts, under its public parameter names. */
    private class ActionSpec(
        val member: RegisteredTool,
        val props: JsonObject,
        val required: Set<String>,
        val toMember: Map<String, String>,
        val usage: String,
        val example: JsonObject,
    )

    /**
     * Publishes the tools registered on [legacy] onto [target]: groups merged, the rest copied.
     * Every published tool rejects parameters it does not declare, coerces values toward the
     * declared type ([ToolArgs.coerce]) and adds `usage`/`example` to argument errors.
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
            val specs = members.mapValues { (action, rt) -> spec(g, action, rt) }
            val tool = Tool(
                name = g.tool,
                description = describe(g, members, specs),
                inputSchema = schema(g, members),
                annotations = ToolHints.of(g.tool),
            )
            target.addTool(tool) { request -> dispatch(g, specs, request) }
        }
        registered.filterKeys { it !in grouped }.values.forEach { rt -> publishKept(rt, target) }
    }

    private fun spec(g: Group, action: String, rt: RegisteredTool): ActionSpec {
        val renames = g.renames[action].orEmpty()
        val props = JsonObject(rt.tool.inputSchema.properties.orEmpty().mapKeys { (k, _) -> renames[k] ?: k })
        val required = rt.tool.inputSchema.required.orEmpty().map { renames[it] ?: it }.toSet()
        return ActionSpec(
            member = rt,
            props = props,
            required = required,
            toMember = renames.entries.associate { (memberName, publicName) -> publicName to memberName },
            usage = ToolArgs.signature(g.tool, action, props, required),
            example = ToolArgs.example(action, props, required),
        )
    }

    /** Publishes an ungrouped tool with modernized text, annotations and the shared argument checks. */
    private fun publishKept(rt: RegisteredTool, target: Server) {
        val name = rt.tool.name
        val props = rt.tool.inputSchema.properties ?: JsonObject(emptyMap())
        val required = rt.tool.inputSchema.required.orEmpty().toSet()
        val usage = ToolArgs.signature(name, null, props, required)
        val example = ToolArgs.example(null, props, required)
        val tool = rt.tool.copy(
            description = rt.tool.description?.let(::modernize),
            inputSchema = rt.tool.inputSchema.copy(properties = modernizeProps(rt.tool.inputSchema.properties)),
            annotations = ToolHints.of(name),
        )
        target.addTool(tool) { request ->
            val args = request.params.arguments ?: JsonObject(emptyMap())
            if (ToolArgs.unknownParams(props, args, emptySet()).isNotEmpty()) {
                return@addTool ToolArgs.unknownParameterError(
                    name, props, args, emptySet(), usage, example, destructive = tool.annotations?.destructiveHint == true,
                )
            }
            val c = ToolArgs.coerce(props, args)
            val forwarded = if (c.args === args) request else CallToolRequest(request.params.copy(arguments = c.args))
            ToolArgs.withNotes(ToolArgs.enrich(rt.handler(this, forwarded), usage, example, props, c.args), c.notes)
        }
    }

    private fun publicParam(g: Group, action: String, member: String) = g.renames[action]?.get(member) ?: member

    private fun schema(
        g: Group,
        members: Map<String, RegisteredTool>,
    ): ToolSchema {
        // public param -> (action, member definition) for every action declaring it
        val params = LinkedHashMap<String, MutableList<Pair<String, JsonObject>>>()
        members.forEach { (action, rt) ->
            rt.tool.inputSchema.properties?.forEach { (name, def) ->
                val pub = publicParam(g, action, name)
                if (pub == "action") {
                    error("Tool group '${g.tool}', action '$action' declares parameter '$name' that collides with dispatch parameter 'action'; add a rename.")
                }
                params.getOrPut(pub) { mutableListOf() } += action to (def as? JsonObject ?: JsonObject(emptyMap()))
            }
        }
        val props = buildJsonObject {
            putJsonObject("action") {
                put("type", "string")
                putJsonArray("enum") { g.actions.keys.forEach { add(it) } }
                put("description", "Operation to run; see the tool description for each action's parameters.")
            }
            params.forEach { (name, uses) -> put(name, modernizeDescription(mergeParam(uses, members.size))) }
        }
        return ToolSchema(properties = props, required = listOf("action"))
    }

    /**
     * Merges the definitions of one public parameter declared by several actions of a group.
     *
     * Structure (`type`, `enum`, `items`, ...) is merged by [mergeStructure]: enums are united, and a
     * type the actions disagree on drops the parameter to a permissive schema. The description keeps
     * every action's own text plus whatever constraint the merged schema no longer carries for it
     * (its own enum, type, default, ...), so no action's documentation is lost.
     *
     * @param uses (action, member definition) pairs, in action order.
     * @param groupSize number of actions in the group, to tell when a parameter applies to all of them.
     */
    internal fun mergeParam(uses: List<Pair<String, JsonObject>>, groupSize: Int): JsonObject {
        val merged = mergeStructure(uses.map { it.second })
        val typeConflict = uses.map { it.second["type"] }.distinct().size > 1
        val byText = LinkedHashMap<String, MutableList<String>>()
        uses.forEach { (action, def) -> byText.getOrPut(actionText(def, merged)) { mutableListOf() } += action }
        val text = if (byText.size == 1) {
            val (t, actions) = byText.entries.first()
            val scope = if (actions.size == groupSize) "" else " [actions: ${actions.joinToString(", ")}]"
            (t + scope).trim()
        } else {
            byText.entries.joinToString("\n") { (t, actions) -> "[${actions.joinToString(", ")}] $t".trimEnd() }
        }
        val description = if (typeConflict) "Type depends on the action, so any JSON value is accepted here.\n$text" else text
        return JsonObject(merged - "description" + ("description" to JsonPrimitive(description)))
    }

    /**
     * Structural union of several JSON schemas for the same value. Enums are united (kept only when
     * every definition has one, since a definition without an enum accepts anything), `items` and
     * `properties` are merged recursively, and any other key survives only when all definitions agree.
     * Definitions whose `type` differs (including one with and one without a type) merge to `{}`.
     */
    private fun mergeStructure(defs: List<JsonObject>): JsonObject {
        if (defs.size == 1) return defs[0]
        if (defs.map { it["type"] }.distinct().size > 1) return JsonObject(emptyMap())
        val out = LinkedHashMap<String, JsonElement>()
        for (key in defs.flatMap { it.keys }.distinct()) {
            val values = defs.map { it[key] }
            when (key) {
                "enum" -> if (values.all { it is JsonArray }) {
                    out[key] = JsonArray(values.flatMap { it as JsonArray }.distinct())
                }
                "items" -> if (values.all { it is JsonObject }) {
                    out[key] = mergeStructure(values.map { it as JsonObject })
                }
                "properties" -> if (values.all { it is JsonObject }) {
                    val objects = values.map { it as JsonObject }
                    out[key] = JsonObject(objects.flatMap { it.keys }.distinct().associateWith { name ->
                        mergeStructure(objects.mapNotNull { it[name] as? JsonObject })
                    })
                }
                else -> if (values.all { it != null && it == values[0] }) out[key] = values[0]!!
            }
        }
        return JsonObject(out)
    }

    /** One action's description of a parameter, plus the constraints [merged] no longer states for it. */
    private fun actionText(def: JsonObject, merged: JsonObject): String {
        val base = (def["description"] as? JsonPrimitive)?.contentOrNull?.trim().orEmpty()
        val notes = mutableListOf<String>()
        def["type"]?.let { if (merged["type"] != it) notes += "type: ${it.text()}" }
        (def["enum"] as? JsonArray)?.let { if (merged["enum"] != it) notes += "one of: ${it.joinToString(", ") { v -> v.text() }}" }
        val items = def["items"] as? JsonObject
        (items?.get("enum") as? JsonArray)?.let {
            if ((merged["items"] as? JsonObject)?.get("enum") != it) notes += "items one of: ${it.joinToString(", ") { v -> v.text() }}"
        }
        def.forEach { (k, v) ->
            if (k !in STRUCTURAL_KEYS && merged[k] != v) notes += "$k: ${v.text()}"
        }
        return if (notes.isEmpty()) base else "$base (${notes.joinToString("; ")})".trim()
    }

    private val STRUCTURAL_KEYS = setOf("description", "type", "enum", "items", "properties")

    private fun JsonElement.text(): String = (this as? JsonPrimitive)?.contentOrNull ?: toString()

    private fun describe(
        g: Group,
        members: Map<String, RegisteredTool>,
        specs: Map<String, ActionSpec>,
    ): String = buildString {
        val shown = specs.values.firstOrNull { it.required.isNotEmpty() } ?: specs.values.first()
        append(g.intro).append('\n')
        append("Call with {\"action\": \"<action>\", ...that action's parameters}; * marks a required parameter. Example: ")
            .append(shown.example.toString()).append('\n')
        members.forEach { (action, rt) ->
            val required = rt.tool.inputSchema.required.orEmpty().toSet()
            val params = rt.tool.inputSchema.properties?.keys.orEmpty().joinToString(", ") {
                publicParam(g, action, it) + if (it in required) "*" else ""
            }
            append("- ").append(action).append('(').append(params).append("): ")
                .append(modernize(summary(rt.tool.description))).append('\n')
        }
    }.trimEnd()

    /**
     * First sentence of a member description, capped, so the merged description stays compact.
     * A sentence ends at `.`, `!` or `?` followed by whitespace or the end, unless the period closes
     * an abbreviation such as `e.g.`.
     */
    internal fun summary(description: String?): String {
        val text = description.orEmpty().replace(Regex("\\s+"), " ").trim()
        val end = SENTENCE_END.findAll(text).firstOrNull { m ->
            val i = m.range.first
            text[i] != '.' ||
                text.substring(text.lastIndexOf(' ', i) + 1, i + 1).trimStart('(', '[', '"', '\'').lowercase() !in ABBREVIATIONS
        }?.range?.first ?: text.length
        val sentence = text.substring(0, minOf(end + 1, text.length)).trim()
        return if (sentence.length <= 160) sentence else sentence.take(157).trimEnd() + "..."
    }

    private val SENTENCE_END = Regex("[.!?](?=\\s|$)")
    private val ABBREVIATIONS = setOf("e.g.", "i.e.", "vs.", "cf.", "approx.", "incl.", "a.k.a.", "resp.")

    private suspend fun ClientConnection.dispatch(
        g: Group,
        specs: Map<String, ActionSpec>,
        request: CallToolRequest,
    ): CallToolResult {
        var args = request.params.arguments ?: JsonObject(emptyMap())
        val raw = (args["action"] as? JsonPrimitive)?.contentOrNull
        val available = g.actions.keys.joinToString(", ")
        if (raw == null) {
            val shown = specs.values.firstOrNull { it.required.isNotEmpty() } ?: specs.values.first()
            return ToolArgs.error(
                "missing_action",
                "Missing 'action' for tool '${g.tool}'. Set \"action\" to one of: $available.",
            ) {
                putJsonArray("available") { g.actions.keys.forEach { add(it) } }
                put("example", shown.example)
            }
        }
        val notes = mutableListOf<String>()
        var action = resolveAction(g.tool, raw)
        if (action == null) {
            ToolNames.semanticAction(g.tool, raw)?.let { (semantic, extra) ->
                action = semantic
                args = JsonObject(extra + args + ("action" to JsonPrimitive(semantic)))
                notes += "ran action '$raw' as '$semantic' with $extra"
            }
        }
        val resolved = action
        if (resolved == null) {
            val hints = ToolArgs.closest(raw, g.actions.keys)
            val hint = hints.firstOrNull()?.let { " Did you mean '$it'?" }.orEmpty()
            return ToolArgs.error(
                "unknown_action",
                "Unknown action '$raw' for tool '${g.tool}'.$hint Valid actions: $available.",
            ) {
                put("param", "action")
                put("got", raw)
                putJsonArray("did_you_mean") { hints.forEach { add(it) } }
                if (hints.size == 1 && !ToolNames.destructive(g.tool, hints[0], null)) {
                    put("retry", JsonObject(args + ("action" to JsonPrimitive(hints[0]))))
                }
                putJsonArray("available") { g.actions.keys.forEach { add(it) } }
            }
        }
        val spec = specs.getValue(resolved)
        val call = "${g.tool}(action='$resolved')"

        if (ToolArgs.unknownParams(spec.props, args, setOf("action")).isNotEmpty()) {
            return ToolArgs.unknownParameterError(
                call, spec.props, args, setOf("action"), spec.usage, spec.example,
                ToolNames.destructive(g.tool, resolved, null),
            )
        }

        val missing = spec.required.filter { args[it] == null || args[it] is JsonNull }
        if (missing.isNotEmpty()) {
            return ToolArgs.error(
                "missing_parameter",
                "$call is missing required parameter(s): ${missing.joinToString(", ") { "'$it'" }}. " +
                    "Retry with every required parameter set, as in 'example'.",
            ) {
                put("param", missing.first())
                put("usage", spec.usage)
                put("example", spec.example)
            }
        }

        val c = ToolArgs.coerce(spec.props, args)
        notes += c.notes
        val forwarded = buildJsonObject {
            c.args.forEach { (k, v) -> if (k != "action") put(spec.toMember[k] ?: k, v) }
        }
        val member = spec.member
        val result = member.handler(
            this,
            CallToolRequest(
                CallToolRequestParams(
                    name = member.tool.name,
                    arguments = forwarded,
                    meta = request.params.meta,
                )
            )
        )
        return ToolArgs.withNotes(ToolArgs.enrich(result, spec.usage, spec.example, spec.props, c.args), notes)
    }
}
