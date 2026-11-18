package io.bitbytelab.raijin.tools.session

import burp.api.montoya.core.ToolType
import io.bitbytelab.raijin.bridge.HttpBridge
import io.bitbytelab.raijin.bridge.HttpModes
import io.bitbytelab.raijin.bridge.SessionBridge
import io.bitbytelab.raijin.bridge.SessionMacroEngine
import io.bitbytelab.raijin.bridge.SessionRuleEngine
import io.bitbytelab.raijin.core.asLongSafe
import io.bitbytelab.raijin.core.asStringList
import io.bitbytelab.raijin.safety.ScopeGate
import io.bitbytelab.raijin.state.SessionMacro
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.tools.http.ToolArgs
import io.bitbytelab.raijin.tools.http.enumProperty
import io.bitbytelab.raijin.tools.http.property
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

/**
 * MCP tools for session handling: rules that extract dynamic tokens from HTTP responses and inject
 * them into subsequent requests (CSRF tokens, session tokens; [SessionBridge]), and login macros
 * that re-establish an expired session automatically ([SessionMacroEngine], owned by [HttpBridge]
 * because its global HTTP handler runs them).
 */
object SessionTools {

    private val TOOL_TYPES: List<String> = ToolType.entries.map { it.name }

    private const val MAX_MIN_INTERVAL_MS = 3_600_000L
    private const val MAX_FAILURES = 100
    private val STEP_TIMEOUTS_MS = 100L..60_000L

    fun register(server: Server, httpBridge: HttpBridge, stateManager: StateManager) {
        val bridge = SessionBridge(stateManager)
        val macros = httpBridge.sessionMacros

        // 1. session_create_token_rule
        server.addTool(
            name = "session_create_token_rule",
            description = "Create a session handling rule: extract a value (CSRF token, session ID, bearer token) from " +
                "responses in scope and inject it into later requests in scope. extract_from 'header' reads every " +
                "header line named extract_header_name (each Set-Cookie on its own) and takes the first that yields a " +
                "value; 'body' reads the body. The value is selected by extract_json_path or extract_xpath, then by " +
                "extract_regex (first capture group, else the whole match; after a path it cuts a part out of the " +
                "selected value). inject_into 'header', 'cookie', 'body' (form parameter), 'query' (URL parameter, " +
                "written as rendered) or 'json' (inject_name is a JSONPath naming one value; an existing value is " +
                "replaced in place and numbers stay numbers). A rendered value containing CR/LF is never written into a " +
                "header, cookie or parameter. Raijin's internal unauthenticated probes never get rule values.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    property("rule_name", "string", "Unique name for this rule")
                    enumProperty("scope", SessionRuleEngine.SCOPES, "'all', 'suite' (Burp target scope) or 'custom' (scope_pattern)")
                    property("scope_pattern", "string", "URL regex when scope is 'custom'")
                    enumProperty("extract_from", SessionRuleEngine.EXTRACT_SOURCES, "Where to extract the value from")
                    property("extract_header_name", "string", "Header to read when extract_from is 'header' (every line of it, e.g. each Set-Cookie)")
                    property("extract_regex", "string", "Regex; the first capture group (else the whole match) is the value. Optional when a JSONPath or XPath is given")
                    property("extract_json_path", "string", "JSONPath selecting the value in a JSON body: $.data.token, data.token, $..token, $.items[0].id, $['a-b']")
                    property("extract_xpath", "string", "XPath 1.0 selecting the value in an XML body: //csrf, //input[@name='csrf']/@value, string(//token)")
                    enumProperty("inject_into", SessionRuleEngine.INJECT_TARGETS, "Where to inject the value")
                    property("inject_name", "string", "Header, cookie or parameter name; for 'json' a JSONPath naming one value ($.auth.token)")
                    property("inject_value_template", "string", "Rendered value: {value}, or {value|url} / {value|base64|url} through the encoders url, url_all, double_url, json, base64, base64url, html, hex, raw")
                    property("inject_if_missing", "boolean", "Add the header/cookie/parameter/JSON member to requests that lack it (default true); false only updates existing ones")
                    property("enabled", "boolean", "Whether the rule is active (default true)")
                },
                required = listOf("rule_name", "scope", "extract_from", "inject_into", "inject_name", "inject_value_template")
            )
        ) { request ->
            try {
                val a = ToolArgs(request.params.arguments ?: emptyMap())
                toolJsonResult(bridge.createTokenRule(
                    ruleName = a.string("rule_name") ?: return@addTool toolError("Missing required parameter: rule_name"),
                    scope = a.enum("scope", SessionRuleEngine.SCOPES) ?: return@addTool toolError("Missing required parameter: scope"),
                    scopePattern = a.string("scope_pattern"),
                    extractFrom = a.enum("extract_from", SessionRuleEngine.EXTRACT_SOURCES)
                        ?: return@addTool toolError("Missing required parameter: extract_from"),
                    extractHeaderName = a.string("extract_header_name"),
                    extractRegex = a.string("extract_regex"),
                    extractJsonPath = a.string("extract_json_path"),
                    extractXPath = a.string("extract_xpath"),
                    injectInto = a.enum("inject_into", SessionRuleEngine.INJECT_TARGETS)
                        ?: return@addTool toolError("Missing required parameter: inject_into"),
                    injectName = a.string("inject_name") ?: return@addTool toolError("Missing required parameter: inject_name"),
                    injectValueTemplate = a.string("inject_value_template")
                        ?: return@addTool toolError("Missing required parameter: inject_value_template"),
                    injectIfMissing = a.bool("inject_if_missing") ?: true,
                    enabled = a.bool("enabled") ?: true,
                ))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 2. session_list_rules
        server.addTool(
            name = "session_list_rules",
            description = "List session handling rules: extraction (header/body, regex, JSONPath, XPath) and injection " +
                "(target, name, template, inject_if_missing) settings, enabled flag and the last extracted value.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { _ ->
            try {
                toolJsonResult(bridge.listRules())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 3. session_remove_rule
        server.addTool(
            name = "session_remove_rule",
            description = "Remove a session handling rule by its name. The rule will no longer " +
                "extract or inject values for matching requests.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    property("rule_name", "string", "The name of the rule to remove")
                },
                required = listOf("rule_name")
            )
        ) { request ->
            try {
                val a = ToolArgs(request.params.arguments ?: emptyMap())
                val ruleName = a.string("rule_name") ?: return@addTool toolError("Missing required parameter: rule_name")
                toolJsonResult(bridge.removeRule(ruleName))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 4. session_macro_set
        server.addTool(
            name = "session_macro_set",
            description = "Create or replace (by name) a login macro that re-establishes an expired session " +
                "automatically. When a response the macro covers (scope, tool_filter) shows an expired session " +
                "(status in trigger_status, or trigger_regex matching status line + headers + body) and its request " +
                "carried credentials, the macro's steps are replayed and the original request is sent once more with " +
                "the refreshed session; that response replaces the expired one and reports reauthenticated: <name>. " +
                "Session rules extract from step responses (use one to capture a new token); cookies set by the " +
                "steps replace same-named cookies in covered requests, never added. While a macro is enabled, a " +
                "deliberately stale session cookie is replaced too: disable it to send one. Safeguards: one run at a " +
                "time, min_interval_ms between automatic runs, step_timeout_ms per step and for the retry, at most " +
                "${SessionMacroEngine.MAX_STEPS} steps and ${SessionMacroEngine.MAX_RUN_MS / 1000} s per run, suspension " +
                "after max_failures runs that did not help (session_macro_run or session_macro_set resumes it). Steps and " +
                "retries never trigger a macro; Raijin's internal unauthenticated probes never trigger one nor get its " +
                "cookies. Replacing a macro resets its state. " + ScopeGate.TOOL_NOTE + " Steps and the retry are checked.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    property("name", "string", "Unique macro name; a macro of the same name is replaced")
                    putJsonObject("steps") {
                        put("type", "array")
                        putJsonObject("items") { put("type", "object") }
                        put("description", "Login requests in order (at most ${SessionMacroEngine.MAX_STEPS}), as http_send_request_chain steps: raw_request or url/method/headers/body, optional extract [{name, pattern | json_path | xpath, from}] feeding {{name}} placeholders of later steps. Sent as stored: no session value is injected into them.")
                    }
                    enumProperty("scope", SessionRuleEngine.SCOPES, "Which responses trigger the macro and which requests get its cookies: 'all', 'suite' (Burp target scope) or 'custom' (scope_pattern)")
                    property("scope_pattern", "string", "URL regex when scope is 'custom'")
                    putJsonObject("trigger_status") {
                        put("type", "array")
                        putJsonObject("items") { put("type", "integer") }
                        put("description", "Response status codes meaning 'session expired' (default [401]); [] to rely on trigger_regex alone")
                    }
                    property("trigger_regex", "string", "Regex over the response status line, headers and body meaning 'session expired', e.g. 'Location: /login'")
                    putJsonObject("tool_filter") {
                        put("type", "array")
                        putJsonObject("items") {
                            put("type", "string")
                            putJsonArray("enum") { TOOL_TYPES.forEach { add(it) } }
                        }
                        put("description", "Burp tools whose traffic the macro covers (default: every tool except PROXY, so the browser's traffic is left alone)")
                    }
                    property("require_credentials", "boolean", "Only a request carrying an Authorization or Cookie header, or a session-rule value, can trigger the macro (default true), so a deliberately unauthenticated request stays unauthenticated")
                    property("update_cookies", "boolean", "Cookies set by step responses replace same-named cookies in covered requests (default true); they are never added to a request without them")
                    property("min_interval_ms", "integer", "Shortest time between automatic runs, 0-$MAX_MIN_INTERVAL_MS (default ${SessionMacro.DEFAULT_MIN_INTERVAL_MS}); a request sent before the last run is still retried")
                    property("max_failures", "integer", "Runs in a row that did not help before the macro suspends itself, 0-$MAX_FAILURES (default ${SessionMacro.DEFAULT_MAX_FAILURES}; 0 = never)")
                    property("step_timeout_ms", "integer", "Hard timeout of each step and of the retry, ${STEP_TIMEOUTS_MS.first}-${STEP_TIMEOUTS_MS.last} (default ${SessionMacro.DEFAULT_STEP_TIMEOUT_MS})")
                    enumProperty("http_mode", HttpModes.NAMES, "HTTP version of the steps (default AUTO)")
                    property("enabled", "boolean", "false keeps the macro stored but inactive: no automatic runs, no cookie updates (default true)")
                },
                required = listOf("name", "steps", "scope")
            )
        ) { request ->
            try {
                val a = ToolArgs(request.params.arguments ?: emptyMap())
                val macro = SessionMacro(
                    name = a.string("name") ?: return@addTool toolError("Missing required parameter: name"),
                    steps = a.objectList("steps", "step") ?: return@addTool toolError("Missing required parameter: steps (array of step objects)"),
                    scope = a.enum("scope", SessionRuleEngine.SCOPES) ?: return@addTool toolError("Missing required parameter: scope"),
                    scopePattern = a.string("scope_pattern"),
                    triggerStatus = statusCodes(a, "trigger_status") ?: SessionMacro.DEFAULT_TRIGGER_STATUS,
                    triggerRegex = a.string("trigger_regex")?.ifEmpty { null },
                    toolFilter = toolNames(a, "tool_filter") ?: SessionMacro.DEFAULT_TOOL_FILTER,
                    requireCredentials = a.bool("require_credentials") ?: true,
                    updateCookies = a.bool("update_cookies") ?: true,
                    minIntervalMs = a.clampedLong("min_interval_ms", 0L..MAX_MIN_INTERVAL_MS) ?: SessionMacro.DEFAULT_MIN_INTERVAL_MS,
                    maxFailures = a.clampedInt("max_failures", 0..MAX_FAILURES) ?: SessionMacro.DEFAULT_MAX_FAILURES,
                    stepTimeoutMs = a.clampedLong("step_timeout_ms", STEP_TIMEOUTS_MS) ?: SessionMacro.DEFAULT_STEP_TIMEOUT_MS,
                    httpMode = a.enum("http_mode", HttpModes.NAMES),
                    enabled = a.bool("enabled") ?: true,
                )
                toolJsonResult(a.withNotes(macros.set(macro)))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 5. session_macro_list
        server.addTool(
            name = "session_macro_list",
            description = "List login macros with their settings and state: runs, last run time and result, " +
                "consecutive failures, suspension, retries and the names of the cookies they learned.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { _ ->
            try {
                toolJsonResult(macros.list())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 6. session_macro_remove
        server.addTool(
            name = "session_macro_remove",
            description = "Remove a login macro by name; it no longer runs and its learned cookies are no longer applied.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    property("name", "string", "The macro to remove")
                },
                required = listOf("name")
            )
        ) { request ->
            try {
                val a = ToolArgs(request.params.arguments ?: emptyMap())
                val name = a.string("name") ?: return@addTool toolError("Missing required parameter: name")
                toolJsonResult(macros.remove(name))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 7. session_macro_run
        server.addTool(
            name = "session_macro_run",
            description = "Run a login macro now, whatever its trigger, interval or suspension: to prime the session " +
                "or debug the steps. Reports each step's status code, extracted variables and Set-Cookie values, the " +
                "cookies learned and the session rules that captured a new value. A run whose steps all succeed " +
                "resumes a suspended macro. " + ScopeGate.TOOL_NOTE,
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    property("name", "string", "The macro to run")
                },
                required = listOf("name")
            )
        ) { request ->
            try {
                val a = ToolArgs(request.params.arguments ?: emptyMap())
                val name = a.string("name") ?: return@addTool toolError("Missing required parameter: name")
                toolJsonResult(macros.runNow(name))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }

    /** Status codes under [name] (an array, or one number), each clamped into 100-599 with a note. */
    private fun statusCodes(a: ToolArgs, name: String): Set<Int>? {
        val element = a[name] ?: return null
        val items = element as? JsonArray ?: listOf(element)
        return items.mapTo(LinkedHashSet()) { item ->
            val code = item.asLongSafe()
                ?: throw IllegalArgumentException("Parameter '$name' must be an array of HTTP status codes (got $item)")
            if (code !in 100L..599L) a.notes += "Parameter '$name' value $code is outside 100-599; ${code.coerceIn(100L, 599L)} was used."
            code.coerceIn(100L, 599L).toInt()
        }
    }

    /** Burp tool names under [name], matched case-insensitively; an unknown one is an error. */
    private fun toolNames(a: ToolArgs, name: String): Set<String>? {
        val element = a[name] ?: return null
        val names = element.asStringList() ?: throw IllegalArgumentException("Parameter '$name' must be an array of Burp tool names")
        val tools = names.mapTo(LinkedHashSet()) { tool ->
            TOOL_TYPES.firstOrNull { it.equals(tool.trim(), ignoreCase = true) }
                ?: throw IllegalArgumentException("$name: unknown tool '$tool'. Allowed: ${TOOL_TYPES.joinToString(", ")}")
        }
        require(tools.isNotEmpty()) { "Parameter '$name' must name at least one Burp tool" }
        return tools
    }
}
