package io.bitbytelab.raijin.tools.scancheck

import io.bitbytelab.raijin.bridge.HistoryFilter
import io.bitbytelab.raijin.bridge.ScanCheckBridge
import io.bitbytelab.raijin.bridge.ScanCheckLogic
import io.bitbytelab.raijin.core.asJsonObjectList
import io.bitbytelab.raijin.core.asLongSafe
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/**
 * Registers the 6 Script-mode scan check MCP tools onto the given [Server].
 *
 * Script mode uses the Montoya API's ScanCheck interface to create runtime
 * scan checks from JSON. Unlike BCheck (DSL-based), Script mode supports
 * multi-step payload chains, AND/OR condition lists with negation, and
 * comparison with the baseline response.
 */
object ScanCheckTools {

    private const val CONDITION_FIELDS =
        "location [response_body, response_headers, status_code, response_length, request_body, " +
            "request_headers, request_url], pattern [regex or string], condition_type [matches (default), " +
            "contains, equals; all case-insensitive], negate [true/false]"

    fun register(server: Server, bridge: ScanCheckBridge) {

        // ---------------------------------------------------------------
        // 1. scancheck_create_passive
        // ---------------------------------------------------------------
        server.addTool(
            name = "scancheck_create_passive",
            description = "Create a passive Script-mode scan check that analyzes every response during " +
                "scanning. More powerful than BCheck -- supports several conditions joined by AND or OR, " +
                "negation, and regex/contains/equals matching across response body, headers, status " +
                "code, request fields, and more. Parameters: name (required, check name; creating a " +
                "name again replaces that check), description (required, what it detects), conditions " +
                "(required, array of condition objects -- each with: $CONDITION_FIELDS), match_mode " +
                "(all = every condition must hold, the default; any = one is enough), severity (required: " +
                "high, medium, low, information), confidence (required: certain, firm, tentative), " +
                "issue_detail (required, detailed issue description), issue_remediation (optional, how to fix). " +
                "Use scancheck_templates first to see examples and the full condition reference, and " +
                "scancheck_dry_run to see what the conditions match in the proxy history before deploying.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("name") { put("type", "string"); put("description", "Check name") }
                    putJsonObject("description") { put("type", "string"); put("description", "What the check detects") }
                    conditionsProperty()
                    matchModeProperty()
                    enumProperty("severity", ScanCheckLogic.SEVERITIES, "Issue severity")
                    enumProperty("confidence", ScanCheckLogic.CONFIDENCES, "Issue confidence")
                    putJsonObject("issue_detail") { put("type", "string"); put("description", "Detailed issue description") }
                    putJsonObject("issue_remediation") { put("type", "string"); put("description", "How to fix the issue") }
                },
                required = listOf("name", "description", "conditions", "severity", "confidence", "issue_detail")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val name = args.text("name") ?: return@addTool toolError("Missing required parameter: name")
                val description = args.text("description")
                    ?: return@addTool toolError("Missing required parameter: description")
                val conditions = args["conditions"]?.asJsonObjectList()
                    ?: return@addTool toolError("Missing required parameter: conditions (array of {location, pattern, condition_type, negate})")
                val severity = args.text("severity")
                    ?: return@addTool toolError("Missing required parameter: severity (high, medium, low, information)")
                val confidence = args.text("confidence")
                    ?: return@addTool toolError("Missing required parameter: confidence (certain, firm, tentative)")
                val issueDetail = args.text("issue_detail")
                    ?: return@addTool toolError("Missing required parameter: issue_detail")

                toolJsonResult(
                    bridge.createPassive(
                        name = name,
                        description = description,
                        conditions = conditions,
                        severity = severity,
                        confidence = confidence,
                        issueDetail = issueDetail,
                        issueRemediation = args.text("issue_remediation"),
                        matchMode = args.text("match_mode")
                    )
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 2. scancheck_create_active
        // ---------------------------------------------------------------
        server.addTool(
            name = "scancheck_create_active",
            description = "Create an active Script-mode scan check that injects payloads at insertion " +
                "points during active scanning. Supports multi-step payload chains: inject payload A, " +
                "check response, inject payload B, confirm. The check reports only when a step matches " +
                "and the response to the unmodified request would not have matched the same conditions, " +
                "so a pattern the page shows anyway never raises an issue. Parameters: name (required, " +
                "check name; creating a name again replaces that check), description (required, what it " +
                "detects), steps (required, array of step objects -- each with: payload [string to inject], " +
                "response_conditions [array of condition objects like passive checks; at least one step " +
                "needs a condition on the response], match_mode [all | any for that step], stop_if_no_match " +
                "[boolean, default true = required step: no match or no response ends the check without a " +
                "report; false = optional step]), match_mode (default for steps: all | any), severity " +
                "(required: high, medium, low, information), confidence (required: certain, firm, " +
                "tentative), issue_detail (required, detailed issue description), issue_remediation " +
                "(optional, how to fix). Use scancheck_templates first to see multi-step examples.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("name") { put("type", "string"); put("description", "Check name") }
                    putJsonObject("description") { put("type", "string"); put("description", "What the check detects") }
                    stepsProperty()
                    matchModeProperty()
                    enumProperty("severity", ScanCheckLogic.SEVERITIES, "Issue severity")
                    enumProperty("confidence", ScanCheckLogic.CONFIDENCES, "Issue confidence")
                    putJsonObject("issue_detail") { put("type", "string"); put("description", "Detailed issue description") }
                    putJsonObject("issue_remediation") { put("type", "string"); put("description", "How to fix the issue") }
                },
                required = listOf("name", "description", "steps", "severity", "confidence", "issue_detail")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val name = args.text("name") ?: return@addTool toolError("Missing required parameter: name")
                val description = args.text("description")
                    ?: return@addTool toolError("Missing required parameter: description")
                val steps = args["steps"]?.asJsonObjectList()
                    ?: return@addTool toolError("Missing required parameter: steps (array of {payload, response_conditions[], stop_if_no_match})")
                val severity = args.text("severity")
                    ?: return@addTool toolError("Missing required parameter: severity (high, medium, low, information)")
                val confidence = args.text("confidence")
                    ?: return@addTool toolError("Missing required parameter: confidence (certain, firm, tentative)")
                val issueDetail = args.text("issue_detail")
                    ?: return@addTool toolError("Missing required parameter: issue_detail")

                toolJsonResult(
                    bridge.createActive(
                        name = name,
                        description = description,
                        steps = steps,
                        severity = severity,
                        confidence = confidence,
                        issueDetail = issueDetail,
                        issueRemediation = args.text("issue_remediation"),
                        matchMode = args.text("match_mode")
                    )
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 3. scancheck_dry_run
        // ---------------------------------------------------------------
        server.addTool(
            name = "scancheck_dry_run",
            description = "Try a Script-mode scan check definition against the proxy history Burp has already " +
                "recorded, before deploying it. Nothing is registered and nothing is sent. Give 'conditions' " +
                "(as for scancheck_create_passive) to see which recorded messages the passive check would " +
                "report, with an excerpt of what matched. Give 'steps' (as for scancheck_create_active) to " +
                "see how many recorded responses already satisfy each step's response conditions without " +
                "any payload: those are requests the step cannot prove anything on, and a high count means " +
                "the conditions are too broad. Parameters: conditions or steps (exactly one), match_mode " +
                "(all | any), url_pattern (regex on the URL), in_scope_only, max_items (newest history " +
                "items to read, default ${HistoryFilter.DEFAULT_ITEMS}), max_matches (matches listed in " +
                "full, default ${HistoryFilter.DEFAULT_MATCHES}).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    conditionsProperty()
                    stepsProperty()
                    matchModeProperty()
                    historyFilterProperties()
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                toolJsonResult(
                    bridge.dryRun(
                        conditions = args["conditions"]?.takeUnless { it is JsonNull }?.let {
                            it.asJsonObjectList()
                                ?: return@addTool toolError("Parameter 'conditions' must be an array of condition objects")
                        },
                        steps = args["steps"]?.takeUnless { it is JsonNull }?.let {
                            it.asJsonObjectList()
                                ?: return@addTool toolError("Parameter 'steps' must be an array of step objects")
                        },
                        matchMode = args.text("match_mode"),
                        urlPattern = args.text("url_pattern"),
                        inScopeOnly = args.flag("in_scope_only") ?: false,
                        maxItems = args.int("max_items"),
                        maxMatches = args.int("max_matches")
                    )
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 4. scancheck_templates
        // ---------------------------------------------------------------
        server.addTool(
            name = "scancheck_templates",
            description = "Get Script-mode scan check templates, examples, and full condition reference. " +
                "Returns passive and active check templates with realistic examples (sensitive data " +
                "exposure, missing security headers, error disclosure, SQL injection, SSTI, reflected " +
                "XSS), plus a complete reference of condition locations, types, match modes, active step " +
                "fields and how the baseline comparison works. Call this BEFORE creating Script-mode checks " +
                "to understand the capabilities and correct parameter structure. No parameters required.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { _ ->
            try {
                toolJsonResult(bridge.getTemplates())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 5. scancheck_list
        // ---------------------------------------------------------------
        server.addTool(
            name = "scancheck_list",
            description = "List all custom scan checks deployed via MCP, including those registered with " +
                "scanner_register_check. Returns the count and details of each deployed check: its ID, " +
                "name, mode (passive/active/both), issue name, severity, confidence and deployment " +
                "timestamp. No parameters required.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { _ ->
            try {
                toolJsonResult(bridge.list())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 6. scancheck_remove
        // ---------------------------------------------------------------
        server.addTool(
            name = "scancheck_remove",
            description = "Remove a deployed Script-mode scan check by its ID. This fully deregisters " +
                "the check from Burp's scanner -- unlike BCheck removal, Script-mode checks are " +
                "completely removed at runtime. Parameters: id (required, the scan check ID returned " +
                "by scancheck_create_passive or scancheck_create_active, e.g. 'scheck-001', or the " +
                "check's name).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("id") { put("type", "string"); put("description", "Scan check ID (or name) to remove") }
                },
                required = listOf("id")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val id = args.text("id") ?: return@addTool toolError("Missing required parameter: id")

                toolJsonResult(bridge.remove(id))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }

    /** The JSON schema of one condition object. */
    private fun JsonObjectBuilder.conditionSchema() {
        put("type", "object")
        putJsonObject("properties") {
            enumProperty("location", ScanCheckLogic.LOCATIONS, "Part of the message to look at")
            putJsonObject("pattern") { put("type", "string"); put("description", "Regex (matches) or text (contains, equals)") }
            enumProperty("condition_type", ScanCheckLogic.CONDITION_TYPES, "How pattern is compared, case-insensitively (default matches)")
            putJsonObject("negate") { put("type", "boolean"); put("description", "Invert the condition (default false)") }
        }
        putJsonArray("required") { add("location"); add("pattern") }
    }

    private fun JsonObjectBuilder.conditionsProperty() {
        putJsonObject("conditions") {
            put("type", "array")
            putJsonObject("items") { conditionSchema() }
            put("description", "Condition objects: location, pattern, condition_type, negate")
        }
    }

    private fun JsonObjectBuilder.stepsProperty() {
        putJsonObject("steps") {
            put("type", "array")
            putJsonObject("items") {
                put("type", "object")
                putJsonObject("properties") {
                    putJsonObject("payload") { put("type", "string"); put("description", "String to inject at the insertion point") }
                    putJsonObject("response_conditions") {
                        put("type", "array")
                        putJsonObject("items") { conditionSchema() }
                        put("description", "Conditions on the response to this payload")
                    }
                    enumProperty("match_mode", ScanCheckLogic.MATCH_MODES, "How this step's conditions combine (default: the call's match_mode)")
                    putJsonObject("stop_if_no_match") { put("type", "boolean"); put("description", "true (default): required step. false: optional step") }
                }
                putJsonArray("required") { add("payload") }
            }
            put("description", "Step objects: payload, response_conditions[], match_mode, stop_if_no_match")
        }
    }

    private fun JsonObjectBuilder.matchModeProperty() {
        enumProperty("match_mode", ScanCheckLogic.MATCH_MODES, "How conditions in a list combine: all (default) or any")
    }
}

/** The history-selection parameters every dry-run tool takes. */
private fun JsonObjectBuilder.historyFilterProperties() {
    putJsonObject("url_pattern") { put("type", "string"); put("description", "Only read history items whose URL matches this regex (case-insensitive)") }
    putJsonObject("in_scope_only") { put("type", "boolean"); put("description", "Only read in-scope history items (default false)") }
    putJsonObject("max_items") {
        put("type", "integer"); put("minimum", 1); put("maximum", HistoryFilter.MAX_ITEMS)
        put("description", "How many of the newest matching history items to read (default ${HistoryFilter.DEFAULT_ITEMS})")
    }
    putJsonObject("max_matches") {
        put("type", "integer"); put("minimum", 1); put("maximum", HistoryFilter.MAX_MATCHES)
        put("description", "How many matches to list in full (default ${HistoryFilter.DEFAULT_MATCHES})")
    }
}

/** Adds a string property whose value must be one of [values]. */
private fun JsonObjectBuilder.enumProperty(name: String, values: Collection<String>, description: String) {
    putJsonObject(name) {
        put("type", "string")
        putJsonArray("enum") { values.forEach { add(it) } }
        put("description", description)
    }
}

private fun Map<String, JsonElement>.text(name: String): String? = (this[name] as? JsonPrimitive)?.contentOrNull

private fun Map<String, JsonElement>.flag(name: String): Boolean? = (this[name] as? JsonPrimitive)?.booleanOrNull

/**
 * An optional integer argument. Its range is checked where it is used.
 *
 * @throws IllegalArgumentException naming the parameter when it is not an integer.
 */
private fun Map<String, JsonElement>.int(name: String): Int? {
    val raw = this[name]?.takeUnless { it is JsonNull } ?: return null
    val value = raw.asLongSafe() ?: throw IllegalArgumentException("Parameter '$name' must be an integer")
    return value.coerceIn(Int.MIN_VALUE.toLong(), Int.MAX_VALUE.toLong()).toInt()
}
