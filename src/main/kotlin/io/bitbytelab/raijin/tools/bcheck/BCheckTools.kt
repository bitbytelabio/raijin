package io.bitbytelab.raijin.tools.bcheck

import io.bitbytelab.raijin.bridge.BCheckBridge
import io.bitbytelab.raijin.bridge.HistoryFilter
import io.bitbytelab.raijin.core.asLongSafe
import io.bitbytelab.raijin.core.asStringList
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/**
 * Registers the 6 BCheck MCP tools onto the given [Server].
 *
 * BChecks are Burp Suite's domain-specific language for custom vulnerability
 * scan checks. These tools allow an AI agent to create, dry-run, import, list, and
 * manage BCheck scripts that run during passive and active scanning.
 */
object BCheckTools {

    /** What each definition parameter means for each check type; shared by bcheck_create and bcheck_dry_run. */
    private const val TYPE_GUIDE =
        "passive_response: match_pattern is looked for in match_location (response_body, the default; " +
            "response_headers; status_code). " +
            "passive_request: match_pattern is looked for in match_location (request_url, the default; " +
            "request_headers; request_body). " +
            "insertion_point: each of payloads is injected, and the check reports when response_match_pattern " +
            "appears in the response body and was not in the response to the unmodified request. " +
            "host_level: one GET of path (default /) per host, reported when the answer is 200 and its body " +
            "shows response_match_pattern. " +
            "path_level: each of payloads is a suffix appended to every path (default .bak, .old, .orig, .swp, ~), " +
            "reported when the answer is 200, differs from the answer to a random path and, if given, shows " +
            "response_match_pattern. " +
            "collaborator: the header named by match_location (default Referer) is set to match_pattern, which " +
            "must contain {generate_collaborator_address()} (default https://{generate_collaborator_address()}); " +
            "reported on a collaborator_payload_type (dns, the default, or http) interaction. " +
            "match_condition says how a pattern is compared: matches (regex, the default), contains (literal " +
            "substring) or is (exact value); comparisons are case-sensitive unless a regex says (?i)."

    fun register(server: Server, bridge: BCheckBridge) {

        // ---------------------------------------------------------------
        // 1. bcheck_create
        // ---------------------------------------------------------------
        server.addTool(
            name = "bcheck_create",
            description = "Generate and deploy a BCheck custom scan check from structured parameters. " +
                "BChecks are Burp Suite's DSL for defining custom vulnerability detection rules that run " +
                "during scanning. Any text is safe in any parameter: it is written into the script as a " +
                "string, never as DSL. Parameters: name (required, check name), description (required, what " +
                "it detects), type (required), severity (required), confidence (required), author (optional, " +
                "defaults to Raijin AI Agent), tags (optional, comma-separated), issue_detail, " +
                "issue_remediation, and the definition: $TYPE_GUIDE " +
                "An empty or missing pattern is rejected, since it would match everything. Use bcheck_dry_run " +
                "with the same definition to see what it does with the recorded proxy history first, and " +
                "bcheck_templates for the DSL itself.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("name") { put("type", "string"); put("description", "Check name") }
                    putJsonObject("description") { put("type", "string"); put("description", "What the check detects") }
                    definitionProperties()
                    enumProperty("severity", BCheckBridge.ALLOWED_SEVERITIES, "Issue severity")
                    enumProperty("confidence", BCheckBridge.ALLOWED_CONFIDENCES, "Issue confidence")
                    putJsonObject("author") { put("type", "string"); put("description", "Author name") }
                    putJsonObject("tags") { put("type", "string"); put("description", "Comma-separated tags") }
                    putJsonObject("issue_detail") { put("type", "string"); put("description", "Detailed issue description") }
                    putJsonObject("issue_remediation") { put("type", "string"); put("description", "How to fix the issue") }
                },
                required = listOf("name", "description", "type", "severity", "confidence")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val name = args.text("name") ?: return@addTool toolError("Missing required parameter: name")
                val description = args.text("description")
                    ?: return@addTool toolError("Missing required parameter: description")
                val type = args.text("type")
                    ?: return@addTool toolError("Missing required parameter: type (passive_response, passive_request, insertion_point, host_level, path_level, collaborator)")
                val severity = args.text("severity")
                    ?: return@addTool toolError("Missing required parameter: severity (high, medium, low, information)")
                val confidence = args.text("confidence")
                    ?: return@addTool toolError("Missing required parameter: confidence (certain, firm, tentative)")

                toolJsonResult(
                    bridge.create(
                        name = name,
                        description = description,
                        author = args.text("author"),
                        tags = args.text("tags"),
                        type = type,
                        matchPattern = args.text("match_pattern"),
                        matchLocation = args.text("match_location"),
                        matchCondition = args.text("match_condition"),
                        payloads = args["payloads"]?.asStringList(),
                        responseMatchPattern = args.text("response_match_pattern"),
                        collaboratorPayloadType = args.text("collaborator_payload_type"),
                        severity = severity,
                        confidence = confidence,
                        issueDetail = args.text("issue_detail"),
                        issueRemediation = args.text("issue_remediation"),
                        path = args.text("path")
                    )
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 2. bcheck_import
        // ---------------------------------------------------------------
        server.addTool(
            name = "bcheck_import",
            description = "Import a raw BCheck script directly into Burp Suite. Use this when you have " +
                "a complete BCheck script in BCheck DSL format. The script must include a metadata block " +
                "with language, name, and description fields, followed by the check logic. " +
                "Parameters: script (required, the full BCheck DSL script as a string). " +
                "Use bcheck_templates to see the correct syntax and available DSL constructs.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("script") { put("type", "string"); put("description", "Full BCheck DSL script") }
                },
                required = listOf("script")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val script = args.text("script") ?: return@addTool toolError("Missing required parameter: script")
                if (script.isBlank()) return@addTool toolError("Script cannot be empty")

                toolJsonResult(bridge.importRaw(script))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 3. bcheck_dry_run
        // ---------------------------------------------------------------
        server.addTool(
            name = "bcheck_dry_run",
            description = "Try a bcheck_create definition against the proxy history Burp has already recorded, " +
                "before deploying it. Nothing is imported and nothing is sent. A passive check is evaluated in " +
                "full: the result lists the recorded messages it would report, with an excerpt of what matched. " +
                "A check that sends requests cannot be run dry, so the result says how many requests a scan " +
                "would add and what the history already shows: responses that carry the response pattern " +
                "before any payload (insertion_point), or recorded responses for the very paths the check " +
                "would request (host_level, path_level). The generated script is returned too. The definition " +
                "parameters are those of bcheck_create: $TYPE_GUIDE " +
                "History selection: url_pattern (regex on the URL), in_scope_only, max_items (newest history " +
                "items to read, default ${HistoryFilter.DEFAULT_ITEMS}), max_matches (matches listed in full, " +
                "default ${HistoryFilter.DEFAULT_MATCHES}).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    definitionProperties()
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
                },
                required = listOf("type")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val type = args.text("type")
                    ?: return@addTool toolError("Missing required parameter: type (passive_response, passive_request, insertion_point, host_level, path_level, collaborator)")

                toolJsonResult(
                    bridge.dryRun(
                        type = type,
                        matchPattern = args.text("match_pattern"),
                        matchLocation = args.text("match_location"),
                        matchCondition = args.text("match_condition"),
                        payloads = args["payloads"]?.asStringList(),
                        responseMatchPattern = args.text("response_match_pattern"),
                        collaboratorPayloadType = args.text("collaborator_payload_type"),
                        path = args.text("path"),
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
        // 4. bcheck_templates
        // ---------------------------------------------------------------
        server.addTool(
            name = "bcheck_templates",
            description = "Get all BCheck templates with full examples, DSL reference, and usage guidance. " +
                "Returns 7 templates covering all BCheck types: passive_response, passive_request, " +
                "insertion_point, host_level, path_level, collaborator, and multi_step. Each template " +
                "includes a complete working example, use cases, and descriptions. Also returns a " +
                "comprehensive DSL reference covering metadata fields, scope keywords, request operations, " +
                "conditions, strings and escaping, variables, and reporting options. Call this BEFORE " +
                "writing a BCheck script by hand. No parameters required.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { _ ->
            try {
                toolJsonResult(bridge.getTemplates())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 5. bcheck_list
        // ---------------------------------------------------------------
        server.addTool(
            name = "bcheck_list",
            description = "List all BChecks that have been deployed via MCP. Returns the count and details " +
                "of each deployed BCheck including its ID, name, type, deployment timestamp, and a " +
                "preview of the script. No parameters required.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { _ ->
            try {
                toolJsonResult(bridge.list())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 6. bcheck_remove
        // ---------------------------------------------------------------
        server.addTool(
            name = "bcheck_remove",
            description = "Remove a deployed BCheck from MCP tracking by its ID. The ID is returned " +
                "when creating or importing a BCheck. Note: this removes the BCheck from MCP tracking; " +
                "to fully remove it from Burp Suite, manual removal in the Burp UI may be needed. " +
                "Parameters: id (required, the BCheck ID from bcheck_create or bcheck_import).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    // custom_check shows this description for scancheck_remove's id as well.
                    putJsonObject("id") { put("type", "string"); put("description", "ID of the check to remove") }
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

    /** The parameters that define what a BCheck does; bcheck_create and bcheck_dry_run take the same ones. */
    private fun JsonObjectBuilder.definitionProperties() {
        enumProperty("type", BCheckBridge.ALLOWED_TYPES, "Check type")
        putJsonObject("match_pattern") { put("type", "string"); put("description", "Regex or text to match. For collaborator: the header value to inject") }
        putJsonObject("match_location") {
            put("type", "string")
            put("description", "Where to match. passive_response: response_body, response_headers, status_code. " +
                "passive_request: request_url, request_headers, request_body. collaborator: the header to set")
        }
        enumProperty("match_condition", BCheckBridge.ALLOWED_CONDITIONS, "How a pattern is compared (default matches)")
        putJsonObject("payloads") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "insertion_point: payloads to inject. path_level: suffixes to append to each path") }
        putJsonObject("response_match_pattern") { put("type", "string"); put("description", "What the response body must show (insertion_point, host_level; optional for path_level)") }
        putJsonObject("path") { put("type", "string"); put("description", "host_level: the path requested on every host (default /)") }
        enumProperty("collaborator_payload_type", BCheckBridge.ALLOWED_INTERACTIONS, "Collaborator interaction that counts (default dns)")
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
