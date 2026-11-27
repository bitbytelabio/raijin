package io.bitbytelab.raijin.tools.scanner

import io.bitbytelab.raijin.bridge.ScannerBridge
import io.bitbytelab.raijin.core.asClampedInt
import io.bitbytelab.raijin.core.asLongSafe
import io.bitbytelab.raijin.core.asStringList
import io.bitbytelab.raijin.core.withClampReport
import io.bitbytelab.raijin.safety.ScopeGate
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.*

/**
 * Registers all 13 scanner MCP tools onto the given [Server].
 *
 * Each tool delegates to the [ScannerBridge] and catches exceptions so that errors are returned as
 * structured JSON inside a tool result rather than propagating unhandled.
 */
object ScannerTools {

    private val SEVERITIES = listOf("high", "medium", "low", "information")
    private val CONFIDENCES = listOf("certain", "firm", "tentative")

    fun register(server: Server, bridge: ScannerBridge, stateManager: StateManager) {

        // ---------------------------------------------------------------
        // 1. scanner_start_crawl
        // ---------------------------------------------------------------
        server.addTool(
            name = "scanner_start_crawl",
            description =
                "Start a web crawl against one or more target URLs. Returns a task ID for tracking progress. Pro edition only. " +
                    "max_depth is NOT supported by Burp's Montoya API (no depth control exists) and is always ignored — check the response's " +
                    "'ignored' field. in_scope_only IS enforced: out-of-scope seed URLs are dropped before crawling. Burp's own request_count " +
                    "in scanner_task_status can be unreliable; use sitemap_query (only_with_response=true) to gauge real progress. " +
                    ScopeGate.ADVISORY_NOTE +
                    " Flagged seeds are listed in scope_warnings (with sent_out_of_scope).",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("urls") {
                                put("type", "array")
                                putJsonObject("items") { put("type", "string") }
                                put("description", "Target URLs to crawl")
                            }
                            putJsonObject("max_depth") {
                                put("type", "integer")
                                put("minimum", 0)
                                put(
                                    "description",
                                    "Not supported by Montoya's CrawlConfiguration — accepted but always ignored",
                                )
                            }
                            putJsonObject("in_scope_only") {
                                put("type", "boolean")
                                put(
                                    "description",
                                    "Restrict crawl to in-scope URLs (enforced by filtering seeds before crawling)",
                                )
                            }
                        },
                    required = listOf("urls"),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val urls =
                    args["urls"].asStringList()
                        ?: return@addTool toolError(
                            "Parameter 'urls' is required (array of URL strings)",
                        )
                val maxDepth =
                    args["max_depth"].asClampedInt("max_depth", 0, Int.MAX_VALUE).getOrElse {
                        return@addTool toolError(it.message ?: "Invalid max_depth")
                    }
                val inScopeOnly = args.flag("in_scope_only") ?: false

                toolJsonResult(
                    bridge
                        .startCrawl(urls, maxDepth?.value, inScopeOnly)
                        .withClampReport("max_depth", maxDepth),
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 2. scanner_start_audit
        // ---------------------------------------------------------------
        server.addTool(
            name = "scanner_start_audit",
            description =
                "Start an active audit (vulnerability scan) against target URLs or specific HTTP requests. Pro edition only. " +
                    "'urls' are resolved to requests and added to the audit. audit_mode: light=passive checks, normal/thorough=active checks — " +
                    "Montoya's BuiltInAuditConfiguration has no separate 'thorough' preset, so thorough currently runs identically to normal " +
                    "(see the response's 'ignored' field). insertion_point_types is accepted but NOT enforced — Montoya cannot restrict the " +
                    "built-in audit by insertion point type. crawl_first, when urls is non-empty, starts a REAL crawl on those urls — but " +
                    "Montoya has no crawl-then-audit pipe, so the crawl's discoveries are not auto-added to this audit (see 'crawl_note'). " +
                    "auth_header_name + auth_header_value set one header on the audit's requests: only on Scanner traffic to the hosts in " +
                    "'urls' / the Host headers of 'requests', replacing a value the request already has, and only until the audit ends " +
                    "or is deleted. A Cookie header sets only the cookies it names; the request's other cookies (the Scanner's cookie " +
                    "payloads, CSRF and load balancer cookies) stay. " +
                    ScopeGate.ADVISORY_NOTE +
                    " Flagged targets are listed in scope_warnings (with sent_out_of_scope).",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("urls") {
                                put("type", "array")
                                putJsonObject("items") { put("type", "string") }
                                put(
                                    "description",
                                    "Target URLs to audit (resolved to requests and added directly)",
                                )
                            }
                            putJsonObject("requests") {
                                put("type", "array")
                                putJsonObject("items") { put("type", "string") }
                                put("description", "Base64-encoded HTTP requests to audit")
                            }
                            enumProperty(
                                "audit_mode",
                                ScannerBridge.AUDIT_MODES,
                                "light (passive) | normal (default) | thorough (normal and thorough currently run the same Montoya audit configuration)",
                            )
                            putJsonObject("crawl_first") {
                                put("type", "boolean")
                                put(
                                    "description",
                                    "Default true. When true and urls is non-empty, starts a real crawl on those urls alongside the audit — the two tasks run independently, see 'crawl_note' in the response",
                                )
                            }
                            putJsonObject("insertion_point_types") {
                                put("type", "array")
                                putJsonObject("items") { put("type", "string") }
                                put(
                                    "description",
                                    "Not enforced — Montoya's built-in audit cannot be restricted by insertion point type",
                                )
                            }
                            putJsonObject("auth_header_name") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Name of a header to set on the audit's requests, e.g. Authorization or Cookie. Needs auth_header_value",
                                )
                            }
                            putJsonObject("auth_header_value") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Value of that header. For Cookie, name=value pairs separated by ';': each replaces that cookie and the rest of the request's Cookie header stays",
                                )
                            }
                        },
                    required = emptyList(),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val urls = args["urls"].asStringList()
                val requests = args["requests"].asStringList()
                if (urls.isNullOrEmpty() && requests.isNullOrEmpty()) {
                    return@addTool toolError(
                        "At least one of 'urls' or 'requests' must be provided",
                    )
                }

                toolJsonResult(
                    bridge.startAudit(
                        urls = urls,
                        requests = requests,
                        auditMode = args.text("audit_mode"),
                        crawlFirst = args.flag("crawl_first") ?: true,
                        insertionPointTypes = args["insertion_point_types"].asStringList(),
                        authHeaderName = args.text("auth_header_name"),
                        authHeaderValue = args.text("auth_header_value"),
                    ),
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 3. scanner_task_status
        // ---------------------------------------------------------------
        server.addTool(
            name = "scanner_task_status",
            description =
                "Get the current status of a scanner task including request count, error count, and issue count. " +
                    "For an audit started with an auth header it also says whether the auth rule is still in place.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("task_id") {
                                put("type", "string")
                                put("description", "Scanner task ID")
                            }
                        },
                    required = listOf("task_id"),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val taskId =
                    args.text("task_id")
                        ?: return@addTool toolError("Parameter 'task_id' is required")

                toolJsonResult(bridge.getTaskStatus(taskId))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 4. scanner_task_list
        // ---------------------------------------------------------------
        server.addTool(
            name = "scanner_task_list",
            description =
                "List all scanner tasks (crawl and audit), optionally filtered by status.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("status") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Keep tasks whose status message contains this text (case-insensitive)",
                                )
                            }
                        },
                    required = emptyList(),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val tasks = bridge.listTasks(args.text("status"))

                toolJsonResult(
                    buildJsonObject {
                        put("task_count", tasks.size)
                        put("tasks", tasks)
                    },
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 5. scanner_task_delete
        // ---------------------------------------------------------------
        server.addTool(
            name = "scanner_task_delete",
            description =
                "Cancel and delete a scanner task by its task ID. An audit's auth header rule is removed with it.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("task_id") {
                                put("type", "string")
                                put("description", "Scanner task ID")
                            }
                        },
                    required = listOf("task_id"),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val taskId =
                    args.text("task_id")
                        ?: return@addTool toolError("Parameter 'task_id' is required")

                toolJsonResult(bridge.deleteTask(taskId))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 6. scanner_task_add_request
        // ---------------------------------------------------------------
        server.addTool(
            name = "scanner_task_add_request",
            description =
                "Add an HTTP request to an existing audit task for scanning. The request must be base64-encoded. " +
                    "An auth header the audit was started with stays limited to the hosts it started with. " +
                    ScopeGate.ADVISORY_NOTE,
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("task_id") {
                                put("type", "string")
                                put("description", "Audit task ID")
                            }
                            putJsonObject("request") {
                                put("type", "string")
                                put("description", "Base64-encoded HTTP request")
                            }
                            putJsonObject("host") {
                                put("type", "string")
                                put("description", "Target host")
                            }
                            putJsonObject("port") {
                                put("type", "integer")
                                put("minimum", 1)
                                put("maximum", 65535)
                                put(
                                    "description",
                                    "Target port (default 443 with use_tls, else 80)",
                                )
                            }
                            putJsonObject("use_tls") {
                                put("type", "boolean")
                                put("description", "Use TLS for the request")
                            }
                        },
                    required = listOf("task_id", "request"),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val taskId =
                    args.text("task_id")
                        ?: return@addTool toolError("Parameter 'task_id' is required")
                val reqData =
                    args.text("request")
                        ?: return@addTool toolError(
                            "Parameter 'request' is required (base64-encoded HTTP request)",
                        )

                toolJsonResult(
                    bridge.addRequestToTask(
                        taskId,
                        reqData,
                        args.text("host"),
                        args.int("port", 1..65535),
                        args.flag("use_tls"),
                    ),
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 7. scanner_task_issues
        // ---------------------------------------------------------------
        server.addTool(
            name = "scanner_task_issues",
            description =
                "Get all issues found by a specific audit task. On a Burp version that cannot list a task's issues, " +
                    "the result holds the site map's issues under the task's targets instead and is marked \"source\": \"site_map\".",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("task_id") {
                                put("type", "string")
                                put("description", "Audit task ID")
                            }
                        },
                    required = listOf("task_id"),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val taskId =
                    args.text("task_id")
                        ?: return@addTool toolError("Parameter 'task_id' is required")

                toolJsonResult(bridge.getTaskIssues(taskId))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 8. scanner_get_all_issues
        // ---------------------------------------------------------------
        server.addTool(
            name = "scanner_get_all_issues",
            description =
                "Get all scanner issues from the site map with optional filtering by URL prefix, severity, and confidence.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("url_prefix") {
                                put("type", "string")
                                put("description", "URL prefix filter")
                            }
                            enumProperty("severity", SEVERITIES, "Issue severity")
                            enumProperty("confidence", CONFIDENCES, "Issue confidence")
                            putJsonObject("max_results") {
                                put("type", "integer")
                                put("minimum", 1)
                                put(
                                    "description",
                                    "Maximum number of issues to return (default: all); a value below 1 is clamped to 1 and reported as max_results_clamped_to",
                                )
                            }
                        },
                    required = emptyList(),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val maxResults =
                    args["max_results"].asClampedInt("max_results", 1, Int.MAX_VALUE).getOrElse {
                        return@addTool toolError(it.message ?: "Invalid max_results")
                    }

                toolJsonResult(
                    bridge
                        .getAllIssues(
                            args.text("url_prefix"),
                            args.text("severity"),
                            args.text("confidence"),
                            maxResults?.value,
                        )
                        .withClampReport("max_results", maxResults),
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 9. scanner_generate_report
        // ---------------------------------------------------------------
        server.addTool(
            name = "scanner_generate_report",
            description =
                "Generate a scan report in HTML or XML format. Can filter by URL prefix and severity levels. Pro edition only.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            enumProperty(
                                "format",
                                listOf("HTML", "XML"),
                                "Report format (default HTML)",
                            )
                            putJsonObject("output_path") {
                                put("type", "string")
                                put("description", "Report output filename")
                            }
                            putJsonObject("url_prefix") {
                                put("type", "string")
                                put("description", "URL prefix filter")
                            }
                            putJsonObject("severity_filter") {
                                put("type", "array")
                                putJsonObject("items") {
                                    put("type", "string")
                                    putJsonArray("enum") { SEVERITIES.forEach { add(it) } }
                                }
                                put("description", "Severities to include (default: all)")
                            }
                        },
                    required = listOf("output_path"),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val outputPath =
                    args.text("output_path")
                        ?: return@addTool toolError("Parameter 'output_path' is required")

                toolJsonResult(
                    bridge.generateReport(
                        args.text("format") ?: "HTML",
                        args.text("url_prefix"),
                        args["severity_filter"].asStringList(),
                        outputPath,
                    ),
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 10. scanner_create_issue
        // ---------------------------------------------------------------
        server.addTool(
            name = "scanner_create_issue",
            description =
                "Create a custom audit issue and add it to the site map. Useful for manual findings or integration with external tools.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("name") {
                                put("type", "string")
                                put("description", "Issue name")
                            }
                            putJsonObject("detail") {
                                put("type", "string")
                                put("description", "Detailed issue description")
                            }
                            putJsonObject("remediation") {
                                put("type", "string")
                                put("description", "Remediation guidance")
                            }
                            enumProperty("severity", SEVERITIES, "Issue severity")
                            enumProperty("confidence", CONFIDENCES, "Issue confidence")
                            putJsonObject("url") {
                                put("type", "string")
                                put("description", "Affected URL")
                            }
                            putJsonObject("request") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Associated HTTP request as plain text (base64 also accepted). Must be paired with 'response' to attach evidence.",
                                )
                            }
                            putJsonObject("response") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Associated HTTP response as plain text (base64 also accepted). Must be paired with 'request' to attach evidence.",
                                )
                            }
                        },
                    required = listOf("name", "url"),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val name =
                    args.text("name") ?: return@addTool toolError("Parameter 'name' is required")
                val url =
                    args.text("url") ?: return@addTool toolError("Parameter 'url' is required")

                toolJsonResult(
                    bridge.createCustomIssue(
                        name,
                        args.text("detail"),
                        args.text("remediation"),
                        args.text("severity") ?: "information",
                        args.text("confidence") ?: "tentative",
                        url,
                        args.text("request"),
                        args.text("response"),
                    ),
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 11. scanner_import_bcheck
        // ---------------------------------------------------------------
        server.addTool(
            name = "scanner_import_bcheck",
            description =
                "Import a BCheck script into the Burp Suite scanner. BChecks define custom scan checks in Burp's domain-specific language. Pro edition only.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("script") {
                                put("type", "string")
                                put("description", "BCheck script content")
                            }
                        },
                    required = listOf("script"),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val script =
                    args.text("script")
                        ?: return@addTool toolError(
                            "Parameter 'script' is required (BCheck script content)",
                        )

                toolJsonResult(bridge.importBCheck(script))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 12. scanner_register_check
        // ---------------------------------------------------------------
        server.addTool(
            name = "scanner_register_check",
            description =
                "Register a custom scan check (passive or active) that matches response content and reports issues. " +
                    "Passive checks report when passive_response_match (body) or passive_header_match (headers) matches. " +
                    "Active checks inject each payload at every insertion point and report when active_response_match matches the " +
                    "response to a payload but not the response to the unmodified request. Registering a check_name again replaces " +
                    "that check. Regexes are case-insensitive and validated here. Pro edition only.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("check_name") {
                                put("type", "string")
                                put("description", "Name of the scan check")
                            }
                            enumProperty(
                                "check_type",
                                ScannerBridge.CHECK_TYPES,
                                "Which part to run (default passive). both: passive and active, each needing its own parameters",
                            )
                            putJsonObject("issue_name") {
                                put("type", "string")
                                put("description", "Name of the reported issue")
                            }
                            enumProperty(
                                "issue_severity",
                                SEVERITIES,
                                "Issue severity (default information)",
                            )
                            enumProperty(
                                "issue_confidence",
                                CONFIDENCES,
                                "Issue confidence (default tentative)",
                            )
                            putJsonObject("issue_detail") {
                                put("type", "string")
                                put("description", "Detailed issue description")
                            }
                            putJsonObject("issue_remediation") {
                                put("type", "string")
                                put("description", "Remediation guidance")
                            }
                            putJsonObject("passive_response_match") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Regex matched against response body for passive checks",
                                )
                            }
                            putJsonObject("passive_header_match") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Regex matched against response headers for passive checks",
                                )
                            }
                            putJsonObject("active_payloads") {
                                put("type", "array")
                                putJsonObject("items") { put("type", "string") }
                                put("description", "Payloads to inject for active checks")
                            }
                            putJsonObject("active_response_match") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Regex the response body must match after injection, and must not match before it",
                                )
                            }
                            putJsonObject("active_grep_match") {
                                put("type", "string")
                                put("description", "Alias for active_response_match")
                            }
                        },
                    required = listOf("check_name", "issue_name"),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val checkName =
                    args.text("check_name")
                        ?: return@addTool toolError("Parameter 'check_name' is required")
                val issueName =
                    args.text("issue_name")
                        ?: return@addTool toolError("Parameter 'issue_name' is required")

                toolJsonResult(
                    bridge.registerScanCheck(
                        checkName = checkName,
                        checkType = args.text("check_type") ?: "passive",
                        issueName = issueName,
                        severity = args.text("issue_severity") ?: "information",
                        confidence = args.text("issue_confidence") ?: "tentative",
                        detail = args.text("issue_detail") ?: "",
                        remediation = args.text("issue_remediation") ?: "",
                        passiveResponseMatch = args.text("passive_response_match"),
                        passiveHeaderMatch = args.text("passive_header_match"),
                        activePayloads = args["active_payloads"].asStringList(),
                        // active_grep_match is accepted as an alias for active_response_match
                        activeResponseMatch =
                            args.text("active_response_match") ?: args.text("active_grep_match"),
                    ),
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // 13. scanner_unregister_check
        // ---------------------------------------------------------------
        server.addTool(
            name = "scanner_unregister_check",
            description =
                "Deregister a custom scan check previously created with scanner_register_check, " +
                    "removing it from Burp's scanner. Pro edition only.",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("check_name") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Name of the scan check to remove (as used when registering)",
                                )
                            }
                        },
                    required = listOf("check_name"),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val checkName =
                    args.text("check_name")
                        ?: return@addTool toolError("Parameter 'check_name' is required")

                toolJsonResult(bridge.unregisterScanCheck(checkName))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }
}

/** Adds a string property whose value must be one of [values]. */
private fun JsonObjectBuilder.enumProperty(
    name: String,
    values: Collection<String>,
    description: String,
) {
    putJsonObject(name) {
        put("type", "string")
        putJsonArray("enum") { values.forEach { add(it) } }
        put("description", description)
    }
}

private fun Map<String, JsonElement>.text(name: String): String? =
    (this[name] as? JsonPrimitive)?.contentOrNull

private fun Map<String, JsonElement>.flag(name: String): Boolean? =
    (this[name] as? JsonPrimitive)?.booleanOrNull

/**
 * An optional integer argument that has to lie in [range].
 *
 * @throws IllegalArgumentException naming the parameter, for the handler to report.
 */
private fun Map<String, JsonElement>.int(name: String, range: IntRange): Int? {
    val raw = this[name]?.takeUnless { it is JsonNull } ?: return null
    val value =
        raw.asLongSafe() ?: throw IllegalArgumentException("Parameter '$name' must be an integer")
    require(value in range.first.toLong()..range.last.toLong()) {
        "Parameter '$name' must be between ${range.first} and ${range.last}"
    }
    return value.toInt()
}
