package io.bitbytelab.raijin.tools.turbo

import io.bitbytelab.raijin.bridge.TurboBridge
import io.bitbytelab.raijin.core.ClampedInt
import io.bitbytelab.raijin.core.EnumValidation
import io.bitbytelab.raijin.core.asBodyString
import io.bitbytelab.raijin.core.asBooleanSafe
import io.bitbytelab.raijin.core.asClampedInt
import io.bitbytelab.raijin.core.asIntSafe
import io.bitbytelab.raijin.core.asLongSafe
import io.bitbytelab.raijin.core.withClampReport
import io.bitbytelab.raijin.safety.ScopeGate
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.bitbytelab.raijin.turbo.mcp.McpResourceHandlers
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runInterruptible
import kotlinx.serialization.json.*

/**
 * Raijin Turbo tools. Use these for high-volume or timing-critical traffic (single-packet
 * race conditions, HTTP/2 and HTTP/3 gates, desync work); for ordinary requests prefer the
 * `http_*` tools, which are quicker to set up.
 *
 * A *run* is a Python script executed by the Turbo engine. `turbo_start_run` blocks until the
 * run finishes (or 55 s), then returns the 100 most anomalous results; poll longer runs with
 * `turbo_run_status`.
 */
object TurboTools {

    private val SEARCH_IN = listOf("responses", "labels", "all")

    private fun prop(type: String, description: String, enum: List<String>? = null) = buildJsonObject {
        put("type", type)
        put("description", description)
        if (enum != null) putJsonArray("enum") { enum.forEach { add(it) } }
    }

    private fun obj(vararg props: Pair<String, JsonObject>) = buildJsonObject {
        props.forEach { (name, schema) -> put(name, schema) }
    }

    private fun CallToolRequest.arg(name: String): JsonElement? = params.arguments?.get(name)
    private fun CallToolRequest.str(name: String): String? = (arg(name) as? JsonPrimitive)?.contentOrNull
    private fun CallToolRequest.int(name: String): Int? = arg(name).asIntSafe()
    private fun CallToolRequest.long(name: String): Long? = arg(name).asLongSafe()
    private fun CallToolRequest.bool(name: String): Boolean? = arg(name).asBooleanSafe()

    /** A required string argument, or a tool error naming it when it is absent or blank. */
    private inline fun CallToolRequest.required(name: String, onMissing: (CallToolResult) -> Nothing): String =
        str(name)?.takeIf { it.isNotBlank() } ?: onMissing(toolError("Missing required parameter: $name"))

    /**
     * Runs [block] off the MCP dispatcher (handlers block on the engine) and maps failures to tool
     * errors. A handler result carrying an `error` key comes back flagged as an error. A cancelled
     * call interrupts the blocking wait, which then answers with the run's state as it is.
     * [clamps] are reported on the result (`<name>_clamped_to`).
     */
    private suspend fun guarded(vararg clamps: Pair<String, ClampedInt?>, block: () -> Any?): CallToolResult = try {
        var json = TurboBridge.toJson(runInterruptible(Dispatchers.IO) { block() })
        if (json is JsonObject) clamps.forEach { (name, arg) -> json = (json as JsonObject).withClampReport(name, arg) }
        toolJsonResult(json)
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        toolError(e.message ?: e.toString())
    }

    /** An integer argument clamped into [min]..[max], or a tool error for a value that is not an integer. */
    private inline fun CallToolRequest.clamped(name: String, min: Int, max: Int, onError: (CallToolResult) -> Nothing): ClampedInt? =
        arg(name).asClampedInt(name, min, max).getOrElse { onError(toolError(it.message ?: "Parameter '$name' must be an integer")) }

    fun register(server: Server, bridge: TurboBridge) {
        val runId = "run_id" to prop("string", "Run id")

        server.addTool(
            name = "turbo_start_run",
            description = "Start a Raijin Turbo run: a Python script driving the Turbo request engine (single-packet " +
                "attack, HTTP/2 + HTTP/3 gates, high-concurrency sends, desync probes). Blocks until the run completes " +
                "or timeout_ms, then returns the top results by anomaly rank (or a run_id to poll with turbo_run_status). " +
                "Read turbo_get_docs('api-quickstart') and turbo_list_examples first. A callback that raises is counted in " +
                "callback_errors (last_callback_error), not in fails. " + ScopeGate.ADVISORY_NOTE +
                " The endpoint is checked at start, and every other origin the script queues to once (scope_warnings).",
            inputSchema = ToolSchema(
                properties = obj(
                    "script" to prop("string", "Python script code that controls the run (defines queueRequests(target, wordlists))"),
                    "base_request" to prop("string", "Base HTTP request template; mark injection points with %s"),
                    "endpoint" to prop("string", "Target endpoint URL, e.g. https://example.com"),
                    "base_input" to prop("string", "Input data fed to the script (e.g. wordlist content)"),
                    "timeout_ms" to prop("integer", "How long to wait, default 55000 (1-600000, clamped and reported). After that the run keeps going and a run_id is returned."),
                    "normalize_line_endings" to prop("boolean", "Normalize mixed \\n and \\r\\n to \\r\\n. Default true."),
                ),
                required = listOf("script", "base_request", "endpoint")
            )
        ) { req ->
            val script = req.required("script") { return@addTool it }
            val endpoint = req.required("endpoint") { return@addTool it }
            val timeout = req.clamped("timeout_ms", 1, 600_000) { return@addTool it }
            guarded("timeout_ms" to timeout) {
                bridge.tools.startRun(
                    script = script,
                    baseRequest = req.arg("base_request").asBodyString() ?: "",
                    endpoint = endpoint,
                    baseInput = req.arg("base_input").asBodyString() ?: "",
                    timeoutMs = (timeout?.value ?: 55_000).toLong(),
                    normalizeLineEndings = req.bool("normalize_line_endings") ?: true
                )
            }
        }

        server.addTool(
            name = "turbo_stop_run",
            description = "Stop a Turbo run. Aborts it but keeps the results.",
            inputSchema = ToolSchema(properties = obj(runId), required = listOf("run_id"))
        ) { req ->
            val id = req.required("run_id") { return@addTool it }
            guarded { bridge.tools.stopRun(id) }
        }

        server.addTool(
            name = "turbo_delete_run",
            description = "Delete a Turbo run and all its results. Also stops it if it is still executing.",
            inputSchema = ToolSchema(properties = obj(runId), required = listOf("run_id"))
        ) { req ->
            val id = req.required("run_id") { return@addTool it }
            guarded { bridge.tools.deleteRun(id) }
        }

        server.addTool(
            name = "turbo_start_run_async",
            description = "Start a Turbo run and return immediately with a run_id, without blocking. Use this instead " +
                "of turbo_start_run when the run may take longer than your own call timeout. Poll with " +
                "turbo_run_status (optionally wait=true) or turbo_list_runs to recover the run_id later. " + ScopeGate.ADVISORY_NOTE,
            inputSchema = ToolSchema(
                properties = obj(
                    "script" to prop("string", "Python script code that controls the run (defines queueRequests(target, wordlists))"),
                    "base_request" to prop("string", "Base HTTP request template; mark injection points with %s"),
                    "endpoint" to prop("string", "Target endpoint URL, e.g. https://example.com"),
                    "base_input" to prop("string", "Input data fed to the script (e.g. wordlist content)"),
                    "normalize_line_endings" to prop("boolean", "Normalize mixed \\n and \\r\\n to \\r\\n. Default true."),
                ),
                required = listOf("script", "base_request", "endpoint")
            )
        ) { req ->
            val script = req.required("script") { return@addTool it }
            val endpoint = req.required("endpoint") { return@addTool it }
            guarded {
                bridge.tools.startRunAsync(
                    script = script,
                    baseRequest = req.arg("base_request").asBodyString() ?: "",
                    endpoint = endpoint,
                    baseInput = req.arg("base_input").asBodyString() ?: "",
                    normalizeLineEndings = req.bool("normalize_line_endings") ?: true
                )
            }
        }

        server.addTool(
            name = "turbo_list_runs",
            description = "List all known Turbo runs (this MCP session and the GUI), newest first, with " +
                "status/result_count/fails/created_at/source. Use this to recover a run_id you lost track of, " +
                "e.g. after turbo_start_run's blocking window elapsed, or to find and stop an orphaned run.",
            inputSchema = ToolSchema(properties = obj(), required = emptyList())
        ) { _ ->
            guarded { bridge.tools.listRuns() }
        }

        server.addTool(
            name = "turbo_run_status",
            description = "Status of a Turbo run: running state, result count, fails (requests that got no response) and " +
                "status message. Set wait=true to long-poll until the run completes (up to 50 s).",
            inputSchema = ToolSchema(
                properties = obj(
                    runId,
                    "wait" to prop("boolean", "Long-poll until the run completes (up to 50 s). Default false."),
                ),
                required = listOf("run_id")
            )
        ) { req ->
            val id = req.required("run_id") { return@addTool it }
            guarded { bridge.resources.getRunStatus(id, if (req.bool("wait") == true) 50_000L else 0L) }
        }

        server.addTool(
            name = "turbo_run_results",
            description = "Paginated results of a Turbo run. Timing: ttfb = time to first byte, ttlb = time to last byte " +
                "(microseconds). Without sort_by, results follow the order the script set with table.setSortOrder(...), " +
                "else id (arrival order). The response names the sort_by and descending it applied.",
            inputSchema = ToolSchema(
                properties = obj(
                    runId,
                    "sort_by" to prop(
                        "string",
                        "Sort field. Default: the script's table.setSortOrder order, else id",
                        McpResourceHandlers.SORT_FIELDS
                    ),
                    "descending" to prop("boolean", "Default: the script's sort direction, else true"),
                    "limit" to prop("integer", "Default 100 (1-1000, clamped and reported)"),
                    "offset" to prop("integer", "Default 0"),
                ),
                required = listOf("run_id")
            )
        ) { req ->
            val id = req.required("run_id") { return@addTool it }
            val limit = req.clamped("limit", 1, 1000) { return@addTool it }
            guarded("limit" to limit) {
                bridge.resources.getResults(
                    runId = id,
                    sortBy = req.str("sort_by"),
                    descending = req.bool("descending"),
                    limit = limit?.value ?: 100,
                    offset = req.int("offset") ?: 0
                )
            }
        }

        server.addTool(
            name = "turbo_run_result",
            description = "Full request and response of one result of a Turbo run. The response body is cut to its " +
                "first body_limit lines and at most 200,000 characters (response_body_truncated, " +
                "response_body_total_lines and response_body_total_length describe the whole body); " +
                "body_limit=0 returns it whole, and export=true writes the complete exchange to files instead.",
            inputSchema = ToolSchema(
                properties = obj(
                    runId,
                    "id" to prop("integer", "Result id (from turbo_run_results)"),
                    "body_limit" to prop("integer", "Max response body lines, default 100; 0 returns the whole body"),
                    "export" to prop("boolean", "Export the full exchange to files. Default false."),
                ),
                required = listOf("run_id", "id")
            )
        ) { req ->
            val run = req.required("run_id") { return@addTool it }
            val id = req.int("id") ?: return@addTool toolError("Missing required parameter: id (an integer)")
            guarded {
                bridge.resources.getRequestDetail(
                    runId = run,
                    requestId = id,
                    bodyLimit = (req.int("body_limit") ?: 100).coerceAtLeast(0),
                    exportFile = req.bool("export") ?: false
                )
            }
        }

        server.addTool(
            name = "turbo_run_script",
            description = "The Python script a Turbo run was started with.",
            inputSchema = ToolSchema(properties = obj(runId), required = listOf("run_id"))
        ) { req ->
            val id = req.required("run_id") { return@addTool it }
            guarded { bridge.resources.getRunScript(id) }
        }

        server.addTool(
            name = "turbo_search_responses",
            description = "Search the responses (or labels) of a Turbo run for a substring; returns matching result ids.",
            inputSchema = ToolSchema(
                properties = obj(
                    runId,
                    "query" to prop("string", "Substring to look for"),
                    "search_in" to prop("string", "Where to look (default all)", SEARCH_IN),
                ),
                required = listOf("run_id", "query")
            )
        ) { req ->
            val id = req.required("run_id") { return@addTool it }
            val query = req.str("query")?.takeIf { it.isNotEmpty() }
                ?: return@addTool toolError("Missing required parameter: query")
            val searchIn = req.str("search_in")?.trim()?.lowercase()?.takeIf { it.isNotEmpty() } ?: "all"
            EnumValidation.error(searchIn, SEARCH_IN.toSet(), "search_in")?.let { return@addTool toolJsonResult(it) }
            guarded { bridge.tools.searchResponses(id, query, searchIn) }
        }

        server.addTool(
            name = "turbo_save_to_organizer",
            description = "Save results from a Turbo run to Burp's Organizer with notes (the run id and script are appended to the notes).",
            inputSchema = ToolSchema(
                properties = obj(
                    runId,
                    "items" to prop("string", "JSON array of {\"request_id\": int, \"notes\": string}"),
                ),
                required = listOf("run_id", "items")
            )
        ) { req ->
            val id = req.required("run_id") { return@addTool it }
            // An agent may pass the array itself rather than its JSON text; both mean the same.
            val items = req.arg("items").asBodyString()?.takeIf { it.isNotBlank() }
                ?: return@addTool toolError("Missing required parameter: items")
            guarded { bridge.tools.saveToOrganizer(id, items) }
        }

        server.addTool(
            name = "turbo_get_docs",
            description = "Documentation for writing Turbo scripts. Call with no topic to list the topics and what " +
                "each covers; start with index or api-quickstart.",
            inputSchema = ToolSchema(
                properties = obj(
                    "topic" to prop("string", "Doc topic; omit to list", bridge.resources.docTopics.keys.toList())
                )
            )
        ) { req ->
            val topic = req.str("topic")?.trim()
            guarded {
                if (topic.isNullOrEmpty()) mapOf("topics" to bridge.resources.docTopics)
                else bridge.resources.getDoc(topic)
            }
        }

        server.addTool(
            name = "turbo_list_examples",
            description = "List the example Turbo scripts (race conditions, HTTP/2, HTTP/3, desync, rate limits, ...).",
            inputSchema = ToolSchema(properties = obj())
        ) {
            guarded { bridge.resources.listExamples() }
        }

        server.addTool(
            name = "turbo_get_example",
            description = "Source of an example Turbo script by name (see turbo_list_examples).",
            inputSchema = ToolSchema(
                properties = obj(
                    "name" to prop("string", "Example name, e.g. race-single-packet-attack", bridge.resources.exampleNames)
                ),
                required = listOf("name")
            )
        ) { req ->
            val name = req.required("name") { return@addTool it }
            guarded { bridge.resources.getExample(name.trim()) }
        }
    }
}
