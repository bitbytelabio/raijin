package io.bitbytelab.raijin.tools.turbo

import io.bitbytelab.raijin.bridge.TurboBridge
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
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

    private fun obj(vararg props: Pair<String, Pair<String, String>>) = buildJsonObject {
        props.forEach { (name, typeAndDesc) ->
            putJsonObject(name) { put("type", typeAndDesc.first); put("description", typeAndDesc.second) }
        }
    }

    private fun ok(value: Any?) = CallToolResult(content = listOf(TextContent(TurboBridge.toJson(value).toString())))

    private fun err(message: String) = CallToolResult(
        content = listOf(TextContent(buildJsonObject { put("error", message) }.toString())),
        isError = true
    )

    private fun CallToolRequest.str(name: String): String? = params.arguments?.get(name)?.jsonPrimitive?.contentOrNull
    private fun CallToolRequest.int(name: String): Int? = params.arguments?.get(name)?.jsonPrimitive?.intOrNull
    private fun CallToolRequest.long(name: String): Long? = params.arguments?.get(name)?.jsonPrimitive?.longOrNull
    private fun CallToolRequest.bool(name: String): Boolean? = params.arguments?.get(name)?.jsonPrimitive?.booleanOrNull

    /** Runs [block] off the MCP dispatcher (handlers block on the engine) and maps failures to tool errors. */
    private suspend fun guarded(block: () -> Any?): CallToolResult = try {
        ok(withContext(Dispatchers.IO) { block() })
    } catch (e: Exception) {
        err(e.message ?: e.toString())
    }

    fun register(server: Server, bridge: TurboBridge) {

        server.addTool(
            name = "turbo_start_run",
            description = "Start a Raijin Turbo run: a Python script driving the Turbo request engine (single-packet " +
                "attack, HTTP/2 + HTTP/3 gates, high-concurrency sends, desync probes). Blocks until the run completes " +
                "or timeout_ms, then returns the top results by anomaly rank (or a run_id to poll with turbo_run_status). " +
                "Read turbo_get_docs('api-quickstart') and turbo_list_examples first. Requires the user to enable " +
                "'Allow MCP clients to run Turbo scripts' in Burp's settings.",
            inputSchema = ToolSchema(
                properties = obj(
                    "script" to ("string" to "Python script code that controls the run (defines queueRequests(target, wordlists))"),
                    "base_request" to ("string" to "Base HTTP request template; mark injection points with %s"),
                    "endpoint" to ("string" to "Target endpoint URL, e.g. https://example.com"),
                    "base_input" to ("string" to "Input data fed to the script (e.g. wordlist content)"),
                    "timeout_ms" to ("integer" to "How long to wait, default 55000. After that the run keeps going and a run_id is returned."),
                    "normalize_line_endings" to ("boolean" to "Normalize mixed \\n and \\r\\n to \\r\\n. Default true."),
                ),
                required = listOf("script", "base_request", "endpoint")
            )
        ) { req ->
            if (!bridge.runsAllowed()) return@addTool err(TurboBridge.RUNS_DISABLED_MESSAGE)
            guarded {
                bridge.tools.startRun(
                    script = req.str("script") ?: "",
                    baseRequest = req.str("base_request") ?: "",
                    endpoint = req.str("endpoint") ?: "",
                    baseInput = req.str("base_input") ?: "",
                    timeoutMs = req.long("timeout_ms") ?: 55000,
                    normalizeLineEndings = req.bool("normalize_line_endings") ?: true
                )
            }
        }

        server.addTool(
            name = "turbo_stop_run",
            description = "Stop a Turbo run. Aborts it but keeps the results.",
            inputSchema = ToolSchema(properties = obj("run_id" to ("string" to "Run id")), required = listOf("run_id"))
        ) { req ->
            guarded { bridge.tools.stopRun(req.str("run_id") ?: "") }
        }

        server.addTool(
            name = "turbo_delete_run",
            description = "Delete a Turbo run and all its results. Also stops it if it is still executing.",
            inputSchema = ToolSchema(properties = obj("run_id" to ("string" to "Run id")), required = listOf("run_id"))
        ) { req ->
            guarded { bridge.tools.deleteRun(req.str("run_id") ?: "") }
        }

        server.addTool(
            name = "turbo_run_status",
            description = "Status of a Turbo run: running state, result count, fails (requests that got no response) and " +
                "status message. Set wait=true to long-poll until the run completes (up to 50 s).",
            inputSchema = ToolSchema(
                properties = obj(
                    "run_id" to ("string" to "Run id"),
                    "wait" to ("boolean" to "Long-poll until the run completes (up to 50 s). Default false."),
                ),
                required = listOf("run_id")
            )
        ) { req ->
            guarded { bridge.resources.getRunStatus(req.str("run_id") ?: "", if (req.bool("wait") == true) 50_000L else 0L) }
        }

        server.addTool(
            name = "turbo_run_results",
            description = "Paginated results of a Turbo run. Timing: ttfb = time to first byte, ttlb = time to last byte " +
                "(microseconds). sort_by: id|status|length|ttfb|ttlb|wordcount|anomaly_rank.",
            inputSchema = ToolSchema(
                properties = obj(
                    "run_id" to ("string" to "Run id"),
                    "sort_by" to ("string" to "Sort field, default id"),
                    "descending" to ("boolean" to "Default true"),
                    "limit" to ("integer" to "Default 100"),
                    "offset" to ("integer" to "Default 0"),
                ),
                required = listOf("run_id")
            )
        ) { req ->
            guarded {
                bridge.resources.getResults(
                    runId = req.str("run_id") ?: "",
                    sortBy = req.str("sort_by") ?: "id",
                    descending = req.bool("descending") ?: true,
                    limit = req.int("limit") ?: 100,
                    offset = req.int("offset") ?: 0
                )
            }
        }

        server.addTool(
            name = "turbo_run_result",
            description = "Full request and response of one result of a Turbo run. Response bodies are truncated to " +
                "body_limit lines; set export=true to write the complete exchange to a file instead.",
            inputSchema = ToolSchema(
                properties = obj(
                    "run_id" to ("string" to "Run id"),
                    "id" to ("integer" to "Result id (from turbo_run_results)"),
                    "body_limit" to ("integer" to "Max body lines, default 100"),
                    "export" to ("boolean" to "Export the full exchange to a file. Default false."),
                ),
                required = listOf("run_id", "id")
            )
        ) { req ->
            val id = req.int("id") ?: return@addTool err("Missing required parameter: id")
            guarded {
                bridge.resources.getRequestDetail(
                    runId = req.str("run_id") ?: "",
                    requestId = id,
                    bodyLimit = req.int("body_limit") ?: 100,
                    exportFile = req.bool("export") ?: false
                )
            }
        }

        server.addTool(
            name = "turbo_run_script",
            description = "The Python script a Turbo run was started with.",
            inputSchema = ToolSchema(properties = obj("run_id" to ("string" to "Run id")), required = listOf("run_id"))
        ) { req ->
            guarded { bridge.resources.getRunScript(req.str("run_id") ?: "") }
        }

        server.addTool(
            name = "turbo_search_responses",
            description = "Search the responses (or labels) of a Turbo run for a substring; returns matching result ids.",
            inputSchema = ToolSchema(
                properties = obj(
                    "run_id" to ("string" to "Run id"),
                    "query" to ("string" to "Substring to look for"),
                    "search_in" to ("string" to "responses | labels | all (default)"),
                ),
                required = listOf("run_id", "query")
            )
        ) { req ->
            guarded { bridge.tools.searchResponses(req.str("run_id") ?: "", req.str("query") ?: "", req.str("search_in") ?: "all") }
        }

        server.addTool(
            name = "turbo_save_to_organizer",
            description = "Save results from a Turbo run to Burp's Organizer with notes (the run id and script are appended to the notes).",
            inputSchema = ToolSchema(
                properties = obj(
                    "run_id" to ("string" to "Run id"),
                    "items" to ("string" to "JSON array of {\"request_id\": int, \"notes\": string}"),
                ),
                required = listOf("run_id", "items")
            )
        ) { req ->
            guarded { bridge.tools.saveToOrganizer(req.str("run_id") ?: "", req.str("items") ?: "[]") }
        }

        server.addTool(
            name = "turbo_get_docs",
            description = "Documentation for writing Turbo scripts. Call with no topic to list topics " +
                "(api-quickstart, engines, settings, race-conditions, response-processing, decorators, misc).",
            inputSchema = ToolSchema(properties = obj("topic" to ("string" to "Doc topic; omit to list")))
        ) { req ->
            val topic = req.str("topic")
            guarded {
                if (topic.isNullOrBlank()) mapOf("topics" to bridge.resources.docTopics)
                else bridge.resources.getDoc(topic)
            }
        }

        server.addTool(
            name = "turbo_list_examples",
            description = "List the example Turbo scripts (race conditions, HTTP/2, HTTP/3, desync, rate limits, ...).",
            inputSchema = ToolSchema(properties = buildJsonObject {})
        ) {
            guarded { bridge.resources.listExamples() }
        }

        server.addTool(
            name = "turbo_get_example",
            description = "Source of an example Turbo script by name (see turbo_list_examples).",
            inputSchema = ToolSchema(properties = obj("name" to ("string" to "Example name, e.g. race-single-packet-attack")), required = listOf("name"))
        ) { req ->
            guarded { bridge.resources.getExample(req.str("name") ?: "") }
        }
    }
}
