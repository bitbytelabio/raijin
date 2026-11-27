package io.bitbytelab.raijin.tools.analysis

import io.bitbytelab.raijin.bridge.AnalysisBridge
import io.bitbytelab.raijin.bridge.BridgeFactory
import io.bitbytelab.raijin.core.EnumValidation
import io.bitbytelab.raijin.core.asBooleanSafe
import io.bitbytelab.raijin.core.asBoundedInt
import io.bitbytelab.raijin.core.asClampedInt
import io.bitbytelab.raijin.core.asStringList
import io.bitbytelab.raijin.core.withClampReport
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object AnalysisTools {

    private val DIFF_TYPES = listOf("request", "response")

    fun register(server: Server, bridges: BridgeFactory.Bridges) = register(server, bridges.analysis)

    fun register(server: Server, analysis: AnalysisBridge) {
        // 1. analyze_request
        server.addTool(
            name = "analyze_request",
            description = "Parse and analyze a raw HTTP request. Returns the method, URL, path, " +
                "headers, cookies, parameters (URL, body, cookie), body content, and content type. " +
                "Parameters: request (string, the raw HTTP request to analyze).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("request") { put("type", "string"); put("description", "The raw HTTP request to analyze") }
                },
                required = listOf("request")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val rawRequest = args.string("request")
                    ?: return@addTool toolError("Missing required parameter: request")
                toolJsonResult(analysis.analyzeRequest(rawRequest))
            } catch (e: Exception) {
                toolError(
                    "'request' could not be read as a raw HTTP request (${e.message ?: e.javaClass.simpleName}); " +
                        "send the request line, headers and a blank line, e.g. \"GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n\""
                )
            }
        }

        // 2. analyze_response
        server.addTool(
            name = "analyze_response",
            description = "Parse and analyze a raw HTTP response. Returns the status code, reason " +
                "phrase, headers, cookies (with domain, path, expiration), body, stated and " +
                "inferred MIME types. Parameters: response (string, the raw HTTP response to analyze).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("response") { put("type", "string"); put("description", "The raw HTTP response to analyze") }
                },
                required = listOf("response")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val rawResponse = args.string("response")
                    ?: return@addTool toolError("Missing required parameter: response")
                toolJsonResult(analysis.analyzeResponse(rawResponse))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 3. analyze_find_reflected
        server.addTool(
            name = "analyze_find_reflected",
            description = "Find reflected parameter values in an HTTP response. Extracts all " +
                "parameter values from the request (URL, body, cookies) and searches for each " +
                "in the response body. For each reflection, determines the surrounding context " +
                "(html_body, html_attribute, javascript, css, url, html_comment). " +
                "Parameters: request (string, raw HTTP request), response (string, raw HTTP " +
                "response), additional_values (optional array of extra strings to check for reflection).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("request") { put("type", "string"); put("description", "Raw HTTP request") }
                    putJsonObject("response") { put("type", "string"); put("description", "Raw HTTP response") }
                    putJsonObject("additional_values") {
                        put("type", "array")
                        put("description", "Extra strings to check for reflection")
                        putJsonObject("items") { put("type", "string") }
                    }
                },
                required = listOf("request", "response")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val rawRequest = args.string("request")
                    ?: return@addTool toolError("Missing required parameter: request")
                val rawResponse = args.string("response")
                    ?: return@addTool toolError("Missing required parameter: response")
                val additionalValues = args["additional_values"].asStringList() ?: emptyList()

                toolJsonResult(analysis.findReflected(rawRequest, rawResponse, additionalValues))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 4. analyze_extract_params
        server.addTool(
            name = "analyze_extract_params",
            description = "Extract all parameters from an HTTP request including URL query params, " +
                "body params, cookies, headers, JSON body fields (recursively flattened), and " +
                "XML element/attribute values. Parameters: request (string, the raw HTTP request).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("request") { put("type", "string"); put("description", "The raw HTTP request") }
                },
                required = listOf("request")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val rawRequest = args.string("request")
                    ?: return@addTool toolError("Missing required parameter: request")
                toolJsonResult(analysis.extractParams(rawRequest))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 5. analyze_insertion_points
        server.addTool(
            name = "analyze_insertion_points",
            description = "Identify all potential injection/insertion points in an HTTP request. " +
                "Returns URL parameters, body parameters, JSON body leaves, cookies, injectable headers " +
                "(User-Agent, Referer, X-Forwarded-For, etc.), and URL path segments. " +
                "Parameters: request (string, raw HTTP request), host (string, target hostname), " +
                "port (number, target port), use_tls (boolean, whether to use HTTPS; default: port==443).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("request") { put("type", "string"); put("description", "Raw HTTP request") }
                    putJsonObject("host") { put("type", "string"); put("description", "Target hostname") }
                    putJsonObject("port") {
                        put("type", "integer"); put("minimum", 1); put("maximum", 65535)
                        put("description", "Target port")
                    }
                    putJsonObject("use_tls") { put("type", "boolean"); put("description", "Whether to use HTTPS (default: port==443)") }
                },
                required = listOf("request", "host", "port")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val rawRequest = args.string("request")
                    ?: return@addTool toolError("Missing required parameter: request")
                if (rawRequest.isBlank()) return@addTool toolError("Empty request: provide a raw HTTP request.")
                val host = args.string("host")
                    ?: return@addTool toolError("Missing required parameter: host")
                val port = args["port"].asBoundedInt("port", 1, 65535)
                    .getOrElse { return@addTool toolError(it.message ?: "Invalid port") }
                    ?: return@addTool toolError("Missing required parameter: port")
                val useTls = args["use_tls"].asBooleanSafe() ?: (port == 443)

                toolJsonResult(analysis.getInsertionPoints(rawRequest, host, port, useTls))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 6. analyze_diff
        server.addTool(
            name = "analyze_diff",
            description = "Compare two HTTP requests or two HTTP responses and identify differences. " +
                "For requests: compares method, path, headers, parameters, and body. " +
                "For responses: compares status code, headers, body, and MIME types. " +
                "Returns a similarity percentage based on bigram overlap. " +
                "Parameters: item1 (string, first raw HTTP message), item2 (string, second raw " +
                "HTTP message), type (string, 'request' or 'response').",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("item1") { put("type", "string"); put("description", "First raw HTTP message") }
                    putJsonObject("item2") { put("type", "string"); put("description", "Second raw HTTP message") }
                    putJsonObject("type") {
                        put("type", "string")
                        putJsonArray("enum") { DIFF_TYPES.forEach { add(it) } }
                        put("description", "What item1 and item2 are")
                    }
                },
                required = listOf("item1", "item2", "type")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val item1 = args.string("item1")
                    ?: return@addTool toolError("Missing required parameter: item1")
                val item2 = args.string("item2")
                    ?: return@addTool toolError("Missing required parameter: item2")
                val type = args.string("type")
                EnumValidation.error(type, DIFF_TYPES.toSet(), "type", required = true)?.let { return@addTool toolJsonResult(it) }

                toolJsonResult(analysis.diff(item1, item2, type.orEmpty().trim()))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 7. analyze_response_body_search
        server.addTool(
            name = "analyze_response_body_search",
            description = "Search response bodies across the proxy history for a regex pattern. " +
                "Useful for finding sensitive data leaks, specific tokens, error messages, " +
                "or patterns across all captured traffic. Matching is case-insensitive and time-bounded: " +
                "a search that runs out of time returns what it found with incomplete=true. " +
                "Parameters: pattern (string, regex pattern to search for), " +
                "max_results (number, maximum matches to return; defaults to 50, and a value outside " +
                "1-${AnalysisBridge.SEARCH_MAX_RESULTS} is clamped and reported as max_results_clamped_to), " +
                "in_scope_only (boolean, restrict to in-scope URLs; defaults to false).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("pattern") { put("type", "string"); put("description", "Regex pattern to search for") }
                    putJsonObject("max_results") {
                        put("type", "integer"); put("minimum", 1); put("maximum", AnalysisBridge.SEARCH_MAX_RESULTS)
                        put("description", "Maximum matches to return (default 50, at most ${AnalysisBridge.SEARCH_MAX_RESULTS}; a value outside that range is clamped and reported as max_results_clamped_to)")
                    }
                    putJsonObject("in_scope_only") { put("type", "boolean"); put("description", "Restrict to in-scope URLs (default false)") }
                },
                required = listOf("pattern")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val pattern = args.string("pattern")
                    ?: return@addTool toolError("Missing required parameter: pattern")
                if (pattern.isEmpty()) return@addTool toolError("Parameter 'pattern' must not be empty")
                val maxResults = args["max_results"].asClampedInt("max_results", 1, AnalysisBridge.SEARCH_MAX_RESULTS)
                    .getOrElse { return@addTool toolError(it.message ?: "Invalid max_results") }
                val inScopeOnly = args["in_scope_only"].asBooleanSafe() ?: false

                toolJsonResult(
                    analysis.searchResponseBodies(pattern, maxResults?.value ?: 50, inScopeOnly)
                        .withClampReport("max_results", maxResults)
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }

    private fun Map<String, JsonElement>.string(name: String): String? = (this[name] as? JsonPrimitive)?.contentOrNull
}
