package io.bitbytelab.raijin.turbo.mcp

import io.bitbytelab.raijin.turbo.Request
import io.bitbytelab.raijin.turbo.SortField
import io.bitbytelab.raijin.turbo.Utils
import java.io.File
import kotlin.io.path.createTempDirectory

fun Request.toSummaryMap(): Map<String, Any?> = mapOf(
    "id" to id,
    "status" to code,
    "length" to length,
    "ttfb" to ttfb,
    "ttlb" to ttlb,
    // Microseconds from the start of the run, unlike ttfb/ttlb which each engine measures from
    // its own idea of "sent", so it is the one field two requests can be compared on directly.
    "arrival" to arrival,
    "wordcount" to wordcount,
    "words" to words,
    "label" to label,
    "anomaly_rank" to anomalyRank,
    // Null unless the request went through an HTTP/3 gate. Which gate released it is not
    // cosmetic: it is what separates a real behavioural difference between two runs from the
    // engine having released them differently.
    "gate_mode" to gateMode
)

class McpResourceHandlers(
    private val manager: RunManager,
    private val desyncMode: () -> Boolean = { false }
) {

    /** Every file in resources/turbo-docs/, by name without `.md`. */
    val docTopics = mapOf(
        "index" to "Overview of the docs and where to start",
        "api-quickstart" to "Quick reference for scripting",
        "engines" to "Engine types (AUTO, THREADED, BURP, BURP2, HTTP3)",
        "settings" to "Complete parameter reference",
        "race-conditions" to "Race condition testing with gates",
        "response-processing" to "Handling and filtering responses",
        "decorators" to "Response decorator reference",
        "performance" to "Tuning for requests per second: engine choice, concurrency, request and response size",
        "misc" to "Wordlists and utilities",
        "desync-techniques" to "HTTP request smuggling: obfuscation technique catalog and canary confirmation",
        "montoya-api-examples" to "Montoya API patterns for Burp extension code",
        "resources" to "Links to the Montoya API docs, source and example extensions"
    )

    // Auto-discovered from resources/examples/
    private val discoveredExamples: Set<String> = setOf(
        "0cl-exploit", "0cl-find-offset", "0cl-poc",
        "apis", "basic", "benchmark-h1-race", "benchmark-h2-race",
        "burpIntegration", "customSortOrder", "debug", "default", "desync-gadget-hunter",
        "desync-smuggler", "desync-h2-downgrade",
        "email-link-extraction", "http2", "http3", "infinite", "micro-crawl",
        "misc", "multiHost", "multipleParameters", "outputToFile",
        "partialReadCallback", "pinwheel", "race-multi-endpoint",
        "race-http3",
        "race-single-packet-attack",
        "ratelimit", "recursive",
        "specialWordlists", "test", "timing", "timingAttackWithState"
    )

    /** Names [getExample] accepts, sorted. */
    val exampleNames: List<String> get() = discoveredExamples.sorted()

    private fun runNotFoundError(runId: String): Map<String, Any?> {
        val error = if (manager.isEvicted(runId)) "evicted" else "not_found"
        return mapOf("error" to error)
    }

    fun getRunStatus(runId: String, waitMs: Long = 0): Map<String, Any?> {
        val run = manager.getRun(runId)
            ?: return runNotFoundError(runId)

        var interrupted = false
        if (waitMs > 0 && run.handler.status() == "running") {
            val deadline = System.currentTimeMillis() + waitMs
            try {
                while (run.handler.status() == "running" && System.currentTimeMillis() < deadline) {
                    Thread.sleep(100)
                }
            } catch (_: InterruptedException) {
                // The tool call was cancelled: answer with the state as it is, and keep the interrupt.
                Thread.currentThread().interrupt()
                interrupted = true
            }
        }

        val status = run.handler.status()
        val baseStatus = mutableMapOf<String, Any?>(
            "run_id" to run.id,
            "status" to status,
            "status_message" to run.handler.statusString(),
            "result_count" to run.store.count(),
            "fails" to run.handler.failCount(),
            "created_at" to run.createdAt
        )
        putCallbackErrors(baseStatus, run)
        run.handler.scopeWarnings.takeIf { it.isNotEmpty() }?.let { baseStatus["scope_warnings"] = it.toList() }
        if (interrupted) baseStatus["note"] = "wait interrupted"

        // Include summary when run is not running
        if (status != "running") {
            val results = run.store.getResults(SortField.ANOMALY_RANK, true, 20, 0)
            val summary = results.map { it.toSummaryMap() }
            return baseStatus + mapOf("summary" to summary)
        }

        return baseStatus
    }

    fun getRunScript(runId: String): Map<String, Any?> {
        val run = manager.getRun(runId)
            ?: return runNotFoundError(runId)
        return mapOf("script" to run.handler.code)
    }

    /**
     * One page of a run's results. Without [sortBy] they follow the order the script set with
     * `table.setSortOrder(...)`, else id; [descending] defaults to that order's direction, else true.
     * An unknown [sortBy] is an error listing [SORT_FIELDS]; a negative [limit] or [offset] counts as 0.
     */
    fun getResults(
        runId: String,
        sortBy: String?,
        descending: Boolean?,
        limit: Int,
        offset: Int
    ): Map<String, Any?> {
        val requestedField = sortBy?.trim()?.takeIf { it.isNotEmpty() }?.let { name ->
            SortField.entries.firstOrNull { it.name.equals(name, ignoreCase = true) }
                ?: return mapOf("error" to "Unknown sort_by '$sortBy'", "valid_sort_fields" to SORT_FIELDS)
        }
        val run = manager.getRun(runId)
            ?: return runNotFoundError(runId)

        val scriptOrder = run.store.sortOrder().takeIf { requestedField == null }
        val field = requestedField ?: scriptOrder?.field ?: SortField.ID
        val reversed = descending ?: scriptOrder?.descending ?: true
        val results = run.store.getResults(field, reversed, limit.coerceAtLeast(0), offset.coerceAtLeast(0))

        val response = mutableMapOf<String, Any?>(
            "results" to results.map { it.toSummaryMap() },
            "total_count" to run.store.count(),
            "status_codes" to run.store.getUniqueStatusCodes(),
            "sort_by" to field.name.lowercase(),
            "descending" to reversed
        )
        if (scriptOrder != null) response["sort_source"] = "script"
        if (limit < 0 || offset < 0) response["note"] = "Negative limit/offset counted as 0"
        return response
    }

    fun getRequestDetail(
        runId: String,
        requestId: Int,
        bodyLimit: Int = 100,
        exportFile: Boolean = false
    ): Map<String, Any?> {
        val run = manager.getRun(runId)
            ?: return runNotFoundError(runId)

        val request = run.store.getRequest(requestId)
            ?: return mapOf("error" to "request_not_found")

        if ((run.responsesStripped || run.store.droppedBodyCount() > 0) && request.response == null) {
            return mapOf(
                "warning" to "Response body was stripped from this run to free memory. Metadata is still available.",
                "request" to request.getRequest(),
                "status" to request.code,
                "length" to request.length,
                "ttfb" to request.ttfb,
                "ttlb" to request.ttlb,
                "wordcount" to request.wordcount,
                "words" to request.words,
                "label" to request.label,
                "anomaly_rank" to request.anomalyRank
            )
        }

        if (exportFile) {
            val tempDir = createTempDirectory("turbo-${run.id}-").toFile()
            val requestFile = File(tempDir, "request-$requestId.txt")
            val responseFile = File(tempDir, "response-$requestId.txt")
            // Registered directory first: deleteOnExit runs in reverse order, files before their directory.
            tempDir.deleteOnExit()
            requestFile.deleteOnExit()
            responseFile.deleteOnExit()

            // The bytes as they went over the wire (one char per byte), not re-encoded text.
            requestFile.writeBytes(request.getRequestAsBytes())
            val response = request.response
            if (response != null) responseFile.writeBytes(Utils.stringToBytes(response))

            return buildMap {
                put("request_file", requestFile.absolutePath)
                if (response != null) put("response_file", responseFile.absolutePath)
                put("status", request.code)
                put("length", request.length)
                put("ttfb", request.ttfb)
                put("ttlb", request.ttlb)
                put("words", request.words)
            }
        }

        val response = request.response
        val (headers, body) = splitResponse(response)
        val truncatedBody = TruncatedHttpBody(body, bodyLimit)

        return mapOf(
            "request" to request.getRequest(),
            "response_headers" to filterHeaders(headers),
            "status" to request.code,
            "length" to request.length,
            "ttfb" to request.ttfb,
            "ttlb" to request.ttlb,
            "words" to request.words
        ) + truncatedBody.toResponseFields()
    }

    private fun splitResponse(response: String?): Pair<String, String> {
        if (response == null) return Pair("", "")

        val separatorIndex = response.indexOf("\r\n\r\n")
        return if (separatorIndex != -1) {
            Pair(
                response.substring(0, separatorIndex),
                response.substring(separatorIndex + 4)
            )
        } else {
            Pair(response, "")
        }
    }

    private fun filterHeaders(headers: String): String {
        if (!desyncMode()) return headers
        return headers.split("\r\n")
            .filterNot { it.startsWith("Connection:", ignoreCase = true) }
            .joinToString("\r\n")
    }

    // Documentation resources

    fun getDoc(topic: String): Map<String, Any?> {
        if (!docTopics.containsKey(topic)) {
            return mapOf("error" to "unknown_topic", "available_topics" to docTopics.keys.toList())
        }

        val content = loadDocContent(topic)
            ?: return mapOf("error" to "doc_not_found")

        return mapOf(
            "topic" to topic,
            "content" to content
        )
    }

    private fun loadDocContent(topic: String): String? =
        loadResourceFile("/turbo-docs/$topic.md", listOf("src/main/resources/turbo-docs/$topic.md"))

    // Example script resources

    fun listExamples(): Map<String, Any> {
        return mapOf(
            "examples" to discoveredExamples.sorted().map { name ->
                mapOf("name" to name)
            }
        )
    }

    fun getExample(name: String): Map<String, Any?> {
        if (!discoveredExamples.contains(name)) {
            return mapOf("error" to "not_found", "available_examples" to discoveredExamples.sorted())
        }

        val content = loadExampleContent(name)
            ?: return mapOf("error" to "not_found")

        return mapOf(
            "name" to name,
            "content" to content
        )
    }

    private fun loadExampleContent(name: String): String? =
        loadResourceFile("/examples/$name.py", listOf(
            "src/main/resources/examples/$name.py"
        ))

    private fun loadResourceFile(classpathPath: String, filesystemPaths: List<String>): String? {
        javaClass.getResourceAsStream(classpathPath)?.use { return it.bufferedReader().readText() }
        for (path in filesystemPaths) {
            val file = File(path)
            if (file.exists()) return file.readText()
        }
        return null
    }

    companion object {
        /** Values `sort_by` accepts. */
        val SORT_FIELDS: List<String> = SortField.entries.map { it.name.lowercase() }
    }
}
