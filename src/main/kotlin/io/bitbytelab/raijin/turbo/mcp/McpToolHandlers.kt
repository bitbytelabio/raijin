package io.bitbytelab.raijin.turbo.mcp

import io.bitbytelab.raijin.bridge.HttpRequestBuilder
import io.bitbytelab.raijin.core.asBodyString
import io.bitbytelab.raijin.core.asIntSafe
import io.bitbytelab.raijin.turbo.Utils
import io.bitbytelab.raijin.turbo.evalJython
import kotlin.concurrent.thread
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray

/**
 * @param scopeAdvice scope advice for a URL (a `scope_warning` text, or null when in scope).
 *   Advisory only: a run is never refused for it.
 */
class McpToolHandlers(
    private val manager: RunManager,
    private val organizerProvider: OrganizerProvider = BurpOrganizerProvider(),
    private val collaboratorProvider: CollaboratorProvider? = null,
    private val scopeAdvice: ((String) -> String?)? = null,
) {

    fun generateCollaboratorPayload(metadata: String): Map<String, Any?> {
        val provider =
            collaboratorProvider
                ?: return mapOf("error" to "Collaborator requires Burp Suite connection")
        val payload = provider.generatePayload(metadata)
        return mapOf("payload" to payload)
    }

    fun getCollaboratorInteractions(payloads: List<String>?): Map<String, Any> {
        val provider =
            collaboratorProvider
                ?: return mapOf(
                    "error" to "Collaborator requires Burp Suite connection",
                    "interactions" to emptyList<Any>(),
                )
        val interactions = provider.getInteractions(payloads)
        return mapOf(
            "interactions" to
                interactions.map { interaction ->
                    mapOf(
                        "payload" to interaction.payload,
                        "metadata" to interaction.metadata,
                        "type" to interaction.type,
                        "timestamp" to interaction.timestamp,
                        "client_ip" to interaction.clientIp,
                        "details" to interaction.details,
                    )
                },
        )
    }

    private fun runNotFoundMessage(runId: String): String {
        return if (manager.isEvicted(runId)) "Run was evicted to free memory" else "No run found"
    }

    fun saveToOrganizer(runId: String, items: String): Map<String, Any> {
        val run =
            manager.getRun(runId)
                ?: return mapOf("error" to runNotFoundMessage(runId), "saved" to emptyList<Int>())

        val itemList: JsonArray =
            try {
                Json.parseToJsonElement(items).jsonArray
            } catch (e: Exception) {
                return mapOf(
                    "saved" to emptyList<Int>(),
                    "errors" to
                        listOf(mapOf("error" to "items must be a JSON array: ${e.message}")),
                )
            }

        val saved = mutableListOf<Int>()
        val errors = mutableListOf<Map<String, Any>>()

        val runIdSection = "\n\nRun ID: ${run.id}"

        val scriptSection =
            if (run.handler.code.isNotBlank()) {
                "\n\n--- Script ---\n${run.handler.code}"
            } else ""

        for (item in itemList) {
            val obj = item as? JsonObject
            val requestId = obj?.get("request_id").asIntSafe()
            val notes = obj?.get("notes").asBodyString() ?: ""
            if (requestId == null) {
                errors.add(
                    mapOf("error" to "item must be an object with an integer request_id: $item"),
                )
                continue
            }
            val request = run.store.getRequest(requestId)
            if (request == null) {
                errors.add(mapOf("request_id" to requestId, "error" to "Request not found"))
                continue
            }
            val sent =
                try {
                    organizerProvider.sendToOrganizer(request, notes + runIdSection + scriptSection)
                } catch (e: Exception) {
                    errors.add(
                        mapOf(
                            "request_id" to requestId,
                            "error" to
                                "Organizer refused it: ${e.message ?: e.javaClass.simpleName}",
                        ),
                    )
                    continue
                }
            if (!sent) {
                errors.add(
                    mapOf(
                        "request_id" to requestId,
                        "error" to
                            "Not saved: no response stored for it, or Burp's Organizer is not available",
                    ),
                )
                continue
            }
            saved.add(requestId)
        }

        return mapOf("saved" to saved, "errors" to errors)
    }

    fun startRun(
        script: String,
        baseRequest: String,
        endpoint: String,
        baseInput: String,
        timeoutMs: Long = 55000,
        normalizeLineEndings: Boolean = true,
    ): Map<String, Any?> {
        val normalized = normalizeScriptLineEndings(script, normalizeLineEndings)
        val scopeWarning = scopeAdvice?.invoke(endpoint)
        val run = manager.startRun()
        launchRun(run, normalized.script, baseRequest, endpoint, baseInput)

        // Wait for completion or timeout
        val startTime = System.currentTimeMillis()
        while (run.handler.status() == "running") {
            if (System.currentTimeMillis() - startTime > timeoutMs) {
                val result =
                    runningResult(
                        run,
                        "The run is still executing. Call turbo_run.status with wait=true to long-poll until completion.",
                    )
                normalized.warning?.let { result["warning"] = it }
                return withScope(result, scopeWarning, run)
            }
            try {
                Thread.sleep(50)
            } catch (_: InterruptedException) {
                // The tool call was cancelled: report where the run is, and keep the interrupt.
                Thread.currentThread().interrupt()
                val result = runningResult(run, "wait interrupted")
                result["note"] = "wait interrupted"
                return withScope(result, scopeWarning, run)
            }
        }

        // Get results sorted by anomaly rank descending
        val status = run.handler.status()
        val results =
            run.store.getResults(io.bitbytelab.raijin.turbo.SortField.ANOMALY_RANK, true, 100, 0)
        val result =
            mutableMapOf<String, Any?>(
                "status" to status,
                "run_id" to run.id,
                "status_message" to run.handler.msg,
                "result_count" to run.store.count(),
                "fails" to run.handler.failCount(),
                "results" to results.map { it.toSummaryMap() },
            )
        putCallbackErrors(result, run)
        if (status == "failed") {
            result["error_message"] = run.handler.statusString()
        } else if (
            run.store.count() == 0 &&
                run.handler.failCount() > 0 &&
                run.handler.callbackFailures() == 0
        ) {
            // The engine composes this so that a client here and a user watching the GUI status
            // line are told the same thing: an HTTP/3 run that never got a handshake through says
            // so, rather than both layers spelling out a connection error their own way.
            result["error_message"] =
                run.handler.failureSummary()
                    ?: "All ${run.handler.failCount()} requests failed with connection errors"
        }
        normalized.warning?.let { result["warning"] = it }
        return withScope(result, scopeWarning, run)
    }

    private fun runningResult(run: ActiveRun, message: String): MutableMap<String, Any?> {
        val result =
            mutableMapOf<String, Any?>(
                "status" to "running",
                "message" to message,
                "run_id" to run.id,
                "status_message" to run.handler.statusString(),
                "result_count" to run.store.count(),
                "fails" to run.handler.failCount(),
                "created_at" to run.createdAt,
            )
        putCallbackErrors(result, run)
        return result
    }

    /**
     * [result] with the start-time `scope_warning` first and the per-origin `scope_warnings`
     * gathered so far.
     */
    private fun withScope(
        result: Map<String, Any?>,
        scopeWarning: String?,
        run: ActiveRun,
    ): Map<String, Any?> {
        val warnings = run.handler.scopeWarnings.toList()
        if (scopeWarning == null && warnings.isEmpty()) return result
        val out = LinkedHashMap<String, Any?>()
        scopeWarning?.let { out["scope_warning"] = it }
        out.putAll(result)
        if (warnings.isNotEmpty()) out["scope_warnings"] = warnings
        return out
    }

    fun startRunAsync(
        script: String,
        baseRequest: String,
        endpoint: String,
        baseInput: String,
        normalizeLineEndings: Boolean = true,
    ): Map<String, Any?> {
        val normalized = normalizeScriptLineEndings(script, normalizeLineEndings)
        val scopeWarning = scopeAdvice?.invoke(endpoint)
        val run = manager.startRun()
        launchRun(run, normalized.script, baseRequest, endpoint, baseInput)
        val result = mutableMapOf<String, Any?>("status" to "started", "run_id" to run.id)
        normalized.warning?.let { result["warning"] = it }
        return withScope(result, scopeWarning, run)
    }

    fun stopRun(runId: String): Map<String, String> {
        return mapOf("status" to manager.stopRun(runId))
    }

    fun deleteRun(runId: String): Map<String, String> {
        return mapOf("status" to manager.deleteRun(runId))
    }

    /**
     * All known runs (this MCP session and the GUI), newest first — recovers a run_id lost after
     * `turbo_start_run`'s blocking window elapsed, or lets an orphaned run be found and stopped.
     */
    fun listRuns(): List<Map<String, Any?>> =
        manager.listRuns().map { run ->
            val entry =
                mutableMapOf<String, Any?>(
                    "run_id" to run.id,
                    "status" to run.handler.status(),
                    "status_message" to run.handler.statusString(),
                    "result_count" to run.store.count(),
                    "fails" to run.handler.failCount(),
                    "created_at" to run.createdAt,
                    "source" to run.source,
                )
            putCallbackErrors(entry, run)
            run.handler.scopeWarnings
                .takeIf { it.isNotEmpty() }
                ?.let { entry["scope_warnings"] = it.toList() }
            entry
        }

    fun searchResponses(runId: String, query: String, searchIn: String = "all"): Map<String, Any> {
        val run = manager.getRun(runId) ?: return mapOf("error" to runNotFoundMessage(runId))

        // Responses are held one char per byte: a non-ASCII query is looked for in that form too.
        val asBytes = String(query.toByteArray(Charsets.UTF_8), Charsets.ISO_8859_1)
        fun inResponse(text: String?) =
            text != null && (text.contains(query) || (asBytes != query && text.contains(asBytes)))
        val all =
            run.store
                .getAllRquests()
                .filter { req ->
                    when (searchIn) {
                        "labels" -> req.label.contains(query)
                        "responses" -> inResponse(req.response)
                        else -> inResponse(req.response) || req.label.contains(query)
                    }
                }
                .map { it.id }
        val matches = all.take(MAX_SEARCH_MATCHES)

        val result =
            mutableMapOf<String, Any>(
                "matches" to matches,
                "match_count" to all.size,
            )
        if (all.size > matches.size) result["truncated"] = true

        if (searchIn != "labels") {
            val dropped = run.store.droppedBodyCount()
            if (run.responsesStripped) {
                result["warning"] =
                    "Response bodies have been stripped from this run to free memory. Only label search is available."
            } else if (dropped > 0) {
                result["warning"] =
                    "$dropped older response bodies were dropped to stay within the run's memory budget and were not searched."
            }
        }

        return result
    }

    private fun launchRun(
        run: ActiveRun,
        script: String,
        baseRequest: String,
        endpoint: String,
        baseInput: String,
    ) {
        val host =
            HttpRequestBuilder.splitUrl(endpoint)?.authority?.let {
                HttpRequestBuilder.parseHostValue(it)?.first
            } ?: endpoint.removePrefix("https://").removePrefix("http://").substringBefore("/")

        val normalizedRequest = Utils.normalizeLineEndings(baseRequest)
        // MCP-started runs only: every origin the script queues to is scope-advised once.
        scopeAdvice?.let { advice ->
            run.handler.targetObserver = { url -> run.handler.observeTarget(url, advice) }
        }

        thread {
            try {
                evalJython(
                    code = script,
                    baseRequest = normalizedRequest,
                    rawRequest = normalizedRequest.toByteArray(Charsets.ISO_8859_1),
                    endpoint = endpoint,
                    host = host,
                    baseInput = baseInput,
                    store = run.store,
                    handler = run.handler,
                    reqs = null,
                    requestTable = null,
                )
            } catch (e: Throwable) {
                run.handler.overrideStatus(
                    "Run failed to start: ${e.message ?: e.javaClass.simpleName}",
                )
            } finally {
                run.handler.markScriptCompleted()
            }
        }
    }

    companion object {
        /** Most request ids `turbo_search_responses` lists; `match_count` still counts them all. */
        const val MAX_SEARCH_MATCHES = 1000
    }
}

/** Adds `callback_errors` and `last_callback_error` when the script's callbacks raised. */
internal fun putCallbackErrors(result: MutableMap<String, Any?>, run: ActiveRun) {
    val failures = run.handler.callbackFailures()
    if (failures == 0) return
    result["callback_errors"] = failures
    run.handler.lastCallbackError()?.let { result["last_callback_error"] = it }
}
