package io.bitbytelab.raijin.transport

import burp.api.montoya.http.message.HttpRequestResponse
import io.bitbytelab.raijin.core.BodyText
import io.bitbytelab.raijin.core.truncateJsonForSummary
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.safety.ActionPolicy
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.tools.ToolConsolidation
import io.bitbytelab.raijin.tools.toolError
import io.modelcontextprotocol.kotlin.sdk.server.RegisteredTool
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.coroutines.ThreadContextElement
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.*
import java.time.Instant
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.cancellation.CancellationException

/**
 * Wraps all registered MCP tools on a [Server] so that every tool invocation
 * emits a `tool.called` event on the [EventBus] and records an activity entry
 * in the [StateManager] for the native Burp UI tab, plus an [AuditLog] entry for
 * security-relevant and mutating calls. A call that throws or is cancelled is
 * recorded too, as an error.
 *
 * Call [wrapAll] **after** all tools have been registered via [ToolRegistry].
 */
object ToolCallTracker {

    /** Tool families that change Burp or target state; their read-only members are excluded by [READ_ONLY_WORDS]. */
    private val MUTATING_TOOL_PREFIXES = listOf(
        "turbo_",
        "config_",
        "websocket_",
        "persistence_",
        "preference_",
        "scanner_",
        "bcheck_",
        "scancheck_",
        "bambda_",
        "autorize_",
        "burp_import_",
        "session_",
        "proxy_set_",
        "proxy_remove_",
        "proxy_intercept_",
        "http_set_",
        "http_remove_"
    )

    /** A word after the family prefix that marks a read-only tool (turbo_run_status, websocket_list, ...). */
    private val READ_ONLY_WORDS = setOf(
        "get", "list", "status", "result", "results", "script", "search", "templates", "issues",
        "docs", "example", "examples", "messages", "history", "info", "wait"
    )

    private val MUTATING_TOOL_NAMES = setOf(
        "http_send_requests_parallel",
        "http_race",
        "http_fuzz",
        "http_send_request_chain",
        "http_send_pipeline",
        "http_pipeline_connections",
        "http_cookie_jar_set",
        "http_cookie_jar_delete",
        "burp_task_engine_set",
        "intruder_register_payload_processor",
        "proxy_rule",
        "proxy_auto_auth",
        "proxy_annotate",
        "organizer_annotate",
        "sitemap_annotate",
        "http_rule",
        "scope",
        "scope_include",
        "scope_exclude",
        "scope_remove",
        "findings_add",
        "findings_remove",
        "events_clear",
        "collaborator_create_client",
        "collaborator_restore_client",
        "collaborator_remove_client"
    )

    private val JWT_KEY_MUTATING_ACTIONS = setOf("generate", "import", "delete")

    fun wrapAll(server: Server, eventBus: EventBus, stateManager: StateManager) {
        val toolsCopy = server.tools.values.toList()
        server.removeTools(toolsCopy.map { it.tool.name })

        val wrappedTools = toolsCopy.map { registeredTool ->
            val originalHandler = registeredTool.handler
            val toolName = registeredTool.tool.name

            RegisteredTool(
                tool = registeredTool.tool,
                handler = { request: CallToolRequest ->
                    val startNanos = System.nanoTime()
                    val startInstant = Instant.now()
                    val holder = HttpCaptureHolder()
                    var result: CallToolResult? = null
                    var failure: Throwable? = null
                    try {
                        val r = withContext(ToolCallCaptureContext(holder)) {
                            originalHandler(this@RegisteredTool, request)
                        }
                        result = r
                        r
                    } catch (t: Throwable) {
                        failure = t
                        throw t
                    } finally {
                        val elapsedMs = (System.nanoTime() - startNanos) / 1_000_000
                        try {
                            recordToolCall(
                                eventBus, stateManager, toolName, request,
                                result ?: failureResult(failure), elapsedMs, startInstant, holder.value
                            )
                        } catch (_: Exception) {
                        }
                    }
                }
            )
        }

        server.addTools(wrappedTools)
    }

    /**
     * What an activity / audit record says about one call. Every value is read defensively: an
     * argument or result field may be an array, an object or missing.
     */
    internal data class CallSummary(
        val toolName: String,
        val arguments: JsonObject,
        val resultSummary: String,
        val url: String,
        val method: String,
        val host: String,
        val statusCode: Int,
        val isError: Boolean,
        /** The result reports an out-of-scope target: warned, advised, sent or blocked. */
        val outOfScope: Boolean = false,
    )

    /** Results above this size are not parsed for the summary; the scope flag then comes from a text search. */
    private const val MAX_PARSED_RESULT_CHARS = 262_144

    /**
     * Builds the [CallSummary] of a call to [mergedToolName]. Grouped tools are reported under the
     * member's original name (e.g. scope_include) so the Activity tab, audit log and destructive-action
     * policy keep their granularity.
     */
    internal fun summarize(mergedToolName: String, args: Map<String, JsonElement>?, result: CallToolResult): CallSummary {
        val action = (args?.get("action") as? JsonPrimitive)?.contentOrNull
        val toolName = ToolConsolidation.legacyName(mergedToolName, action) ?: mergedToolName
        val arguments = buildJsonObject {
            args?.forEach { (key, value) -> put(key, truncateJsonForSummary(value, 200)) }
        }

        val resultText = result.content.filterIsInstance<TextContent>().firstOrNull()?.text
        val resultSummary = resultText?.let { if (it.length > 500) BodyText.truncate(it, 500) + "..." else it } ?: ""

        val parse = resultText != null && resultText.length <= MAX_PARSED_RESULT_CHARS
        val resultJson = if (parse) runCatching { Json.parseToJsonElement(resultText) }.getOrNull() as? JsonObject else null
        val outOfScope = if (parse) {
            resultJson != null && (
                resultJson["scope_warning"] != null ||
                    ((resultJson["scope_warnings"] as? JsonArray)?.isNotEmpty() == true) ||
                    (resultJson["out_of_scope"] as? JsonPrimitive)?.booleanOrNull == true ||
                    ((resultJson["sent_out_of_scope"] as? JsonPrimitive)?.intOrNull ?: 0) > 0 ||
                    ((resultJson["skipped_out_of_scope"] as? JsonPrimitive)?.intOrNull ?: 0) > 0
                )
        } else {
            resultText != null && (
                resultText.contains("\"scope_warning\":") || resultText.contains("\"out_of_scope\":true") ||
                    resultText.contains("\"scope_warnings\":[\"")
                )
        }
        val requestJson = resultJson?.get("request") as? JsonObject
        val responseJson = resultJson?.get("response") as? JsonObject
        fun JsonObject?.text(key: String): String = ((this?.get(key)) as? JsonPrimitive)?.contentOrNull.orEmpty()
        fun JsonObject?.int(key: String): Int = ((this?.get(key)) as? JsonPrimitive)?.intOrNull ?: 0
        val argsJson = args?.let(::JsonObject)

        val url = resultJson.text("url").ifEmpty { requestJson.text("url") }.ifEmpty { argsJson.text("url") }
        val method = resultJson.text("method").ifEmpty { requestJson.text("method") }.ifEmpty { argsJson.text("method") }
        var host = resultJson.text("host").ifEmpty { argsJson.text("host") }
        if (host.isEmpty() && url.isNotEmpty()) host = runCatching { java.net.URI(url).host }.getOrNull().orEmpty()
        val statusCode = resultJson.int("status_code").takeIf { it != 0 } ?: responseJson.int("status_code")

        return CallSummary(toolName, arguments, resultSummary, url, method, host, statusCode, result.isError ?: false, outOfScope)
    }

    /** The result recorded for a call that threw or was cancelled instead of returning. */
    internal fun failureResult(failure: Throwable?): CallToolResult = toolError(
        when (failure) {
            null -> "tool call failed"
            is CancellationException -> "cancelled before completion (client disconnected or the call was cancelled)"
            else -> "${failure::class.simpleName}: ${failure.message ?: "no message"}"
        }
    )

    private fun recordToolCall(
        eventBus: EventBus,
        stateManager: StateManager,
        mergedToolName: String,
        request: CallToolRequest,
        result: CallToolResult,
        elapsedMs: Long,
        timestamp: Instant,
        httpReqResp: HttpRequestResponse?
    ) {
        val args = request.params.arguments
        val s = summarize(mergedToolName, args, result)

        // Record in StateManager for native Burp UI tab
        stateManager.addMcpActivity(
            toolName = s.toolName,
            timestamp = timestamp.toString(),
            durationMs = elapsedMs,
            method = s.method,
            url = s.url,
            host = s.host,
            statusCode = s.statusCode,
            isError = s.isError,
            argsSummary = s.arguments.toString(),
            resultSummary = s.resultSummary,
            requestResponse = httpReqResp,
            outOfScope = s.outOfScope,
        )

        // Emit event for web dashboard
        eventBus.emit("tool.called", buildJsonObject {
            put("tool_name", s.toolName)
            put("timestamp", timestamp.toString())
            put("duration_ms", elapsedMs)
            put("is_error", s.isError)
            put("arguments", s.arguments)
            put("result_summary", s.resultSummary)
            put("url", s.url)
            put("method", s.method)
            put("host", s.host)
            put("status_code", s.statusCode)
            put("out_of_scope", s.outOfScope)
        })

        // Durable, append-only audit trail for security-relevant and mutating calls
        val action = (args?.get("action") as? JsonPrimitive)?.contentOrNull
        if (shouldAudit(s.toolName, s.url, s.host, s.isError, action, s.outOfScope)) {
            AuditLog.record(
                s.toolName, timestamp.toString(), elapsedMs, s.isError,
                args, s.url, s.host, s.method, s.statusCode, s.outOfScope
            )
        }
    }

    internal fun shouldAudit(
        toolName: String,
        url: String,
        host: String,
        isError: Boolean,
        action: String? = null,
        outOfScope: Boolean = false,
    ): Boolean =
        outOfScope ||
            url.isNotEmpty() ||
            host.isNotEmpty() ||
            isError ||
            ActionPolicy.isDestructive(toolName) ||
            toolName in MUTATING_TOOL_NAMES ||
            (toolName == "jwt_keys" && action?.trim()?.lowercase() in JWT_KEY_MUTATING_ACTIONS) ||
            isMutatingFamilyMember(toolName)

    private fun isMutatingFamilyMember(toolName: String): Boolean {
        val prefix = MUTATING_TOOL_PREFIXES.firstOrNull { toolName.startsWith(it) } ?: return false
        return toolName.removePrefix(prefix).split('_').none { it in READ_ONLY_WORDS }
    }

    /** Holds the most recent Montoya [HttpRequestResponse] sent during one tool call. */
    internal class HttpCaptureHolder(@Volatile var value: HttpRequestResponse? = null)

    private val captureThreadLocal = ThreadLocal<HttpCaptureHolder?>()

    /**
     * Coroutine-context element carrying a call's [HttpCaptureHolder]. It installs the holder in a
     * thread-local only while the call's coroutine runs on a thread and restores the previous value
     * whenever it suspends, finishes or throws, so blocking bridge code can reach it through
     * [recordSentResult] across `Dispatchers.IO` hops without anything leaking to the next call.
     */
    internal class ToolCallCaptureContext(
        private val holder: HttpCaptureHolder
    ) : ThreadContextElement<HttpCaptureHolder?> {
        companion object Key : CoroutineContext.Key<ToolCallCaptureContext>
        override val key: CoroutineContext.Key<*> get() = Key

        override fun updateThreadContext(context: CoroutineContext): HttpCaptureHolder? {
            val prev = captureThreadLocal.get()
            captureThreadLocal.set(holder)
            return prev
        }

        override fun restoreThreadContext(context: CoroutineContext, oldState: HttpCaptureHolder?) {
            if (oldState == null) captureThreadLocal.remove() else captureThreadLocal.set(oldState)
        }
    }

    /** Records the latest [HttpRequestResponse] sent during the currently active tool invocation. */
    fun recordSentResult(result: HttpRequestResponse?) {
        captureThreadLocal.get()?.value = result
    }
}
