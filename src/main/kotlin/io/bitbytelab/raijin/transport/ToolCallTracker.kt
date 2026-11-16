package io.bitbytelab.raijin.transport

import io.bitbytelab.raijin.core.truncateJsonForSummary
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.state.StateManager
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

/**
 * Wraps all registered MCP tools on a [Server] so that every tool invocation
 * emits a `tool.called` event on the [EventBus] and records an activity entry
 * in the [StateManager] for the native Burp UI tab.
 *
 * Call [wrapAll] **after** all tools have been registered via [ToolRegistry].
 */
object ToolCallTracker {

    private val MUTATING_TOOL_PREFIXES = listOf(
        "turbo_run",
        "turbo_start",
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

    private val MUTATING_TOOL_NAMES = setOf(
        "http_send_requests_parallel",
        "http_race",
        "http_fuzz",
        "http_send_request_chain",
        "http_send_pipeline",
        "proxy_rule",
        "http_rule",
        "scope",
        "scope_include",
        "scope_exclude",
        "scope_remove"
    )

    fun wrapAll(server: Server, eventBus: EventBus, stateManager: StateManager) {
        val toolsCopy = server.tools.values.toList()
        val toolNames = toolsCopy.map { it.tool.name }
        server.removeTools(toolNames)

        val wrappedTools = toolsCopy.map { registeredTool ->
            val originalHandler = registeredTool.handler
            val toolName = registeredTool.tool.name

            RegisteredTool(
                tool = registeredTool.tool,
                handler = { request: CallToolRequest ->
                    val startTime = System.nanoTime()
                    val startInstant = Instant.now()
                    val holder = HttpCaptureHolder()

                    val result: CallToolResult = withContext(ToolCallCaptureContext(holder)) {
                        originalHandler(this@RegisteredTool, request)
                    }

                    val elapsedMs = (System.nanoTime() - startTime) / 1_000_000

                    try {
                        recordToolCall(eventBus, stateManager, toolName, request, result, elapsedMs, startInstant, holder.value)
                    } catch (_: Exception) {}

                    result
                }
            )
        }

        server.addTools(wrappedTools)
    }

    private fun recordToolCall(
        eventBus: EventBus,
        stateManager: StateManager,
        mergedToolName: String,
        request: CallToolRequest,
        result: CallToolResult,
        elapsedMs: Long,
        timestamp: Instant,
        httpReqResp: burp.api.montoya.http.message.HttpRequestResponse?
    ) {
        // Grouped tools are reported under the member's original name (e.g. scope_include) so the
        // Activity tab, audit log and destructive-action policy keep their granularity.
        val args = request.params.arguments
        val action = (args?.get("action") as? JsonPrimitive)?.contentOrNull
        val toolName = io.bitbytelab.raijin.tools.ToolConsolidation.legacyName(mergedToolName, action) ?: mergedToolName
        val argsJson = buildJsonObject {
            args?.forEach { (key, value) -> put(key, truncateJsonForSummary(value, 200)) }
        }

        val resultSummary = result.content
            .filterIsInstance<TextContent>()
            .firstOrNull()
            ?.text
            ?.let { if (it.length > 500) it.take(500) + "..." else it }
            ?: ""

        // Extract HTTP info from result JSON without crashing on non-primitive JSON values
        var url = ""
        var method = ""
        var host = ""
        var statusCode = 0
        try {
            val resultJson = result.content
                .filterIsInstance<TextContent>()
                .firstOrNull()
                ?.text
                ?.let { Json.parseToJsonElement(it) as? JsonObject }
            url = (resultJson?.get("url") as? JsonPrimitive)?.contentOrNull ?: ""
            method = (resultJson?.get("method") as? JsonPrimitive)?.contentOrNull ?: ""
            host = (resultJson?.get("host") as? JsonPrimitive)?.contentOrNull ?: ""
            statusCode = (resultJson?.get("status_code") as? JsonPrimitive)?.intOrNull ?: 0

            val reqObj = resultJson?.get("request") as? JsonObject
            val respObj = resultJson?.get("response") as? JsonObject
            if (url.isEmpty()) url = (reqObj?.get("url") as? JsonPrimitive)?.contentOrNull ?: ""
            if (method.isEmpty()) method = (reqObj?.get("method") as? JsonPrimitive)?.contentOrNull ?: ""
            if (statusCode == 0) statusCode = (respObj?.get("status_code") as? JsonPrimitive)?.intOrNull ?: 0
        } catch (_: Exception) {}

        // Safe fallback from arguments (never invoke .jsonPrimitive on arrays/objects)
        if (url.isEmpty()) url = (args?.get("url") as? JsonPrimitive)?.contentOrNull ?: ""
        if (host.isEmpty()) host = (args?.get("host") as? JsonPrimitive)?.contentOrNull ?: ""
        if (method.isEmpty()) method = (args?.get("method") as? JsonPrimitive)?.contentOrNull ?: ""
        if (host.isEmpty() && url.isNotEmpty()) {
            try { host = java.net.URI(url).host ?: "" } catch (_: Exception) {}
        }

        val isError = result.isError ?: false

        // Record in StateManager for native Burp UI tab
        stateManager.addMcpActivity(
            toolName = toolName,
            timestamp = timestamp.toString(),
            durationMs = elapsedMs,
            method = method,
            url = url,
            host = host,
            statusCode = statusCode,
            isError = isError,
            argsSummary = argsJson.toString(),
            resultSummary = resultSummary,
            requestResponse = httpReqResp
        )

        // Emit event for web dashboard
        eventBus.emit("tool.called", buildJsonObject {
            put("tool_name", toolName)
            put("timestamp", timestamp.toString())
            put("duration_ms", elapsedMs)
            put("is_error", isError)
            put("arguments", argsJson)
            put("result_summary", resultSummary)
            put("url", url)
            put("method", method)
            put("host", host)
            put("status_code", statusCode)
        })

        // Durable, append-only audit trail for security-relevant and mutating calls
        if (shouldAudit(toolName, url, host, isError)) {
            AuditLog.record(
                toolName, timestamp.toString(), elapsedMs, isError,
                args, url, host, method, statusCode
            )
        }
    }

    internal fun shouldAudit(toolName: String, url: String, host: String, isError: Boolean): Boolean =
        url.isNotEmpty() ||
            host.isNotEmpty() ||
            isError ||
            io.bitbytelab.raijin.safety.ActionPolicy.isDestructive(toolName) ||
            toolName in MUTATING_TOOL_NAMES ||
            MUTATING_TOOL_PREFIXES.any { toolName.startsWith(it) }

    /** Coroutine-bound holder for the most recent Montoya [HttpRequestResponse] sent during a tool call. */
    internal class HttpCaptureHolder(@Volatile var value: burp.api.montoya.http.message.HttpRequestResponse? = null)

    private val captureThreadLocal = ThreadLocal<HttpCaptureHolder?>()

    /**
     * Propagates [HttpCaptureHolder] across coroutine dispatcher hops / suspension points without
     * leaking thread-locals when a handler suspends, throws, or migrates across `Dispatchers.IO`.
     */
    private class ToolCallCaptureContext(
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
    fun recordSentResult(result: burp.api.montoya.http.message.HttpRequestResponse?) {
        captureThreadLocal.get()?.value = result
    }
}
