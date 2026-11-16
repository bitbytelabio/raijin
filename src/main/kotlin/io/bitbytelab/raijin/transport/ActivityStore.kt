package io.bitbytelab.raijin.transport

import io.bitbytelab.raijin.state.McpActivityEntry
import kotlinx.serialization.json.*
import java.io.File
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

class ActivityFileStore(private val file: File) {
    private val lock = ReentrantLock()

    @Volatile
    var lastError: String? = null
        private set

    fun path(): String = file.absolutePath

    fun append(e: McpActivityEntry, project: String, enabled: Boolean) {
        if (!enabled) return
        lock.withLock {
            try {
                JsonlStoreSupport.appendLine(file, ActivityStore.buildEntry(e, project))
                lastError = null
            } catch (ex: Exception) {
                recordError("append", ex)
            }
        }
    }

    fun rewriteProject(project: String, replacement: List<McpActivityEntry>) {
        lock.withLock {
            try {
                val existing = if (file.exists()) file.readLines().mapNotNull { ActivityStore.parseEntry(it) } else emptyList()
                val lines = ActivityStore.rebuildLines(existing, project, replacement)
                if (lines.isEmpty()) {
                    if (file.exists()) file.delete()
                } else {
                    JsonlStoreSupport.atomicWriteLines(file, lines)
                }
                lastError = null
            } catch (ex: Exception) {
                recordError("rewriteProject", ex)
            }
        }
    }

    fun load(project: String, max: Int): List<McpActivityEntry> = lock.withLock {
        try {
            if (!file.exists()) emptyList()
            else {
                val res = ActivityStore.selectForProject(file.readLines().mapNotNull { ActivityStore.parseEntry(it) }, project, max)
                lastError = null
                res
            }
        } catch (ex: Exception) {
            recordError("load", ex)
            emptyList()
        }
    }

    fun compact(maxLines: Int) {
        lock.withLock {
            try {
                if (!file.exists()) return
                val lines = file.readLines()
                if (lines.size <= maxLines) return
                JsonlStoreSupport.atomicWriteLines(file, lines.takeLast(maxLines))
                lastError = null
            } catch (ex: Exception) {
                recordError("compact", ex)
            }
        }
    }

    private fun recordError(op: String, ex: Exception) {
        lastError = ex.message ?: ex::class.simpleName
        System.err.println("Raijin: ActivityStore.$op failed (${file.absolutePath}): $lastError")
    }
}

/**
 * Durable, append-only persistence for the dashboard's MCP activity log so it survives
 * extension reloads, Burp restarts, and crashes — the in-memory `StateManager.mcpActivity`
 * deque (and the EventBus that drives the web dashboard) are otherwise recreated empty on
 * every reload, wiping the dashboard.
 *
 * Mirrors [AuditLog]: JSON Lines under the user home, appended per entry (crash-safe, no
 * project-file bloat), and **project-tagged** so reopening an engagement restores its own
 * history. On startup the extension loads the current project's most-recent entries back
 * into the deque (Swing tab) and re-seeds the EventBus (web dashboard) via [toEventData].
 *
 * The heavy `HttpRequestResponse` field is NOT persisted (a Montoya object); restored rows
 * have it null, so only the raw Request/Response detail tabs are empty for restored entries —
 * the table, Info panel, and web dashboard are fully repopulated.
 */
object ActivityStore {
    private const val MAX_SUMMARY = 4000

    /** Upper bound on retained file lines; older lines are dropped on startup [compact]. */
    const val MAX_LINES = 20000

    private val defaultStore = ActivityFileStore(File(System.getProperty("user.home") ?: ".", ".raijin-activity.jsonl"))
    private val json = Json { ignoreUnknownKeys = true }

    val lastError: String? get() = defaultStore.lastError

    fun path(): String = defaultStore.path()

    /**
     * Whether new entries are written to disk. Operator-controlled (Burp pref
     * `mcp_persist_activity`, default true) via the Server/Activity tab toggle. When false,
     * [append] no-ops so MCP activity is session-only (pre-2.2.0 behaviour). See issue #8.
     */
    @Volatile
    var enabled: Boolean = true

    /** Serializes one activity entry to a JSONL record (pure; no I/O). */
    fun buildEntry(e: McpActivityEntry, project: String): String = buildJsonObject {
        put("id", e.id)
        put("ts", e.timestamp)
        put("tool", e.toolName)
        put("duration_ms", e.durationMs)
        put("method", e.method)
        put("url", e.url)
        put("host", e.host)
        put("status_code", e.statusCode)
        put("is_error", e.isError)
        put("args", e.argsSummary.take(MAX_SUMMARY))
        put("result", e.resultSummary.take(MAX_SUMMARY))
        put("project", project)
    }.toString()

    /** Parses a JSONL record back to (entry, project); null if malformed (pure; no I/O). */
    fun parseEntry(line: String): Pair<McpActivityEntry, String>? = try {
        val o = json.parseToJsonElement(line).jsonObject
        McpActivityEntry(
            id = o["id"]?.jsonPrimitive?.longOrNull ?: 0L,
            toolName = o["tool"]?.jsonPrimitive?.contentOrNull ?: "",
            timestamp = o["ts"]?.jsonPrimitive?.contentOrNull ?: "",
            durationMs = o["duration_ms"]?.jsonPrimitive?.longOrNull ?: 0L,
            method = o["method"]?.jsonPrimitive?.contentOrNull ?: "",
            url = o["url"]?.jsonPrimitive?.contentOrNull ?: "",
            host = o["host"]?.jsonPrimitive?.contentOrNull ?: "",
            statusCode = o["status_code"]?.jsonPrimitive?.intOrNull ?: 0,
            isError = o["is_error"]?.jsonPrimitive?.booleanOrNull ?: false,
            argsSummary = o["args"]?.jsonPrimitive?.contentOrNull ?: "",
            resultSummary = o["result"]?.jsonPrimitive?.contentOrNull ?: "",
            requestResponse = null
        ) to (o["project"]?.jsonPrimitive?.contentOrNull ?: "")
    } catch (_: Exception) {
        null
    }

    /**
     * Pure: given parsed (entry, project) pairs in file order (oldest-first), return the last
     * [max] entries for [project], **newest-first** (matching the live deque's ordering).
     */
    fun selectForProject(parsed: List<Pair<McpActivityEntry, String>>, project: String, max: Int): List<McpActivityEntry> =
        parsed.filter { it.second == project }.map { it.first }.takeLast(max.coerceAtLeast(0)).asReversed()

    /** The web-dashboard `tool.called` event payload for a restored entry (pure; mirrors ToolCallTracker). */
    fun toEventData(e: McpActivityEntry): JsonObject = buildJsonObject {
        put("tool_name", e.toolName)
        put("timestamp", e.timestamp)
        put("duration_ms", e.durationMs)
        put("is_error", e.isError)
        put("arguments", try { json.parseToJsonElement(e.argsSummary) } catch (_: Exception) { JsonPrimitive(e.argsSummary) })
        put("result_summary", e.resultSummary)
        put("url", e.url)
        put("method", e.method)
        put("host", e.host)
        put("status_code", e.statusCode)
    }

    /** Appends one entry to the durable store. No-ops when [enabled] is false (session-only mode). */
    fun append(e: McpActivityEntry, project: String) = defaultStore.append(e, project, enabled)

    /**
     * Pure: rebuild the file's lines, dropping every entry tagged [project] and re-adding
     * [replacementForProject] (given oldest-first) for that project. A delete is
     * `replacementForProject = emptyList()`; a flush passes the current in-memory entries. Other
     * projects' lines are preserved (the store is multi-project). Returns oldest-first file order.
     */
    fun rebuildLines(
        parsed: List<Pair<McpActivityEntry, String>>,
        project: String,
        replacementForProject: List<McpActivityEntry>
    ): List<String> {
        val others = parsed.filter { it.second != project }.map { buildEntry(it.first, it.second) }
        val mine = replacementForProject.map { buildEntry(it, project) }
        return others + mine
    }

    /** Permanently deletes [project]'s saved history from disk (keeps other projects). Issue #8. */
    fun deleteForProject(project: String) = defaultStore.rewriteProject(project, emptyList())

    /**
     * Snapshots the current in-memory [entries] (newest-first, as the live deque) to disk for
     * [project], replacing any prior saved entries for it. Used by "flush on enable" so turning
     * persistence on saves what you already have — not just future calls.
     */
    fun flushProject(entries: List<McpActivityEntry>, project: String) =
        defaultStore.rewriteProject(project, entries.asReversed())

    /** Loads up to [max] most-recent entries for [project], newest-first. Empty on any error. */
    fun load(project: String, max: Int): List<McpActivityEntry> = defaultStore.load(project, max)

    /** Bounds file growth by rewriting only the last [maxLines] lines. Called on startup. */
    fun compact(maxLines: Int) = defaultStore.compact(maxLines)
}
