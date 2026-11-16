package io.bitbytelab.raijin.transport

import io.bitbytelab.raijin.state.StoredFinding
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.io.File
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Durable, per-project persistence for the agent's findings working memory
 * ([io.bitbytelab.raijin.state.StateManager.findings]) so it survives extension reloads, Burp restarts,
 * and crashes — the in-memory list is otherwise wiped by [io.bitbytelab.raijin.state.StateManager.cleanup]
 * on every unload, while the (persisted) MCP activity log still *shows* the historical
 * `findings_add` calls, making it look like the findings were lost for no reason.
 *
 * Mirrors [ActivityStore]: JSON Lines under the user home, appended per entry
 * (crash-safe), project-tagged so each engagement restores its own findings.
 * Deletes and clears rewrite the file atomically with the project's section replaced,
 * preserving other projects' lines.
 */
class FindingsFileStore(private val file: File) {
    private val lock = ReentrantLock()
    private val json = Json { ignoreUnknownKeys = true }

    @Volatile
    var lastError: String? = null
        private set

    fun path(): String = file.absolutePath

    fun append(f: StoredFinding, project: String) {
        lock.withLock {
            try {
                JsonlStoreSupport.appendLine(file, FindingsStore.buildEntry(f, project))
                lastError = null
            } catch (ex: Exception) {
                recordError("append", ex)
            }
        }
    }

    fun load(project: String): List<StoredFinding> = lock.withLock {
        try {
            if (!file.exists()) emptyList()
            else file.readLines().mapNotNull { FindingsStore.parseEntry(it) }
                .filter { it.second == project }
                .map { it.first }
        } catch (ex: Exception) {
            recordError("load", ex)
            emptyList()
        }
    }

    fun replaceProject(project: String, findings: List<StoredFinding>) {
        lock.withLock {
            try {
                val existing = if (file.exists()) {
                    file.readLines().mapNotNull { FindingsStore.parseEntry(it) }
                } else {
                    emptyList()
                }
                val lines = FindingsStore.rebuildLines(existing, project, findings)
                if (lines.isEmpty()) {
                    if (file.exists()) file.delete()
                } else {
                    JsonlStoreSupport.atomicWriteLines(file, lines)
                }
                lastError = null
            } catch (ex: Exception) {
                recordError("replaceProject", ex)
            }
        }
    }

    private fun recordError(op: String, ex: Exception) {
        lastError = ex.message ?: ex::class.simpleName
        System.err.println("Raijin: FindingsStore.$op failed (${file.absolutePath}): $lastError")
    }
}

object FindingsStore {
    private val defaultStore = FindingsFileStore(File(System.getProperty("user.home") ?: ".", ".raijin-findings.jsonl"))
    private val json = Json { ignoreUnknownKeys = true }

    val lastError: String? get() = defaultStore.lastError

    fun path(): String = defaultStore.path()

    /** Serializes one finding to a JSONL record (pure; no I/O). */
    fun buildEntry(f: StoredFinding, project: String): String = buildJsonObject {
        put("id", f.id)
        put("type", f.type)
        put("severity", f.severity)
        put("url", f.url)
        put("location", f.location)
        put("detail", f.detail)
        put("evidence", f.evidence)
        put("cvss_score", f.cvssScore)
        put("cvss_vector", f.cvssVector)
        put("owasp_category", f.owaspCategory)
        put("steps_to_reproduce", f.stepsToReproduce)
        put("request", f.request)
        put("response", f.response)
        put("created_at", f.createdAt)
        put("project", project)
    }.toString()

    /** Parses a JSONL record back to (finding, project); null if malformed (pure; no I/O). */
    fun parseEntry(line: String): Pair<StoredFinding, String>? = try {
        val o = json.parseToJsonElement(line).jsonObject
        StoredFinding(
            id = o["id"]?.jsonPrimitive?.contentOrNull ?: "",
            type = o["type"]?.jsonPrimitive?.contentOrNull ?: "",
            severity = o["severity"]?.jsonPrimitive?.contentOrNull ?: "",
            url = o["url"]?.jsonPrimitive?.contentOrNull ?: "",
            location = o["location"]?.jsonPrimitive?.contentOrNull ?: "",
            detail = o["detail"]?.jsonPrimitive?.contentOrNull ?: "",
            evidence = o["evidence"]?.jsonPrimitive?.contentOrNull ?: "",
            createdAt = o["created_at"]?.jsonPrimitive?.contentOrNull ?: "",
            cvssScore = o["cvss_score"]?.jsonPrimitive?.contentOrNull ?: "",
            cvssVector = o["cvss_vector"]?.jsonPrimitive?.contentOrNull ?: "",
            owaspCategory = o["owasp_category"]?.jsonPrimitive?.contentOrNull ?: "",
            stepsToReproduce = o["steps_to_reproduce"]?.jsonPrimitive?.contentOrNull ?: "",
            request = o["request"]?.jsonPrimitive?.contentOrNull ?: "",
            response = o["response"]?.jsonPrimitive?.contentOrNull ?: ""
        ) to (o["project"]?.jsonPrimitive?.contentOrNull ?: "")
    } catch (_: Exception) {
        null
    }

    /** Appends one finding to the durable store (oldest-first file order). */
    fun append(f: StoredFinding, project: String) = defaultStore.append(f, project)

    /** Loads all findings for [project] in file order (oldest-first). Empty on any error. */
    fun load(project: String): List<StoredFinding> = defaultStore.load(project)

    /**
     * Pure: rebuild the file's lines, dropping every finding tagged [project] and
     * re-adding [replacementForProject] for that project. A delete/clear is
     * `replacementForProject = emptyList()`; other projects' lines are preserved.
     * Returns oldest-first file order.
     */
    fun rebuildLines(
        parsed: List<Pair<StoredFinding, String>>,
        project: String,
        replacementForProject: List<StoredFinding>
    ): List<String> {
        val others = parsed.filter { it.second != project }.map { buildEntry(it.first, it.second) }
        val mine = replacementForProject.map { buildEntry(it, project) }
        return others + mine
    }

    /** Reads the store, replaces [project]'s findings with [findings], and rewrites (deletes file if empty). */
    fun replaceProject(project: String, findings: List<StoredFinding>) = defaultStore.replaceProject(project, findings)
}
