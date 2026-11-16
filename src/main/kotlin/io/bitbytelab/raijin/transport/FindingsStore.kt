package io.bitbytelab.raijin.transport

import io.bitbytelab.raijin.state.StoredFinding
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.io.File
import java.nio.file.Files
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
 * preserving other projects' lines. All operations on one file share [JsonlStoreSupport.lockFor].
 */
class FindingsFileStore(private val file: File) {
    private val lock = JsonlStoreSupport.lockFor(file)

    @Volatile
    var lastError: String? = null
        private set

    fun path(): String = file.absolutePath

    fun append(f: StoredFinding, project: String) {
        lock.withLock {
            try {
                JsonlStoreSupport.appendLine(file, FindingsStore.buildEntry(f, project))
                succeeded()
            } catch (ex: Exception) {
                failed("append", ex)
            }
        }
    }

    fun load(project: String): List<StoredFinding> = lock.withLock {
        try {
            val res = FindingsStore.dedupe(readParsed()).filter { it.second == project }.map { it.first }
            succeeded()
            res
        } catch (ex: Exception) {
            failed("load", ex)
            emptyList()
        }
    }

    fun replaceProject(project: String, findings: List<StoredFinding>) = replaceProject(project) { findings }

    /**
     * Replaces [project]'s saved findings with [snapshot], evaluated while the file lock is held. A
     * finding added meanwhile is in the snapshot, appended after the rewrite, or both (the duplicate
     * is dropped on load), so a caller on any thread loses nothing.
     */
    fun replaceProject(project: String, snapshot: () -> List<StoredFinding>) {
        lock.withLock {
            try {
                val lines = FindingsStore.rebuildLines(FindingsStore.dedupe(readParsed()), project, snapshot())
                if (lines.isEmpty()) Files.deleteIfExists(file.toPath()) else JsonlStoreSupport.atomicWriteLines(file, lines)
                succeeded()
            } catch (ex: Exception) {
                failed("replaceProject", ex)
            }
        }
    }

    private fun readParsed(): List<Pair<StoredFinding, String>> =
        if (file.exists()) file.readLines().mapNotNull { FindingsStore.parseEntry(it) } else emptyList()

    private fun succeeded() {
        lastError = null
        JsonlStoreSupport.recovered(file)
    }

    private fun failed(op: String, ex: Exception) {
        lastError = JsonlStoreSupport.reportFailure("FindingsStore", op, file, ex)
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

    /**
     * Pure: drops repeated records of one finding (same project, id and creation time), keeping the
     * first. They come from an append racing with a rewrite that already included the finding.
     */
    fun dedupe(parsed: List<Pair<StoredFinding, String>>): List<Pair<StoredFinding, String>> =
        parsed.distinctBy { (finding, project) -> Triple(project, finding.id, finding.createdAt) }

    /** Reads the store, replaces [project]'s findings with [findings], and rewrites (deletes file if empty). */
    fun replaceProject(project: String, findings: List<StoredFinding>) = defaultStore.replaceProject(project, findings)

    /** Like [replaceProject], but [snapshot] is taken under the file lock: safe from any thread. */
    fun replaceProject(project: String, snapshot: () -> List<StoredFinding>) = defaultStore.replaceProject(project, snapshot)
}
