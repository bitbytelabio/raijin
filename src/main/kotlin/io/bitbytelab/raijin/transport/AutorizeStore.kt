package io.bitbytelab.raijin.transport

import io.bitbytelab.raijin.core.BodyText
import io.bitbytelab.raijin.state.AutorizeMatch
import io.bitbytelab.raijin.state.AutorizeReplay
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import java.io.File
import java.nio.file.Files
import kotlin.concurrent.withLock

/**
 * File-backed store of Autorize matches. All operations on one file share
 * [JsonlStoreSupport.lockFor]. Matches carry message text, so the file is bounded by size rather
 * than by line count: once it grows past [maxBytes] it is trimmed to the newest lines that fit in
 * half of that.
 */
class AutorizeFileStore(private val file: File, private val maxBytes: Long = AutorizeStore.MAX_BYTES) {
    private val lock = JsonlStoreSupport.lockFor(file)

    @Volatile
    var lastError: String? = null
        private set

    fun path(): String = file.absolutePath

    fun append(match: AutorizeMatch, project: String) {
        lock.withLock {
            try {
                JsonlStoreSupport.appendLine(file, AutorizeStore.buildEntry(match, project))
                if (maxBytes > 0 && file.length() > maxBytes) compactLocked()
                succeeded()
            } catch (ex: Exception) {
                failed("append", ex)
            }
        }
    }

    /** Up to [max] most recent matches of [project], newest first. Empty on any error. */
    fun load(project: String, max: Int): List<AutorizeMatch> = lock.withLock {
        try {
            val res = AutorizeStore.selectForProject(AutorizeStore.dedupe(readParsed()), project, max)
            succeeded()
            res
        } catch (ex: Exception) {
            failed("load", ex)
            emptyList()
        }
    }

    /**
     * Replaces [project]'s saved matches with [snapshot] (newest first, as the live log), evaluated
     * while the file lock is held. Other projects' lines are kept.
     */
    fun replaceProject(project: String, snapshot: () -> List<AutorizeMatch>) {
        lock.withLock {
            try {
                val lines = AutorizeStore.rebuildLines(AutorizeStore.dedupe(readParsed()), project, snapshot().asReversed())
                if (lines.isEmpty()) Files.deleteIfExists(file.toPath()) else JsonlStoreSupport.atomicWriteLines(file, lines)
                succeeded()
            } catch (ex: Exception) {
                failed("replaceProject", ex)
            }
        }
    }

    private fun compactLocked() {
        val kept = AutorizeStore.newestWithin(file.readLines(), maxBytes / 2)
        JsonlStoreSupport.atomicWriteLines(file, kept)
    }

    private fun readParsed(): List<Pair<AutorizeMatch, String>> =
        if (file.exists()) file.readLines().mapNotNull { AutorizeStore.parseEntry(it) } else emptyList()

    private fun succeeded() {
        lastError = null
        JsonlStoreSupport.recovered(file)
    }

    private fun failed(op: String, ex: Exception) {
        lastError = JsonlStoreSupport.reportFailure("AutorizeStore", op, file, ex)
    }
}

/**
 * Durable, per-project persistence for the matches of the live Autorize taps
 * ([io.bitbytelab.raijin.state.StateManager.autorizeMatches]), so what a tap flagged survives an
 * extension reload or a Burp restart. Mirrors [FindingsStore]: JSON Lines under the user home,
 * appended per match (crash-safe) and project-tagged so each engagement restores its own. A clear
 * rewrites the file atomically with the project's section replaced.
 *
 * The rules themselves are not saved: they hold session credentials and are set again per session.
 */
object AutorizeStore {
    /** File size beyond which the store is trimmed to its newest lines. */
    const val MAX_BYTES = 64L * 1024 * 1024

    /** The store the extension uses, under the user home. */
    val defaultStore = AutorizeFileStore(File(System.getProperty("user.home") ?: ".", ".raijin-autorize.jsonl"))

    private val json = Json { ignoreUnknownKeys = true }

    /** Serializes one match to a JSONL record (pure; no I/O). */
    fun buildEntry(m: AutorizeMatch, project: String): String = buildJsonObject {
        put("id", m.id)
        put("rule_id", m.ruleId)
        put("ts", m.timestamp)
        put("method", m.method)
        put("url", m.url)
        put("original_status", m.originalStatus)
        put("soft_denial", m.softDenial)
        put("findings", buildJsonArray { m.findings.forEach { add(it) } })
        put("request", encodable(m.request))
        put("response", encodable(m.response))
        put("replays", buildJsonArray {
            m.replays.forEach { replay ->
                add(buildJsonObject {
                    put("identity", replay.identity)
                    put("status", replay.status)
                    put("request", encodable(replay.request))
                    put("response", encodable(replay.response))
                })
            }
        })
        put("project", project)
    }.toString()

    /** Parses a JSONL record back to (match, project); null if malformed (pure; no I/O). */
    fun parseEntry(line: String): Pair<AutorizeMatch, String>? = try {
        val o = json.parseToJsonElement(line).jsonObject
        AutorizeMatch(
            id = o["id"]?.jsonPrimitive?.longOrNull ?: 0L,
            ruleId = o.text("rule_id"),
            timestamp = o.text("ts"),
            method = o.text("method"),
            url = o.text("url"),
            originalStatus = o["original_status"]?.jsonPrimitive?.intOrNull ?: 0,
            findings = (o["findings"] as? JsonArray).orEmpty().filterIsInstance<JsonObject>(),
            request = o.text("request"),
            response = o.text("response"),
            replays = (o["replays"] as? JsonArray).orEmpty().filterIsInstance<JsonObject>().map { r ->
                AutorizeReplay(
                    identity = r.text("identity"),
                    status = r["status"]?.jsonPrimitive?.intOrNull ?: 0,
                    request = r.text("request"),
                    response = r.text("response"),
                )
            },
            softDenial = o["soft_denial"]?.jsonPrimitive?.booleanOrNull ?: false,
        ) to o.text("project")
    } catch (_: Exception) {
        null
    }

    /**
     * Pure: given parsed (match, project) pairs in file order (oldest first), the last [max]
     * matches of [project], newest first (the order of the live log).
     */
    fun selectForProject(parsed: List<Pair<AutorizeMatch, String>>, project: String, max: Int): List<AutorizeMatch> =
        parsed.filter { it.second == project }.map { it.first }.takeLast(max.coerceAtLeast(0)).asReversed()

    /**
     * Pure: drops repeated records of one match (same project, id and timestamp), keeping the first.
     * They come from an append racing with a rewrite that already included the match.
     */
    fun dedupe(parsed: List<Pair<AutorizeMatch, String>>): List<Pair<AutorizeMatch, String>> =
        parsed.distinctBy { (match, project) -> Triple(project, match.id, match.timestamp) }

    /**
     * Pure: rebuild the file's lines, dropping every match tagged [project] and re-adding
     * [replacementForProject] (oldest first) for it. Other projects' lines are preserved.
     */
    fun rebuildLines(
        parsed: List<Pair<AutorizeMatch, String>>,
        project: String,
        replacementForProject: List<AutorizeMatch>,
    ): List<String> {
        val others = parsed.filter { it.second != project }.map { buildEntry(it.first, it.second) }
        val mine = replacementForProject.map { buildEntry(it, project) }
        return others + mine
    }

    /**
     * Pure: the newest of [lines] (file order, oldest first) whose text fits in [budget] characters,
     * in file order. The newest line is kept whatever its size.
     */
    fun newestWithin(lines: List<String>, budget: Long): List<String> {
        var used = 0L
        var first = lines.size
        while (first > 0) {
            val size = lines[first - 1].length + 1L
            if (first < lines.size && used + size > budget) break
            used += size
            first--
        }
        return lines.subList(first, lines.size)
    }

    /** Message text as a JSON string that always encodes: an unpaired surrogate has no UTF-8 form and would fail the write. */
    private fun encodable(text: String): String = BodyText.stripLoneSurrogates(text)

    private fun JsonObject.text(key: String): String = this[key]?.jsonPrimitive?.contentOrNull ?: ""
}
