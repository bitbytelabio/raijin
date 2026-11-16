package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.core.BodyText
import io.bitbytelab.raijin.safety.SafeRegex
import kotlinx.serialization.json.*

/**
 * The proxy history's response bodies searched with a caller-supplied regex, for [AnalysisBridge],
 * within a time budget and body size cap.
 */
internal class AnalysisResponseSearch(private val api: MontoyaApi) {

    /** [value] is the matched text (capped), [snippet] the match with some context around it. */
    data class BodyMatch(val value: String, val position: Int, val snippet: String)

    /**
     * Searches response bodies across proxy history for a regex pattern (case-insensitive).
     *
     * The pattern is caller-supplied, so every match goes through [SafeRegex]: an invalid pattern
     * is reported instead of thrown, one body holds the search for at most [SEARCH_BODY_TIMEOUT_MS],
     * and the whole call stops after [SEARCH_BUDGET_MS] with what it found so far (`incomplete`).
     *
     * @param pattern Regex pattern to search for.
     * @param maxResults Maximum number of matching results (1..[SEARCH_MAX_RESULTS]).
     * @param inScopeOnly Whether to limit search to in-scope items.
     */
    fun searchResponseBodies(pattern: String, maxResults: Int, inScopeOnly: Boolean): JsonObject {
        SafeRegex.validate(pattern, ignoreCase = true)?.let { err ->
            return buildJsonObject { put("error", "Invalid regex: $err") }
        }
        val limit = maxResults.coerceIn(1, SEARCH_MAX_RESULTS)

        val proxyHistory = api.proxy().history()
        val deadline = System.nanoTime() + SEARCH_BUDGET_MS * 1_000_000
        var scanned = 0
        var oversize = 0
        var incomplete = false
        val matches = buildJsonArray {
            var matchCount = 0
            for (entry in proxyHistory) {
                if (matchCount >= limit) break
                if (System.nanoTime() > deadline) {
                    incomplete = true
                    break
                }

                try {
                    val req = entry.finalRequest() ?: continue
                    val resp = entry.originalResponse() ?: continue
                    val url = req.url()

                    if (inScopeOnly && !api.scope().isInScope(url)) continue

                    val responseBody = resp.bodyToString()
                    scanned++
                    if (responseBody.length > SEARCH_MAX_BODY_CHARS) {
                        oversize++
                        continue
                    }
                    val match = matchBody(pattern, responseBody) ?: continue
                    addJsonObject {
                        put("url", url)
                        put("method", req.method())
                        put("status_code", resp.statusCode())
                        put("match_value", match.value)
                        put("match_position", match.position)
                        put("snippet", match.snippet)
                    }
                    matchCount++
                } catch (_: Exception) {
                    // Skip entries that fail to parse
                }
            }
        }

        return buildJsonObject {
            put("pattern", pattern)
            put("in_scope_only", inScopeOnly)
            put("match_count", matches.size)
            put("max_results", limit)
            put("entries_scanned", scanned)
            if (oversize > 0) put("skipped_oversize_bodies", oversize)
            if (incomplete) {
                put("incomplete", true)
                put(
                    "note",
                    "Stopped after ${SEARCH_BUDGET_MS / 1000}s with part of the history searched: narrow it with in_scope_only or use a cheaper pattern."
                )
            }
            put("matches", matches)
        }
    }

    companion object {
        /** Largest `max_results` of a response-body search. */
        const val SEARCH_MAX_RESULTS = 500

        /** Whole-call budget of a response-body search; it returns what it has when this runs out. */
        const val SEARCH_BUDGET_MS = 20_000L

        /** Longest time one body may hold the search (a pattern that backtracks on it is abandoned). */
        const val SEARCH_BODY_TIMEOUT_MS = 500L

        /** Bodies longer than this are not searched; they are counted as skipped. */
        const val SEARCH_MAX_BODY_CHARS = 2_000_000

        private const val SEARCH_MATCH_CHARS = 500
        private const val SEARCH_CONTEXT_CHARS = 50

        /**
         * First match of the caller-supplied [pattern] in [body], or null when there is none, the
         * pattern is invalid, or matching ran out of time. Output is capped and safe to serialize
         * whatever the body holds.
         */
        fun matchBody(pattern: String, body: String): BodyMatch? {
            val match = SafeRegex.find(
                pattern, body, ignoreCase = true,
                maxInputLen = SEARCH_MAX_BODY_CHARS, timeoutMs = SEARCH_BODY_TIMEOUT_MS
            ) ?: return null
            val start = match.range.first
            val shownEnd = minOf(match.range.last + 1, start + SEARCH_MATCH_CHARS)
            val snippet = body.substring(
                maxOf(0, start - SEARCH_CONTEXT_CHARS),
                minOf(body.length, shownEnd + SEARCH_CONTEXT_CHARS)
            )
            return BodyMatch(
                value = BodyText.stripLoneSurrogates(BodyText.truncate(match.value, SEARCH_MATCH_CHARS)),
                position = start,
                snippet = BodyText.stripLoneSurrogates(snippet)
            )
        }
    }
}
