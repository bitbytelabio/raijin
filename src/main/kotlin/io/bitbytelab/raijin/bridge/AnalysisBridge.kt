package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.safety.BoundedHttp
import kotlinx.serialization.json.JsonObject

/**
 * Cross-cutting analysis bridge that combines multiple Montoya APIs
 * to perform request/response analysis, reflection detection,
 * parameter extraction, diff comparison, and response body searching.
 *
 * Raw messages are analysed offline by [AnalysisMessages] and compared by [AnalysisDiff], the
 * proxy history is searched by [AnalysisResponseSearch], and `auth_diff` runs in [AnalysisAuthDiff].
 */
class AnalysisBridge(api: MontoyaApi) {

    private val search = AnalysisResponseSearch(api)
    private val authDiffs = AnalysisAuthDiff(api)

    /** The parts of a raw HTTP request; see [AnalysisMessages.analyzeRequest]. */
    fun analyzeRequest(rawRequest: String): JsonObject = AnalysisMessages.analyzeRequest(rawRequest)

    /** The parts of a raw HTTP response; see [AnalysisMessages.analyzeResponse]. */
    fun analyzeResponse(rawResponse: String): JsonObject = AnalysisMessages.analyzeResponse(rawResponse)

    /** The request values a response reflects, with their context; see [AnalysisMessages.findReflected]. */
    fun findReflected(
        rawRequest: String,
        rawResponse: String,
        additionalValues: List<String>
    ): JsonObject = AnalysisMessages.findReflected(rawRequest, rawResponse, additionalValues)

    /** Every parameter of a raw HTTP request; see [AnalysisMessages.extractParams]. */
    fun extractParams(rawRequest: String): JsonObject = AnalysisMessages.extractParams(rawRequest)

    /** The insertion points of a raw HTTP request; see [AnalysisMessages.getInsertionPoints]. */
    fun getInsertionPoints(
        rawRequest: String,
        host: String,
        port: Int,
        useTls: Boolean
    ): JsonObject = AnalysisMessages.getInsertionPoints(rawRequest, host, port, useTls)

    /** Compares two requests or two responses; see [AnalysisDiff.diff]. */
    fun diff(item1: String, item2: String, type: String): JsonObject = AnalysisDiff.diff(item1, item2, type)

    /** Searches the proxy history's response bodies; see [AnalysisResponseSearch.searchResponseBodies]. */
    fun searchResponseBodies(pattern: String, maxResults: Int, inScopeOnly: Boolean): JsonObject =
        search.searchResponseBodies(pattern, maxResults, inScopeOnly)

    /** Sends a request as each identity and compares the answers; see [AnalysisAuthDiff.authDiff]. */
    fun authDiff(
        request: String,
        host: String,
        port: Int,
        useTls: Boolean,
        authLevels: List<JsonObject>,
        compareFields: List<String>?,
        deniedRegex: String? = null
    ): JsonObject = authDiffs.authDiff(request, host, port, useTls, authLevels, compareFields, deniedRegex)

    /**
     * Pure, Burp-independent helpers. Kept `internal` so unit tests can
     * exercise the parsing/validation logic without a live Montoya API
     * (the API is compileOnly and cannot be instantiated in tests).
     */
    internal companion object {

        /**
         * Normalizes line endings in a raw HTTP message to canonical CRLF.
         *
         * Callers frequently supply messages using bare LF delimiters (either
         * as literal newlines or as the escaped "\n"/"\r\n" sequences that
         * survive JSON transport). Montoya's parser is strict about CRLF header
         * delimiting, so an LF-only message would otherwise have its headers
         * silently dropped. Mirrors the 3-step normalization used in authDiff().
         */
        fun normalizeCrlfMessage(raw: String): String =
            io.bitbytelab.raijin.safety.RequestHygiene.normalizeCrlf(raw)

        /**
         * Produces a caller-safe description of a thrown exception. Some Montoya
         * internals raise exceptions with a null message (e.g. a bare
         * StringIndexOutOfBoundsException), which would otherwise surface as the
         * literal string "null" to MCP callers. Falling back to the simple class
         * name keeps the error actionable without leaking raw internals.
         */
        fun describeException(e: Throwable): String {
            val msg = e.message
            return if (msg.isNullOrBlank()) e.javaClass.simpleName else msg
        }

        /** See [AnalysisMessages.pathSegments]. */
        fun pathSegments(path: String): List<String> = AnalysisMessages.pathSegments(path)

        /** See [AnalysisAuthDiff.AUTH_DIFF_FIELDS]. */
        val AUTH_DIFF_FIELDS = AnalysisAuthDiff.AUTH_DIFF_FIELDS

        /** See [AnalysisResponseSearch.SEARCH_MAX_RESULTS]. */
        const val SEARCH_MAX_RESULTS = AnalysisResponseSearch.SEARCH_MAX_RESULTS

        /** See [AnalysisResponseSearch.matchBody]. */
        fun matchBody(pattern: String, body: String): AnalysisResponseSearch.BodyMatch? =
            AnalysisResponseSearch.matchBody(pattern, body)

        /** See [AnalysisAuthDiff.levelFailure]. */
        fun levelFailure(levelName: String, elapsedMs: Long, timeoutMs: Long = BoundedHttp.DEFAULT_TIMEOUT_MS): String =
            AnalysisAuthDiff.levelFailure(levelName, elapsedMs, timeoutMs)

        /** See [AnalysisAuthDiff.authDiffReport]. */
        fun authDiffReport(
            results: List<AuthLevelResponse>,
            errors: List<String>,
            fields: List<String> = AUTH_DIFF_FIELDS,
            url: String? = null,
            deniedRegex: String? = null
        ): JsonObject = AnalysisAuthDiff.authDiffReport(results, errors, fields, url, deniedRegex)
    }
}
