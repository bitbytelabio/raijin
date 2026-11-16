package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import io.bitbytelab.raijin.safety.SafeRegex
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray

// Dry runs of custom checks (scan checks and BChecks) against the proxy history: what a check
// would match in traffic Burp has already recorded. Nothing here sends a request.

/** One proxy history entry as a dry run sees it. */
internal class HistoryItem(
    val id: Int,
    val method: String,
    val url: String,
    val host: String,
    val path: String,
    val exchange: CheckExchange,
)

/** Which history items a dry run reads: the newest [maxItems] that pass the filters. */
internal class HistoryFilter private constructor(
    val urlPattern: String?,
    val inScopeOnly: Boolean,
    val maxItems: Int,
) {
    fun toJson(): JsonObject = buildJsonObject {
        if (urlPattern != null) put("url_pattern", urlPattern)
        put("in_scope_only", inScopeOnly)
        put("max_items", maxItems)
    }

    companion object {
        const val DEFAULT_ITEMS = 200
        const val MAX_ITEMS = 5000
        const val DEFAULT_MATCHES = 20
        const val MAX_MATCHES = 200

        /** @throws InvalidCheckException on an invalid `url_pattern` or an out-of-range `max_items`. */
        fun of(urlPattern: String?, inScopeOnly: Boolean, maxItems: Int?): HistoryFilter {
            val pattern = urlPattern?.takeIf { it.isNotEmpty() }
            if (pattern != null) {
                SafeRegex.validate(pattern, ignoreCase = true)?.let {
                    throw InvalidCheckException("Invalid url_pattern regex: $it")
                }
            }
            return HistoryFilter(pattern, inScopeOnly, bounded(maxItems, DEFAULT_ITEMS, MAX_ITEMS, "max_items"))
        }

        /** How many matches a dry run lists in full. @throws InvalidCheckException when out of range. */
        fun matchLimit(maxMatches: Int?): Int = bounded(maxMatches, DEFAULT_MATCHES, MAX_MATCHES, "max_matches")

        private fun bounded(value: Int?, default: Int, max: Int, param: String): Int {
            if (value == null) return default
            if (value !in 1..max) throw InvalidCheckException("$param must be between 1 and $max")
            return value
        }
    }
}

/** Reads the proxy history for a dry run. */
internal class HistorySampler(private val api: MontoyaApi) {

    /**
     * Hands the newest items that pass [filter] to [visit], newest first, one at a time so only
     * one message body is held in memory.
     *
     * @param parts the message parts the run looks at ([CheckCondition.location] values); only
     *   those are read from Burp.
     * @return the size of the whole proxy history.
     */
    fun forEach(filter: HistoryFilter, parts: Set<String>, visit: (HistoryItem) -> Unit): Int {
        val history = api.proxy().history()
        val newestFirst = history.listIterator(history.size)
        var visited = 0
        while (visited < filter.maxItems && newestFirst.hasPrevious()) {
            // A malformed entry throws from url()/httpService(); it is skipped, not fatal.
            val item = try { read(newestFirst.previous(), filter, parts) } catch (_: Exception) { null } ?: continue
            visit(item)
            visited++
        }
        return history.size
    }

    private fun read(entry: ProxyHttpRequestResponse, filter: HistoryFilter, parts: Set<String>): HistoryItem? {
        val request = entry.finalRequest()
        val url = request.url()
        if (filter.urlPattern != null && !SafeRegex.containsMatchIn(filter.urlPattern, url, ignoreCase = true)) return null
        if (filter.inScopeOnly && !request.isInScope) return null
        val response = if (entry.hasResponse()) entry.originalResponse() else null
        return HistoryItem(
            id = entry.id(),
            method = request.method(),
            url = url,
            host = request.httpService().host(),
            path = request.pathWithoutQuery(),
            exchange = exchangeOf(request, response, parts),
        )
    }
}

/** A history item as dry-run output refers to it; `index` is what the proxy tools call it. */
internal fun historyRef(item: HistoryItem, extra: JsonObjectBuilder.() -> Unit = {}): JsonObject = buildJsonObject {
    put("index", item.id)
    put("method", item.method)
    put("url", item.url)
    if (item.exchange.hasResponse) put("status", item.exchange.statusCode)
    extra()
}

/** The common frame of every dry-run result around the figures in [body]. */
internal fun dryRunReport(
    check: String,
    historySize: Int,
    filter: HistoryFilter,
    body: JsonObject,
    note: String,
): JsonObject = buildJsonObject {
    put("dry_run", true)
    put("check", check)
    put("requests_sent", 0)
    put("history_size", historySize)
    put("history_filter", filter.toJson())
    body.forEach { (key, value) -> put(key, value) }
    put("note", note)
}

/** What a set of conditions would report over the history items it is shown. */
internal class PassiveDryRun(
    private val conditions: List<CheckCondition>,
    private val mode: MatchMode,
    private val maxMatches: Int,
) {
    /** The message parts this run reads. */
    val parts: Set<String> = ScanCheckLogic.locations(conditions)

    private var evaluated = 0
    private var withoutResponse = 0
    private var hits = 0
    private val paths = HashSet<String>()
    private val matches = ArrayList<JsonObject>()

    fun visit(item: HistoryItem) {
        evaluated++
        if (!item.exchange.hasResponse) withoutResponse++
        if (!ScanCheckLogic.satisfied(conditions, mode, item.exchange)) return
        hits++
        paths += item.host + item.path
        if (matches.size >= maxMatches) return
        matches += historyRef(item) {
            putJsonArray("matched") {
                conditions.forEachIndexed { i, condition ->
                    if (!ScanCheckLogic.matches(condition, item.exchange)) return@forEachIndexed
                    addJsonObject {
                        put("condition", i)
                        ScanCheckLogic.excerpt(condition, item.exchange)?.let { put("excerpt", it) }
                    }
                }
            }
        }
    }

    /** `distinct_paths` is how many issues remain once Burp consolidates by path. */
    fun toJson(): JsonObject = buildJsonObject {
        put("items_evaluated", evaluated)
        put("items_without_response", withoutResponse)
        put("would_report", hits)
        put("distinct_paths", paths.size)
        put("matches", JsonArray(matches))
        if (hits > matches.size) put("matches_omitted", hits - matches.size)
    }
}

/**
 * For an active check: how many recorded responses already satisfy each step with no payload
 * sent. Where the baseline satisfies a step, that step cannot count as evidence, and a request
 * whose baseline satisfies every judging step can never be reported.
 *
 * Only a step's conditions on the response are evaluated: the request a payload produces is not
 * in the history.
 */
internal class BaselineDryRun(private val steps: List<ActiveStep>, private val maxExamples: Int) {
    private val responseConditions = steps.map { step -> step.conditions.filter { it.onResponse } }
    private val judging = steps.indices.filter { responseConditions[it].isNotEmpty() }

    /** The message parts this run reads. */
    val parts: Set<String> = ScanCheckLogic.locations(responseConditions.flatten())

    private val baselineMatches = IntArray(steps.size)
    private val examples = List(steps.size) { ArrayList<JsonObject>() }
    private var evaluated = 0
    private var withoutResponse = 0
    private var neverReportable = 0

    fun visit(item: HistoryItem) {
        evaluated++
        if (!item.exchange.hasResponse) {
            withoutResponse++
            return
        }
        var everyStepMatches = judging.isNotEmpty()
        for (i in judging) {
            if (ScanCheckLogic.satisfied(responseConditions[i], steps[i].mode, item.exchange)) {
                baselineMatches[i]++
                if (examples[i].size < maxExamples) examples[i] += historyRef(item)
            } else {
                everyStepMatches = false
            }
        }
        if (everyStepMatches) neverReportable++
    }

    fun toJson(): JsonObject = buildJsonObject {
        put("items_evaluated", evaluated)
        put("items_without_response", withoutResponse)
        putJsonArray("steps") {
            steps.forEachIndexed { i, step ->
                addJsonObject {
                    put("step", i + 1)
                    put("payload", step.payload)
                    if (i in judging) {
                        put("baseline_matches", baselineMatches[i])
                        put("baseline_examples", JsonArray(examples[i]))
                    } else {
                        put("judges_response", false)
                    }
                }
            }
        }
        put("cannot_report_on", neverReportable)
    }
}

/**
 * For a check that requests extra paths (one per host, or one per recorded path and suffix): how
 * much it would probe, and which recorded responses for such a path already meet its conditions.
 *
 * @param isProbePath whether a recorded path is one the check would request.
 */
internal class ProbeDryRun(
    private val isProbePath: (String) -> Boolean,
    private val conditions: List<CheckCondition>,
    private val maxMatches: Int,
) {
    private val hosts = HashSet<String>()
    private val paths = HashSet<String>()
    private var evaluated = 0
    private var hits = 0
    private val matches = ArrayList<JsonObject>()

    /** The message parts this run reads. */
    val parts: Set<String> = ScanCheckLogic.locations(conditions)

    val itemCount: Int get() = evaluated
    val hostCount: Int get() = hosts.size
    val pathCount: Int get() = paths.size

    fun visit(item: HistoryItem) {
        evaluated++
        hosts += item.host
        paths += item.host + item.path
        if (!isProbePath(item.path) || !ScanCheckLogic.satisfied(conditions, MatchMode.ALL, item.exchange)) return
        hits++
        if (matches.size < maxMatches) matches += historyRef(item)
    }

    fun toJson(): JsonObject = buildJsonObject {
        put("items_evaluated", evaluated)
        put("recorded_hits", hits)
        put("matches", JsonArray(matches))
        if (hits > matches.size) put("matches_omitted", hits - matches.size)
    }
}
