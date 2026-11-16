package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.core.BodyText
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import java.util.TreeMap
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToLong

/**
 * Groups the responses of one run (a race batch, a fuzz run) into clusters of equivalent
 * responses, so a report reads "19 x 409, 1 x 200 with another body" instead of listing every
 * response or comparing raw lengths.
 *
 * Two responses share a cluster when they have the same status code and their bodies are the same
 * text, or close in length and at least `similarity` percent alike (character-bigram Dice
 * coefficient, the metric of [io.bitbytelab.raijin.core.TextSimilarity], on a body prefix). A
 * rotating token or timestamp therefore does not split a cluster; another message or amount does.
 * Response times are not a clustering key (they are noise on most targets): they are reported per
 * cluster, and the slow ones as outliers.
 */
internal object HttpResponseClusters {

    const val DEFAULT_SIMILARITY = 90.0

    /** Bodies are compared on a prefix: the bigram metric gains little from more text and costs linear time. */
    const val MAX_COMPARED_CHARS = 20_000

    /** Clusters kept apart; responses that fit none beyond that share one overflow cluster. */
    const val MAX_CLUSTERS = 64

    private const val MAX_LISTED_INDICES = 100
    private const val MAX_EXAMPLES = 5
    private const val SAMPLE_CHARS = 160

    /**
     * One response as clustering sees it.
     *
     * @param index position of the request in its run.
     * @param status status code; 0 when no response arrived.
     * @param length body length in bytes.
     * @param body body text; only the first [MAX_COMPARED_CHARS] characters are compared.
     * @param timeMs time to the response, when it was measured.
     * @param label what identifies the request to the caller (its payload), listed as an example.
     */
    class Sample(
        val index: Int,
        val status: Int,
        val length: Int,
        val body: String,
        val timeMs: Double? = null,
        val label: String? = null,
    )

    /**
     * @param clusterOf request index -> cluster number, as numbered in [json].
     * @param clusterCount clusters of answered requests (status other than 0).
     * @param unanswered requests that got no response.
     * @param json `cluster_count`, `uniform`, `clusters`, `status_code_distribution` and `timing`.
     */
    class Summary(val clusterOf: Map<Int, Int>, val clusterCount: Int, val unanswered: Int, val json: JsonObject)

    private class Cluster(val status: Int, leader: Sample, val prefix: String, val overflow: Boolean) {
        val leaderIndex = leader.index
        val leaderLength = leader.length
        var bigrams: Set<Int>? = null
        var minLength = leader.length
        var maxLength = leader.length
        val indices = ArrayList<Int>()
        val examples = ArrayList<String>()
        val times = ArrayList<Double>()
        val statuses = TreeMap<Int, Int>()

        fun add(sample: Sample) {
            indices += sample.index
            minLength = min(minLength, sample.length)
            maxLength = max(maxLength, sample.length)
            statuses.merge(sample.status, 1, Int::plus)
            sample.timeMs?.let { times += it }
            val label = sample.label
            if (label != null && examples.size < MAX_EXAMPLES && label !in examples) examples += label
        }
    }

    /**
     * Assigns responses to clusters as they arrive, keeping only the body of each cluster's first
     * response, so a long run costs memory per cluster and not per response. Safe to call from
     * several threads.
     */
    class Builder(similarity: Double = DEFAULT_SIMILARITY) {
        private val threshold = similarity.coerceIn(0.0, 100.0)
        private val clusters = ArrayList<Cluster>()
        private val timed = ArrayList<Pair<Int, Double>>()
        private val statusCounts = TreeMap<Int, Int>()

        /** Returns the index of the first response of the cluster [sample] joined (its own index when it starts one). */
        @Synchronized
        fun add(sample: Sample): Int {
            statusCounts.merge(sample.status, 1, Int::plus)
            sample.timeMs?.let { timed += sample.index to it }
            val prefix = if (sample.body.length > MAX_COMPARED_CHARS) sample.body.substring(0, MAX_COMPARED_CHARS) else sample.body
            var sampleBigrams: Set<Int>? = null
            val match = clusters.firstOrNull { cluster ->
                !cluster.overflow && cluster.status == sample.status &&
                    equivalent(cluster, sample.length, prefix) { sampleBigrams ?: bigrams(prefix).also { sampleBigrams = it } }
            }
            val target = match ?: if (clusters.count { !it.overflow } < MAX_CLUSTERS) {
                Cluster(sample.status, sample, prefix, overflow = false).also { clusters += it }
            } else {
                clusters.firstOrNull { it.overflow } ?: Cluster(sample.status, sample, prefix, overflow = true).also { clusters += it }
            }
            target.add(sample)
            return target.leaderIndex
        }

        private fun equivalent(cluster: Cluster, length: Int, prefix: String, sampleBigrams: () -> Set<Int>): Boolean {
            if (cluster.prefix == prefix && cluster.leaderLength == length) return true
            if (threshold >= 100.0) return false
            // The share of the longer body the shorter one can cover at best: a far shorter or
            // longer body is another response however alike its text is.
            val shorter = min(cluster.leaderLength, length)
            val longer = max(cluster.leaderLength, length)
            if (longer > 0 && 200.0 * shorter / (shorter + longer) < threshold) return false
            val leaderBigrams = cluster.bigrams ?: bigrams(cluster.prefix).also { cluster.bigrams = it }
            return dice(leaderBigrams, sampleBigrams()) >= threshold
        }

        /** Clusters numbered from the largest down; among equals the one seen first comes first. */
        @Synchronized
        fun build(): Summary {
            val ordered = clusters.sortedWith(
                compareBy<Cluster> { it.overflow }.thenByDescending { it.indices.size }.thenBy { it.indices.minOrNull() ?: Int.MAX_VALUE }
            )
            val clusterOf = HashMap<Int, Int>()
            ordered.forEachIndexed { id, cluster -> cluster.indices.forEach { clusterOf[it] = id } }
            val answered = ordered.count { !it.overflow && it.status != 0 } + if (ordered.any { it.overflow }) 1 else 0
            val unanswered = statusCounts[0] ?: 0
            val json = buildJsonObject {
                put("cluster_count", ordered.size)
                put("uniform", ordered.size <= 1)
                putJsonArray("clusters") {
                    ordered.forEachIndexed { id, cluster -> add(clusterJson(id, cluster)) }
                }
                putJsonObject("status_code_distribution") {
                    statusCounts.forEach { (status, count) -> put(status.toString(), count) }
                }
                timingJson()?.let { put("timing", it) }
            }
            return Summary(clusterOf, answered, unanswered, json)
        }

        private fun clusterJson(id: Int, cluster: Cluster): JsonObject = buildJsonObject {
            put("cluster", id)
            put("count", cluster.indices.size)
            if (cluster.overflow) {
                putJsonObject("status_codes") { cluster.statuses.forEach { (status, count) -> put(status.toString(), count) } }
            } else {
                put("status_code", cluster.status)
                if (cluster.status == 0) put("no_response", true)
            }
            if (cluster.minLength == cluster.maxLength) {
                put("body_length", cluster.minLength)
            } else {
                putJsonObject("body_length") { put("min", cluster.minLength); put("max", cluster.maxLength) }
            }
            if (cluster.times.isNotEmpty()) {
                val sorted = cluster.times.sorted()
                putJsonObject("time_ms") {
                    put("min", round1(sorted.first()))
                    put("median", round1(median(sorted)))
                    put("max", round1(sorted.last()))
                }
            }
            put("representative_index", cluster.leaderIndex)
            val indices = cluster.indices.sorted()
            putJsonArray("indices") { indices.take(MAX_LISTED_INDICES).forEach { add(it) } }
            if (indices.size > MAX_LISTED_INDICES) put("indices_truncated", true)
            if (cluster.examples.isNotEmpty()) putJsonArray("examples") { cluster.examples.forEach { add(it) } }
            if (cluster.prefix.isNotEmpty()) put("sample", BodyText.render(cluster.prefix, SAMPLE_CHARS).text)
            if (cluster.overflow) {
                put("overflow", true)
                put("note", "More than $MAX_CLUSTERS different responses: the rest are counted here without being compared.")
            }
        }

        private fun timingJson(): JsonObject? {
            if (timed.isEmpty()) return null
            val sorted = timed.map { it.second }.sorted()
            val middle = median(sorted)
            return buildJsonObject {
                put("min_ms", round1(sorted.first()))
                put("median_ms", round1(middle))
                put("max_ms", round1(sorted.last()))
                val limit = outlierLimit(sorted, middle)
                val slow = if (limit == null) emptyList() else timed.filter { it.second > limit }.sortedByDescending { it.second }
                if (slow.isNotEmpty()) {
                    putJsonArray("outliers") {
                        slow.take(MAX_LISTED_INDICES).forEach { (index, time) ->
                            add(buildJsonObject { put("index", index); put("time_ms", round1(time)) })
                        }
                    }
                }
            }
        }
    }

    /** Clusters [samples] in order. */
    fun cluster(samples: List<Sample>, similarity: Double = DEFAULT_SIMILARITY): Summary =
        Builder(similarity).also { builder -> samples.forEach { builder.add(it) } }.build()

    /**
     * How the responses of a race batch read. `race_condition_likely` is only claimed for identical
     * requests that were answered in more than one way: with a payload per request the requests
     * differ, so different answers are expected and the clusters must be read against the payloads.
     */
    fun raceAnalysis(summary: Summary, identicalRequests: Boolean, similarity: Double = DEFAULT_SIMILARITY): JsonObject {
        val variation = summary.clusterCount > 1
        val note = when {
            summary.clusterCount == 0 -> "No response was received."
            !variation ->
                "Every response is equivalent (same status, bodies at least ${similarity.toInt()}% alike), so the responses " +
                    "themselves show no race. An effect may still exist in the application state (a balance, a counter, " +
                    "duplicate objects): check it."
            identicalRequests ->
                "Identical requests released together were answered in ${summary.clusterCount} different ways. For a " +
                    "once-only or limited action, count the responses in the success cluster: more than the limit allows " +
                    "means the race was won."
            else ->
                "The responses fall into ${summary.clusterCount} clusters, but the requests carried different payloads: " +
                    "compare each cluster with its payloads before reading this as a race."
        }
        return buildJsonObject {
            put("race_condition_likely", variation && identicalRequests)
            put("variation", variation)
            summary.json.forEach { (key, value) -> put(key, value) }
            if (summary.unanswered > 0) put("unanswered", summary.unanswered)
            put("note", note)
        }
    }

    /** Character bigrams of [text], each packed into an Int. */
    internal fun bigrams(text: String): Set<Int> {
        if (text.length < 2) return emptySet()
        val out = HashSet<Int>(min(text.length, 4096))
        for (i in 0 until text.length - 1) out += (text[i].code shl 16) or text[i + 1].code
        return out
    }

    /** Dice coefficient of two bigram sets as a percentage (0..100); two empty sets share nothing. */
    internal fun dice(a: Set<Int>, b: Set<Int>): Double {
        val total = a.size + b.size
        if (total == 0) return 0.0
        val (small, large) = if (a.size <= b.size) a to b else b to a
        var shared = 0
        for (bigram in small) if (bigram in large) shared++
        return 200.0 * shared / total
    }

    /**
     * Time above which a response counts as slow: the median plus three scaled median absolute
     * deviations, and at least half the median and 50 ms on top of it so jitter is not reported.
     * Null with fewer than four timings.
     */
    internal fun outlierLimit(sortedTimes: List<Double>, middle: Double): Double? {
        if (sortedTimes.size < 4) return null
        val deviation = median(sortedTimes.map { abs(it - middle) }.sorted())
        return middle + max(max(3 * 1.4826 * deviation, 0.5 * middle), 50.0)
    }

    private fun median(sorted: List<Double>): Double {
        val mid = sorted.size / 2
        return if (sorted.size % 2 == 1) sorted[mid] else (sorted[mid - 1] + sorted[mid]) / 2
    }

    private fun round1(value: Double): Double = (value * 10).roundToLong() / 10.0
}
