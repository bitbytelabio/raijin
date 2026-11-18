package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.safety.SafeRegex
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.LockSupport
import kotlin.math.min

/**
 * Spaces out calls to [await] so that no more than [ratePerSecond] start per second, across every
 * thread that calls it. A rate of zero or less does not wait.
 */
internal class RatePacer(
    ratePerSecond: Double,
    private val nanoTime: () -> Long = System::nanoTime,
    private val sleepNanos: (Long) -> Unit = { LockSupport.parkNanos(it) },
) {
    private val intervalNanos: Long = if (ratePerSecond > 0) (1_000_000_000.0 / ratePerSecond).toLong() else 0L
    private var nextSlot = 0L // guarded by this
    private var started = false // guarded by this

    fun await() {
        if (intervalNanos <= 0) return
        val slot = synchronized(this) {
            val now = nanoTime()
            val mine = if (!started || nextSlot < now) now else nextSlot
            started = true
            nextSlot = mine + intervalNanos
            mine
        }
        // parkNanos may return early, so wait until the slot has really come.
        while (true) {
            val remaining = slot - nanoTime()
            if (remaining <= 0) return
            sleepNanos(remaining)
        }
    }
}

/**
 * Runs a planned fuzz attack: sends the requests (in order, or several at a time), applies the
 * rate limit, stop condition and response filter, and reports the kept results together with a
 * cluster summary of every response. How a request is actually sent is left to [send], so the
 * run logic is testable without Burp.
 *
 * @param send sends one planned request; an exception is recorded as a failed request.
 */
internal class HttpFuzzRunner(private val send: (HttpFuzzPlan.AttackRequest) -> Sent) {

    sealed class Sent {
        /**
         * @param status response status code, 0 when no response came back.
         * @param bodyLength response body length in bytes.
         * @param head status line and headers, for the regex filters.
         * @param json the full exchange as listed in the results, built only for a listed response.
         */
        class Answered(
            val status: Int,
            val bodyLength: Int,
            val head: String,
            val body: String,
            val elapsedMs: Long,
            val json: () -> JsonObject,
        ) : Sent()

        class Failed(val error: String, val timeout: Boolean) : Sent()
    }

    /**
     * @param concurrency requests in flight at once; 1 sends them one after the other.
     * @param ratePerSecond most requests started per second; 0 = no limit.
     * @param report [REPORT_ALL] lists every kept exchange in full, [REPORT_CLUSTERS] lists one
     *   line per kept request plus the first exchange of each cluster, [REPORT_SUMMARY] lists nothing.
     * @param payloadsCount size of the first payload set, reported as `payloads_count`.
     */
    class Options(
        val concurrency: Int = 1,
        val ratePerSecond: Double = 0.0,
        val stopOnStatusCodes: List<Int>? = null,
        val stopOnBodyRegex: String? = null,
        val filter: FuzzResponseFilter = FuzzResponseFilter.NONE,
        val report: String = REPORT_ALL,
        val clusterSimilarity: Double = HttpResponseClusters.DEFAULT_SIMILARITY,
        val payloadsCount: Int = 0,
        val pacer: RatePacer? = null,
    )

    private class Record(
        val index: Int,
        val request: HttpFuzzPlan.AttackRequest,
        val status: Int,
        val bodyLength: Int,
        val elapsedMs: Long?,
        val kept: Boolean,
        val leader: Boolean,
        val json: JsonObject?,
        val error: String?,
        val timeout: Boolean,
    )

    fun run(plan: HttpFuzzPlan.AttackPlan, options: Options): JsonObject {
        val iterator = plan.requests.iterator()
        val feed = Any()
        var nextIndex = 0
        val stop = AtomicBoolean(false)
        val pacer = options.pacer ?: RatePacer(options.ratePerSecond)
        val clusters = HttpResponseClusters.Builder(options.clusterSimilarity)
        val records = ArrayList<Record>()
        val keepJson = options.report == REPORT_ALL
        val keepLeaderJson = options.report == REPORT_CLUSTERS
        val workerFailures = ArrayList<String>()

        fun take(): Pair<Int, HttpFuzzPlan.AttackRequest>? = synchronized(feed) {
            if (stop.get() || !iterator.hasNext()) null else (nextIndex++ to iterator.next())
        }

        fun work() {
            while (!Thread.currentThread().isInterrupted) {
                val (index, request) = take() ?: return
                pacer.await()
                if (stop.get()) return
                val sent = try {
                    send(request)
                } catch (e: Exception) {
                    Sent.Failed(e.message ?: "send failed", timeout = false)
                }
                val record = when (sent) {
                    is Sent.Failed -> {
                        val leader = clusters.add(HttpResponseClusters.Sample(index, 0, 0, "", label = request.label)) == index
                        Record(
                            index, request, status = 0, bodyLength = 0, elapsedMs = null,
                            kept = options.filter.keeps(0, 0) { "" }, leader = leader, json = null,
                            error = sent.error, timeout = sent.timeout,
                        )
                    }
                    is Sent.Answered -> {
                        val leader = clusters.add(
                            HttpResponseClusters.Sample(index, sent.status, sent.bodyLength, sent.body, sent.elapsedMs.toDouble(), request.label)
                        ) == index
                        val kept = options.filter.keeps(sent.status, sent.bodyLength) { sent.head + "\r\n\r\n" + sent.body }
                        if (sent.status != 0 && stopMatches(sent, options)) stop.set(true)
                        Record(
                            index, request, sent.status, sent.bodyLength, sent.elapsedMs,
                            kept = kept, leader = leader,
                            json = if ((keepJson && kept) || (keepLeaderJson && leader)) {
                                try {
                                    sent.json()
                                } catch (e: Exception) {
                                    buildJsonObject {
                                        put("index", index)
                                        put("serialize_error", e.message ?: e.javaClass.simpleName)
                                    }
                                }
                            } else {
                                null
                            },
                            error = null, timeout = false,
                        )
                    }
                }
                synchronized(records) { records += record }
            }
        }

        val workers = min(options.concurrency.coerceAtLeast(1).toLong(), plan.planned.coerceAtLeast(1)).toInt()
        if (workers <= 1) {
            work()
        } else {
            val pool = Executors.newFixedThreadPool(workers) { runnable ->
                Thread(runnable, "raijin-fuzz-${System.nanoTime()}").apply { isDaemon = true }
            }
            try {
                val running = List(workers) { pool.submit { work() } }
                for (future in running) {
                    try {
                        future.get()
                    } catch (e: ExecutionException) {
                        // work() records a failed send itself; anything else ends that worker only.
                        workerFailures += "worker failed: ${e.cause?.message ?: e.message}"
                    } catch (_: InterruptedException) {
                        stop.set(true)
                        Thread.currentThread().interrupt()
                        break
                    }
                }
            } finally {
                pool.shutdownNow()
            }
        }

        val done = synchronized(records) { records.sortedBy { it.index } }
        val summary = clusters.build()
        val failed = done.count { it.error != null }
        val hidden = done.count { !it.kept }
        return buildJsonObject {
            put("total_requests", done.size)
            put("payloads_count", options.payloadsCount)
            put("mode", plan.positionMode)
            put("attack_mode", plan.mode.id)
            put("positions", plan.positions)
            put("planned_requests", plan.planned)
            if (plan.total != plan.planned) put("attack_requests", plan.total)
            put("stopped_early", stop.get())
            if (failed > 0) put("failed_requests", failed)
            if (options.filter.active) put("filtered_out", hidden)
            put("summary", summary.json)
            when (options.report) {
                REPORT_SUMMARY -> Unit
                REPORT_CLUSTERS -> {
                    put("representatives", buildJsonArray {
                        done.filter { it.leader }.forEach { add(fullEntry(it, plan.mode, summary)) }
                    })
                    put("results", buildJsonArray {
                        done.filter { it.kept }.forEach { add(lineEntry(it, plan.mode, summary)) }
                    })
                }
                else -> put("results", buildJsonArray {
                    done.filter { it.kept }.forEach { add(fullEntry(it, plan.mode, summary)) }
                })
            }
            val notes = plan.notes + workerFailures
            if (notes.isNotEmpty()) putJsonArray("notes") { notes.forEach { add(it) } }
        }
    }

    private fun stopMatches(sent: Sent.Answered, options: Options): Boolean {
        val statusMatch = options.stopOnStatusCodes != null && sent.status in options.stopOnStatusCodes
        val boundedBody = if (sent.body.length > SafeRegex.DEFAULT_MAX_INPUT_LEN) {
            sent.body.substring(0, SafeRegex.DEFAULT_MAX_INPUT_LEN)
        } else {
            sent.body
        }
        val bodyMatch = options.stopOnBodyRegex != null && SafeRegex.find(options.stopOnBodyRegex, boundedBody) != null
        return statusMatch || bodyMatch
    }

    private fun JsonObjectBuilder.payloadFields(record: Record, mode: HttpFuzzPlan.AttackMode) {
        val request = record.request
        if (mode == HttpFuzzPlan.AttackMode.SNIPER || mode == HttpFuzzPlan.AttackMode.BATTERING_RAM) {
            put("payload", request.payloads.firstOrNull { it != null } ?: "")
            if (request.position >= 0) put("position", request.position)
        } else {
            putJsonArray("payloads") { request.payloads.forEach { add(it) } }
        }
    }

    private fun JsonObjectBuilder.failureFields(record: Record) {
        put("error", record.error ?: "send failed")
        put("is_timeout", record.timeout)
    }

    /** A result with the whole exchange, as http_fuzz has always listed it. */
    private fun fullEntry(record: Record, mode: HttpFuzzPlan.AttackMode, summary: HttpResponseClusters.Summary): JsonObject =
        buildJsonObject {
            put("index", record.index)
            payloadFields(record, mode)
            if (record.error != null) failureFields(record)
            record.json?.forEach { (key, value) -> put(key, value) }
            summary.clusterOf[record.index]?.let { put("cluster", it) }
        }

    /** A result reduced to what tells responses apart. */
    private fun lineEntry(record: Record, mode: HttpFuzzPlan.AttackMode, summary: HttpResponseClusters.Summary): JsonObject =
        buildJsonObject {
            put("index", record.index)
            payloadFields(record, mode)
            if (record.error != null) {
                failureFields(record)
            } else {
                put("status_code", record.status)
                put("response_body_length", record.bodyLength)
                record.elapsedMs?.let { put("elapsed_ms", it) }
            }
            summary.clusterOf[record.index]?.let { put("cluster", it) }
        }

    companion object {
        const val REPORT_ALL = "all"
        const val REPORT_CLUSTERS = "clusters"
        const val REPORT_SUMMARY = "summary"
        val REPORTS = listOf(REPORT_ALL, REPORT_CLUSTERS, REPORT_SUMMARY)
    }
}
