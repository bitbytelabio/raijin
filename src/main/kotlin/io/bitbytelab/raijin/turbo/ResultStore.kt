package io.bitbytelab.raijin.turbo

enum class SortField {
    ID,
    STATUS,
    LENGTH,
    TIME,
    TTFB,
    TTLB,
    WORDCOUNT,
    ANOMALY_RANK,
    ARRIVAL,
    PAYLOAD,
    LABEL,
    QUEUE_ID,
    CONNECTION_ID,
}

/** The GUI results table's columns, in order (RequestTableModel.columns), as sort fields. */
private val COLUMN_SORT_FIELDS = listOf(
    SortField.ID, // Row
    SortField.PAYLOAD, // Payload
    SortField.STATUS, // Status
    SortField.ANOMALY_RANK, // Anomaly rank
    SortField.WORDCOUNT, // Words
    SortField.LENGTH, // Length
    SortField.TTFB, // TTFB
    SortField.TTLB, // TTLB
    SortField.ARRIVAL, // Arrival
    SortField.LABEL, // Label
    SortField.QUEUE_ID, // Queue ID
    SortField.CONNECTION_ID, // Connection ID
)

/**
 * A sort order a script set with `table.setSortOrder(column, descending)`. [column] indexes the
 * GUI results table's columns, so the same script line means the same order with or without the GUI.
 */
data class ResultSortOrder(val column: Int, val descending: Boolean) {
    init {
        require(column in COLUMN_SORT_FIELDS.indices) {
            "No results column $column: columns are numbered 0 to ${COLUMN_SORT_FIELDS.lastIndex}"
        }
    }

    val field: SortField get() = COLUMN_SORT_FIELDS[column]
}

class ResultStore @JvmOverloads constructor(
    /**
     * Characters of response body this store keeps. Past it the oldest results drop their bodies
     * and keep their metadata (status, length, word count, timings), so a long run stays bounded.
     */
    private val responseBodyBudget: Long = defaultResponseBodyBudget(),
) : OutputHandler {
    private val results = ArrayList<Request>()
    // The three below are guarded by results.
    private var retainedBodyChars = 0L
    private var oldestRetained = 0
    private var droppedBodies = 0
    @Volatile private var requestedSortOrder: ResultSortOrder? = null

    override fun add(req: Request) {
        synchronized(results) {
            results.add(req)
            retainedBodyChars += req.response?.length ?: 0
            if (retainedBodyChars > responseBodyBudget) dropOldestBodies()
        }
    }

    /**
     * Drops bodies oldest first until the store is within budget again. The newest results always
     * keep theirs: the callbacks that added them may still be reading them.
     */
    private fun dropOldestBodies() {
        val keepFrom = results.size - ALWAYS_RETAINED
        while (retainedBodyChars > responseBodyBudget && oldestRetained < keepFrom) {
            val oldest = results[oldestRetained++]
            val held = oldest.response?.length ?: continue
            oldest.dropResponseBody()
            retainedBodyChars -= held
            droppedBodies++
        }
        if (retainedBodyChars < 0) retainedBodyChars = 0
    }

    override fun getAllRquests(): List<Request> = synchronized(results) { ArrayList(results) }

    fun count(): Int = synchronized(results) { results.size }

    /** How many results have dropped their bodies to keep this store within its budget. */
    fun droppedBodyCount(): Int = synchronized(results) { droppedBodies }

    fun clear() {
        synchronized(results) {
            results.clear()
            retainedBodyChars = 0
            oldestRetained = 0
            droppedBodies = 0
        }
    }

    fun stripResponseBodies() {
        synchronized(results) {
            results.forEach { it.stripResponseBody() }
            retainedBodyChars = 0
            oldestRetained = results.size
        }
    }

    fun getRequest(id: Int): Request? {
        return synchronized(results) { results.find { it.id == id } }
    }

    fun getRequestByIndex(index: Int): Request? {
        return synchronized(results) { results.getOrNull(index) }
    }

    /**
     * Same signature as [RequestTable.setSortOrder], so a script's `table.setSortOrder(column,
     * descending)` also works without the GUI. Results read without an explicit order follow it.
     */
    fun setSortOrder(column: Int, descending: Boolean) {
        requestedSortOrder = ResultSortOrder(column, descending)
    }

    /** The order set by [setSortOrder], or null when the script set none. */
    fun sortOrder(): ResultSortOrder? = requestedSortOrder

    /**
     * Results in [sortBy] order. Without [sortBy] they follow the script's [setSortOrder], else
     * arrival in this store, newest first. [SortField.ID] is that arrival order.
     */
    fun getResults(
        sortBy: SortField? = null,
        descending: Boolean? = null,
        limit: Int = 100,
        offset: Int = 0
    ): List<Request> {
        val requested = requestedSortOrder.takeIf { sortBy == null }
        val field = sortBy ?: requested?.field ?: SortField.ID
        val reversed = descending ?: requested?.descending ?: true
        val snapshot = synchronized(results) { ArrayList(results) }

        // The snapshot is already in arrival order, so ID needs no sort, and no indexOf per comparison.
        val comparator = comparatorFor(field)
        val ordered = when {
            comparator == null -> if (reversed) snapshot.asReversed() else snapshot
            reversed -> snapshot.sortedWith(comparator.reversed())
            else -> snapshot.sortedWith(comparator)
        }

        return ordered.drop(offset).take(limit)
    }

    fun getUniqueStatusCodes(): Set<Int> {
        return synchronized(results) { results.map { it.code }.toSet() }
    }

    private companion object {
        /** Results, newest first, that never drop their bodies to the budget. */
        const val ALWAYS_RETAINED = 256

        fun defaultResponseBodyBudget(): Long = Runtime.getRuntime().maxMemory() / 8

        /** Null for [SortField.ID], which is arrival order rather than a property of a result. */
        fun comparatorFor(field: SortField): Comparator<Request>? = when (field) {
            SortField.ID -> null
            SortField.STATUS -> compareBy { it.code }
            SortField.LENGTH -> compareBy { it.length }
            SortField.TIME, SortField.TTFB -> compareBy { it.ttfb }
            SortField.TTLB -> compareBy { it.ttlb }
            SortField.WORDCOUNT -> compareBy { it.wordcount }
            SortField.ANOMALY_RANK -> compareBy { it.anomalyRank ?: 0 }
            SortField.ARRIVAL -> compareBy { it.arrival }
            SortField.PAYLOAD -> compareBy { it.words.joinToString(separator = "/") }
            SortField.LABEL -> compareBy { it.label }
            SortField.QUEUE_ID -> compareBy { it.id }
            SortField.CONNECTION_ID -> compareBy { it.connectionId ?: "" }
        }
    }
}
