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
    ARRIVAL
}

class ResultStore : OutputHandler {
    private val results = ArrayList<Request>()

    override fun add(req: Request) {
        synchronized(results) { results.add(req) }
    }

    override fun getAllRquests(): List<Request> = synchronized(results) { ArrayList(results) }

    fun count(): Int = synchronized(results) { results.size }

    fun clear() {
        synchronized(results) { results.clear() }
    }

    fun stripResponseBodies() {
        synchronized(results) {
            results.forEach { it.stripResponseBody() }
        }
    }

    fun getRequest(id: Int): Request? {
        return synchronized(results) { results.find { it.id == id } }
    }

    fun getRequestByIndex(index: Int): Request? {
        return synchronized(results) { results.getOrNull(index) }
    }

    fun getResults(
        sortBy: SortField = SortField.ID,
        descending: Boolean = true,
        limit: Int = 100,
        offset: Int = 0
    ): List<Request> {
        val snapshot = synchronized(results) { ArrayList(results) }

        val comparator: Comparator<Request> = when (sortBy) {
            SortField.ID -> compareBy { snapshot.indexOf(it) }
            SortField.STATUS -> compareBy { it.code }
            SortField.LENGTH -> compareBy { it.length }
            SortField.TIME -> compareBy { it.ttfb }
            SortField.TTFB -> compareBy { it.ttfb }
            SortField.TTLB -> compareBy { it.ttlb }
            SortField.WORDCOUNT -> compareBy { it.wordcount }
            SortField.ANOMALY_RANK -> compareBy { it.anomalyRank ?: 0 }
            SortField.ARRIVAL -> compareBy { it.arrival }
        }

        val sorted = if (descending) {
            snapshot.sortedWith(comparator.reversed())
        } else {
            snapshot.sortedWith(comparator)
        }

        return sorted.drop(offset).take(limit)
    }

    fun getUniqueStatusCodes(): Set<Int> {
        return synchronized(results) { results.map { it.code }.toSet() }
    }
}
