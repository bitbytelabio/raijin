package io.bitbytelab.raijin.turbo.mcp

import java.util.ArrayDeque

data class CollaboratorInteractionData(
    val payload: String,
    val metadata: String?,
    val type: String,
    val timestamp: String,
    val clientIp: String,
    val details: Map<String, Any>
)

interface CollaboratorProvider {
    fun generatePayload(metadata: String): String
    fun getInteractions(payloads: List<String>?): List<CollaboratorInteractionData>
}

/**
 * DNS part of an interaction. [queryName] is the decoded QNAME; when the raw query ([queryHex]) is
 * not a valid DNS question it is null and [queryNameError] says why.
 */
data class CollaboratorDnsDetails(
    val queryType: String,
    val queryName: String?,
    val queryNameError: String?,
    val queryHex: String,
)

/**
 * HTTP part of an interaction: the raw [request] the Collaborator server received and the raw
 * [response] it sent back. Either may have been cut to a storage cap; [requestLength] and
 * [responseLength] are the sizes before that cut.
 */
data class CollaboratorHttpDetails(
    val protocol: String,
    val method: String,
    val url: String,
    val status: Int?,
    val request: String,
    val response: String?,
    val responseMimeType: String? = null,
    val requestLength: Int = request.length,
    val responseLength: Int = response?.length ?: 0,
)

/** SMTP part of an interaction; [conversationLength] is the size before any storage cut. */
data class CollaboratorSmtpDetails(
    val protocol: String,
    val conversation: String,
    val conversationLength: Int = conversation.length,
)

/**
 * One Collaborator interaction as kept in [CollaboratorHistory].
 *
 * @property payloadId the interaction id, which is the id of the payload that caused it.
 * @property type [DNS], [HTTP] or [SMTP].
 * @property detailsError why the type-specific details are missing, when they are.
 * @property seq position in the history, assigned by [CollaboratorHistory.add].
 */
data class CollaboratorRecord(
    val clientId: String,
    val payloadId: String,
    val type: String,
    val timestamp: String,
    val clientIp: String,
    val clientPort: Int,
    val customData: String? = null,
    val dns: CollaboratorDnsDetails? = null,
    val http: CollaboratorHttpDetails? = null,
    val smtp: CollaboratorSmtpDetails? = null,
    val detailsError: String? = null,
    val seq: Long = 0,
) {
    companion object {
        const val DNS = "DNS"
        const val HTTP = "HTTP"
        const val SMTP = "SMTP"
    }
}

/**
 * One page of a [CollaboratorHistory.query].
 *
 * @property records the matching records, oldest first.
 * @property nextSince cursor to pass as `since` to continue with the same filters.
 * @property hasMore more matching records follow [records]; the limit cut the page.
 * @property filteredOut records up to [nextSince] that the query's predicate left out.
 * @property truncated records newer than the query's `since` were evicted by the history bound
 *   before this query could return them.
 */
data class CollaboratorPage(
    val records: List<CollaboratorRecord>,
    val nextSince: Long,
    val hasMore: Boolean,
    val filteredOut: Int,
    val truncated: Boolean,
)

/**
 * Bounded log of Collaborator interactions, oldest first.
 *
 * Polling a Collaborator client drains the server: each interaction is handed out once. Keeping
 * every fetched interaction here is what lets a caller filter by type, payload or client, or page
 * by [CollaboratorRecord.seq], without discarding the interactions it did not ask for.
 *
 * The log is bounded by record count and by the text it stores; past either bound the oldest
 * records are evicted, and [CollaboratorPage.truncated] tells a reader that happened.
 *
 * @param clock source of the lower bound for a new seq. With the wall clock (the default) a seq is
 *   never reused after an extension reload, so a cursor a caller kept from before the reload still
 *   means "everything after this".
 */
class CollaboratorHistory(
    private val maxRecords: Int = DEFAULT_MAX_RECORDS,
    private val maxChars: Long = DEFAULT_MAX_CHARS,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    /** Per client: how many of its records the bounds evicted, and the seq of the newest of them. */
    private class Evicted(var count: Long = 0, var newestSeq: Long = 0)

    /** What the history holds for one client. */
    data class Summary(val retained: Int, val lastTimestamp: String?, val evicted: Long)

    private val records = ArrayDeque<CollaboratorRecord>()
    private var lastSeq = 0L
    private var chars = 0L
    private val evicted = HashMap<String, Evicted>()

    init {
        require(maxRecords > 0) { "maxRecords must be positive" }
    }

    /** Appends [record] and returns it with its seq; evicts the oldest records past the bounds. */
    @Synchronized
    fun add(record: CollaboratorRecord): CollaboratorRecord {
        lastSeq = maxOf(lastSeq + 1, clock())
        val stored = record.copy(seq = lastSeq)
        records.addLast(stored)
        chars += weight(stored)
        while (records.size > 1 && (records.size > maxRecords || chars > maxChars)) {
            val oldest = records.pollFirst()
            chars -= weight(oldest)
            val lost = evicted.getOrPut(oldest.clientId) { Evicted() }
            lost.count++
            lost.newestSeq = oldest.seq
        }
        return stored
    }

    /**
     * Records after [since] (exclusive) of [clientId] (every client when null) that satisfy
     * [matches], oldest first and at most [limit].
     *
     * A [since] beyond the newest seq cannot have come from this history (a clock that stepped back
     * across a reload), so it is read as 0 rather than hiding everything.
     */
    @Synchronized
    fun query(
        clientId: String? = null,
        since: Long = 0,
        limit: Int = Int.MAX_VALUE,
        matches: (CollaboratorRecord) -> Boolean = { true },
    ): CollaboratorPage {
        require(limit > 0) { "limit must be positive" }
        val from = if (since > lastSeq) 0L else since
        val page = ArrayList<CollaboratorRecord>()
        var filteredOut = 0
        var skippedSincePage = 0
        var hasMore = false
        for (record in records) {
            if (record.seq <= from || (clientId != null && record.clientId != clientId)) continue
            if (!matches(record)) {
                skippedSincePage++
                continue
            }
            if (page.size == limit) {
                hasMore = true
                break
            }
            page += record
            filteredOut += skippedSincePage
            skippedSincePage = 0
        }
        if (!hasMore) filteredOut += skippedSincePage
        val newestEvicted =
            if (clientId != null) evicted[clientId]?.newestSeq ?: 0L else evicted.values.maxOfOrNull { it.newestSeq } ?: 0L
        return CollaboratorPage(
            records = page,
            nextSince = if (hasMore) page.last().seq else maxOf(from, lastSeq),
            hasMore = hasMore,
            filteredOut = filteredOut,
            truncated = newestEvicted > from,
        )
    }

    /** Retained and evicted record counts of [clientId], with the timestamp of its newest record. */
    @Synchronized
    fun summary(clientId: String): Summary {
        var retained = 0
        var lastTimestamp: String? = null
        for (record in records) {
            if (record.clientId == clientId) {
                retained++
                lastTimestamp = record.timestamp
            }
        }
        return Summary(retained, lastTimestamp, evicted[clientId]?.count ?: 0L)
    }

    /** Forgets everything recorded for [clientId]. */
    @Synchronized
    fun removeClient(clientId: String) {
        val iterator = records.iterator()
        while (iterator.hasNext()) {
            val record = iterator.next()
            if (record.clientId == clientId) {
                chars -= weight(record)
                iterator.remove()
            }
        }
        evicted.remove(clientId)
    }

    private fun weight(record: CollaboratorRecord): Long {
        var size = RECORD_OVERHEAD
        record.dns?.let { size += it.queryHex.length + (it.queryName?.length ?: 0) }
        record.http?.let { size += it.url.length + it.request.length + (it.response?.length ?: 0) }
        record.smtp?.let { size += it.conversation.length }
        return size
    }

    companion object {
        const val DEFAULT_MAX_RECORDS = 5_000

        /** About 32 MB of stored request, response and conversation text. */
        const val DEFAULT_MAX_CHARS = 32L * 1024 * 1024

        /** Charged per record on top of its text, so a flood of tiny records also counts. */
        private const val RECORD_OVERHEAD = 256L
    }
}

/**
 * A payload generated through Raijin.
 *
 * @property payloadId the payload's interaction id; every interaction it causes carries the same id.
 * @property payload the full payload host, e.g. `abc123.oastify.com`.
 * @property metadata the label a Turbo caller attached when generating it.
 */
data class CollaboratorPayloadInfo(
    val payloadId: String,
    val payload: String,
    val clientId: String,
    val customData: String? = null,
    val metadata: String? = null,
    val createdAt: String = "",
)

/**
 * The payloads generated through Raijin, by interaction id, so an interaction can be traced to the
 * payload (and its label) that caused it. Bounded: past [maxEntries] the oldest payload is dropped,
 * which only costs later interactions of that payload their `payload` / `metadata` annotation.
 */
class CollaboratorPayloads(private val maxEntries: Int = DEFAULT_MAX_ENTRIES) {
    private val byId = LinkedHashMap<String, CollaboratorPayloadInfo>()
    private val generated = HashMap<String, Int>()

    @Synchronized
    fun register(info: CollaboratorPayloadInfo) {
        byId.remove(info.payloadId)
        byId[info.payloadId] = info
        generated[info.clientId] = (generated[info.clientId] ?: 0) + 1
        val oldest = byId.values.iterator()
        while (byId.size > maxEntries && oldest.hasNext()) {
            oldest.next()
            oldest.remove()
        }
    }

    @Synchronized
    operator fun get(payloadId: String): CollaboratorPayloadInfo? = byId[payloadId]

    /** How many payloads [clientId] generated since the extension loaded. */
    @Synchronized
    fun generatedBy(clientId: String): Int = generated[clientId] ?: 0

    /**
     * The clients that generated the payloads named by [filters], or null when one of them is not a
     * payload known here, in which case any client may own it.
     */
    @Synchronized
    fun clientsOf(filters: Collection<String>): Set<String>? {
        val clients = HashSet<String>()
        for (filter in filters) {
            val owner = byId.values.firstOrNull { matches(filter, it.payloadId, it.payload) } ?: return null
            clients += owner.clientId
        }
        return clients
    }

    /** Forgets the payloads of [clientId]. */
    @Synchronized
    fun removeClient(clientId: String) {
        byId.values.removeIf { it.clientId == clientId }
        generated.remove(clientId)
    }

    companion object {
        const val DEFAULT_MAX_ENTRIES = 20_000

        /**
         * True when [filter] names the payload with interaction id [payloadId] and, when known, full
         * host [payload]. A filter may be the id, the payload host, or a URL or `host:port` around
         * either. A host whose first label is the id matches too, which covers a payload generated
         * before an extension reload, when its full host is no longer known here.
         */
        fun matches(filter: String, payloadId: String, payload: String?): Boolean {
            val wanted = hostOf(filter)
            if (wanted.isEmpty() || payloadId.isEmpty()) return false
            return wanted.equals(payloadId, ignoreCase = true) ||
                (payload != null && wanted.equals(hostOf(payload), ignoreCase = true)) ||
                wanted.substringBefore('.').equals(payloadId, ignoreCase = true)
        }

        /** The host of a payload reference: scheme, port, path and query removed. */
        private fun hostOf(reference: String): String =
            reference.trim().substringAfter("://").substringBefore('/').substringBefore('?')
                .substringBefore(':').trimEnd('.')
    }
}

/** What [BurpCollaboratorProvider] needs done in Burp. The Collaborator bridge implements it. */
interface CollaboratorBackend {
    /** Generates a payload on the client kept for Turbo, registers it with [metadata] and returns its host. */
    fun generatePayload(metadata: String): String

    /**
     * Polls the Collaborator server and adds what is new to the history: for [clientIds], or for
     * every client when null. Throws when no client could be polled.
     */
    fun sync(clientIds: Set<String>?)
}

/**
 * The Collaborator state shared by the MCP `collaborator` tools and Turbo: the interaction
 * [history] and the generated [payloads].
 *
 * `BurpCollaboratorProvider()` is a handle on one process-wide state, so the instance `TurboBridge`
 * builds and the one `CollaboratorBridge` uses see the same interactions whoever polled them. The
 * bridge owns the Burp side (clients, polling) and plugs it in through [attach].
 */
class BurpCollaboratorProvider internal constructor(private val state: State) : CollaboratorProvider {

    constructor() : this(shared)

    internal class State(
        val history: CollaboratorHistory = CollaboratorHistory(),
        val payloads: CollaboratorPayloads = CollaboratorPayloads(),
    ) {
        @Volatile
        var backend: CollaboratorBackend? = null
    }

    val history: CollaboratorHistory get() = state.history
    val payloads: CollaboratorPayloads get() = state.payloads

    /** Routes Turbo payload generation and polling through [backend]. */
    fun attach(backend: CollaboratorBackend) {
        state.backend = backend
    }

    override fun generatePayload(metadata: String): String {
        val backend = state.backend ?: throw IllegalStateException("Burp Collaborator is not available")
        return backend.generatePayload(metadata)
    }

    /**
     * Interactions of [payloads] (payload hosts or ids), or every recorded interaction when null.
     * Reads the history after polling, so a repeated call returns the same interactions again plus
     * any new ones.
     */
    override fun getInteractions(payloads: List<String>?): List<CollaboratorInteractionData> {
        val backend = state.backend ?: return emptyList()
        backend.sync(payloads?.let { state.payloads.clientsOf(it) })
        return query(payloads = payloads).records.map { toInteractionData(it) }
    }

    /**
     * Recorded interactions after [since], narrowed to [clientId], [type] (case-insensitive) and
     * [payloads] (see [CollaboratorPayloads.matches]) where given. Nothing is removed by a query.
     */
    fun query(
        clientId: String? = null,
        type: String? = null,
        payloads: Collection<String>? = null,
        since: Long = 0,
        limit: Int = Int.MAX_VALUE,
    ): CollaboratorPage = state.history.query(clientId, since, limit) { record ->
        (type == null || record.type.equals(type, ignoreCase = true)) &&
            (payloads == null || matchesAny(payloads, record))
    }

    private fun matchesAny(payloads: Collection<String>, record: CollaboratorRecord): Boolean {
        val known = state.payloads[record.payloadId]?.payload
        return payloads.any { CollaboratorPayloads.matches(it, record.payloadId, known) }
    }

    private fun toInteractionData(record: CollaboratorRecord): CollaboratorInteractionData {
        val info = state.payloads[record.payloadId]
        return CollaboratorInteractionData(
            payload = info?.payload ?: record.payloadId,
            metadata = info?.metadata,
            type = record.type,
            timestamp = record.timestamp,
            clientIp = record.clientIp,
            details = details(record)
        )
    }

    private fun details(record: CollaboratorRecord): Map<String, Any> {
        val details = mutableMapOf<String, Any>()
        record.dns?.let { dns ->
            details["query_type"] = dns.queryType
            dns.queryName?.let { details["query_name"] = it }
            dns.queryNameError?.let { details["query_name_error"] = it }
            details["query_hex"] = dns.queryHex
        }
        record.http?.let { http ->
            details["protocol"] = http.protocol
            details["request"] = http.request
            http.response?.let { details["response"] = it }
        }
        record.smtp?.let { smtp ->
            details["protocol"] = smtp.protocol
            details["conversation"] = smtp.conversation
        }
        return details
    }

    private companion object {
        val shared = State()
    }
}
