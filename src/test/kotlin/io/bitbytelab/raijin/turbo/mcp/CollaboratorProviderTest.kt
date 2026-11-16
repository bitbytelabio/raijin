package io.bitbytelab.raijin.turbo.mcp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

private fun dns(client: String = "c1", payload: String = "p1") = CollaboratorRecord(
    clientId = client,
    payloadId = payload,
    type = CollaboratorRecord.DNS,
    timestamp = "2026-11-17T10:00:00Z",
    clientIp = "203.0.113.5",
    clientPort = 53,
    dns = CollaboratorDnsDetails("A", "$payload.oast.test", null, "00"),
)

private fun http(client: String = "c1", payload: String = "p1", body: String = "") = CollaboratorRecord(
    clientId = client,
    payloadId = payload,
    type = CollaboratorRecord.HTTP,
    timestamp = "2026-11-17T10:00:01Z",
    clientIp = "203.0.113.5",
    clientPort = 44321,
    http = CollaboratorHttpDetails(
        protocol = "HTTP",
        method = "GET",
        url = "http://$payload.oast.test/",
        status = 200,
        request = "GET / HTTP/1.1\r\nHost: $payload.oast.test\r\n\r\n$body",
        response = "HTTP/1.1 200 OK\r\n\r\nok",
    ),
)

private fun smtp(client: String = "c1", payload: String = "p1") = CollaboratorRecord(
    clientId = client,
    payloadId = payload,
    type = CollaboratorRecord.SMTP,
    timestamp = "2026-11-17T10:00:02Z",
    clientIp = "203.0.113.5",
    clientPort = 2525,
    smtp = CollaboratorSmtpDetails("SMTP", "EHLO x\r\n"),
)

/** A history whose seq counts 1, 2, 3, ... instead of following the wall clock. */
private fun history(maxRecords: Int = 100, maxChars: Long = 1_000_000) =
    CollaboratorHistory(maxRecords, maxChars, clock = { 0L })

private fun CollaboratorPage.seqs(): List<Long> = records.map { it.seq }

class CollaboratorHistoryTest {

    @Test
    fun `records get an increasing seq in arrival order`() {
        val history = history()
        assertEquals(listOf(1L, 2L, 3L), listOf(dns(), http(), smtp()).map { history.add(it).seq })
        assertEquals(listOf("DNS", "HTTP", "SMTP"), history.query().records.map { it.type })
    }

    @Test
    fun `filtering by type leaves every other interaction in place`() {
        val history = history()
        listOf(dns(), http(), smtp(), dns()).forEach { history.add(it) }

        val onlyHttp = history.query { it.type == CollaboratorRecord.HTTP }
        assertEquals(listOf(2L), onlyHttp.seqs())
        assertEquals(3, onlyHttp.filteredOut)

        // the DNS and SMTP interactions are still there for whoever asks next
        assertEquals(listOf(1L, 4L), history.query { it.type == CollaboratorRecord.DNS }.seqs())
        assertEquals(listOf(3L), history.query { it.type == CollaboratorRecord.SMTP }.seqs())
        assertEquals(4, history.query().records.size)
        assertEquals(listOf(2L), history.query { it.type == CollaboratorRecord.HTTP }.seqs(), "reading is repeatable")
    }

    @Test
    fun `since returns only later records and next_since resumes from there`() {
        val history = history()
        listOf(dns(), http()).forEach { history.add(it) }
        val first = history.query()
        assertEquals(2L, first.nextSince)
        assertFalse(first.hasMore)

        val nothingNew = history.query(since = first.nextSince)
        assertTrue(nothingNew.records.isEmpty())
        assertEquals(2L, nothingNew.nextSince, "an empty poll keeps the cursor")

        history.add(smtp())
        val later = history.query(since = first.nextSince)
        assertEquals(listOf(3L), later.seqs())
        assertEquals(3L, later.nextSince)
    }

    @Test
    fun `a limit pages through every match without skipping`() {
        val history = history()
        repeat(5) { history.add(dns()) }
        val seen = ArrayList<Long>()
        var since = 0L
        var pages = 0
        do {
            val page = history.query(since = since, limit = 2)
            seen += page.seqs()
            since = page.nextSince
            pages++
        } while (page.hasMore)
        assertEquals(listOf(1L, 2L, 3L, 4L, 5L), seen)
        assertEquals(3, pages)
        assertEquals(5L, since)
    }

    @Test
    fun `filtered_out counts only what lies before the cursor it returns`() {
        val history = history()
        listOf(dns(), http(), dns(), http(), dns()).forEach { history.add(it) } // http is seq 2 and 4

        val firstPage = history.query(limit = 1) { it.type == CollaboratorRecord.HTTP }
        assertEquals(listOf(2L), firstPage.seqs())
        assertTrue(firstPage.hasMore)
        assertEquals(2L, firstPage.nextSince)
        assertEquals(1, firstPage.filteredOut, "only seq 1 precedes the page")

        val secondPage = history.query(since = firstPage.nextSince, limit = 1) { it.type == CollaboratorRecord.HTTP }
        assertEquals(listOf(4L), secondPage.seqs())
        assertFalse(secondPage.hasMore)
        assertEquals(5L, secondPage.nextSince, "a finished page moves the cursor past the non-matching tail")
        assertEquals(2, secondPage.filteredOut)
    }

    @Test
    fun `a query can be scoped to one client`() {
        val history = history()
        listOf(dns(client = "c1"), http(client = "c2"), smtp(client = "c1")).forEach { history.add(it) }

        assertEquals(listOf(1L, 3L), history.query(clientId = "c1").seqs())
        assertEquals(listOf(2L), history.query(clientId = "c2").seqs())
        assertEquals(0, history.query(clientId = "c1").filteredOut, "another client's records are not 'filtered out'")
        assertEquals(CollaboratorHistory.Summary(retained = 2, lastTimestamp = "2026-11-17T10:00:02Z", evicted = 0), history.summary("c1"))
    }

    @Test
    fun `the record bound evicts the oldest and says so`() {
        val history = history(maxRecords = 3)
        repeat(5) { history.add(dns()) }

        val all = history.query()
        assertEquals(listOf(3L, 4L, 5L), all.seqs())
        assertTrue(all.truncated, "seq 1 and 2 were dropped before this reader saw them")
        assertTrue(history.query(since = 1).truncated)
        assertFalse(history.query(since = 2).truncated, "a reader already past the dropped records missed nothing")
        assertEquals(CollaboratorHistory.Summary(retained = 3, lastTimestamp = "2026-11-17T10:00:00Z", evicted = 2), history.summary("c1"))
    }

    @Test
    fun `eviction is reported to the client that lost records`() {
        val history = history(maxRecords = 2)
        listOf(dns(client = "noisy"), dns(client = "quiet"), dns(client = "noisy")).forEach { history.add(it) }

        assertTrue(history.query(clientId = "noisy").truncated)
        assertFalse(history.query(clientId = "quiet").truncated)
        assertEquals(1L, history.summary("noisy").evicted)
        assertEquals(0L, history.summary("quiet").evicted)
    }

    @Test
    fun `the size bound evicts by stored text and always keeps the newest record`() {
        val history = history(maxChars = 5_000)
        repeat(3) { history.add(http(body = "x".repeat(2_000))) } // about 2.3k each: two fit, three do not
        assertEquals(listOf(2L, 3L), history.query().seqs())

        history.add(http(body = "y".repeat(50_000))) // alone above the bound
        assertEquals(listOf(4L), history.query().seqs())

        history.add(dns())
        assertEquals(listOf(5L), history.query().seqs(), "the oversized record goes as soon as there is a newer one")
    }

    @Test
    fun `removing a client drops only its records and frees their share of the bound`() {
        val history = history(maxChars = 5_000)
        history.add(http(client = "gone", body = "x".repeat(2_000)))
        history.add(dns(client = "kept"))

        history.removeClient("gone")
        assertEquals(listOf(2L), history.query().seqs())
        assertEquals(0, history.summary("gone").retained)

        // had the removed record still counted, these two would not both fit
        repeat(2) { history.add(http(client = "kept", body = "x".repeat(2_000))) }
        assertEquals(listOf(2L, 3L, 4L), history.query().seqs())
    }

    @Test
    fun `seq follows the clock so a cursor kept from before a reload still means everything after`() {
        var now = 1_000L
        val beforeReload = CollaboratorHistory(clock = { now })
        assertEquals(1_000L, beforeReload.add(dns()).seq)
        assertEquals(1_001L, beforeReload.add(dns()).seq, "two records in one millisecond still get distinct seq")
        val cursor = beforeReload.query().nextSince

        now = 5_000L
        val afterReload = CollaboratorHistory(clock = { now })
        assertTrue(afterReload.query(since = cursor).records.isEmpty())
        afterReload.add(http())
        assertEquals(listOf(5_000L), afterReload.query(since = cursor).seqs())
    }

    @Test
    fun `a cursor ahead of the history is read as the start instead of hiding everything`() {
        val history = history()
        listOf(dns(), http()).forEach { history.add(it) }

        val page = history.query(since = 999)
        assertEquals(listOf(1L, 2L), page.seqs())
        assertEquals(2L, page.nextSince)
    }
}

class CollaboratorPayloadsTest {

    @Test
    fun `a payload filter matches the id, the host, and a URL around either`() {
        val accepted = listOf(
            "abc123", "ABC123", " abc123 ", "abc123.oastify.com", "ABC123.OASTIFY.COM.",
            "http://abc123.oastify.com/x?y=1", "https://abc123.oastify.com:8443/", "abc123.oastify.com:25",
        )
        for (filter in accepted) {
            assertTrue(CollaboratorPayloads.matches(filter, "abc123", "abc123.oastify.com"), filter)
        }
        val rejected = listOf("abc12", "abc1234", "x.abc123.oastify.com", "other.oastify.com", "", "   ")
        for (filter in rejected) {
            assertFalse(CollaboratorPayloads.matches(filter, "abc123", "abc123.oastify.com"), "'$filter'")
        }
    }

    @Test
    fun `a host whose first label is the id matches when the payload itself is no longer known`() {
        assertTrue(CollaboratorPayloads.matches("abc123.oastify.com", "abc123", null))
        assertFalse(CollaboratorPayloads.matches("abc123.oastify.com", "zzz999", null))
        assertFalse(CollaboratorPayloads.matches("abc123", "", null), "an interaction without an id matches no payload")
    }

    @Test
    fun `a payload whose host does not start with its id is found by the registered host`() {
        // what a payload carrying custom data may look like
        assertTrue(CollaboratorPayloads.matches("http://mark7abc123.oastify.com/", "abc123", "mark7abc123.oastify.com"))
        assertFalse(CollaboratorPayloads.matches("mark7abc123.oastify.com", "abc123", null))
    }

    @Test
    fun `the registry is bounded and forgets the oldest payload first`() {
        val payloads = CollaboratorPayloads(maxEntries = 2)
        listOf("p1", "p2", "p3").forEach { payloads.register(CollaboratorPayloadInfo(it, "$it.oast.test", "c1")) }

        assertNull(payloads["p1"])
        assertEquals("p2.oast.test", payloads["p2"]?.payload)
        assertEquals("p3.oast.test", payloads["p3"]?.payload)
        assertEquals(3, payloads.generatedBy("c1"), "the count is of payloads generated, not of those still remembered")
    }

    @Test
    fun `clientsOf resolves the owners of known payloads and gives up on an unknown one`() {
        val payloads = CollaboratorPayloads()
        payloads.register(CollaboratorPayloadInfo("p1", "p1.oast.test", "c1"))
        payloads.register(CollaboratorPayloadInfo("p2", "p2.oast.test", "c2"))

        assertEquals(setOf("c1"), payloads.clientsOf(listOf("p1.oast.test")))
        assertEquals(setOf("c1", "c2"), payloads.clientsOf(listOf("p1", "http://p2.oast.test/")))
        assertEquals(emptySet<String>(), payloads.clientsOf(emptyList()))
        assertNull(payloads.clientsOf(listOf("p1", "stranger.oast.test")))
    }

    @Test
    fun `removing a client forgets its payloads only`() {
        val payloads = CollaboratorPayloads()
        payloads.register(CollaboratorPayloadInfo("p1", "p1.oast.test", "gone"))
        payloads.register(CollaboratorPayloadInfo("p2", "p2.oast.test", "kept"))

        payloads.removeClient("gone")
        assertNull(payloads["p1"])
        assertEquals(0, payloads.generatedBy("gone"))
        assertEquals("kept", payloads["p2"]?.clientId)
        assertEquals(1, payloads.generatedBy("kept"))
    }
}

class BurpCollaboratorProviderTest {

    /** A provider on its own state, with a stand-in for Burp that "fetches" [pending] on every sync. */
    private class Fixture {
        val provider = BurpCollaboratorProvider(BurpCollaboratorProvider.State(CollaboratorHistory(clock = { 0L })))
        val pending = ArrayList<CollaboratorRecord>()
        val synced = ArrayList<Set<String>?>()
        private var generated = 0

        init {
            provider.attach(object : CollaboratorBackend {
                override fun generatePayload(metadata: String): String {
                    val id = "t${++generated}"
                    provider.payloads.register(CollaboratorPayloadInfo(id, "$id.oast.test", "turbo-client", metadata = metadata))
                    return "$id.oast.test"
                }

                override fun sync(clientIds: Set<String>?) {
                    synced.add(clientIds)
                    pending.forEach { provider.history.add(it) }
                    pending.clear()
                }
            })
        }
    }

    @Test
    fun `interactions carry the payload host and the label it was generated with`() {
        val f = Fixture()
        assertEquals("t1.oast.test", f.provider.generatePayload("SSRF in webhook"))
        f.pending.add(http(client = "turbo-client", payload = "t1"))
        f.pending.add(dns(client = "other", payload = "unknown9"))

        val interactions = f.provider.getInteractions(null)
        assertEquals(2, interactions.size)
        val (hit, stray) = interactions

        assertEquals("t1.oast.test", hit.payload)
        assertEquals("SSRF in webhook", hit.metadata)
        assertEquals("HTTP", hit.type)
        assertEquals("2026-11-17T10:00:01Z", hit.timestamp)
        assertEquals("203.0.113.5", hit.clientIp)
        assertEquals("HTTP", hit.details["protocol"])
        assertEquals("GET / HTTP/1.1\r\nHost: t1.oast.test\r\n\r\n", hit.details["request"])
        assertEquals("HTTP/1.1 200 OK\r\n\r\nok", hit.details["response"])

        assertEquals("unknown9", stray.payload, "a payload generated elsewhere is named by its id")
        assertNull(stray.metadata)
        assertEquals("DNS", stray.type)
        assertEquals("A", stray.details["query_type"])
        assertEquals("unknown9.oast.test", stray.details["query_name"])
    }

    @Test
    fun `asking for one payload returns its interactions and keeps the others for later`() {
        val f = Fixture()
        val first = f.provider.generatePayload("A")
        val second = f.provider.generatePayload("B")
        f.pending.add(dns(client = "turbo-client", payload = "t1"))
        f.pending.add(http(client = "turbo-client", payload = "t2"))
        f.pending.add(smtp(client = "turbo-client", payload = "t2"))

        assertEquals(listOf("DNS"), f.provider.getInteractions(listOf(first)).map { it.type })
        // that poll fetched everything; the second payload's interactions were not thrown away
        assertEquals(listOf("HTTP", "SMTP"), f.provider.getInteractions(listOf(second)).map { it.type })
        assertEquals(listOf("B", "B"), f.provider.getInteractions(listOf(second)).map { it.metadata }, "and reading them again works")
        assertEquals(3, f.provider.getInteractions(null).size)
        assertTrue(f.provider.getInteractions(emptyList()).isEmpty())
    }

    @Test
    fun `a poll for known payloads only syncs the clients that own them`() {
        val f = Fixture()
        val payload = f.provider.generatePayload("A")

        f.provider.getInteractions(listOf(payload))
        f.provider.getInteractions(listOf("stranger.oast.test"))
        f.provider.getInteractions(null)

        assertEquals(listOf(setOf("turbo-client"), null, null), f.synced)
    }

    @Test
    fun `query narrows by client, type and payload without consuming anything`() {
        val f = Fixture()
        f.provider.payloads.register(CollaboratorPayloadInfo("p1", "p1.oast.test", "c1"))
        listOf(dns("c1", "p1"), http("c1", "p1"), http("c1", "p2"), http("c2", "p3")).forEach { f.provider.history.add(it) }

        assertEquals(listOf(2L, 3L), f.provider.query(clientId = "c1", type = "http").seqs())
        assertEquals(listOf(1L, 2L), f.provider.query(clientId = "c1", payloads = listOf("p1.oast.test")).seqs())
        assertEquals(listOf(2L), f.provider.query(clientId = "c1", type = "HTTP", payloads = listOf("p1")).seqs())
        assertEquals(listOf(1L), f.provider.query(clientId = "c1", type = "dns").seqs(), "still there after the http queries")
        assertEquals(4, f.provider.query().records.size)
    }

    @Test
    fun `providers on one state see each other's history and payloads`() {
        val state = BurpCollaboratorProvider.State()
        val bridgeSide = BurpCollaboratorProvider(state)
        val turboSide = BurpCollaboratorProvider(state)
        bridgeSide.history.add(dns())
        bridgeSide.payloads.register(CollaboratorPayloadInfo("p1", "p1.oast.test", "c1", metadata = "label"))
        bridgeSide.attach(object : CollaboratorBackend {
            override fun generatePayload(metadata: String): String = "unused"
            override fun sync(clientIds: Set<String>?) = Unit
        })

        val seen = turboSide.getInteractions(null).single()
        assertEquals("p1.oast.test", seen.payload)
        assertEquals("label", seen.metadata)
    }

    @Test
    fun `providers built without arguments are handles on the same state`() {
        val one = BurpCollaboratorProvider()
        val other = BurpCollaboratorProvider()
        assertSame(one.history, other.history)
        assertSame(one.payloads, other.payloads)
    }

    @Test
    fun `without Burp attached generating fails clearly and reading returns nothing`() {
        val provider = BurpCollaboratorProvider(BurpCollaboratorProvider.State())
        val failure = assertFailsWith<IllegalStateException> { provider.generatePayload("x") }
        assertEquals("Burp Collaborator is not available", failure.message)
        assertTrue(provider.getInteractions(null).isEmpty())
    }
}
