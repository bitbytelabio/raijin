package io.bitbytelab.raijin.turbo

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach

class ResultStoreTest {

    private lateinit var store: ResultStore

    @BeforeEach
    fun setUp() {
        store = ResultStore()
    }

    @Test
    fun `add stores request`() {
        val request = Request("GET / HTTP/1.1")

        store.add(request)

        assertEquals(1, store.count())
    }

    @Test
    fun `getAllRquests returns all added requests`() {
        val req1 = Request("GET /1 HTTP/1.1")
        val req2 = Request("GET /2 HTTP/1.1")

        store.add(req1)
        store.add(req2)

        val all = store.getAllRquests()
        assertEquals(2, all.size)
        assertTrue(all.contains(req1))
        assertTrue(all.contains(req2))
    }

    @Test
    fun `count returns zero for empty store`() {
        assertEquals(0, store.count())
    }

    @Test
    fun `clear removes all requests`() {
        store.add(Request("GET /1 HTTP/1.1"))
        store.add(Request("GET /2 HTTP/1.1"))

        store.clear()

        assertEquals(0, store.count())
    }

    @Test
    fun `getRequest returns request by ID`() {
        val req = Request("GET / HTTP/1.1")
        req.id = 42
        store.add(req)

        val retrieved = store.getRequest(42)

        assertSame(req, retrieved)
    }

    @Test
    fun `getRequest returns null for non-existent ID`() {
        val req = Request("GET / HTTP/1.1")
        req.id = 1
        store.add(req)

        assertNull(store.getRequest(999))
    }

    @Test
    fun `getRequest finds correct request among multiple`() {
        val req1 = Request("GET /1 HTTP/1.1").apply { id = 10 }
        val req2 = Request("GET /2 HTTP/1.1").apply { id = 20 }
        val req3 = Request("GET /3 HTTP/1.1").apply { id = 30 }
        store.add(req1)
        store.add(req2)
        store.add(req3)

        assertSame(req2, store.getRequest(20))
    }

    @Test
    fun `getResults respects limit`() {
        repeat(10) { store.add(Request("GET /$it HTTP/1.1")) }

        val results = store.getResults(limit = 3)

        assertEquals(3, results.size)
    }

    @Test
    fun `getResults respects offset`() {
        repeat(5) { i ->
            val req = Request("GET /$i HTTP/1.1")
            store.add(req)
        }

        val results = store.getResults(offset = 2, limit = 10)

        assertEquals(3, results.size)
    }

    @Test
    fun `getResults sorts by status code ascending`() {
        val req200 = Request("GET / HTTP/1.1").apply { response = "HTTP/1.1 200 OK\r\n\r\n" }
        val req404 = Request("GET / HTTP/1.1").apply { response = "HTTP/1.1 404 Not Found\r\n\r\n" }
        val req500 = Request("GET / HTTP/1.1").apply { response = "HTTP/1.1 500 Error\r\n\r\n" }

        store.add(req404)
        store.add(req200)
        store.add(req500)

        val results = store.getResults(sortBy = SortField.STATUS, descending = false)

        assertEquals(200, results[0].code)
        assertEquals(404, results[1].code)
        assertEquals(500, results[2].code)
    }

    @Test
    fun `getResults sorts by status code descending`() {
        val req200 = Request("GET / HTTP/1.1").apply { response = "HTTP/1.1 200 OK\r\n\r\n" }
        val req404 = Request("GET / HTTP/1.1").apply { response = "HTTP/1.1 404 Not Found\r\n\r\n" }
        val req500 = Request("GET / HTTP/1.1").apply { response = "HTTP/1.1 500 Error\r\n\r\n" }

        store.add(req404)
        store.add(req200)
        store.add(req500)

        val results = store.getResults(sortBy = SortField.STATUS, descending = true)

        assertEquals(500, results[0].code)
        assertEquals(404, results[1].code)
        assertEquals(200, results[2].code)
    }

    @Test
    fun `getResults sorts by length`() {
        val short = Request("GET / HTTP/1.1").apply { response = "HTTP/1.1 200 OK\r\n\r\na" }
        val long = Request("GET / HTTP/1.1").apply { response = "HTTP/1.1 200 OK\r\n\r\n" + "x".repeat(100) }

        store.add(short)
        store.add(long)

        val results = store.getResults(sortBy = SortField.LENGTH, descending = true)

        assertTrue(results[0].length > results[1].length)
    }

    @Test
    fun `getResults sorts by time using ttfb`() {
        val slow = Request("GET / HTTP/1.1").apply { ttfb = 1000L; time = 1000L }
        val fast = Request("GET / HTTP/1.1").apply { ttfb = 100L; time = 100L }

        store.add(slow)
        store.add(fast)

        val results = store.getResults(sortBy = SortField.TIME, descending = false)

        assertEquals(100L, results[0].ttfb)
        assertEquals(1000L, results[1].ttfb)
    }

    @Test
    fun `getResults sorts by TTFB`() {
        val slow = Request("GET / HTTP/1.1").apply { ttfb = 1000L }
        val fast = Request("GET / HTTP/1.1").apply { ttfb = 100L }

        store.add(slow)
        store.add(fast)

        val results = store.getResults(sortBy = SortField.TTFB, descending = false)

        assertEquals(100L, results[0].ttfb)
        assertEquals(1000L, results[1].ttfb)
    }

    @Test
    fun `getResults sorts by TTLB`() {
        val slow = Request("GET / HTTP/1.1").apply { ttlb = 2000L }
        val fast = Request("GET / HTTP/1.1").apply { ttlb = 200L }

        store.add(slow)
        store.add(fast)

        val results = store.getResults(sortBy = SortField.TTLB, descending = false)

        assertEquals(200L, results[0].ttlb)
        assertEquals(2000L, results[1].ttlb)
    }

    @Test
    fun `getResults sorts by anomaly rank with nulls`() {
        val high = Request("GET / HTTP/1.1").apply { anomalyRank = 100 }
        val low = Request("GET / HTTP/1.1").apply { anomalyRank = 10 }
        val none = Request("GET / HTTP/1.1") // anomalyRank is null

        store.add(none)
        store.add(high)
        store.add(low)

        val results = store.getResults(sortBy = SortField.ANOMALY_RANK, descending = true)

        assertEquals(100, results[0].anomalyRank)
        assertEquals(10, results[1].anomalyRank)
        assertEquals(null, results[2].anomalyRank) // null treated as 0
    }

    @Test
    fun `getResults pagination with offset and limit`() {
        repeat(10) { i ->
            val req = Request("GET /$i HTTP/1.1").apply { ttfb = i.toLong(); time = i.toLong() }
            store.add(req)
        }

        // Get page 2 (items 3-5) sorted by ttfb ascending
        val results = store.getResults(sortBy = SortField.TTFB, descending = false, offset = 3, limit = 3)

        assertEquals(3, results.size)
        assertEquals(3L, results[0].ttfb)
        assertEquals(4L, results[1].ttfb)
        assertEquals(5L, results[2].ttfb)
    }

    @Test
    fun `getUniqueStatusCodes returns all distinct status codes`() {
        val req200a = Request("GET /a HTTP/1.1").apply { response = "HTTP/1.1 200 OK\r\n\r\n" }
        val req200b = Request("GET /b HTTP/1.1").apply { response = "HTTP/1.1 200 OK\r\n\r\n" }
        val req404 = Request("GET /c HTTP/1.1").apply { response = "HTTP/1.1 404 Not Found\r\n\r\n" }
        val req500 = Request("GET /d HTTP/1.1").apply { response = "HTTP/1.1 500 Error\r\n\r\n" }

        store.add(req200a)
        store.add(req200b)
        store.add(req404)
        store.add(req500)

        val statusCodes = store.getUniqueStatusCodes()

        assertEquals(setOf(200, 404, 500), statusCodes)
    }

    @Test
    fun `getUniqueStatusCodes returns empty set for empty store`() {
        val statusCodes = store.getUniqueStatusCodes()

        assertEquals(emptySet<Int>(), statusCodes)
    }

    @Test
    fun `getRequestByIndex returns request at position regardless of ID`() {
        val req1 = Request("GET /1 HTTP/1.1").apply { id = 100 }
        val req2 = Request("GET /2 HTTP/1.1").apply { id = 200 }
        val req3 = Request("GET /3 HTTP/1.1").apply { id = 300 }
        store.add(req1)
        store.add(req2)
        store.add(req3)

        assertSame(req1, store.getRequestByIndex(0))
        assertSame(req2, store.getRequestByIndex(1))
        assertSame(req3, store.getRequestByIndex(2))
    }

    @Test
    fun `getRequestByIndex returns null for out of bounds index`() {
        val req = Request("GET / HTTP/1.1").apply { id = 1 }
        store.add(req)

        assertNull(store.getRequestByIndex(-1))
        assertNull(store.getRequestByIndex(1))
        assertNull(store.getRequestByIndex(999))
    }

    @Test
    fun `stripResponseBodies nulls all response bodies but preserves metadata`() {
        val req1 = Request("GET /1 HTTP/1.1").apply {
            response = "HTTP/1.1 200 OK\r\n\r\nBody1"
            id = 1
        }
        val req2 = Request("GET /2 HTTP/1.1").apply {
            response = "HTTP/1.1 404 Not Found\r\n\r\nBody2"
            id = 2
        }
        store.add(req1)
        store.add(req2)

        store.stripResponseBodies()

        assertNull(req1.response)
        assertNull(req2.response)
        assertEquals(200, req1.code)
        assertEquals(404, req2.code)
    }

    private fun response(status: Int, body: String = "") = "HTTP/1.1 $status X\r\n\r\n$body"

    @Test
    fun `ID order is the order results arrived in`() {
        val requests = (1..5).map { i -> Request("GET /$i HTTP/1.1").apply { id = 10 - i } }
        requests.forEach(store::add)

        assertEquals(requests, store.getResults(SortField.ID, descending = false, limit = 10))
        assertEquals(requests.reversed(), store.getResults(SortField.ID, descending = true, limit = 10))
        assertEquals(requests.reversed().drop(1).take(2), store.getResults(SortField.ID, true, limit = 2, offset = 1))
    }

    @Test
    fun `ties keep arrival order in either direction`() {
        val requests = (1..4).map { i -> Request("GET /$i HTTP/1.1").apply { response = response(200) } }
        requests.forEach(store::add)

        assertEquals(requests, store.getResults(SortField.STATUS, descending = false))
        assertEquals(requests, store.getResults(SortField.STATUS, descending = true))
    }

    @Test
    fun `setSortOrder takes the GUI table's column numbers and orders results read without an explicit sort`() {
        val ok = Request("GET /a HTTP/1.1").apply { response = response(200) }
        val missing = Request("GET /b HTTP/1.1").apply { response = response(404) }
        val broken = Request("GET /c HTTP/1.1").apply { response = response(500) }
        listOf(missing, broken, ok).forEach(store::add)

        store.setSortOrder(2, false) // Status, ascending

        assertEquals(ResultSortOrder(2, false), store.sortOrder())
        assertEquals(SortField.STATUS, store.sortOrder()!!.field)
        assertEquals(listOf(ok, missing, broken), store.getResults())
        assertEquals(listOf(broken, missing, ok), store.getResults(descending = true))
        // An explicit sort still wins.
        assertEquals(listOf(ok, broken, missing), store.getResults(SortField.ID, descending = true))
    }

    @Test
    fun `every GUI column has a sort field and other column numbers are rejected`() {
        val expected = listOf(
            SortField.ID, SortField.PAYLOAD, SortField.STATUS, SortField.ANOMALY_RANK, SortField.WORDCOUNT,
            SortField.LENGTH, SortField.TTFB, SortField.TTLB, SortField.ARRIVAL, SortField.LABEL,
            SortField.QUEUE_ID, SortField.CONNECTION_ID,
        )
        expected.forEachIndexed { column, field -> assertEquals(field, ResultSortOrder(column, true).field) }

        assertThrows(IllegalArgumentException::class.java) { store.setSortOrder(12, true) }
        assertThrows(IllegalArgumentException::class.java) { store.setSortOrder(-1, true) }
        assertNull(store.sortOrder())
    }

    @Test
    fun `the GUI table applies each order a script sets, once`() {
        assertNull(scriptSortOrderToApply(store.sortOrder(), null), "no order set, nothing to apply")

        store.setSortOrder(2, false)
        val first = store.sortOrder()
        assertNotNull(first)
        assertSame(first, scriptSortOrderToApply(first, null))
        // Applied once, so a sort the user then picks by hand stays.
        assertNull(scriptSortOrderToApply(store.sortOrder(), first))

        // The same call again sorts again.
        store.setSortOrder(2, false)
        val repeated = store.sortOrder()
        assertNotNull(repeated)
        assertSame(repeated, scriptSortOrderToApply(repeated, first))
    }

    @Test
    fun `sorts by label and queue id`() {
        val b = Request("GET / HTTP/1.1", emptyList(), 0, "b").apply { id = 1 }
        val a = Request("GET / HTTP/1.1", emptyList(), 0, "a").apply { id = 2 }
        store.add(b)
        store.add(a)

        assertEquals(listOf(a, b), store.getResults(SortField.LABEL, descending = false))
        assertEquals(listOf(b, a), store.getResults(SortField.QUEUE_ID, descending = false))
    }

    @Test
    fun `past its budget a store drops the oldest bodies and keeps their metadata`() {
        val budgeted = ResultStore(responseBodyBudget = 1_000)
        val body = "x".repeat(100)
        val requests = (1..300).map { Request("GET / HTTP/1.1").apply { response = response(201, body) } }
        requests.forEach(budgeted::add)

        // The newest 256 always keep their bodies, so only the 44 before them can give theirs up.
        assertEquals(44, budgeted.droppedBodyCount())
        requests.take(44).forEach { dropped ->
            assertNull(dropped.response)
            assertEquals(201, dropped.code)
            assertEquals(response(201, body).length, dropped.length)
        }
        requests.drop(44).forEach { assertNotNull(it.response) }
        assertEquals(300, budgeted.count())
    }

    @Test
    fun `a store within its budget keeps every body`() {
        val budgeted = ResultStore(responseBodyBudget = 1_000_000)
        val requests = (1..300).map { Request("GET / HTTP/1.1").apply { response = response(200, "body") } }
        requests.forEach(budgeted::add)

        assertEquals(0, budgeted.droppedBodyCount())
        requests.forEach { assertNotNull(it.response) }
    }
}
