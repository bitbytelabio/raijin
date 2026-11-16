package io.bitbytelab.raijin.bridge

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class HttpFuzzRunnerTest {

    private fun sniper(vararg payloads: String): HttpFuzzPlan.AttackPlan =
        (HttpFuzzPlan.planAttack("GET /?u=FUZZ HTTP/1.1", null, listOf(payloads.toList()), null) as HttpFuzzPlan.AttackResult.Ok).plan

    /** "admin" logs in, "boom" fails to send, anything else is refused. */
    private fun target(jsonCalls: AtomicInteger = AtomicInteger()): (HttpFuzzPlan.AttackRequest) -> HttpFuzzRunner.Sent = { request ->
        val payload = request.label
        when (payload) {
            "boom" -> throw IllegalStateException("connection refused")
            "admin" -> HttpFuzzRunner.Sent.Answered(200, 13, "HTTP/1.1 200 OK\r\nX-Role: admin", "welcome admin", 5, json(jsonCalls, 200))
            else -> HttpFuzzRunner.Sent.Answered(401, 6, "HTTP/1.1 401 Unauthorized", "denied", 5, json(jsonCalls, 401))
        }
    }

    private fun json(calls: AtomicInteger, status: Int): () -> JsonObject = {
        calls.incrementAndGet()
        buildJsonObject { put("status_code", status) }
    }

    private fun JsonObject.results() = getValue("results").jsonArray.map { it.jsonObject }

    @Test
    fun `every request is reported in order with its payload, cluster and exchange`() {
        val out = HttpFuzzRunner(target()).run(sniper("a", "admin", "b"), HttpFuzzRunner.Options(payloadsCount = 3))
        assertEquals(3, out.getValue("total_requests").jsonPrimitive.int)
        assertEquals("sniper", out.getValue("attack_mode").jsonPrimitive.content)
        assertEquals(HttpFuzzPlan.KEYWORD_POSITIONS, out.getValue("mode").jsonPrimitive.content)
        assertFalse(out.getValue("stopped_early").jsonPrimitive.boolean)
        val results = out.results()
        assertEquals(listOf("a", "admin", "b"), results.map { it.getValue("payload").jsonPrimitive.content })
        assertEquals(listOf(401, 200, 401), results.map { it.getValue("status_code").jsonPrimitive.int })
        assertEquals(listOf(0, 1, 0), results.map { it.getValue("cluster").jsonPrimitive.int })
        assertEquals(2, out.getValue("summary").jsonObject.getValue("cluster_count").jsonPrimitive.int)
    }

    @Test
    fun `a stop condition ends the run after the matching response`() {
        val byStatus = HttpFuzzRunner(target()).run(sniper("a", "admin", "b", "c"), HttpFuzzRunner.Options(stopOnStatusCodes = listOf(200)))
        assertTrue(byStatus.getValue("stopped_early").jsonPrimitive.boolean)
        assertEquals(2, byStatus.getValue("total_requests").jsonPrimitive.int)

        val byBody = HttpFuzzRunner(target()).run(sniper("a", "admin", "b"), HttpFuzzRunner.Options(stopOnBodyRegex = "welcome\\s+\\w+"))
        assertEquals(2, byBody.getValue("total_requests").jsonPrimitive.int)
    }

    @Test
    fun `filters shorten the list but every response is still clustered`() {
        val out = HttpFuzzRunner(target()).run(
            sniper("a", "admin", "b"),
            HttpFuzzRunner.Options(filter = FuzzResponseFilter(hideStatus = setOf(401))),
        )
        assertEquals(listOf("admin"), out.results().map { it.getValue("payload").jsonPrimitive.content })
        assertEquals(2, out.getValue("filtered_out").jsonPrimitive.int)
        assertEquals(3, out.getValue("total_requests").jsonPrimitive.int)
        assertEquals(2, out.getValue("summary").jsonObject.getValue("cluster_count").jsonPrimitive.int)

        val grep = HttpFuzzRunner(target()).run(sniper("a", "admin"), HttpFuzzRunner.Options(filter = FuzzResponseFilter(grepRegex = "X-Role: admin")))
        assertEquals(listOf("admin"), grep.results().map { it.getValue("payload").jsonPrimitive.content })
    }

    @Test
    fun `a failed send is an entry of its own and the run goes on`() {
        val out = HttpFuzzRunner(target()).run(sniper("boom", "admin"), HttpFuzzRunner.Options())
        assertEquals(1, out.getValue("failed_requests").jsonPrimitive.int)
        val failed = out.results().first()
        assertEquals("connection refused", failed.getValue("error").jsonPrimitive.content)
        assertFalse(failed.getValue("is_timeout").jsonPrimitive.boolean)
        assertEquals(200, out.results()[1].getValue("status_code").jsonPrimitive.int)
    }

    @Test
    fun `report modes trade detail for size and exchanges are only built when listed`() {
        val calls = AtomicInteger()
        val summary = HttpFuzzRunner(target(calls)).run(sniper("a", "admin", "b"), HttpFuzzRunner.Options(report = HttpFuzzRunner.REPORT_SUMMARY))
        assertNull(summary["results"])
        assertEquals(0, calls.get())

        val clusters = HttpFuzzRunner(target(calls)).run(sniper("a", "admin", "b"), HttpFuzzRunner.Options(report = HttpFuzzRunner.REPORT_CLUSTERS))
        assertEquals(2, clusters.getValue("representatives").jsonArray.size)
        assertEquals(2, calls.get())
        val line = clusters.results().first()
        assertEquals(401, line.getValue("status_code").jsonPrimitive.int)
        assertEquals(6, line.getValue("response_body_length").jsonPrimitive.int)
    }

    @Test
    fun `multi-set attacks list the payloads of every position`() {
        val plan = (HttpFuzzPlan.planAttack(
            "GET /?u=§u§&p=§p§ HTTP/1.1", null, listOf(listOf("admin", "root"), listOf("x")), null, HttpFuzzPlan.AttackMode.CLUSTER_BOMB,
        ) as HttpFuzzPlan.AttackResult.Ok).plan
        val out = HttpFuzzRunner { HttpFuzzRunner.Sent.Answered(200, 2, "HTTP/1.1 200 OK", "ok", 1) { buildJsonObject {} } }
            .run(plan, HttpFuzzRunner.Options())
        assertEquals(
            listOf(listOf("admin", "x"), listOf("root", "x")),
            out.results().map { r -> r.getValue("payloads").jsonArray.map { it.jsonPrimitive.content } },
        )
    }

    @Test
    fun `concurrency keeps the given number of requests in flight and loses none`() {
        val inFlight = AtomicInteger()
        val peak = AtomicInteger()
        val runner = HttpFuzzRunner { request ->
            val now = inFlight.incrementAndGet()
            peak.accumulateAndGet(now) { a, b -> maxOf(a, b) }
            Thread.sleep(20)
            inFlight.decrementAndGet()
            HttpFuzzRunner.Sent.Answered(200, 2, "HTTP/1.1 200 OK", request.label, 1) { buildJsonObject {} }
        }
        val payloads = (0 until 20).map { "p$it" }
        val out = runner.run(sniper(*payloads.toTypedArray()), HttpFuzzRunner.Options(concurrency = 4, report = HttpFuzzRunner.REPORT_CLUSTERS))
        assertEquals((0 until 20).toList(), out.results().map { it.getValue("index").jsonPrimitive.int })
        assertTrue(peak.get() in 2..4, "peak in flight ${peak.get()}")
    }

    @Test
    fun `the rate pacer spaces starts evenly across threads`() {
        var now = 0L
        val starts = ArrayList<Long>()
        val pacer = RatePacer(10.0, nanoTime = { now }, sleepNanos = { now += it })
        repeat(3) {
            pacer.await()
            starts += now
        }
        assertEquals(listOf(0L, 100_000_000L, 200_000_000L), starts)
        RatePacer(0.0, nanoTime = { error("an unlimited pacer never reads the clock") }).await()
    }

    @Test
    fun `filter lengths and statuses parse lists, ranges and single values`() {
        val lengths = FuzzResponseFilter.parseLengths(Json.parseToJsonElement("""[100, "200-300", "5,6", "400 - 350"]"""))
        assertEquals(listOf(100..100, 200..300, 5..5, 6..6, 350..400), lengths)
        assertEquals(listOf(42..42), FuzzResponseFilter.parseLengths(Json.parseToJsonElement("42")))
        assertFailsWith<IllegalArgumentException> { FuzzResponseFilter.parseLengths(Json.parseToJsonElement("""["big"]""")) }
        assertEquals(setOf(404, 500), FuzzResponseFilter.parseStatuses(Json.parseToJsonElement("""[404, "500"]"""), "hide_status"))
        assertEquals(setOf(301), FuzzResponseFilter.parseStatuses(Json.parseToJsonElement("301"), "hide_status"))
        assertFailsWith<IllegalArgumentException> { FuzzResponseFilter.parseStatuses(Json.parseToJsonElement("""["x"]"""), "hide_status") }
    }

    @Test
    fun `a filter only builds the response text when a regex needs it`() {
        val built = AtomicInteger()
        val text = { built.incrementAndGet(); "HTTP/1.1 200 OK\r\n\r\nsecret" }
        assertTrue(FuzzResponseFilter(hideStatus = setOf(404)).keeps(200, 6, text))
        assertFalse(FuzzResponseFilter(hideLengths = listOf(0..10)).keeps(200, 6, text))
        assertEquals(0, built.get())
        assertTrue(FuzzResponseFilter(grepRegex = "secret").keeps(200, 6, text))
        assertFalse(FuzzResponseFilter(hideRegex = "secret").keeps(200, 6, text))
        assertFalse(FuzzResponseFilter(grepRegex = "secret").keeps(0, 0) { "" })
        assertEquals(2, built.get())
    }
}
