package io.bitbytelab.raijin.bridge

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Dry runs of custom checks against recorded traffic (plan P2.5): what a scan check or a
 * BCheck definition would have done with the proxy history, worked out without sending anything.
 */
class CheckDryRunTest {

    private var nextId = 1

    /** A history item for [url]; a null [body] is a request that never got a response. */
    private fun item(url: String, body: String? = "", status: Int = 200, headers: String = ""): HistoryItem {
        val afterScheme = url.substringAfter("://")
        return HistoryItem(
            id = nextId++,
            method = "GET",
            url = url,
            host = afterScheme.substringBefore('/'),
            path = "/" + afterScheme.substringAfter('/', "").substringBefore('?'),
            exchange = CheckExchange(
                requestUrl = url,
                hasResponse = body != null,
                statusCode = if (body != null) status else 0,
                responseHeaders = headers,
                responseBody = body.orEmpty(),
                responseLength = body?.length ?: 0,
            ),
        )
    }

    private fun body(pattern: String, type: String = "contains", negate: Boolean = false) =
        CheckCondition("response_body", pattern, type, negate)

    private fun JsonObject.int(key: String): Int = getValue(key).jsonPrimitive.int

    private fun JsonObject.objects(key: String): List<JsonObject> = getValue(key).jsonArray.map { it.jsonObject }

    private fun bcheck(
        type: String,
        matchPattern: String? = null,
        matchLocation: String? = null,
        matchCondition: String? = null,
        payloads: List<String>? = null,
        responseMatchPattern: String? = null,
        path: String? = null,
        maxMatches: Int = 10,
    ): BCheckDryRun = BCheckBridge.dryRunOf(
        BCheckBridge.resolve(type, matchPattern, matchLocation, matchCondition, payloads, responseMatchPattern, null, path),
        maxMatches,
    )

    private fun BCheckDryRun.over(vararg items: HistoryItem): JsonObject {
        items.forEach(visit)
        return result()
    }

    // ---- passive scan checks ----------------------------------------------------

    @Test
    fun `a passive dry run lists what would be reported and why`() {
        val run = PassiveDryRun(listOf(body("AKIA[0-9A-Z]{16}", "matches")), MatchMode.ALL, maxMatches = 10)
        val leaking = item("https://t/config.js?v=1", "var key = 'AKIAIOSFODNN7EXAMPLE';")
        listOf(leaking, item("https://t/index.html", "hello"), item("https://t/config.js?v=2", "AKIAIOSFODNN7EXAMPLE"), item("https://t/slow", null))
            .forEach(run::visit)

        val result = run.toJson()
        assertEquals(4, result.int("items_evaluated"))
        assertEquals(1, result.int("items_without_response"))
        assertEquals(2, result.int("would_report"))
        assertEquals(1, result.int("distinct_paths"), "the same path with two query strings is one issue")

        val first = result.objects("matches").first()
        assertEquals(leaking.id, first.int("index"))
        assertEquals("https://t/config.js?v=1", first.getValue("url").jsonPrimitive.content)
        assertEquals(200, first.int("status"))
        val matched = first.objects("matched").single()
        assertEquals(0, matched.int("condition"))
        assertTrue("AKIAIOSFODNN7EXAMPLE" in matched.getValue("excerpt").jsonPrimitive.content)
        assertNull(result["matches_omitted"])
    }

    @Test
    fun `a negated condition does not report requests that never got a response`() {
        val noHsts = CheckCondition("response_headers", "strict-transport-security", "matches", negate = true)
        val run = PassiveDryRun(listOf(noHsts), MatchMode.ALL, maxMatches = 10)
        listOf(item("https://t/a", "x", headers = "Server: nginx"), item("https://t/b", null), item("https://t/c", "x", headers = "Strict-Transport-Security: max-age=1"))
            .forEach(run::visit)
        assertEquals(1, run.toJson().int("would_report"))
    }

    @Test
    fun `match mode any reports on one condition and says which`() {
        val run = PassiveDryRun(listOf(body("alpha"), body("beta")), MatchMode.ANY, maxMatches = 10)
        run.visit(item("https://t/a", "only beta here"))
        val matched = run.toJson().objects("matches").single().objects("matched")
        assertEquals(listOf(1), matched.map { it.int("condition") })
    }

    @Test
    fun `matches beyond the limit are counted, not listed`() {
        val run = PassiveDryRun(listOf(body("x")), MatchMode.ALL, maxMatches = 2)
        repeat(5) { run.visit(item("https://t/p$it", "x")) }
        val result = run.toJson()
        assertEquals(5, result.int("would_report"))
        assertEquals(2, result.objects("matches").size)
        assertEquals(3, result.int("matches_omitted"))
    }

    // ---- active scan checks -------------------------------------------------------

    @Test
    fun `an active dry run shows how much of the baseline each step already matches`() {
        val broad = ActiveStep("'", listOf(body("(?i)database|query", "matches")))
        val narrow = ActiveStep("' OR '1'='1", listOf(body("You have an error in your SQL syntax")), stopIfNoMatch = false)
        val run = BaselineDryRun(listOf(broad, narrow), maxExamples = 5)
        listOf(
            item("https://t/search", "Type your query"),
            item("https://t/admin/db", "database console"),
            item("https://t/about", "about us"),
            item("https://t/broken", "You have an error in your SQL syntax near database"),
            item("https://t/timeout", null),
        ).forEach(run::visit)

        val result = run.toJson()
        assertEquals(5, result.int("items_evaluated"))
        assertEquals(1, result.int("items_without_response"))
        val (first, second) = result.objects("steps")
        assertEquals(3, first.int("baseline_matches"), "a pattern this broad is on the page before any payload")
        assertEquals(1, second.int("baseline_matches"))
        assertEquals("' OR '1'='1", second.getValue("payload").jsonPrimitive.content)
        assertEquals(1, result.int("cannot_report_on"), "only /broken matches every step as it is")
    }

    @Test
    fun `only conditions on the response are held against the baseline`() {
        // The request a payload produces is not in the history; a condition on it says nothing about the baseline.
        val step = ActiveStep("'", listOf(CheckCondition("request_url", "search", "contains"), body("sql")))
        val priming = ActiveStep("x", listOf(CheckCondition("request_url", "search", "contains")))
        val run = BaselineDryRun(listOf(step, priming), maxExamples = 5)
        run.visit(item("https://t/search", "welcome"))
        run.visit(item("https://t/search2", "sql console"))

        val (judging, notJudging) = run.toJson().objects("steps")
        assertEquals(1, judging.int("baseline_matches"))
        assertFalse(notJudging.getValue("judges_response").jsonPrimitive.boolean)
        assertNull(notJudging["baseline_matches"])
    }

    // ---- BCheck definitions ---------------------------------------------------------

    @Test
    fun `a passive BCheck is evaluated in full and case-sensitively, as Burp would`() {
        val result = bcheck("passive_response", matchPattern = "Apache/2", matchLocation = "response_headers")
            .over(
                item("https://t/a", "x", headers = "Server: Apache/2.4.1"),
                item("https://t/b", "x", headers = "server: apache/2.4.1"),
                item("https://t/c", "Apache/2 in the body only"),
            )
        assertEquals(1, result.int("would_report"))
        assertEquals("https://t/a", result.objects("matches").single().getValue("url").jsonPrimitive.content)
    }

    @Test
    fun `a passive request BCheck looks at the request`() {
        val result = bcheck("passive_request", matchPattern = "token=", matchCondition = "contains")
            .over(item("https://t/a?token=abc"), item("https://t/b?id=1"))
        assertEquals(1, result.int("would_report"))
    }

    @Test
    fun `an insertion point BCheck reports what its baseline guard would skip`() {
        val run = bcheck("insertion_point", payloads = listOf("'", "\""), responseMatchPattern = "syntax error")
        val result = run.over(item("https://t/a", "ok"), item("https://t/docs", "how to read a syntax error"), item("https://t/b", "ok"))

        val step = result.objects("steps").single()
        assertEquals(1, step.int("baseline_matches"))
        assertEquals("', \"", step.getValue("payload").jsonPrimitive.content)
        assertEquals(1, result.int("cannot_report_on"))
        assertTrue("No payload was sent" in run.note)
    }

    @Test
    fun `a host level BCheck counts the hosts it would probe and the recorded answers for its path`() {
        val run = bcheck("host_level", path = "/.git/config", responseMatchPattern = "\\[core\\]", maxMatches = 10)
        val result = run.over(
            item("https://a.example/index.html", "home"),
            item("https://a.example/.git/config", "[core]\n\trepositoryformatversion = 0"),
            item("https://b.example/.git/config", "Not found", status = 404),
            item("https://b.example/.git/config", "<html>every path answers 200</html>"),
            item("https://c.example/x/.git/config", "[core]"),
        )
        assertEquals(3, result.int("hosts"))
        assertEquals(3, result.int("probe_requests"))
        assertEquals(1, result.int("recorded_hits"), "200 and the pattern, on exactly that path")
        assertEquals("https://a.example/.git/config", result.objects("matches").single().getValue("url").jsonPrimitive.content)
        assertTrue("GET /.git/config" in run.note)
    }

    @Test
    fun `a path level BCheck counts the requests it would add`() {
        val result = bcheck("path_level", payloads = listOf(".bak", ".old")).over(
            item("https://t/app.js"),
            item("https://t/app.js?v=2"),
            item("https://t/login"),
            item("https://t/db.sql.bak", "CREATE TABLE users"),
            item("https://t/missing.old", "gone", status = 404),
        )
        assertEquals(4, result.int("distinct_paths"))
        assertEquals(8, result.int("probe_requests"))
        assertEquals(1, result.int("recorded_hits"))
    }

    @Test
    fun `a collaborator BCheck can only say how many requests it would resend`() {
        val run = BCheckBridge.dryRunOf(BCheckBridge.resolve("collaborator", null, "X-Forwarded-Host", null, null, null, "http", null), 10)
        listOf(item("https://t/a"), item("https://t/b")).forEach(run.visit)
        assertEquals(2, run.result().int("probe_requests"))
        assertTrue("X-Forwarded-Host" in run.note && "http interaction" in run.note, run.note)
    }

    // ---- which history is read ---------------------------------------------------

    @Test
    fun `the history selection has defaults and bounds`() {
        val defaults = HistoryFilter.of(null, false, null)
        assertEquals(HistoryFilter.DEFAULT_ITEMS, defaults.maxItems)
        assertNull(defaults.urlPattern)
        assertEquals(HistoryFilter.DEFAULT_MATCHES, HistoryFilter.matchLimit(null))
        assertEquals(HistoryFilter.MAX_ITEMS, HistoryFilter.of("/api/", true, HistoryFilter.MAX_ITEMS).maxItems)

        assertTrue("max_items" in assertFailsWith<InvalidCheckException> { HistoryFilter.of(null, false, 0) }.message!!)
        assertTrue("max_items" in assertFailsWith<InvalidCheckException> { HistoryFilter.of(null, false, HistoryFilter.MAX_ITEMS + 1) }.message!!)
        assertTrue("max_matches" in assertFailsWith<InvalidCheckException> { HistoryFilter.matchLimit(-1) }.message!!)
        assertTrue("url_pattern" in assertFailsWith<InvalidCheckException> { HistoryFilter.of("([", false, null) }.message!!)
    }

    @Test
    fun `every dry run result says that nothing was sent and what was read`() {
        val filter = HistoryFilter.of("/api/", true, 50)
        val report = dryRunReport("passive", historySize = 1234, filter = filter, body = PassiveDryRun(listOf(body("x")), MatchMode.ALL, 5).toJson(), note = "n")
        assertTrue(report.getValue("dry_run").jsonPrimitive.boolean)
        assertEquals(0, report.int("requests_sent"))
        assertEquals(1234, report.int("history_size"))
        val read = report.getValue("history_filter").jsonObject
        assertEquals("/api/", read.getValue("url_pattern").jsonPrimitive.content)
        assertEquals(50, read.int("max_items"))
        assertEquals(0, report.int("would_report"))
    }
}
