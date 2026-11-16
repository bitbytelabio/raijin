package io.bitbytelab.raijin.bridge

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The rules every custom scan check runs on, whichever tool created it: how a condition is
 * judged, when an active check may report, and when two issues are the same issue.
 *
 * The active-check tests are the regression for plan P0.3 item 2: a check must not report
 * when no request was answered, nor for something the unmodified response shows as well.
 */
class ScanCheckLogicTest {

    private fun response(body: String = "", status: Int = 200, headers: String = "", url: String = "https://t/a?q=1") =
        CheckExchange(
            requestUrl = url, hasResponse = true, statusCode = status,
            responseHeaders = headers, responseBody = body, responseLength = body.length,
        )

    private val noResponse = CheckExchange(requestUrl = "https://t/a?q=1")

    private fun body(pattern: String, type: String = "contains", negate: Boolean = false) =
        CheckCondition("response_body", pattern, type, negate)

    private fun step(payload: String, vararg conditions: CheckCondition, required: Boolean = true, mode: MatchMode = MatchMode.ALL) =
        ActiveStep(payload, conditions.toList(), mode, stopIfNoMatch = required)

    /** Runs [steps] with canned responses per payload; a payload without one gets no answer. */
    private fun run(
        steps: List<ActiveStep>,
        baseline: CheckExchange?,
        answers: Map<String, CheckExchange>,
        control: CheckExchange? = null,
    ) = ScanCheckLogic.runActive(
        steps,
        baseline = { baseline },
        send = { payload -> answers[payload]?.let { it.copy(requestUrl = "https://t/a?q=$payload") to payload } },
        control = { control },
    )

    private fun condition(location: String, pattern: String?, type: String? = null, negate: Boolean? = null): JsonObject =
        buildJsonObject {
            put("location", location)
            if (pattern != null) put("pattern", pattern)
            if (type != null) put("condition_type", type)
            if (negate != null) put("negate", negate)
        }

    private fun stepJson(
        payload: String?,
        vararg conditions: JsonObject,
        extra: JsonObjectBuilder.() -> Unit = {},
    ): JsonObject = buildJsonObject {
        if (payload != null) put("payload", payload)
        put("response_conditions", buildJsonArray { conditions.forEach { add(it) } })
        extra()
    }

    // ---- conditions -------------------------------------------------------

    @Test
    fun `the three condition types compare case-insensitively`() {
        val page = response("You have an error in your SQL syntax", status = 500, headers = "Server: nginx")
        assertTrue(ScanCheckLogic.matches(body("sql SYNTAX"), page))
        assertTrue(ScanCheckLogic.matches(body("error.*syntax", "matches"), page))
        assertFalse(ScanCheckLogic.matches(body("error", "equals"), page))
        assertTrue(ScanCheckLogic.matches(CheckCondition("status_code", "500", "equals"), page))
        assertTrue(ScanCheckLogic.matches(CheckCondition("response_headers", "NGINX", "contains"), page))
        assertTrue(ScanCheckLogic.matches(CheckCondition("request_url", "q=1", "contains"), page))
    }

    @Test
    fun `negate inverts a condition`() {
        val page = response(headers = "Server: nginx")
        val hsts = CheckCondition("response_headers", "strict-transport-security", "matches", negate = true)
        assertTrue(ScanCheckLogic.matches(hsts, page))
        assertFalse(ScanCheckLogic.matches(hsts, response(headers = "Strict-Transport-Security: max-age=1")))
    }

    @Test
    fun `a condition on the response never holds without a response, negated or not`() {
        // "status is not 200" and "no HSTS header" would otherwise both be true of a request that timed out.
        assertFalse(ScanCheckLogic.matches(CheckCondition("status_code", "200", "equals", negate = true), noResponse))
        assertFalse(ScanCheckLogic.matches(CheckCondition("response_headers", "hsts", "contains", negate = true), noResponse))
        assertFalse(ScanCheckLogic.matches(body("x", negate = true), noResponse))
        // The request side can still be judged.
        assertTrue(ScanCheckLogic.matches(CheckCondition("request_url", "q=1", "contains"), noResponse))
    }

    @Test
    fun `a negated regex is not flipped by a body too large for the regex engine`() {
        val large = "needle" + "x".repeat(300_000)
        assertFalse(ScanCheckLogic.matches(body("needle", "matches", negate = true), response(large)))
        assertTrue(ScanCheckLogic.matches(body("needle", "matches"), response(large)))
    }

    @Test
    fun `match mode all needs every condition and any needs one`() {
        val page = response("alpha", status = 200)
        val both = listOf(body("alpha"), body("beta"))
        assertFalse(ScanCheckLogic.satisfied(both, MatchMode.ALL, page))
        assertTrue(ScanCheckLogic.satisfied(both, MatchMode.ANY, page))
        assertFalse(ScanCheckLogic.satisfied(listOf(body("beta"), body("gamma")), MatchMode.ANY, page))
    }

    // ---- definition parsing -----------------------------------------------

    @Test
    fun `an invalid regex is rejected when the definition is parsed`() {
        val e = assertFailsWith<InvalidCheckException> {
            ScanCheckLogic.conditions(listOf(condition("response_body", "([unclosed")), "conditions")
        }
        assertTrue(e.message!!.startsWith("Invalid regex in conditions[0].pattern:"), e.message)
        // The same text is fine when it is not a regex.
        assertEquals(1, ScanCheckLogic.conditions(listOf(condition("response_body", "([unclosed", "contains")), "c").size)
    }

    @Test
    fun `conditions that could never be meant are rejected`() {
        fun rejected(c: JsonObject) = assertFailsWith<InvalidCheckException> { ScanCheckLogic.conditions(listOf(c), "conditions") }.message!!
        assertTrue("location" in rejected(condition("response_bdy", "x")))
        assertTrue("condition_type" in rejected(condition("response_body", "x", "regex")))
        assertEquals("conditions[0].pattern is required", rejected(condition("response_body", null)))
        // An empty regex or substring matches every message.
        assertTrue("empty" in rejected(condition("response_body", "")))
        assertTrue("empty" in rejected(condition("response_body", "", "contains")))
        // An empty 'equals' is a real test: the body is empty.
        assertEquals("", ScanCheckLogic.conditions(listOf(condition("response_body", "", "equals")), "c").single().pattern)
    }

    @Test
    fun `condition defaults are matches and not negated`() {
        val parsed = ScanCheckLogic.conditions(listOf(condition(" Response_Body ", "a+")), "conditions").single()
        assertEquals(CheckCondition("response_body", "a+", "matches", negate = false), parsed)
    }

    @Test
    fun `steps default to required and take the call's match mode unless they set their own`() {
        val steps = ScanCheckLogic.steps(
            listOf(
                stepJson("'", condition("response_body", "sql")),
                stepJson("\"", condition("response_body", "sql")) {
                    put("match_mode", "all")
                    put("stop_if_no_match", false)
                },
            ),
            MatchMode.ANY,
        )
        assertEquals(MatchMode.ANY, steps[0].mode)
        assertTrue(steps[0].stopIfNoMatch)
        assertEquals(MatchMode.ALL, steps[1].mode)
        assertFalse(steps[1].stopIfNoMatch)
    }

    @Test
    fun `an active check with no condition on the response is rejected`() {
        // It could only ever report on what it sent itself.
        val onlyRequestSide = listOf(stepJson("'", condition("request_url", "'", "contains")), stepJson("x"))
        val e = assertFailsWith<InvalidCheckException> { ScanCheckLogic.steps(onlyRequestSide, MatchMode.ALL) }
        assertTrue("could never report" in e.message!!, e.message)
    }

    @Test
    fun `malformed steps are rejected by name`() {
        fun rejected(vararg steps: JsonObject) =
            assertFailsWith<InvalidCheckException> { ScanCheckLogic.steps(steps.toList(), MatchMode.ALL) }.message!!
        assertEquals("steps[0].payload is required and must be a string", rejected(stepJson(null, condition("response_body", "x"))))
        assertTrue("steps[0].response_conditions[0].pattern" in rejected(stepJson("'", condition("response_body", "(x"))))
        assertTrue("steps[0].match_mode" in rejected(stepJson("'", condition("response_body", "x")) { put("match_mode", "some") }))
        val notObjects = buildJsonObject {
            put("payload", "'")
            put("response_conditions", buildJsonArray { add(JsonPrimitive("response_body")) })
        }
        assertTrue("array of condition objects" in rejected(notObjects))
    }

    @Test
    fun `severity confidence and match mode are closed sets`() {
        assertEquals("information", ScanCheckLogic.severity("INFO"))
        assertEquals("high", ScanCheckLogic.severity(" High "))
        assertEquals("firm", ScanCheckLogic.confidence("Firm"))
        assertEquals(MatchMode.ALL, ScanCheckLogic.matchMode(null))
        assertEquals(MatchMode.ANY, ScanCheckLogic.matchMode("ANY"))
        assertTrue("severity" in assertFailsWith<InvalidCheckException> { ScanCheckLogic.severity("critical") }.message!!)
        assertTrue("confidence" in assertFailsWith<InvalidCheckException> { ScanCheckLogic.confidence(null) }.message!!)
        assertTrue("match_mode" in assertFailsWith<InvalidCheckException> { ScanCheckLogic.matchMode("either") }.message!!)
    }

    // ---- when an active check may report ----------------------------------

    @Test
    fun `a payload that changes the response is reported with its evidence`() {
        val result = run(
            listOf(step("'", body("sql syntax"))),
            baseline = response("welcome"),
            answers = mapOf("'" to response("error in your SQL syntax")),
        )
        assertTrue(result.report, result.reason)
        assertEquals(listOf("'"), result.novelPayloads)
        assertEquals(listOf("'"), result.evidence)
        assertEquals(listOf(StepTrace(1, answered = true, matched = true, novel = true)), result.trace)
    }

    @Test
    fun `nothing is reported when no request was answered`() {
        // P0.3 item 2: the old check kept "all steps passed" when a step never sent anything.
        val required = run(listOf(step("'", body("sql"))), baseline = response("welcome"), answers = emptyMap())
        assertFalse(required.report)
        assertEquals("step 1 got no response", required.reason)

        val optional = run(listOf(step("'", body("sql"), required = false)), baseline = response("welcome"), answers = emptyMap())
        assertFalse(optional.report)
        assertTrue(optional.evidence.isEmpty())
    }

    @Test
    fun `a probe without a response does not match negated conditions`() {
        val notOk = CheckCondition("status_code", "200", "equals", negate = true)
        val result = run(listOf(step("'", notOk)), baseline = response("ok", status = 200), answers = mapOf("'" to noResponse))
        assertFalse(result.report)
        assertEquals(listOf(StepTrace(1, answered = false, matched = false, novel = false)), result.trace)
    }

    @Test
    fun `what the baseline response shows too is not evidence`() {
        // The page says "database query" with or without the quote.
        val result = run(
            listOf(step("'", body("database|query", "matches"))),
            baseline = response("run a database query here"),
            answers = mapOf("'" to response("run a database query here")),
        )
        assertFalse(result.report)
        assertEquals(listOf(StepTrace(1, answered = true, matched = true, novel = false)), result.trace)
    }

    @Test
    fun `without a baseline response nothing can be shown to differ`() {
        val answers = mapOf("'" to response("sql syntax"))
        assertFalse(run(listOf(step("'", body("sql syntax"))), baseline = null, answers = answers).report)
        assertFalse(run(listOf(step("'", body("sql syntax"))), baseline = noResponse, answers = answers).report)
    }

    @Test
    fun `the payload appearing in the check's own request is not evidence`() {
        // Any one of these holds for every probe, because the probe's URL carries the payload.
        val inUrl = CheckCondition("request_url", "'", "contains")
        val result = run(
            listOf(step("'", inUrl, body("welcome"), mode = MatchMode.ANY)),
            baseline = response("welcome"),
            answers = mapOf("'" to response("welcome")),
        )
        assertFalse(result.report)
    }

    @Test
    fun `a reflected payload is evidence because the baseline cannot contain it`() {
        val result = run(
            listOf(step("<raijin>", body("<raijin>"))),
            baseline = response("hello"),
            answers = mapOf("<raijin>" to response("hello <raijin>")),
        )
        assertTrue(result.report)
    }

    @Test
    fun `a fresh response to the unmodified request that matches as well cancels the evidence`() {
        // The page changed after the baseline was recorded; the payload did not change it.
        val steps = listOf(step("'", body("maintenance")))
        val answers = mapOf("'" to response("down for maintenance"))
        assertFalse(run(steps, response("welcome"), answers, control = response("down for maintenance")).report)
        assertTrue(run(steps, response("welcome"), answers, control = response("welcome")).report)
        // No fresh response available: the recorded baseline decides.
        assertTrue(run(steps, response("welcome"), answers, control = null).report)
    }

    @Test
    fun `a required step that fails ends the chain, an optional one does not`() {
        val seven = step("{{7*7}}", body("49"))
        val six = step("{{7*6}}", body("42"))
        val answers = mapOf("{{7*7}}" to response("49"), "{{7*6}}" to response("nothing"))

        val strict = run(listOf(seven, six), response("page"), answers)
        assertFalse(strict.report)
        assertEquals("step 2 did not match", strict.reason)

        val lenient = run(listOf(seven, six.copy(stopIfNoMatch = false)), response("page"), answers)
        assertTrue(lenient.report)
        assertEquals(listOf("{{7*7}}"), lenient.novelPayloads)
    }

    @Test
    fun `one step whose match differs from the baseline is enough for a chain`() {
        // "49" is on the page anyway (a price); "42" is not.
        val result = run(
            listOf(step("{{7*7}}", body("49")), step("{{7*6}}", body("42"))),
            baseline = response("price: 49"),
            answers = mapOf("{{7*7}}" to response("price: 49"), "{{7*6}}" to response("price: 49 and 42")),
        )
        assertTrue(result.report)
        assertEquals(listOf("{{7*6}}"), result.novelPayloads)
        assertEquals(listOf("{{7*7}}", "{{7*6}}"), result.evidence)
    }

    @Test
    fun `any of several optional payloads can raise the issue`() {
        val steps = listOf("'", "\"", "\\").map { step(it, body("sql syntax"), required = false) }
        val result = run(steps, response("welcome"), mapOf("'" to response("welcome"), "\"" to response("SQL syntax error")))
        assertTrue(result.report)
        assertEquals(listOf("\""), result.novelPayloads)
    }

    @Test
    fun `the baseline and the control are fetched at most once and only when needed`() {
        var baselines = 0
        var controls = 0
        fun runCounting(answer: CheckExchange) = ScanCheckLogic.runActive(
            listOf(step("a", body("hit"), required = false), step("b", body("hit"), required = false)),
            baseline = { baselines++; response("page") },
            send = { payload -> answer to payload },
            control = { controls++; response("page") },
        )

        runCounting(response("nothing"))
        assertEquals(0, baselines, "no step matched, so nothing needed comparing")
        assertEquals(0, controls)

        assertTrue(runCounting(response("hit")).report)
        assertEquals(1, baselines)
        assertEquals(1, controls)
    }

    // ---- issue text and consolidation --------------------------------------

    @Test
    fun `two insertion points on one path are two issues, the same one twice is one`() {
        val q = ScanCheckLogic.activeDetail("SQLi", "q", "PARAM_URL", listOf("'"))
        val id = ScanCheckLogic.activeDetail("SQLi", "id", "PARAM_URL", listOf("'"))
        val url = "https://t/search"
        assertFalse(ScanCheckLogic.isDuplicate("SQLi", url, q, "SQLi", url, id), "different parameters must both be kept")
        assertTrue(ScanCheckLogic.isDuplicate("SQLi", url, q, "SQLi", url, q))
        // Same name, different kind of insertion point.
        val cookie = ScanCheckLogic.activeDetail("SQLi", "q", "PARAM_COOKIE", listOf("'"))
        assertFalse(ScanCheckLogic.isDuplicate("SQLi", url, q, "SQLi", url, cookie))
    }

    @Test
    fun `consolidation compares the path, not the query string`() {
        val detail = ScanCheckLogic.activeDetail("d", "q", "PARAM_URL", listOf("'"))
        assertTrue(ScanCheckLogic.isDuplicate("X", "https://t/a?q=1", detail, "X", "https://t/a?q=2#frag", detail))
        assertFalse(ScanCheckLogic.isDuplicate("X", "https://t/a", detail, "X", "https://t/b", detail))
        assertFalse(ScanCheckLogic.isDuplicate("X", "https://t/a", detail, "Y", "https://t/a", detail))
    }

    @Test
    fun `passive issues, which have no insertion point, consolidate per name and path`() {
        assertTrue(ScanCheckLogic.isDuplicate("Leak", "https://t/a?x=1", "detail", "Leak", "https://t/a?x=2", "detail"))
        assertTrue(ScanCheckLogic.isDuplicate("Leak", "https://t/a", null, "Leak", "https://t/a", null))
    }

    @Test
    fun `the insertion point is read from the end of the detail, not from text the user wrote`() {
        val q = ScanCheckLogic.activeDetail("see ip:deadbeef in the docs", "q", "PARAM_URL", listOf("'"))
        val id = ScanCheckLogic.activeDetail("see ip:deadbeef in the docs", "id", "PARAM_URL", listOf("'"))
        assertFalse(ScanCheckLogic.isDuplicate("X", "https://t/a", q, "X", "https://t/a", id))
    }

    @Test
    fun `active issue detail names the payloads and the insertion point as text, not markup`() {
        val detail = ScanCheckLogic.activeDetail("Base detail", "user<b>", "PARAM_BODY", listOf("<script>alert(1)</script>", "a&b"))
        assertTrue(detail.startsWith("Base detail<br><br>Payloads that changed the response: "), detail)
        assertTrue("<code>&lt;script&gt;alert(1)&lt;/script&gt;</code>, <code>a&amp;b</code>" in detail, detail)
        assertTrue("Insertion point: <b>user&lt;b&gt;</b> (PARAM_BODY, ip:" in detail, detail)
        assertEquals(ScanCheckLogic.insertionPointRef("q", "PARAM_URL"), ScanCheckLogic.insertionPointRef("q", "PARAM_URL"))
    }

    @Test
    fun `an excerpt shows what matched and nothing for a miss or a negated condition`() {
        val page = response("x".repeat(100) + "AKIAABCDEFGHIJKLMNOP" + "y".repeat(100))
        val excerpt = ScanCheckLogic.excerpt(body("AKIA[A-Z]{16}", "matches"), page)!!
        assertTrue("AKIAABCDEFGHIJKLMNOP" in excerpt)
        assertTrue(excerpt.length <= 20 + 80, "excerpt is a window, not the body: ${excerpt.length}")
        assertNull(ScanCheckLogic.excerpt(body("nope"), page))
        assertNull(ScanCheckLogic.excerpt(body("nope", negate = true), page))
    }
}
