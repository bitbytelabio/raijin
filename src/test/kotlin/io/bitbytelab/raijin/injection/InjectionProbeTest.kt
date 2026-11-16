package io.bitbytelab.raijin.injection

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.double
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.net.URLDecoder
import java.net.URLEncoder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The probe against small stand-in servers: each test models one application behaviour and
 * checks that the matching class is found with its evidence, or that behaviour which only looks
 * like a vulnerability (lag, timeouts, content the page shows anyway, an echoed payload) is not.
 */
class InjectionProbeTest {

    private val getRequest = "GET /item?id=FUZZ HTTP/1.1\r\nHost: target.test\r\n\r\n"
    private val xmlRequest = "POST /stock HTTP/1.1\r\nHost: target.test\r\nContent-Type: application/xml\r\nContent-Length: 0\r\n\r\n" +
        "<?xml version=\"1.0\"?><stock><productId>FUZZ</productId></stock>"

    private val passwd = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"

    private fun html(content: String): String = "<html><body>$content</body></html>"

    private fun ok(
        body: String,
        elapsedMs: Long = 20,
        status: Int = 200,
        headers: List<Pair<String, String>> = listOf("Content-Type" to "text/html"),
    ) = Observation(status, headers, body, elapsedMs)

    /** The value [getRequest] carries at FUZZ, decoded as a server would. */
    private fun value(request: String): String =
        URLDecoder.decode(request.substringAfter("id=").substringBefore(" HTTP/1.1"), "UTF-8")

    private class Run(val report: InjectionProbe.Report, val requests: List<String>) {
        val findings: List<Finding> get() = report.findings
    }

    private fun probe(
        vararg classes: InjectionClass,
        request: String = getRequest,
        settings: InjectionProbe.Settings.() -> InjectionProbe.Settings = { this },
        oob: OobChannel? = null,
        clock: () -> Long = { 0L },
        server: (String) -> Observation,
    ): Run {
        val requests = ArrayList<String>()
        var tokens = 0
        val defaults = InjectionProbe.Settings(classes = classes.toList(), targetHost = "target.test", oobWaitMs = 0)
        val report = InjectionProbe(
            FuzzTemplate.parse(request),
            defaults.settings(),
            oob = oob,
            newToken = { "rjntok" + (tokens++).toString().padStart(3, '0') },
            nanoTime = clock,
            pause = { },
        ) { raw, _ ->
            requests += raw
            server(raw)
        }.run()
        return Run(report, requests)
    }

    private class FakeOob : OobChannel {
        val issued = ArrayList<OobChannel.Payload>()
        private val arrived = ArrayList<OobChannel.Interaction>()

        override fun issue(purpose: String): OobChannel.Payload =
            OobChannel.Payload("id${issued.size}", "id${issued.size}.oob.test").also { issued += it }

        override fun collect(): List<OobChannel.Interaction> = arrived.toList().also { arrived.clear() }

        /** The out-of-band server sees [type] for every issued host that [text] names. */
        fun hit(text: String, type: String) {
            for ((id, host) in issued) {
                if (host in text) arrived += OobChannel.Interaction(id, type, "203.0.113.7", "2026-01-01T00:00:00Z", "probe")
            }
        }
    }

    // ---------------------------------------------------------------
    // Baseline, timeouts, budget
    // ---------------------------------------------------------------

    @Test
    fun `nothing is tested when the baseline gets no response`() {
        val run = probe(InjectionClass.SQLI) { Observation.NO_RESPONSE }
        assertTrue("baseline" in run.report.error.orEmpty(), run.report.error)
        assertEquals(3, run.requests.size)
        assertTrue(run.findings.isEmpty())
        assertTrue("error" in run.report.toJson())
    }

    @Test
    fun `a request without the marker is refused`() {
        val run = probe(InjectionClass.SQLI, request = "GET /item?id=1 HTTP/1.1\r\nHost: t\r\n\r\n") { ok("x") }
        assertEquals(InjectionProbe.NO_MARKER, run.report.error)
        assertTrue(run.requests.isEmpty())
    }

    @Test
    fun `every class runs to the end against a static page without a finding`() {
        val run = probe(*InjectionClass.entries.toTypedArray()) { ok(html("<p>static page</p>")) }
        assertNull(run.report.error)
        assertTrue(run.findings.isEmpty(), run.findings.toString())
        assertEquals(InjectionClass.entries.toList(), run.report.classesCompleted)
        assertNull(run.report.stoppedEarly)
        assertTrue(run.requests.size in 100..180, "requests sent: ${run.requests.size}")
        assertTrue(run.report.notes.any { "Out-of-band checks were skipped" in it }, run.report.notes.toString())
    }

    @Test
    fun `requests that time out are never evidence`() {
        val run = probe(InjectionClass.SQLI) { raw ->
            if ("WAITFOR" in value(raw)) Observation(status = 0, elapsedMs = 30_000) else ok(html("item"))
        }
        assertTrue(run.findings.isEmpty(), run.findings.toString())
        assertNull(run.report.stoppedEarly)
        assertEquals(listOf(InjectionClass.SQLI), run.report.classesCompleted)
    }

    @Test
    fun `the run stops when the target stops answering, baseline request included`() {
        var count = 0
        val run = probe(InjectionClass.SQLI, InjectionClass.XSS) { if (++count <= 2) ok(html("item")) else Observation.NO_RESPONSE }
        assertTrue("stopped responding" in run.report.stoppedEarly.orEmpty(), run.report.stoppedEarly)
        assertEquals(listOf(InjectionClass.SQLI, InjectionClass.XSS), run.report.classesNotCompleted)
        assertTrue(run.findings.isEmpty())
        assertEquals(6, run.requests.size, "two baselines, three unanswered probes, one baseline re-check")
    }

    @Test
    fun `probes that are dropped while the baseline still answers do not stop the run`() {
        val run = probe(InjectionClass.SQLI) { raw -> if ("AND" in value(raw)) Observation.NO_RESPONSE else ok(html("item")) }
        assertNull(run.report.stoppedEarly)
        assertEquals(listOf(InjectionClass.SQLI), run.report.classesCompleted)
        assertTrue(run.findings.isEmpty(), run.findings.toString())
        assertTrue(run.report.notes.any { "drops them" in it }, run.report.notes.toString())
    }

    @Test
    fun `the run stops when the time budget is used up`() {
        var now = 0L
        val run = probe(
            InjectionClass.SQLI, InjectionClass.LFI,
            settings = { copy(timeBudgetMs = 4_000) },
            clock = { now += 1_000_000_000L; now },
        ) { ok(html("item")) }
        assertTrue("time budget" in run.report.stoppedEarly.orEmpty(), run.report.stoppedEarly)
        assertEquals(listOf(InjectionClass.SQLI, InjectionClass.LFI), run.report.classesNotCompleted)
        assertTrue(run.requests.size < 10)
    }

    // ---------------------------------------------------------------
    // SQL injection
    // ---------------------------------------------------------------

    @Test
    fun `an SQL error that follows the quote is found, with the evidence to re-check it`() {
        val run = probe(InjectionClass.SQLI) { raw ->
            val v = value(raw)
            if (v.count { it == '\'' } % 2 == 1) {
                ok(html("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near $v"))
            } else {
                ok(html("Item $v"))
            }
        }
        val finding = run.findings.single()
        assertEquals(InjectionClass.SQLI, finding.cls)
        assertEquals("error-based", finding.technique)
        assertEquals(Confidence.CERTAIN, finding.confidence)
        assertEquals("1'", finding.payload)
        assertEquals("1'", finding.evidence.getValue("sent_payload").jsonPrimitive.content)
        assertEquals(false, finding.evidence.getValue("baseline").jsonObject.getValue("sql_error").jsonPrimitive.boolean)
        val observed = finding.evidence.getValue("probe").jsonObject
        assertEquals("mysql", observed.getValue("sql_error").jsonPrimitive.content)
        assertTrue("SQL syntax" in observed.getValue("match").jsonPrimitive.content)
        assertEquals(false, finding.evidence.getValue("doubled_quote").jsonObject.getValue("sql_error").jsonPrimitive.boolean)

        val json = run.report.toJson()
        assertEquals(1, json.getValue("confirmed_count").jsonPrimitive.int)
        assertEquals("certain", json.getValue("findings").jsonArray.single().jsonObject.getValue("confidence").jsonPrimitive.content)
    }

    @Test
    fun `an SQL error the page shows anyway is not a finding`() {
        val run = probe(InjectionClass.SQLI) {
            ok(html("Warning: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"))
        }
        assertTrue(run.findings.isEmpty(), run.findings.toString())
        assertEquals(listOf(InjectionClass.SQLI), run.report.classesCompleted)
    }

    @Test
    fun `a delay that repeats while the zero-delay control stays fast is found`() {
        val run = probe(InjectionClass.SQLI) { raw ->
            val seconds = Regex("SLEEP\\((\\d+)\\)").find(value(raw))?.groupValues?.get(1)?.toLong() ?: 0
            ok(html("item"), elapsedMs = 20 + seconds * 1000)
        }
        val finding = run.findings.single()
        assertEquals("time-based", finding.technique)
        assertEquals(Confidence.FIRM, finding.confidence)
        assertEquals("1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)-- -", finding.payload)
        val evidence = finding.evidence
        assertEquals(5, evidence.getValue("delay_seconds").jsonPrimitive.int)
        assertEquals(5020L, evidence.getValue("first_probe").jsonObject.getValue("elapsed_ms").jsonPrimitive.long)
        assertEquals(5020L, evidence.getValue("probe").jsonObject.getValue("elapsed_ms").jsonPrimitive.long)
        val control = evidence.getValue("zero_delay_control").jsonObject
        assertEquals(20L, control.getValue("elapsed_ms").jsonPrimitive.long)
        assertEquals("1' AND (SELECT 1 FROM (SELECT(SLEEP(0)))a)-- -", control.getValue("payload").jsonPrimitive.content)
        assertEquals(listOf(20L, 20L), evidence.getValue("baseline").jsonObject.getValue("elapsed_ms_samples").jsonArray.map { it.jsonPrimitive.long })
    }

    @Test
    fun `lag that also slows the zero-delay control is not a finding`() {
        val run = probe(InjectionClass.SQLI) { raw ->
            ok(html("item"), elapsedMs = if ("SLEEP" in value(raw)) 6_000 else 20)
        }
        assertTrue(run.findings.isEmpty(), run.findings.toString())
        assertTrue(run.report.notes.any { "control was slow too" in it }, run.report.notes.toString())
        assertTrue(run.report.notes.any { "too unstable" in it }, run.report.notes.toString())
    }

    @Test
    fun `a single slow response that does not repeat is not a finding`() {
        var slowOnce = true
        val run = probe(InjectionClass.SQLI) { raw ->
            val slow = slowOnce && "SLEEP(5)" in value(raw)
            if (slow) slowOnce = false
            ok(html("item"), elapsedMs = if (slow) 6_000 else 20)
        }
        assertTrue(run.findings.isEmpty(), run.findings.toString())
        assertTrue(run.report.notes.any { "did not repeat" in it }, run.report.notes.toString())
    }

    @Test
    fun `a response that follows the condition over three rounds is found`() {
        val welcome = html("<h1>Shop</h1><p>Welcome back!</p><p>Item 1</p>")
        val anonymous = html("<h1>Shop</h1><p>Item 1</p>")
        val condition = Regex("^1' AND '(\\d+)'<'(\\d+)$")
        val run = probe(InjectionClass.SQLI) { raw ->
            val v = value(raw)
            val match = condition.find(v)
            ok(
                when {
                    v == "1" -> welcome
                    match != null -> if (match.groupValues[1] < match.groupValues[2]) welcome else anonymous
                    else -> html("<h1>Shop</h1><p>No such item</p>")
                }
            )
        }
        val finding = run.findings.single()
        assertEquals("boolean-based", finding.technique)
        assertEquals(Confidence.FIRM, finding.confidence)
        val evidence = finding.evidence
        assertEquals("1' AND '49173'<'58231", evidence.getValue("true_payload").jsonPrimitive.content)
        assertEquals("1' AND '58231'<'49173", evidence.getValue("false_payload").jsonPrimitive.content)
        assertEquals("false_diverges", evidence.getValue("polarity").jsonPrimitive.content)
        assertTrue("-Welcome" in evidence.getValue("distinguishing_tokens").jsonArray.map { it.jsonPrimitive.content })
        assertEquals(3, evidence.getValue("rounds").jsonArray.size)
        assertEquals(100.0, evidence.getValue("true_similarity_to_baseline").jsonPrimitive.double)
        assertTrue(evidence.getValue("false_similarity_to_baseline").jsonPrimitive.double < 100.0)
    }

    @Test
    fun `a page that changes on every request and echoes the payload gives no boolean finding`() {
        var count = 0
        val run = probe(InjectionClass.SQLI, InjectionClass.NOSQLI) { raw ->
            ok(html("<input name=csrf value=tok${++count}><p>Results for ${value(raw)}</p>"))
        }
        assertTrue(run.findings.isEmpty(), run.findings.toString())
        assertEquals(listOf(InjectionClass.SQLI, InjectionClass.NOSQLI), run.report.classesCompleted)
    }

    @Test
    fun `payloads are appended to the base value`() {
        val run = probe(InjectionClass.SQLI, settings = { copy(baseValue = "42") }) { ok(html("item")) }
        assertTrue(run.requests.first().startsWith("GET /item?id=42 HTTP/1.1\r\n"), run.requests.first())
        assertTrue(run.requests.any { "id=42'%20AND%20'49173'%3C'58231 " in it })
        assertTrue(run.requests.any { "id=42%20AND%2049173%3C58231 " in it })
    }

    // ---------------------------------------------------------------
    // NoSQL injection
    // ---------------------------------------------------------------

    @Test
    fun `a query error that follows the quote is found as NoSQL injection`() {
        val run = probe(InjectionClass.NOSQLI) { raw ->
            if ('\'' in value(raw)) ok(html("MongoServerError: SyntaxError: unterminated string literal")) else ok(html("No users"))
        }
        val finding = run.findings.single()
        assertEquals("error-based", finding.technique)
        assertEquals("mongodb", finding.evidence.getValue("probe").jsonObject.getValue("query_error").jsonPrimitive.content)
    }

    private val users = listOf("admin", "carlos", "wiener")

    /**
     * The users a MongoDB `find({user: ...})` selects for the `user` query parameter, read the
     * way Express `qs` reads it: `user=x` is the value, `user[$op]=x` an operator. An operator
     * MongoDB would refuse selects nothing.
     */
    private fun mongoUsers(raw: String): List<String> {
        val values = ArrayList<String>()
        val operators = ArrayList<Pair<String, String>>()
        for (pair in raw.substringBefore(" HTTP/1.1").substringAfter('?', "").split('&')) {
            val name = URLDecoder.decode(pair.substringBefore('='), "UTF-8")
            val value = URLDecoder.decode(pair.substringAfter('=', ""), "UTF-8")
            if (name == "user") values += value
            if (name.startsWith("user[") && name.endsWith("]")) operators += name.removePrefix("user[").removeSuffix("]") to value
        }
        if (values.isEmpty() && operators.isEmpty()) return emptyList()
        return users.filter { user ->
            values.all { it == user } && operators.all { (operator, operand) ->
                when (operator) {
                    "\$eq" -> user == operand
                    "\$ne" -> user != operand
                    "\$gt" -> user > operand
                    "\$lt" -> user < operand
                    "\$regex" -> Regex(operand).containsMatchIn(user)
                    else -> false
                }
            }
        }
    }

    private fun userList(found: List<String>): String =
        html(if (found.isEmpty()) "<p>No users found</p>" else found.joinToString("", "<ul>", "</ul>") { "<li>$it</li>" })

    @Test
    fun `operators that narrow the query to the base value are found`() {
        val request = "GET /users?user=FUZZ HTTP/1.1\r\nHost: target.test\r\n\r\n"
        val run = probe(InjectionClass.NOSQLI, request = request, settings = { copy(baseValue = "carlos") }) { raw -> ok(userList(mongoUsers(raw))) }
        val finding = run.findings.single()
        assertEquals("operator injection", finding.technique)
        assertEquals("false_diverges", finding.evidence.getValue("polarity").jsonPrimitive.content)
        assertTrue("user%5B\$eq%5D=carlos&user%5B\$ne%5D=49173 " in finding.evidence.getValue("request").jsonPrimitive.content)
        assertTrue("user%5B\$eq%5D=49173&user%5B\$ne%5D=carlos " in finding.evidence.getValue("false_request").jsonPrimitive.content)
    }

    @Test
    fun `no NoSQL probe selects a document the baseline request leaves alone`() {
        // The probes may land in deleteMany: whatever the base value, they reach its documents or none.
        val request = "GET /users?user=FUZZ HTTP/1.1\r\nHost: target.test\r\n\r\n"
        for (base in listOf("carlos", "1")) {
            val selected = ArrayList<List<String>>()
            val run = probe(InjectionClass.NOSQLI, request = request, settings = { copy(baseValue = base) }) { raw ->
                ok(userList(mongoUsers(raw).also { selected += it }))
            }
            val reachable = users.filter { it == base }
            assertTrue(run.requests.any { "user%5B\$eq%5D=" in it }, "the operator probes ran")
            assertEquals(null, selected.firstOrNull { !reachable.containsAll(it) }, "base '$base': a probe selected documents the baseline does not")
        }
    }

    @Test
    fun `number operators are found in a JSON body that carries a number`() {
        val request = "POST /api/orders HTTP/1.1\r\nHost: target.test\r\nContent-Type: application/json\r\nContent-Length: 8\r\n\r\n{\"id\":FUZZ}"
        val orders = listOf("1", "2", "3")
        val run = probe(InjectionClass.NOSQLI, request = request, settings = { copy(baseValue = "2") }) { raw ->
            // MongoDB matches a number only against a number: {"id":"2"} finds nothing.
            val condition = Json.parseToJsonElement(raw.substringAfter("\r\n\r\n")).jsonObject["id"]
            fun same(id: String, operand: JsonElement?) = operand is JsonPrimitive && !operand.isString && operand.content == id
            val found = orders.filter { id ->
                when (condition) {
                    is JsonObject -> condition.all { (operator, operand) ->
                        when (operator) {
                            "\$eq" -> same(id, operand)
                            "\$ne" -> !same(id, operand)
                            else -> false
                        }
                    }
                    else -> same(id, condition)
                }
            }
            ok("{\"orders\":[" + found.joinToString(",") { "{\"id\":$it,\"item\":\"widget\"}" } + "]}")
        }
        val finding = run.findings.single()
        assertEquals("operator injection", finding.technique)
        assertEquals("numeric equality: {\"\$eq\":2,\"\$ne\":49173}", finding.payload)
        assertTrue("{\"id\":{\"\$eq\":2,\"\$ne\":49173}}" in finding.evidence.getValue("request").jsonPrimitive.content)
    }

    @Test
    fun `operators that are only echoed back are not a finding`() {
        val request = "GET /users?user=FUZZ HTTP/1.1\r\nHost: target.test\r\n\r\n"
        val run = probe(InjectionClass.NOSQLI, request = request) { raw ->
            val target = raw.substringBefore(" HTTP/1.1").substringAfter(" ")
            ok(html("<a href=\"$target&page=2\">next</a><p>No users found</p>"))
        }
        assertTrue(run.findings.isEmpty(), run.findings.toString())
    }

    // ---------------------------------------------------------------
    // Command injection
    // ---------------------------------------------------------------

    @Test
    fun `command output in the response is found`() {
        val run = probe(InjectionClass.CMDI) { raw ->
            if (value(raw).endsWith(";id")) ok(html("uid=33(www-data) gid=33(www-data) groups=33(www-data)")) else ok(html("pong"))
        }
        val finding = run.findings.single()
        assertEquals("output-based", finding.technique)
        assertEquals(Confidence.CERTAIN, finding.confidence)
        assertEquals("1;id", finding.payload)
        assertTrue("uid=33" in finding.evidence.getValue("probe").jsonObject.getValue("match").jsonPrimitive.content)
    }

    @Test
    fun `command output the page shows anyway is not a finding`() {
        val run = probe(InjectionClass.CMDI) { ok(html("Example output: uid=33(www-data) gid=33(www-data)")) }
        assertTrue(run.findings.isEmpty(), run.findings.toString())
    }

    @Test
    fun `shell arithmetic is found when two different products are computed`() {
        val product = Regex("&set /a (\\d+)\\*(\\d+)$")
        val run = probe(InjectionClass.CMDI) { raw ->
            val match = product.find(value(raw))
            ok(html(match?.let { (it.groupValues[1].toLong() * it.groupValues[2].toLong()).toString() } ?: "pong"))
        }
        val finding = run.findings.single()
        assertEquals("output-based (shell arithmetic)", finding.technique)
        assertEquals("1&set /a 1337*1337", finding.payload)
        assertEquals("11446147", finding.evidence.getValue("confirmation").jsonObject.getValue("contains_result").jsonPrimitive.content)
    }

    @Test
    fun `a blind command is found through its out-of-band lookup`() {
        val oob = FakeOob()
        val run = probe(InjectionClass.CMDI, oob = oob) { raw ->
            val v = value(raw)
            if (";nslookup " in v) oob.hit(v, "dns")
            ok(html("pong"))
        }
        val finding = run.findings.single()
        assertEquals("out-of-band", finding.technique)
        assertEquals(Confidence.CERTAIN, finding.confidence)
        assertEquals("1;nslookup id0.oob.test", finding.payload)
        assertEquals("id0.oob.test", finding.evidence.getValue("oob_host").jsonPrimitive.content)
        assertEquals("dns", finding.evidence.getValue("interactions").jsonArray.single().jsonObject.getValue("type").jsonPrimitive.content)
    }

    @Test
    fun `a host that is resolved wherever it is mentioned does not show command execution`() {
        val oob = FakeOob()
        val run = probe(InjectionClass.CMDI, oob = oob) { raw ->
            oob.hit(value(raw), "dns")
            ok(html("pong"))
        }
        assertTrue(run.findings.isEmpty(), run.findings.toString())
        assertTrue(run.report.notes.any { "only mentioned" in it }, run.report.notes.toString())
    }

    // ---------------------------------------------------------------
    // Template injection, file read
    // ---------------------------------------------------------------

    @Test
    fun `template arithmetic is found when two different products are computed`() {
        val expression = Regex("^\\{\\{(\\d+)\\*(\\d+)\\}\\}$")
        val run = probe(InjectionClass.SSTI) { raw ->
            val v = value(raw)
            val match = expression.find(v)
            ok(html("Hello " + (match?.let { (it.groupValues[1].toLong() * it.groupValues[2].toLong()).toString() } ?: v)))
        }
        val finding = run.findings.single()
        assertEquals(InjectionClass.SSTI, finding.cls)
        assertEquals(Confidence.CERTAIN, finding.confidence)
        assertEquals("{{1337*1337}}", finding.payload)
        assertEquals("%7B%7B1337*1337%7D%7D", finding.evidence.getValue("sent_payload").jsonPrimitive.content)
        assertEquals("1787569", finding.evidence.getValue("probe").jsonObject.getValue("contains_result").jsonPrimitive.content)
        assertEquals(false, finding.evidence.getValue("baseline").jsonObject.getValue("contains_result").jsonPrimitive.boolean)
    }

    @Test
    fun `a number the page already shows is not template evaluation`() {
        val run = probe(InjectionClass.SSTI) { raw -> ok(html("Stock: 1787569 units. You asked for ${value(raw)}")) }
        assertTrue(run.findings.isEmpty(), run.findings.toString())
    }

    @Test
    fun `a number that appears for one payload only is not template evaluation`() {
        val run = probe(InjectionClass.SSTI) { raw -> ok(html(if ("1337*1337" in value(raw)) "Order 1787569" else "Order")) }
        assertTrue(run.findings.isEmpty(), run.findings.toString())
        assertTrue(run.report.notes.any { "second calculation" in it }, run.report.notes.toString())
    }

    @Test
    fun `file contents in the response are found`() {
        val run = probe(InjectionClass.LFI) { raw -> if ("etc/passwd" in value(raw)) ok(passwd) else ok(html("image")) }
        val finding = run.findings.single()
        assertEquals("../../../../../../etc/passwd", finding.payload)
        assertEquals("unix-passwd", finding.evidence.getValue("probe").jsonObject.getValue("file_marker").jsonPrimitive.content)
    }

    @Test
    fun `file markers the page shows anyway are not a finding`() {
        val run = probe(InjectionClass.LFI) { ok(html("To change this, edit the [fonts] and [extensions] sections of win.ini")) }
        assertTrue(run.findings.isEmpty(), run.findings.toString())
    }

    // ---------------------------------------------------------------
    // XXE
    // ---------------------------------------------------------------

    @Test
    fun `an external entity that returns a file is found, sent inside the request's own document`() {
        val run = probe(InjectionClass.XXE, request = xmlRequest) { raw ->
            val resolved = "<!ENTITY rjx SYSTEM \"file:///etc/passwd\">" in raw && "<productId>&rjx;</productId>" in raw
            ok(if (resolved) "Invalid product ID: $passwd" else "Invalid product ID")
        }
        val finding = run.findings.single()
        assertEquals("external entity file read", finding.technique)
        assertEquals(Confidence.CERTAIN, finding.confidence)
        val sent = finding.evidence.getValue("request").jsonPrimitive.content
        assertTrue("<?xml version=\"1.0\"?><!DOCTYPE stock [<!ENTITY rjx SYSTEM \"file:///etc/passwd\">]><stock>" in sent, sent)
        val length = sent.substringAfter("\r\n\r\n").length
        assertTrue("Content-Length: $length\r\n" in sent, sent)
    }

    @Test
    fun `a document that is echoed back unparsed is not XXE`() {
        val run = probe(InjectionClass.XXE, request = xmlRequest) { raw -> ok("Received: " + raw.substringAfter("\r\n\r\n")) }
        assertTrue(run.findings.isEmpty(), run.findings.toString())
    }

    @Test
    fun `expanding only internal entities is reported as tentative`() {
        val run = probe(InjectionClass.XXE, request = xmlRequest) { raw ->
            val declared = Regex("<!ENTITY rja \"([a-z0-9]+)\">").find(raw)?.groupValues?.get(1)
            ok(if (declared != null && "&rjx;" in raw) "Invalid product ID: ${declared}z$declared" else "Invalid product ID")
        }
        val finding = run.findings.single()
        assertEquals("internal entity expansion", finding.technique)
        assertEquals(Confidence.TENTATIVE, finding.confidence)
        assertEquals(0, run.report.toJson().getValue("confirmed_count").jsonPrimitive.int)
        assertEquals(1, run.report.toJson().getValue("tentative_count").jsonPrimitive.int)
    }

    @Test
    fun `an entity fetched out-of-band is found and a URL that is merely fetched as text is not`() {
        val fetched = FakeOob()
        val found = probe(InjectionClass.XXE, request = xmlRequest, oob = fetched) { raw ->
            Regex("SYSTEM \"(http://[^\"]+)\"").find(raw)?.let { fetched.hit(it.groupValues[1], "http") }
            ok("Invalid product ID")
        }
        assertEquals(listOf("out-of-band external entity", "out-of-band parameter entity"), found.findings.map { it.technique })
        assertTrue(found.findings.all { it.confidence == Confidence.CERTAIN })

        val everywhere = FakeOob()
        val none = probe(InjectionClass.XXE, request = xmlRequest, oob = everywhere) { raw ->
            everywhere.hit(raw, "http")
            ok("Invalid product ID")
        }
        assertTrue(none.findings.isEmpty(), none.findings.toString())
    }

    // ---------------------------------------------------------------
    // SSRF
    // ---------------------------------------------------------------

    @Test
    fun `internal content returned by a server-side fetch is found`() {
        val run = probe(InjectionClass.SSRF) { raw ->
            if (value(raw).startsWith("http://169.254.169.254")) ok("ami-id\nami-launch-index\ninstance-id\ninstance-type\nlocal-ipv4\n")
            else ok(html("fetch failed"))
        }
        val finding = run.findings.single()
        assertEquals("in-band", finding.technique)
        assertEquals("cloud-metadata", finding.evidence.getValue("probe").jsonObject.getValue("internal_content").jsonPrimitive.content)
    }

    @Test
    fun `a blind fetch is confirmed by the out-of-band host only that probe carried`() {
        val oob = FakeOob()
        val run = probe(InjectionClass.SSRF, oob = oob) { raw ->
            val v = value(raw)
            if (v.startsWith("http://")) oob.hit(v, "http")
            ok(html("queued"))
        }
        val finding = run.findings.single()
        assertEquals("out-of-band", finding.technique)
        assertEquals(Confidence.CERTAIN, finding.confidence)
        assertEquals("high", finding.severity)
        assertEquals("http://id0.oob.test/", finding.payload)
        assertEquals(4, run.report.oobProbes)
        assertEquals(0, finding.evidence.getValue("baseline").jsonObject.getValue("interactions").jsonPrimitive.int)
    }

    @Test
    fun `a lookup without a fetch is reported with lower confidence`() {
        val oob = FakeOob()
        val run = probe(InjectionClass.SSRF, oob = oob) { raw ->
            val v = value(raw)
            if (v.startsWith("https://")) oob.hit(v, "dns")
            ok(html("queued"))
        }
        val finding = run.findings.single()
        assertEquals(Confidence.FIRM, finding.confidence)
        assertEquals("medium", finding.severity)
        assertEquals("https://id1.oob.test/", finding.payload)
    }

    @Test
    fun `no interaction is no finding, and no channel is reported with its reason`() {
        val silent = probe(InjectionClass.SSRF, oob = FakeOob()) { ok(html("queued")) }
        assertTrue(silent.findings.isEmpty())
        assertTrue(silent.report.notes.none { "skipped" in it }, silent.report.notes.toString())

        val reason = "Burp Collaborator needs Burp Suite Professional (this is Community Edition)"
        val without = probe(InjectionClass.SSRF, settings = { copy(oobUnavailable = reason) }) { ok(html("queued")) }
        assertTrue(without.findings.isEmpty())
        assertTrue(without.report.notes.any { reason in it }, without.report.notes.toString())
        assertEquals(0, without.report.oobProbes)
    }

    // ---------------------------------------------------------------
    // XSS
    // ---------------------------------------------------------------

    @Test
    fun `an unencoded reflection in HTML text is found with its context and character treatment`() {
        val run = probe(InjectionClass.XSS) { raw -> ok(html("<p>Results for: ${value(raw)}</p>")) }
        val finding = run.findings.single()
        assertEquals("reflected", finding.technique)
        assertEquals(Confidence.FIRM, finding.confidence)
        assertEquals("<rjntok004 x=1>", finding.payload)
        val evidence = finding.evidence
        assertEquals("html_text", evidence.getValue("reflection").jsonObject.getValue("context").jsonPrimitive.content)
        assertEquals("raw", evidence.getValue("characters").jsonObject.getValue("<").jsonPrimitive.content)
        assertEquals("raw", evidence.getValue("characters").jsonObject.getValue("space").jsonPrimitive.content)
        assertEquals(false, evidence.getValue("baseline").jsonObject.getValue("reflects_probe_value").jsonPrimitive.boolean)
        assertTrue("onerror" in evidence.getValue("example_payload").jsonPrimitive.content)
    }

    @Test
    fun `a reflection inside a quoted attribute is found when the quote survives`() {
        val run = probe(InjectionClass.XSS) { raw ->
            ok(html("<input name=q value=\"" + value(raw).replace("<", "&lt;").replace(">", "&gt;") + "\">"))
        }
        val finding = run.findings.single()
        val reflection = finding.evidence.getValue("reflection").jsonObject
        assertEquals("attr_double_quoted", reflection.getValue("context").jsonPrimitive.content)
        assertEquals("input", reflection.getValue("tag").jsonPrimitive.content)
        assertEquals("value", reflection.getValue("attribute").jsonPrimitive.content)
        assertEquals("html_entity", finding.evidence.getValue("characters").jsonObject.getValue("<").jsonPrimitive.content)
        assertEquals("raw", finding.evidence.getValue("characters").jsonObject.getValue("\"").jsonPrimitive.content)
        assertEquals("\"rjntok004=\"", finding.payload)
    }

    @Test
    fun `an encoded reflection is not a finding`() {
        val run = probe(InjectionClass.XSS) { raw ->
            val encoded = value(raw).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;")
            ok(html("<p>Results for: $encoded</p><input value=\"$encoded\">"))
        }
        assertTrue(run.findings.isEmpty(), run.findings.toString())
        assertTrue(run.report.notes.any { "come back encoded" in it }, run.report.notes.toString())
    }

    @Test
    fun `a reflection in a response that is not a document is not a finding`() {
        val run = probe(InjectionClass.XSS) { raw ->
            ok("{\"q\":\"${value(raw)}\"}", headers = listOf("Content-Type" to "application/json"))
        }
        assertTrue(run.findings.isEmpty(), run.findings.toString())
        assertTrue(run.report.notes.any { "application/json" in it }, run.report.notes.toString())
    }

    @Test
    fun `a filter that removes tags is not a finding`() {
        val tags = Regex("<[a-zA-Z/][^>]*>")
        val run = probe(InjectionClass.XSS) { raw -> ok(html("<p>Results for: ${value(raw).replace(tags, "")}</p>")) }
        assertTrue(run.findings.isEmpty(), run.findings.toString())
    }

    // ---------------------------------------------------------------
    // Open redirect, header injection
    // ---------------------------------------------------------------

    @Test
    fun `a redirect to the supplied host is found`() {
        val run = probe(InjectionClass.OPEN_REDIRECT) { raw -> ok("", status = 302, headers = listOf("Location" to value(raw))) }
        val finding = run.findings.single()
        assertEquals("location_header", finding.technique)
        assertEquals(Confidence.CERTAIN, finding.confidence)
        assertEquals("low", finding.severity)
        assertEquals("https://rjntok000.example.com/", finding.payload)
        assertEquals("1", finding.evidence.getValue("baseline").jsonObject.getValue("location").jsonPrimitive.content)
        assertEquals("https://rjntok000.example.com/", finding.evidence.getValue("probe").jsonObject.getValue("redirect_target").jsonPrimitive.content)
    }

    @Test
    fun `a redirect that only carries the host as a parameter is not a finding`() {
        val run = probe(InjectionClass.OPEN_REDIRECT) { raw ->
            ok("", status = 302, headers = listOf("Location" to "/login?next=" + URLEncoder.encode(value(raw), "UTF-8")))
        }
        assertTrue(run.findings.isEmpty(), run.findings.toString())
    }

    @Test
    fun `an allow-list that only checks the prefix is bypassed and found`() {
        val run = probe(InjectionClass.OPEN_REDIRECT) { raw ->
            val v = value(raw)
            val location = if (v.startsWith("https://target.test")) v else "/"
            ok("", status = 302, headers = listOf("Location" to location))
        }
        assertEquals("https://target.test@rjntok000.example.com/", run.findings.single().payload)
    }

    @Test
    fun `a value that splits the response header block is found`() {
        val run = probe(InjectionClass.CRLF) { raw ->
            val lines = ("Location: /set?lang=" + value(raw)).split("\r\n")
            val headers = lines.mapNotNull { line ->
                val colon = line.indexOf(':')
                if (colon > 0) line.substring(0, colon) to line.substring(colon + 1).trim() else null
            }
            ok("", status = 302, headers = headers)
        }
        val finding = run.findings.single()
        assertEquals("response header injection", finding.technique)
        assertEquals("1\r\nX-rjntok000: 1", finding.payload)
        assertEquals("1%0D%0AX-rjntok000:%201", finding.evidence.getValue("sent_payload").jsonPrimitive.content)
        assertEquals("X-rjntok000", finding.evidence.getValue("probe").jsonObject.getValue("injected_header").jsonPrimitive.content)
        assertEquals(false, finding.evidence.getValue("baseline").jsonObject.getValue("has_injected_header").jsonPrimitive.boolean)
    }

    @Test
    fun `a value kept on its header line is not a finding`() {
        val run = probe(InjectionClass.CRLF) { raw ->
            ok("", status = 302, headers = listOf("Location" to "/set?lang=" + value(raw).replace("\r", "").replace("\n", "")))
        }
        assertTrue(run.findings.isEmpty(), run.findings.toString())
    }

    // ---------------------------------------------------------------
    // Encoding
    // ---------------------------------------------------------------

    @Test
    fun `the encoding setting decides how payloads reach the wire`() {
        val auto = probe(InjectionClass.SSTI) { ok(html("x")) }
        assertTrue(auto.requests.any { it.startsWith("GET /item?id=%7B%7B1337*1337%7D%7D HTTP/1.1\r\n") })

        val raw = probe(InjectionClass.SSTI, settings = { copy(encoding = PayloadEncoding.RAW) }) { ok(html("x")) }
        assertTrue(raw.requests.any { it.startsWith("GET /item?id={{1337*1337}} HTTP/1.1\r\n") })
        assertTrue(raw.requests.any { it.startsWith("GET /item?id=<%= 1337*1337 %> HTTP/1.1\r\n") })
    }

    @Test
    fun `every finding carries payload, baseline and the observation that justifies it`() {
        val run = probe(InjectionClass.LFI, InjectionClass.SSTI, InjectionClass.CMDI) { raw ->
            val v = value(raw)
            when {
                "etc/passwd" in v -> ok(passwd)
                v == "{{1337*1337}}" -> ok(html("1787569"))
                v == "{{2713*4219}}" -> ok(html("11446147"))
                v.endsWith("|id") -> ok(html("uid=0(root) gid=0(root)"))
                else -> ok(html("ok"))
            }
        }
        assertEquals(listOf(InjectionClass.LFI, InjectionClass.SSTI, InjectionClass.CMDI), run.findings.map { it.cls })
        for (finding in run.findings) {
            val json = finding.toJson()
            assertEquals(setOf("class", "technique", "severity", "confidence", "detail", "payload", "evidence"), json.keys)
            assertTrue(finding.payload.isNotEmpty())
            assertNotNull(finding.evidence["sent_payload"] ?: finding.evidence["request"], finding.technique)
            assertEquals(200, finding.evidence.getValue("baseline").jsonObject.getValue("status").jsonPrimitive.int)
            assertNotNull(finding.evidence["probe"], finding.technique)
        }
    }
}
