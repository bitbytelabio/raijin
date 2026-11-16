package io.bitbytelab.raijin.bridge

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * `scanner_register_check` on the shared check engine (plan P4.1): its flat parameters become the
 * same [CheckDefinition] the `scancheck_*` tools build, so both follow the same rules. Also the
 * site map prefixes an audit's targets map to, which the task-issues fallback relies on.
 */
class ScannerCheckDefinitionTest {

    private fun define(
        type: String,
        bodyRegex: String? = null,
        headerRegex: String? = null,
        payloads: List<String>? = null,
        activeRegex: String? = null,
        name: String = "check",
        issue: String = "Issue",
        severity: String = "medium",
        confidence: String = "firm",
    ): CheckDefinition = ScannerBridge.legacyCheckDefinition(
        name, type, issue, severity, confidence, "detail", "fix", bodyRegex, headerRegex, payloads, activeRegex
    )

    private fun rejected(block: () -> Unit): String = assertFailsWith<InvalidCheckException>(block = block).message!!

    private fun page(body: String, headers: String = "") = CheckExchange(
        requestUrl = "https://t/a", hasResponse = true, statusCode = 200,
        responseHeaders = headers, responseBody = body, responseLength = body.length,
    )

    @Test
    fun `a passive check reports when the body regex or the header regex matches`() {
        val definition = define("passive", bodyRegex = "stack trace", headerRegex = "x-powered-by: php")
        val rule = definition.passive!!
        assertNull(definition.active)
        assertEquals("passive", definition.mode)

        assertTrue(ScanCheckLogic.satisfied(rule.conditions, rule.mode, page("a Stack Trace follows")))
        assertTrue(ScanCheckLogic.satisfied(rule.conditions, rule.mode, page("fine", headers = "X-Powered-By: PHP/8")))
        assertFalse(ScanCheckLogic.satisfied(rule.conditions, rule.mode, page("fine", headers = "Server: nginx")))
    }

    @Test
    fun `an active check tries every payload and reports the ones that change the response`() {
        val steps = define("active", payloads = listOf("'", "\"", "\\"), activeRegex = "sql syntax").active!!
        assertEquals(listOf("'", "\"", "\\"), steps.map { it.payload })
        assertTrue(steps.none { it.stopIfNoMatch }, "one payload that does nothing must not stop the others")

        val answers = mapOf("'" to page("welcome"), "\"" to page("You have an error in your SQL syntax"))
        val result = ScanCheckLogic.runActive(steps, baseline = { page("welcome") }, send = { p -> answers[p]?.let { it to p } })
        assertTrue(result.report)
        assertEquals(listOf("\""), result.novelPayloads)

        // The page shows the words anyway: no payload proved anything.
        val noisy = page("see the SQL syntax reference")
        assertFalse(ScanCheckLogic.runActive(steps, baseline = { noisy }, send = { p -> noisy to p }).report)
    }

    @Test
    fun `both runs the parts whose parameters were given`() {
        val both = define("both", bodyRegex = "debug", payloads = listOf("'"), activeRegex = "sql")
        assertEquals("both", both.mode)
        assertEquals("passive", define("both", headerRegex = "x-debug").mode)
        assertEquals("active", define("both", payloads = listOf("'"), activeRegex = "sql").mode)
    }

    @Test
    fun `a check type without its parameters is refused`() {
        assertTrue("passive_response_match" in rejected { define("passive") })
        assertTrue("active_payloads" in rejected { define("active", activeRegex = "sql") })
        assertTrue("active_payloads" in rejected { define("active", payloads = listOf("'")) })
        assertTrue("active_payloads" in rejected { define("active", payloads = emptyList(), activeRegex = "sql") })
        assertTrue("check_type 'both'" in rejected { define("both") })
        // Passive parameters do not make an active check.
        assertTrue("active_payloads" in rejected { define("active", bodyRegex = "x") })
    }

    @Test
    fun `invalid values are refused with the tool's parameter names`() {
        assertTrue(rejected { define("passive", bodyRegex = "([a-z") }.startsWith("Invalid passive_response_match regex:"))
        assertTrue(rejected { define("passive", headerRegex = "*") }.startsWith("Invalid passive_header_match regex:"))
        assertTrue(rejected { define("active", payloads = listOf("'"), activeRegex = "(?<x") }.startsWith("Invalid active_response_match regex:"))
        assertTrue("empty" in rejected { define("passive", bodyRegex = "") })
        assertTrue("check_type" in rejected { define("aggressive", bodyRegex = "x") })
        assertTrue("issue_severity" in rejected { define("passive", bodyRegex = "x", severity = "critical") })
        assertTrue("issue_confidence" in rejected { define("passive", bodyRegex = "x", confidence = "maybe") })
        assertEquals("check_name must not be blank", rejected { define("passive", bodyRegex = "x", name = " ") })
        assertEquals("issue_name must not be blank", rejected { define("passive", bodyRegex = "x", issue = "") })
    }

    @Test
    fun `values are normalised the way the other check tools take them`() {
        val definition = define(" Passive ", bodyRegex = "x", severity = "INFO", confidence = "Certain")
        assertEquals("information", definition.severity)
        assertEquals("certain", definition.confidence)
        assertEquals("Issue", definition.issueName)
        assertEquals("check", definition.name)
    }

    // ---- site map prefixes of an audit's targets --------------------------------

    @Test
    fun `an audit's targets map to site map prefixes without default ports`() {
        assertEquals(
            setOf("https://app.example.com/", "http://intra.example.com:8080/", "https://api.example.com:8443/"),
            ScannerBridge.targetPrefixes(
                listOf("https://App.Example.com:443/a/b?c=d", "http://intra.example.com:8080", "HTTPS://api.example.com:8443/v1", "not-a-url"),
                emptyList(),
            ),
        )
    }

    @Test
    fun `a raw request does not say its scheme, so both are covered`() {
        assertEquals(
            setOf("https://files.example.com/", "http://files.example.com/", "https://dev.example.com:8443/", "http://dev.example.com:8443/"),
            ScannerBridge.targetPrefixes(
                emptyList(),
                listOf(
                    "GET /x HTTP/1.1\r\nHost: files.example.com\r\n\r\n",
                    "POST /y HTTP/1.1\r\nhost: dev.example.com:8443\r\n\r\nbody",
                    "GET /no-host HTTP/1.1\r\n\r\n",
                ),
            ),
        )
        // The prefix ends at the host: a look-alike host is not under it.
        assertFalse("https://files.example.com.evil.net/".startsWith(ScannerBridge.origin("https", "files.example.com")))
    }
}
