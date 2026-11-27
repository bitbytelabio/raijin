package io.bitbytelab.raijin.bridge

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.jsonPrimitive

/**
 * Unit tests for the pure BCheck DSL logic in [BCheckBridge] (companion object).
 *
 * Regression coverage for BUG #32: bcheck_create emitted invalid BCheck DSL and skipped input
 * validation. Concretely:
 * - unknown severity/confidence/type/match_condition were emitted verbatim, producing an
 *   un-importable or degenerate check,
 * - the insertion_point branch emitted `run for each` over a define list under `given insertion
 *   point then`, which the v2-beta grammar does not support,
 * - the `else` fallback turned an unknown type into a `matches ""` passive check that fires on
 *   every response,
 * - `matches ""` could be emitted for active checks with no match pattern.
 *
 * And for plan P2.5: whatever text a caller supplies stays inside its string (the script's
 * structure never depends on it), host_level takes its path and its response pattern separately,
 * and an empty pattern is rejected.
 *
 * These tests exercise only the pure static functions, so no live Burp is needed.
 */
class BCheckBridgeTest {

    private fun emit(
        type: String,
        name: String = "n",
        description: String = "d",
        author: String = "a",
        tags: String = "t",
        matchPattern: String? = null,
        matchLocation: String? = null,
        matchCondition: String? = null,
        payloads: List<String>? = null,
        responseMatchPattern: String? = null,
        collaboratorPayloadType: String? = null,
        severity: String = "high",
        confidence: String = "firm",
        issueDetail: String? = null,
        issueRemediation: String? = null,
        path: String? = null,
    ): String =
        BCheckBridge.emitScript(
            name,
            description,
            author,
            tags,
            type,
            matchPattern,
            matchLocation,
            matchCondition,
            payloads,
            responseMatchPattern,
            collaboratorPayloadType,
            severity,
            confidence,
            issueDetail,
            issueRemediation,
            path,
        )

    private fun error(
        type: String,
        matchPattern: String? = null,
        matchLocation: String? = null,
        matchCondition: String? = null,
        payloads: List<String>? = null,
        responseMatchPattern: String? = null,
        collaboratorPayloadType: String? = null,
        path: String? = null,
    ): String? =
        BCheckBridge.definitionError(
            type,
            matchPattern,
            matchLocation,
            matchCondition,
            payloads,
            responseMatchPattern,
            collaboratorPayloadType,
            path,
        )

    // ---- reading a script the way BCheck's lexer does ------------------------

    /**
     * A string token: its decoded value (a `{variable}` shows as `<variable>`) and the variables it
     * interpolates.
     */
    private data class Str(
        val interpolated: Boolean,
        val value: String,
        val variables: List<String>,
    )

    /** What is left of a script when every string is replaced by a placeholder, and the strings. */
    private data class Lexed(val skeleton: String, val strings: List<Str>) {
        val values: List<String>
            get() = strings.map { it.value }
    }

    /**
     * Tokenises [script]'s strings by the published BCheck lexer rules: in a "literal" the only
     * escape is `\"`; in an `interpolated` string a backslash escapes the next character and `{`
     * opens a variable reference. A string that never closes is the failure this guards against.
     */
    private fun lex(script: String): Lexed {
        val skeleton = StringBuilder()
        val strings = mutableListOf<Str>()
        var i = 0
        while (i < script.length) {
            when (script[i]) {
                '"' -> {
                    val value = StringBuilder()
                    i++
                    while (true) {
                        check(i < script.length) { "a literal string never closes:\n$script" }
                        val c = script[i]
                        if (c == '\\' && script.getOrNull(i + 1) == '"') {
                            value.append('"')
                            i += 2
                        } else if (c == '"') {
                            i++
                            break
                        } else {
                            value.append(c)
                            i++
                        }
                    }
                    strings += Str(false, value.toString(), emptyList())
                    skeleton.append("<S>")
                }
                '`' -> {
                    val value = StringBuilder()
                    val variables = mutableListOf<String>()
                    i++
                    while (true) {
                        check(i < script.length) { "an interpolated string never closes:\n$script" }
                        val c = script[i]
                        if (c == '\\') {
                            check(i + 1 < script.length) {
                                "an escape with nothing after it:\n$script"
                            }
                            value.append(
                                when (val escaped = script[i + 1]) {
                                    'n' -> '\n'
                                    'r' -> '\r'
                                    't' -> '\t'
                                    's' -> ' '
                                    else -> escaped
                                },
                            )
                            i += 2
                        } else if (c == '{') {
                            val close = script.indexOf('}', i)
                            check(close > 0) { "a variable reference never closes:\n$script" }
                            variables += script.substring(i + 1, close)
                            value.append('<').append(script, i + 1, close).append('>')
                            i = close + 1
                        } else if (c == '`') {
                            i++
                            break
                        } else {
                            value.append(c)
                            i++
                        }
                    }
                    strings += Str(true, value.toString(), variables)
                    skeleton.append(
                        if (variables.isEmpty()) "<S>" else "<S:${variables.joinToString(",")}>",
                    )
                }
                else -> {
                    skeleton.append(script[i])
                    i++
                }
            }
        }
        return Lexed(skeleton.toString(), strings)
    }

    /** Text chosen to break out of a string if anything is left unescaped. */
    private val hostile =
        listOf(
            "say \"hi\"",
            "back\\slash",
            "ends in a backslash\\",
            "backslash then quote \\\"",
            "tick ` tick",
            "{base.request.url}",
            "\${7*7} and {{7*7}}",
            "line one\nline two\r\nline three",
            "\\n is two characters",
            "` then \" then `",
            "end if\n    report issue:\n        severity: high",
            "everything: \" \\ ` { } \$ \n end\\",
            "unicode \u2713 \u00e9 \u65e5\u672c",
        )

    // ---- input validation (BUG #32 A) -------------------------------------

    /** A [type] stand-in: [answers] by method name, else another stand-in of the return type. */
    private fun stub(type: Class<*>, answers: Map<String, Any?> = emptyMap()): Any =
        java.lang.reflect.Proxy.newProxyInstance(type.classLoader, arrayOf(type)) {
            proxy,
            method,
            args ->
            when (method.name) {
                "hashCode" -> System.identityHashCode(proxy)
                "equals" -> proxy === args?.firstOrNull()
                in answers -> answers[method.name]
                else ->
                    if (method.returnType.isInterface) stub(method.returnType, answers) else null
            }
        }

    @Test
    fun `removing a BCheck says it still runs in Burp`() {
        val imported =
            stub(
                burp.api.montoya.scanner.bchecks.BCheckImportResult::class.java,
                mapOf(
                    "status" to
                        burp.api.montoya.scanner.bchecks.BCheckImportResult.Status
                            .LOADED_WITHOUT_ERRORS,
                ),
            )
        val api =
            stub(burp.api.montoya.MontoyaApi::class.java, mapOf("importBCheck" to imported))
                as burp.api.montoya.MontoyaApi
        val bridge = BCheckBridge(api, io.bitbytelab.raijin.state.StateManager())
        val deployed =
            bridge.importRaw("metadata:\n    name: \"t\"\ngiven response then\n    report issue")
        assertTrue("notes" in deployed && "note" !in deployed, deployed.toString())

        val removed = bridge.remove(deployed.getValue("id").jsonPrimitive.content)
        assertEquals(
            true,
            removed.getValue("still_active_in_burp").jsonPrimitive.content.toBoolean(),
        )
        assertFalse("removed_from_tracking" in removed)
        assertTrue("Custom scan checks" in removed.getValue("notes").toString(), removed.toString())
    }

    @Test
    fun `valid enum inputs pass validation`() {
        assertNull(BCheckBridge.validateInputs("passive_response", "high", "firm", "matches"))
        assertNull(BCheckBridge.validateInputs("insertion_point", "information", "tentative", null))
        // case/whitespace insensitive (delegated to EnumValidation)
        assertNull(BCheckBridge.validateInputs("  Passive_Request ", "LOW", "Certain", " IS "))
    }

    @Test
    fun `invalid severity is rejected with a clean error naming the value`() {
        val e = BCheckBridge.validateInputs("passive_response", "critical", "firm", "matches")
        assertNotNull(e, "invalid severity must produce an error object")
        val msg = e!!["error"]!!.jsonPrimitive.content
        assertTrue(msg.contains("critical"), msg)
        assertTrue(msg.contains("severity"), msg)
        // an error object must never look like a deployed result
        assertNull(e["status"])
    }

    @Test
    fun `invalid confidence is rejected`() {
        val e = BCheckBridge.validateInputs("passive_response", "high", "very-sure", "matches")
        assertNotNull(e)
        assertTrue(e!!["error"]!!.jsonPrimitive.content.contains("confidence"))
    }

    @Test
    fun `invalid type is rejected`() {
        val e = BCheckBridge.validateInputs("sql_injection", "high", "firm", "matches")
        assertNotNull(e)
        assertTrue(e!!["error"]!!.jsonPrimitive.content.contains("type"))
    }

    @Test
    fun `invalid match_condition is rejected but null is allowed`() {
        assertNotNull(BCheckBridge.validateInputs("passive_response", "high", "firm", "equals"))
        // match_condition is optional
        assertNull(BCheckBridge.validateInputs("passive_response", "high", "firm", null))
    }

    // ---- unknown type never becomes a degenerate check (BUG #32 B) --------

    @Test
    fun `emitScript throws on an unsupported type instead of emitting matches empty`() {
        val ex = assertFailsWith<IllegalArgumentException> { emit("totally_unknown") }
        assertTrue(ex.message!!.contains("Unsupported BCheck type"), ex.message)
    }

    @Test
    fun `a severity or confidence outside the grammar is never emitted`() {
        assertFailsWith<IllegalArgumentException> {
            emit("passive_response", matchPattern = "x", severity = "critical")
        }
        assertFailsWith<IllegalArgumentException> {
            emit("passive_response", matchPattern = "x", confidence = "sure\nreport issue:")
        }
    }

    // ---- an empty pattern is rejected (plan P2.5) ---------------------------

    @Test
    fun `a missing or empty pattern is rejected for every type that matches one`() {
        for (type in listOf("passive_response", "passive_request")) {
            assertTrue("match_pattern" in error(type)!!, type)
            assertTrue("match_pattern" in error(type, matchPattern = "")!!, type)
            assertNull(error(type, matchPattern = "x"))
        }
        assertTrue("response_match_pattern" in error("insertion_point", payloads = listOf("'"))!!)
        assertTrue(
            "response_match_pattern" in
                error("insertion_point", payloads = listOf("'"), responseMatchPattern = "")!!,
        )
        assertTrue("response_match_pattern" in error("host_level", path = "/admin")!!)
        // The emitter enforces the same rule, so no caller can get a `matches ""` out of it.
        assertFailsWith<IllegalArgumentException> { emit("passive_response") }
        assertFailsWith<IllegalArgumentException> { emit("insertion_point") }
    }

    @Test
    fun `a pattern that is not a valid regex is rejected unless it is not used as one`() {
        assertTrue(
            "Invalid match_pattern regex" in
                error("passive_response", matchPattern = "([unclosed")!!,
        )
        assertNull(
            error("passive_response", matchPattern = "([unclosed", matchCondition = "contains"),
        )
        assertNull(error("passive_response", matchPattern = "([unclosed", matchCondition = "is"))
        // Valid for Java inside an unterminated \Q quote, but a BCheck literal cannot end in a
        // backslash.
        assertTrue("backslash" in error("passive_response", matchPattern = "\\Qab\\")!!)
    }

    @Test
    fun `match_location must be one the check type has`() {
        assertNull(
            error("passive_response", matchPattern = "x", matchLocation = "response_headers"),
        )
        assertNull(error("passive_request", matchPattern = "x", matchLocation = "Request_Body"))
        // The response body of a request check does not exist; this used to fall back to the URL
        // silently.
        assertTrue(
            "match_location" in
                error("passive_request", matchPattern = "x", matchLocation = "response_body")!!,
        )
        assertTrue(
            "match_location" in
                error("passive_response", matchPattern = "x", matchLocation = "request_url")!!,
        )
    }

    @Test
    fun `an insertion point check needs something to inject`() {
        assertTrue("payloads" in error("insertion_point", responseMatchPattern = "SQL syntax")!!)
        assertTrue("payloads" in error("insertion_point", matchPattern = "SQL syntax")!!)
        assertNull(
            error("insertion_point", payloads = listOf("'"), responseMatchPattern = "SQL syntax"),
        )
        // The older shape: match_pattern is the payload, response_match_pattern what to look for.
        assertNull(
            error("insertion_point", matchPattern = "'", responseMatchPattern = "SQL syntax"),
        )
    }

    @Test
    fun `a collaborator check must inject a collaborator address and wait for a known interaction`() {
        assertNull(error("collaborator"))
        assertNull(
            error(
                "collaborator",
                matchPattern = "http://{generate_collaborator_address()}/x",
                collaboratorPayloadType = "HTTP",
            ),
        )
        assertTrue(
            "generate_collaborator_address" in
                error("collaborator", matchPattern = "http://example.com/")!!,
        )
        assertTrue(
            "collaborator_payload_type" in
                error("collaborator", collaboratorPayloadType = "smtp")!!,
        )
    }

    // ---- insertion_point emits valid v2-beta DSL (BUG #32 C) --------------

    @Test
    fun `insertion_point emits one send-payload per payload with no run-for-each`() {
        val script =
            emit(
                "insertion_point",
                name = "SSTI",
                tags = "ssti",
                payloads = listOf("\${7*7}", "\${9*9}"),
                responseMatchPattern = "49|81",
                issueDetail = "SSTI",
                issueRemediation = "fix",
            )
        assertTrue(script.contains("given insertion point then"), script)
        // The broken construct must be gone.
        assertFalse(
            script.contains("run for each"),
            "insertion_point must not use run for each: $script",
        )
        // One distinct send payload per payload, each with its own detection block.
        assertTrue(script.contains("send payload called p1:"), script)
        assertTrue(script.contains("send payload called p2:"), script)
        assertTrue(script.contains("if {p1.response.body} matches"), script)
        assertTrue(script.contains("if {p2.response.body} matches"), script)
        assertEquals(2, Regex("send payload called p\\d+:").findAll(script).count())
        // Never a degenerate empty match.
        assertFalse(script.contains("matches \"\""), "must not emit matches \"\": $script")
        // A brace in a payload must not open a variable reference.
        assertEquals(
            listOf("\${7*7}", "\${9*9}"),
            lex(script).values.filter { it.startsWith("\$") },
        )
    }

    @Test
    fun `insertion_point only reports what the unmodified response does not already show`() {
        val script =
            emit("insertion_point", payloads = listOf("'"), responseMatchPattern = "SQL syntax")
        val guard = script.indexOf("if not({base.response.body} matches \"SQL syntax\") then")
        val send = script.indexOf("send payload called p1:")
        assertTrue(guard in 0 until send, "the baseline guard must wrap the payloads:\n$script")
        assertEquals(2, Regex("(?m)^\\s*if ").findAll(script).count())
        assertEquals(2, Regex("(?m)^\\s*end if$").findAll(script).count())
    }

    // ---- severity 'information' must emit the token Burp accepts: 'info' (QA #32, live-verified)
    // --

    @Test
    fun `severity information is emitted as info, not information`() {
        val info =
            emit(
                "passive_response",
                matchPattern = "abc",
                matchLocation = "response_body",
                matchCondition = "matches",
                severity = "information",
                confidence = "tentative",
            )
        assertTrue(info.contains("severity: info"), "must emit BCheck token 'info': $info")
        assertFalse(
            info.contains("severity: information"),
            "Burp's BCheck parser rejects 'information': $info",
        )

        val high =
            emit(
                "passive_response",
                matchPattern = "abc",
                matchLocation = "response_body",
                matchCondition = "matches",
            )
        assertTrue(high.contains("severity: high"), high)
    }

    @Test
    fun `insertion_point with a single match pattern still emits a valid block`() {
        val script =
            emit(
                "insertion_point",
                name = "err",
                matchPattern = "'",
                responseMatchPattern = "SQL syntax",
                severity = "medium",
                confidence = "tentative",
            )
        assertTrue(script.contains("send payload called p1:"), script)
        assertTrue(script.contains("replacing: \"'\""), script)
        assertTrue(script.contains("if {p1.response.body} matches \"SQL syntax\""), script)
        assertFalse(script.contains("run for each"), script)
    }

    // ---- condition remapping: contains -> matches(escaped) ---------------

    @Test
    fun `contains condition is translated to an escaped matches regex`() {
        val (op, pat) = BCheckBridge.normalizeCondition("contains", "a.b(c)")
        assertEquals("matches", op)
        // metacharacters escaped so they are treated literally
        assertEquals("a\\.b\\(c\\)", pat)
    }

    @Test
    fun `is condition passes through unchanged`() {
        val (op, pat) = BCheckBridge.normalizeCondition("is", "200")
        assertEquals("is", op)
        assertEquals("200", pat)
    }

    @Test
    fun `matches and unknown default to matches with the raw pattern`() {
        assertEquals("matches" to "x+", BCheckBridge.normalizeCondition("matches", "x+"))
        assertEquals("matches" to "x+", BCheckBridge.normalizeCondition(null, "x+"))
    }

    @Test
    fun `passive_response contains emits a matches operator not the raw contains keyword`() {
        val script =
            emit(
                "passive_response",
                matchPattern = "secret.value",
                matchLocation = "response_body",
                matchCondition = "contains",
            )
        // The invalid `contains` operator must never appear in the emitted DSL.
        assertFalse(Regex("\\bcontains\\b").containsMatchIn(script), script)
        assertTrue(script.contains("{latest.response.body} matches \"secret\\.value\""), script)
    }

    @Test
    fun `the location and the condition choose the variable and the operator`() {
        assertTrue(
            "if {latest.response.status_code} is \"200\" then" in
                emit(
                    "passive_response",
                    matchPattern = "200",
                    matchLocation = "status_code",
                    matchCondition = "is",
                ),
        )
        assertTrue(
            "if {latest.response.headers} matches \"(?i)^server:\" then" in
                emit("passive_response", matchPattern = "(?i)^server:", matchLocation = "headers"),
        )
        assertTrue(
            "if {base.request.url} matches \"token=\" then" in
                emit("passive_request", matchPattern = "token="),
        )
        assertTrue(
            "if {base.request.body} matches \"password\" then" in
                emit("passive_request", matchPattern = "password", matchLocation = "request_body"),
        )
    }

    // ---- host_level: the path and the response pattern are two things (plan P2.5) ----

    @Test
    fun `host_level requests path and matches response_match_pattern`() {
        val script = emit("host_level", path = "/admin/", responseMatchPattern = "Dashboard")
        assertTrue("        path: \"/admin/\"" in script, script)
        assertTrue("{host_check.response.body} matches \"Dashboard\" then" in script, script)
        assertTrue("if {host_check.response.status_code} is \"200\" and" in script, script)
    }

    @Test
    fun `host_level with a path takes match_pattern as the response pattern`() {
        val script =
            emit("host_level", path = "/server-status", matchPattern = "Apache Server Status")
        assertTrue("path: \"/server-status\"" in script, script)
        assertTrue("{host_check.response.body} matches \"Apache Server Status\"" in script, script)
    }

    @Test
    fun `host_level still reads the older shape where match_pattern was the path`() {
        val script =
            emit("host_level", matchPattern = "/.git/config", responseMatchPattern = "\\[core\\]")
        assertTrue("path: \"/.git/config\"" in script, script)
        assertTrue("{host_check.response.body} matches \"\\[core\\]\"" in script, script)
        // What it must not do any more: use the path as the regex for the body.
        assertTrue("response_match_pattern" in error("host_level", matchPattern = "/.git/config")!!)
    }

    @Test
    fun `host_level defaults to the root path`() {
        assertTrue("path: \"/\"" in emit("host_level", responseMatchPattern = "It works!"))
    }

    // ---- path_level follows the grammar (BUG #32 D) ----------------------

    @Test
    fun `path_level declares its suffixes in a run for each before given`() {
        val script =
            emit(
                "path_level",
                payloads = listOf(".bak", "quote\"here"),
                severity = "medium",
                confidence = "tentative",
            )
        // Every list entry is individually quoted; the stray quote is neutralised
        // so it cannot terminate the list literal.
        assertTrue(script.contains("    extension = \".bak\", \"quote\\\"here\""), script)
        val loop = script.indexOf("run for each:")
        val given = script.indexOf("given path then")
        assertTrue(loop in 0 until given, "run for each must come before given:\n$script")
        assertFalse("define:" in script, "a define block cannot hold a list")
        assertTrue("replacing path: `{base.request.url.path}{extension}`" in script, script)
        assertEquals(
            listOf(".bak", "quote\"here"),
            lex(script).values.filter { it == ".bak" || it.startsWith("quote") },
        )
    }

    @Test
    fun `path_level only reports an answer that differs from the one to a path that cannot exist`() {
        val script = emit("path_level")
        assertTrue("replacing path: `{base.request.url.path}.{random_str(10)}`" in script, script)
        assertTrue("if {garbage_check} differs from {path_check} then" in script, script)
        assertTrue(
            "report issue and continue:" in script,
            "every suffix must get its turn:\n$script",
        )
        assertTrue("extension = \".bak\", \".old\", \".orig\", \".swp\", \"~\"" in script, script)
    }

    @Test
    fun `path_level can also require a pattern in the body`() {
        val script =
            emit("path_level", payloads = listOf(".sql"), responseMatchPattern = "CREATE TABLE")
        assertTrue("if {path_check.response.status_code} is \"200\" and" in script, script)
        assertTrue("{path_check.response.body} matches \"CREATE TABLE\" then" in script, script)
    }

    // ---- collaborator ------------------------------------------------------

    @Test
    fun `collaborator sets the header through a replacing headers block and waits for the interaction`() {
        val http = emit("collaborator", matchLocation = "Referer", collaboratorPayloadType = "HTTP")
        assertTrue(http.contains("if http interactions then"), http)
        assertTrue(
            "        replacing headers:\n            \"Referer\": `https://{generate_collaborator_address()}`" in
                http,
            http,
        )
        assertTrue(emit("collaborator").contains("if dns interactions then"))
    }

    @Test
    fun `a collaborator header value keeps its address variable and nothing else of its braces`() {
        val script =
            emit(
                "collaborator",
                matchLocation = "X-Api",
                matchPattern = "{\"cb\":\"http://{generate_collaborator_address()}/a\"}",
            )
        val value = lex(script).strings.single { it.variables.isNotEmpty() && "cb" in it.value }
        assertEquals(listOf("generate_collaborator_address()"), value.variables)
        assertEquals("{\"cb\":\"http://<generate_collaborator_address()>/a\"}", value.value)
    }

    // ---- metadata is always well-formed ----------------------------------

    @Test
    fun `emitScript always writes the required metadata header`() {
        val script = emit("passive_response", tags = "one, two", matchPattern = "x")
        assertTrue(script.startsWith("metadata:"), script)
        assertTrue(script.contains("language: v2-beta"), script)
        assertTrue(script.contains("tags: \"one\", \"two\""), script)
    }

    @Test
    fun `metadata is one line per field and empty tags are dropped`() {
        val script =
            emit(
                "passive_response",
                name = "two\nlines",
                description = " padded ",
                tags = " , a,, ",
                matchPattern = "x",
            )
        assertTrue("    name: \"two lines\"\n" in script, script)
        assertTrue("    description: \"padded\"\n" in script, script)
        assertTrue("    tags: \"a\"\n" in script, script)
        assertFalse("tags:" in emit("passive_response", tags = " , ", matchPattern = "x"))
    }

    // ---- any text stays inside its string (plan P2.5) --------------------------

    @Test
    fun `string tokens decode to exactly the text they were given`() {
        for (text in hostile + listOf("", "plain")) {
            val token = BCheckBridge.stringToken(text)
            val lexed = lex(token)
            assertEquals("<S>", lexed.skeleton, "one token, nothing outside it: $token")
            assertEquals(text, lexed.values.single(), token)
        }
        // A literal where a literal can hold the text: only the quote is escaped there.
        assertEquals("\"a\\b{c}`d\\\"e\"", BCheckBridge.stringToken("a\\b{c}`d\"e"))
        // A trailing backslash would pair with the closing quote of a literal; a line break would
        // be re-wrapped.
        assertEquals("`a\\\\`", BCheckBridge.stringToken("a\\"))
        assertEquals("`a\\nb`", BCheckBridge.stringToken("a\nb"))
    }

    @Test
    fun `interpolated text keeps braces, backticks and backslashes as text`() {
        for (text in hostile) {
            val lexed = lex("`" + BCheckBridge.interpolatedBody(text) + "`")
            assertEquals(text, lexed.values.single())
            assertTrue(
                lexed.strings.single().variables.isEmpty(),
                "no variable may be interpolated from: $text",
            )
        }
    }

    @Test
    fun `a regex token is one literal that still means the same regex`() {
        assertEquals("\"a\\\"b\"", BCheckBridge.regexToken("a\"b"))
        assertEquals(
            "\"\\d+\\.\\d+\"",
            BCheckBridge.regexToken("\\d+\\.\\d+"),
            "regex escapes pass through untouched",
        )
        // An escaped backslash at the end must not swallow the closing quote.
        assertEquals("\"x\\\\(?:)\"", BCheckBridge.regexToken("x\\\\"))
        assertTrue(Regex(lex(BCheckBridge.regexToken("x\\\\")).values.single()).matches("x\\"))
        // A raw line break becomes its escape; after an escaping backslash it completes that
        // escape.
        assertEquals("\"a\\nb\"", BCheckBridge.regexToken("a\nb"))
        assertEquals("\"a\\nb\"", BCheckBridge.regexToken("a\\\nb"))
        assertTrue(Regex(lex(BCheckBridge.regexToken("a\r\nb")).values.single()).matches("a\r\nb"))

        for (text in hostile) {
            val token = BCheckBridge.regexToken(BCheckBridge.regexEscapeLiteral(text))
            val lexed = lex(token)
            assertEquals("<S>", lexed.skeleton, token)
            assertFalse(lexed.strings.single().interpolated, "matches takes a literal: $token")
            assertTrue(
                Regex(lexed.values.single()).matches(text),
                "the regex must still match its text: $token",
            )
        }
    }

    @Test
    fun `hostile text in any field leaves the script's structure unchanged`() {
        fun scripts(text: String) =
            listOf(
                emit(
                    "passive_response",
                    name = text,
                    description = text,
                    author = text,
                    tags = "x, $text",
                    matchPattern = text,
                    matchCondition = "contains",
                    issueDetail = text,
                    issueRemediation = text,
                ),
                emit(
                    "passive_response",
                    matchPattern = text,
                    matchCondition = "is",
                    issueDetail = text,
                ),
                emit(
                    "passive_request",
                    matchPattern = text,
                    matchCondition = "contains",
                    issueRemediation = text,
                ),
                emit(
                    "insertion_point",
                    payloads = listOf(text, "second $text"),
                    responseMatchPattern = text,
                    matchCondition = "contains",
                    issueDetail = text,
                    issueRemediation = text,
                ),
                emit(
                    "host_level",
                    path = text,
                    responseMatchPattern = text,
                    matchCondition = "contains",
                    issueDetail = text,
                ),
                emit(
                    "path_level",
                    payloads = listOf(text, ".bak"),
                    responseMatchPattern = text,
                    matchCondition = "contains",
                    issueDetail = text,
                    issueRemediation = text,
                ),
                emit(
                    "collaborator",
                    matchLocation = text,
                    matchPattern = "$text{generate_collaborator_address()}$text",
                    issueDetail = text,
                    issueRemediation = text,
                ),
            )

        val expected = scripts("benign").map { lex(it).skeleton }
        for (text in hostile) {
            val actual = scripts(text).map { lex(it) }
            assertEquals(
                expected,
                actual.map { it.skeleton },
                "the script must have the same shape whatever the text is: $text",
            )
        }
    }

    @Test
    fun `hostile text comes out of the script as the text that went in`() {
        for (text in hostile) {
            val active =
                lex(
                    emit(
                        "insertion_point",
                        payloads = listOf(text),
                        responseMatchPattern = "x",
                        issueDetail = text,
                        issueRemediation = text,
                    ),
                )
            assertTrue(text in active.values, "payload and remediation: $text")
            assertTrue("$text Payload: $text" in active.values, "detail: $text")

            val exact = lex(emit("passive_response", matchPattern = text, matchCondition = "is"))
            assertTrue(text in exact.values, "the operand of 'is': $text")

            val host = lex(emit("host_level", path = text, responseMatchPattern = "x"))
            assertTrue(text in host.values, "path: $text")

            val path = lex(emit("path_level", payloads = listOf(text), issueDetail = text))
            assertTrue(text in path.values, "suffix: $text")
            assertTrue("$text Found at: <path_check.request.url>" in path.values, "detail: $text")

            val collaborator =
                lex(
                    emit(
                        "collaborator",
                        matchLocation = text,
                        matchPattern = "$text{generate_collaborator_address()}",
                    ),
                )
            assertTrue(text in collaborator.values, "header name: $text")
            assertTrue(
                "$text<generate_collaborator_address()>" in collaborator.values,
                "header value: $text",
            )
        }
    }
}
