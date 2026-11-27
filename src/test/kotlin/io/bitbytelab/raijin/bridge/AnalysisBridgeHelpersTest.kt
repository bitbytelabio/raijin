package io.bitbytelab.raijin.bridge

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Unit tests for the pure, Burp-independent helpers in [AnalysisBridge].
 *
 * These cover the regressions fixed for:
 * - BUG #3 analyze_request: missing CRLF normalization (LF-delimited headers dropped)
 * - BUG #4 analyze_insertion_points: query string appended to final path segment
 * - BUG #5/#6 empty-input parser exception leakage (via describeException)
 * - BUG #18 auth_diff: bare-null / raw JVM exception leakage
 *
 * The full bridge cannot be instantiated here (the Montoya API is compileOnly), so we exercise the
 * extracted pure logic directly through the internal companion.
 */
class AnalysisBridgeHelpersTest {

    // ---- BUG #3: CRLF normalization -----------------------------------

    @Test
    fun `bare LF delimiters are upgraded to CRLF so headers are not dropped`() {
        val raw = "GET / HTTP/1.1\nHost: example.com\nAccept: */*\n\n"
        val normalized = AnalysisBridge.normalizeCrlfMessage(raw)
        assertEquals("GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n", normalized)
        assertFalse(normalized.contains(Regex("(?<!\r)\n")), "no bare LF should remain")
    }

    @Test
    fun `escaped newline sequences from JSON transport are decoded then normalized`() {
        val raw = "GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n"
        val normalized = AnalysisBridge.normalizeCrlfMessage(raw)
        assertEquals("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", normalized)
    }

    @Test
    fun `already-CRLF messages are left unchanged (idempotent)`() {
        val raw = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        assertEquals(raw, AnalysisBridge.normalizeCrlfMessage(raw))
    }

    @Test
    fun `escaped backslash-n mixed with real CRLF does not double-convert`() {
        val raw = "GET / HTTP/1.1\r\nHost: example.com\\n\r\n\r\n"
        val normalized = AnalysisBridge.normalizeCrlfMessage(raw)
        assertFalse(normalized.contains(Regex("(?<!\r)\n")), "no bare LF should remain")
        assertFalse(normalized.contains("\r\r"), "no doubled CR should be produced")
    }

    // ---- BUG #4: path segment query-string stripping ------------------

    @Test
    fun `path segments strip the query string from the final segment`() {
        val segments = AnalysisBridge.pathSegments("/product/category/e?id=42&q=x")
        assertEquals(listOf("product", "category", "e"), segments)
    }

    @Test
    fun `path segments strip a fragment as well`() {
        val segments = AnalysisBridge.pathSegments("/a/b/c#frag")
        assertEquals(listOf("a", "b", "c"), segments)
    }

    @Test
    fun `path with no query is unaffected and drops empty segments`() {
        val segments = AnalysisBridge.pathSegments("/product//e/")
        assertEquals(listOf("product", "e"), segments)
    }

    @Test
    fun `root path yields no segments`() {
        assertTrue(AnalysisBridge.pathSegments("/").isEmpty())
        assertTrue(AnalysisBridge.pathSegments("/?only=query").isEmpty())
    }

    // ---- BUG #5 / #6 / #18: safe exception description ----------------

    @Test
    fun `null-message exception is described by its class name not the string null`() {
        val e = StringIndexOutOfBoundsException() // message is null
        val described = AnalysisBridge.describeException(e)
        assertEquals("StringIndexOutOfBoundsException", described)
        assertFalse(described.equals("null", ignoreCase = true))
    }

    @Test
    fun `blank-message exception falls back to the class name`() {
        val e = RuntimeException("   ")
        assertEquals("RuntimeException", AnalysisBridge.describeException(e))
    }

    @Test
    fun `present message is preserved verbatim`() {
        val e = IllegalArgumentException("fromIndex(1) > toIndex(0)")
        assertEquals("fromIndex(1) > toIndex(0)", AnalysisBridge.describeException(e))
    }

    // ---- response-body search: one bounded, serializable match per body ----

    @Test
    fun `matchBody returns the match with its position and some context`() {
        val body = "-".repeat(100) + "token=abc123" + "-".repeat(100)
        val match = assertNotNull(AnalysisBridge.matchBody("TOKEN=[a-z0-9]+", body))
        assertEquals("token=abc123", match.value)
        assertEquals(100, match.position)
        assertEquals("-".repeat(50) + "token=abc123" + "-".repeat(50), match.snippet)
    }

    @Test
    fun `matchBody caps a long match and never throws on a pattern it cannot use`() {
        val long = assertNotNull(AnalysisBridge.matchBody("x+", "x".repeat(2000)))
        assertEquals(500, long.value.length)
        assertEquals(550, long.snippet.length)

        assertNull(AnalysisBridge.matchBody("[unclosed", "abc"))
        assertNull(AnalysisBridge.matchBody("zzz", "abc"))

        // An empty match is still a match and must not break the snippet arithmetic.
        val empty = assertNotNull(AnalysisBridge.matchBody("z*", "abc"))
        assertEquals("", empty.value)
        assertEquals("abc", empty.snippet)
    }

    @Test
    fun `matchBody output never carries half a surrogate pair`() {
        // The 50-character context starts between the two halves of the emoji.
        val body = "\uD83D\uDE00" + "a".repeat(49) + "KEY"
        val match = assertNotNull(AnalysisBridge.matchBody("KEY", body))
        assertEquals(51, match.position)
        assertEquals('\uFFFD', match.snippet.first())
        assertTrue(match.snippet.none { it.isSurrogate() }, match.snippet)
    }

    // ---- auth_diff: what the levels that answered add up to ----------------

    private fun level(name: String, status: Int, body: String, location: String? = null) =
        AuthLevelResponse(level = name, statusCode = status, body = body, location = location)

    private fun findings(report: JsonObject, field: String): List<String> =
        report.getValue("findings").jsonArray.map {
            it.jsonObject.getValue(field).jsonPrimitive.content
        }

    private fun strings(report: JsonObject, key: String): List<String> =
        report[key]?.jsonArray?.map { it.jsonPrimitive.content }.orEmpty()

    @Test
    fun `a level without a response is described as a timeout or a connection error`() {
        val timeout = AnalysisBridge.levelFailure("none", 30_004)
        assertTrue(timeout.contains("'none'") && timeout.contains("timed out"), timeout)
        val refused = AnalysisBridge.levelFailure("none", 12)
        assertTrue(refused.contains("'none'") && refused.contains("connection error"), refused)
    }

    @Test
    fun `a level that never answered is an error entry and takes no part in the comparison`() {
        // What authDiff hands over when 'none' timed out: two answers and one error.
        val report =
            AnalysisBridge.authDiffReport(
                listOf(level("admin", 200, "secret"), level("user", 403, "denied")),
                listOf(AnalysisBridge.levelFailure("none", 30_001)),
            )

        assertEquals(2, report.getValue("auth_levels_tested").jsonPrimitive.int)
        val responses = report.getValue("responses").jsonArray.map { it.jsonObject }
        assertEquals(
            listOf("admin", "user"),
            responses.map { it.getValue("level").jsonPrimitive.content },
        )
        assertTrue(responses.none { it.getValue("status_code").jsonPrimitive.int == 0 })
        assertTrue(strings(report, "errors").single().contains("timed out"))
        assertTrue(
            findings(report, "severity").none { it == "critical" || it == "high" },
            report.toString(),
        )
        assertNull(report["code"])
    }

    @Test
    fun `no level answering is a no_response error that keeps the report`() {
        val report =
            AnalysisBridge.authDiffReport(
                emptyList(),
                listOf(
                    AnalysisBridge.levelFailure("admin", 12),
                    AnalysisBridge.levelFailure("none", 12),
                ),
            )
        assertEquals(listOf("error", "code"), report.keys.take(2), report.toString())
        assertEquals("no_response", report.getValue("code").jsonPrimitive.content)
        assertTrue(
            "Level 'admin' failed" in report.getValue("error").jsonPrimitive.content,
            report.toString(),
        )
        assertEquals(0, report.getValue("auth_levels_tested").jsonPrimitive.int)
        assertEquals(2, strings(report, "errors").size)
    }

    @Test
    fun `uniform denials and login redirects report no high or critical finding`() {
        for (status in listOf(401, 403, 404, 500)) {
            val report =
                AnalysisBridge.authDiffReport(
                    listOf(
                        level("admin", status, "denied"),
                        level("user", status, "denied"),
                        level("none", status, "denied"),
                    ),
                    emptyList(),
                )
            assertEquals(
                listOf("all_identical_non_success"),
                findings(report, "id"),
                "status $status",
            )
            assertEquals(listOf("info"), findings(report, "severity"), "status $status")
            assertEquals(true, report.getValue("all_same_status").jsonPrimitive.boolean)
            assertEquals(true, report.getValue("all_same_body").jsonPrimitive.boolean)
        }

        val bounced =
            AnalysisBridge.authDiffReport(
                listOf(
                    level("admin", 302, "", "/login?next=%2Fadmin"),
                    level("none", 302, "", "/login"),
                ),
                emptyList(),
            )
        assertEquals(listOf("info"), findings(bounced, "severity"))
        val first = bounced.getValue("responses").jsonArray[0].jsonObject
        assertEquals(
            "/login?next=%2Fadmin",
            first.getValue("redirect_location").jsonPrimitive.content,
        )
    }

    @Test
    fun `a denied_regex marks a 200 refusal the built-in detection does not know`() {
        val levels =
            listOf(
                level("admin", 200, "<html>Bitte anmelden</html>"),
                level("none", 200, "<html>Bitte anmelden</html>"),
            )

        assertEquals(
            listOf("all_identical"),
            findings(AnalysisBridge.authDiffReport(levels, emptyList()), "id"),
        )

        val tuned =
            AnalysisBridge.authDiffReport(levels, emptyList(), deniedRegex = "bitte ANMELDEN")
        assertEquals(listOf("all_identical_soft_denial"), findings(tuned, "id"))
        assertEquals(listOf("info"), findings(tuned, "severity"))
    }

    @Test
    fun `each response shows how its identity was applied and an unchanged level is noted`() {
        val applied =
            AuthIdentityApplier.Applied(
                "GET / HTTP/1.1\r\n\r\n",
                removed = listOf("Cookie"),
                set = listOf("Authorization"),
                keptCredentials = listOf("X-API-Key"),
            )
        val report =
            AnalysisBridge.authDiffReport(
                listOf(
                    AuthLevelResponse("user", 200, "a", applied = applied),
                    AuthLevelResponse("captured", 200, "b", sentUnchanged = true),
                ),
                emptyList(),
            )

        val user = report.getValue("responses").jsonArray[0].jsonObject
        assertEquals(listOf("Authorization"), strings(user, "headers_set"))
        assertEquals(listOf("Cookie"), strings(user, "headers_removed"))
        assertEquals(listOf("X-API-Key"), strings(user, "credential_headers_kept"))
        assertTrue(strings(report, "notes").single().contains("'captured'"))
    }

    @Test
    fun `compare fields limit the pairwise differences`() {
        val levels =
            listOf(
                AuthLevelResponse("a", 200, "one", headers = mapOf("X" to "1")),
                AuthLevelResponse("b", 403, "two!", headers = mapOf("X" to "2")),
            )
        fun fields(report: JsonObject) =
            report
                .getValue("differences")
                .jsonArray
                .flatMap { pair ->
                    pair.jsonObject.getValue("differences").jsonArray.map {
                        it.jsonObject.getValue("field").jsonPrimitive.content
                    }
                }
                .toSet()

        assertEquals(
            setOf("status_code", "body_length", "body_content", "headers"),
            fields(AnalysisBridge.authDiffReport(levels, emptyList())),
        )
        assertEquals(
            setOf("status_code"),
            fields(
                AnalysisBridge.authDiffReport(levels, emptyList(), fields = listOf("status_code")),
            ),
        )
    }

    @Test
    fun `one answering level cannot be compared and the report says so`() {
        val report =
            AnalysisBridge.authDiffReport(
                listOf(level("admin", 200, "x")),
                listOf("Level 'none' failed: boom"),
            )
        assertTrue(findings(report, "id").isEmpty())
        assertTrue(
            strings(report, "notes").any { it.contains("Fewer than two levels") },
            report.toString(),
        )
        assertEquals(listOf("Level 'none' failed: boom"), strings(report, "errors"))
    }

    // kotlin.test.assertFalse is imported transitively; local shim for clarity.
    private fun assertFalse(condition: Boolean, message: String? = null) =
        kotlin.test.assertFalse(condition, message)
}
