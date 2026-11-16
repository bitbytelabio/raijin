package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.bridge.SessionMacroTrigger.Verdict
import io.bitbytelab.raijin.state.SessionMacro
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** The pure parts of the login macros: when one triggers, its run state, and the cookies it learns. */
class SessionMacrosTest {

    private val login = buildJsonObject { put("url", "https://target.example/login"); put("method", "POST") }

    private fun macro(
        scope: String = "all",
        scopePattern: String? = null,
        triggerStatus: Set<Int> = setOf(401),
        triggerRegex: String? = null,
        toolFilter: Set<String> = SessionMacro.DEFAULT_TOOL_FILTER,
        requireCredentials: Boolean = true,
        enabled: Boolean = true,
    ) = SessionMacro(
        name = "login", steps = listOf(login), scope = scope, scopePattern = scopePattern,
        triggerStatus = triggerStatus, triggerRegex = triggerRegex, toolFilter = toolFilter,
        requireCredentials = requireCredentials, enabled = enabled,
    )

    private fun exchange(
        status: Int = 401,
        tool: String? = "REPEATER",
        url: String = "https://target.example/api/me",
        internalProbe: Boolean = false,
        macroTraffic: Boolean = false,
        suite: Boolean = false,
        text: String = "HTTP/1.1 $status\r\n\r\n",
        credentials: Boolean = true,
    ) = SessionMacroTrigger.Exchange(
        url = url, toolName = tool, statusCode = status, internalProbe = internalProbe, macroTraffic = macroTraffic,
        suiteInScope = { suite }, responseText = { text }, carriesCredentials = { credentials },
    )

    // --- trigger decision ---

    @Test
    fun `an expired session status from a covered tool with credentials triggers`() {
        assertEquals(Verdict.TRIGGER, SessionMacroTrigger.decide(macro(), false, exchange()))
        assertEquals(Verdict.NOT_EXPIRED, SessionMacroTrigger.decide(macro(), false, exchange(status = 200)))
        assertEquals(Verdict.NOT_EXPIRED, SessionMacroTrigger.decide(macro(), false, exchange(status = 403)))
        assertEquals(Verdict.TRIGGER, SessionMacroTrigger.decide(macro(triggerStatus = setOf(401, 403)), false, exchange(status = 403)))
    }

    @Test
    fun `a regex over status line, headers and body also means expired`() {
        val redirect = "HTTP/1.1 302 Found\r\nLocation: /login?next=%2F\r\n\r\n"
        val byHeader = macro(triggerStatus = emptySet(), triggerRegex = "(?m)^Location: /login")
        assertEquals(Verdict.TRIGGER, SessionMacroTrigger.decide(byHeader, false, exchange(status = 302, text = redirect)))
        assertEquals(Verdict.NOT_EXPIRED, SessionMacroTrigger.decide(byHeader, false, exchange(status = 302, text = "HTTP/1.1 302 Found\r\nLocation: /home\r\n\r\n")))
        val byBody = macro(triggerRegex = "Please log in")
        assertEquals(Verdict.TRIGGER, SessionMacroTrigger.decide(byBody, false, exchange(status = 200, text = "HTTP/1.1 200 OK\r\n\r\n<h1>Please log in</h1>")))
        assertTrue(SessionMacroTrigger.expired(byBody, 401) { error("the status already decides") })
    }

    @Test
    fun `scope all, suite and custom limit what triggers`() {
        assertEquals(Verdict.OUT_OF_SCOPE, SessionMacroTrigger.decide(macro(scope = "suite"), false, exchange(suite = false)))
        assertEquals(Verdict.TRIGGER, SessionMacroTrigger.decide(macro(scope = "suite"), false, exchange(suite = true)))
        val custom = macro(scope = "custom", scopePattern = "^https://target\\.example/api/")
        assertEquals(Verdict.TRIGGER, SessionMacroTrigger.decide(custom, false, exchange()))
        assertEquals(Verdict.OUT_OF_SCOPE, SessionMacroTrigger.decide(custom, false, exchange(url = "https://other.example/api/me")))
    }

    @Test
    fun `the default tool filter covers every tool except the proxy`() {
        assertFalse("PROXY" in SessionMacro.DEFAULT_TOOL_FILTER)
        assertTrue("EXTENSIONS" in SessionMacro.DEFAULT_TOOL_FILTER && "SCANNER" in SessionMacro.DEFAULT_TOOL_FILTER)
        assertEquals(Verdict.TOOL_NOT_COVERED, SessionMacroTrigger.decide(macro(), false, exchange(tool = "PROXY")))
        assertEquals(Verdict.TRIGGER, SessionMacroTrigger.decide(macro(), false, exchange(tool = "EXTENSIONS")))
        assertEquals(Verdict.TOOL_NOT_COVERED, SessionMacroTrigger.decide(macro(), false, exchange(tool = null)))
        val scannerOnly = macro(toolFilter = setOf("SCANNER"))
        assertEquals(Verdict.TOOL_NOT_COVERED, SessionMacroTrigger.decide(scannerOnly, false, exchange(tool = "REPEATER")))
        assertEquals(Verdict.TRIGGER, SessionMacroTrigger.decide(macro(toolFilter = setOf("PROXY")), false, exchange(tool = "PROXY")))
    }

    @Test
    fun `a request without credentials never triggers unless the macro allows it`() {
        assertEquals(Verdict.NO_CREDENTIALS, SessionMacroTrigger.decide(macro(), false, exchange(credentials = false)))
        assertEquals(Verdict.TRIGGER, SessionMacroTrigger.decide(macro(requireCredentials = false), false, exchange(credentials = false)))
    }

    @Test
    fun `internal probes, macro traffic, disabled and suspended macros never trigger`() {
        val open = macro(requireCredentials = false)
        assertEquals(Verdict.INTERNAL_PROBE, SessionMacroTrigger.decide(open, false, exchange(tool = "EXTENSIONS", internalProbe = true)))
        assertEquals(Verdict.MACRO_TRAFFIC, SessionMacroTrigger.decide(open, false, exchange(tool = "EXTENSIONS", macroTraffic = true)))
        assertEquals(Verdict.DISABLED, SessionMacroTrigger.decide(macro(enabled = false), false, exchange()))
        assertEquals(Verdict.SUSPENDED, SessionMacroTrigger.decide(open, true, exchange()))
    }

    @Test
    fun `the expensive checks only run when the decision gets that far`() {
        val e = SessionMacroTrigger.Exchange(
            url = "https://x/", toolName = "PROXY", statusCode = 401,
            suiteInScope = { error("scope asked") }, responseText = { error("text built") }, carriesCredentials = { error("credentials checked") },
        )
        assertEquals(Verdict.TOOL_NOT_COVERED, SessionMacroTrigger.decide(macro(scope = "suite", triggerRegex = "x"), false, e))
    }

    @Test
    fun `the regex text is capped where SafeRegex still matches`() {
        val text = SessionMacroTrigger.boundedText("HTTP/1.1 200 OK\r\n\r\n", "x".repeat(1_000_000))
        assertEquals(io.bitbytelab.raijin.safety.SafeRegex.DEFAULT_MAX_INPUT_LEN, text.length)
        assertTrue(text.startsWith("HTTP/1.1 200 OK"))
    }

    // --- run state ---

    private val second = 1_000_000_000L

    @Test
    fun `one run at a time - a concurrent trigger waits for it`() {
        val state = MacroRunState(minIntervalNanos = 5 * second, maxFailures = 3)
        val run = assertIs<MacroRunState.Ticket.Run>(state.begin(now = 0, sentEpoch = 0))
        val wait = assertIs<MacroRunState.Ticket.Wait>(state.begin(now = 1, sentEpoch = 0))
        assertSame(run.run, wait.run)
        assertIs<MacroRunState.Ticket.Wait>(state.beginManual())
        assertFalse(wait.run.isDone)
        state.finish(run, now = 2, manual = false, success = true, epoch = 1, learned = mapOf("session" to "new"), error = null, triggerUrl = "u")
        assertTrue(wait.run.get())
        assertEquals(mapOf("session" to "new"), state.cookies)
    }

    @Test
    fun `within the minimum interval only a request sent before the last run is retried`() {
        val state = MacroRunState(minIntervalNanos = 5 * second, maxFailures = 3)
        val run = assertIs<MacroRunState.Ticket.Run>(state.begin(now = 0, sentEpoch = 0))
        state.finish(run, now = second, manual = false, success = true, epoch = 1, learned = emptyMap(), error = null, triggerUrl = null)
        assertSame(MacroRunState.Ticket.Retry, state.begin(now = 2 * second, sentEpoch = 0))
        assertSame(MacroRunState.Ticket.Throttled, state.begin(now = 2 * second, sentEpoch = 1))
        assertSame(MacroRunState.Ticket.Throttled, state.begin(now = 2 * second, sentEpoch = null))
        // A stale request is retried even after the interval: the session it lacked exists now.
        assertSame(MacroRunState.Ticket.Retry, state.begin(now = 60 * second, sentEpoch = 0))
        assertIs<MacroRunState.Ticket.Run>(state.begin(now = 6 * second + 1, sentEpoch = 1))
    }

    @Test
    fun `runs that did not help open the circuit breaker and a good manual run closes it`() {
        val state = MacroRunState(minIntervalNanos = 0, maxFailures = 2)
        val first = assertIs<MacroRunState.Ticket.Run>(state.begin(now = 0, sentEpoch = null))
        assertFalse(state.finish(first, now = 1, manual = false, success = false, epoch = 0, learned = emptyMap(), error = "Step 0 failed", triggerUrl = null))
        assertFalse(state.suspended)
        val again = assertIs<MacroRunState.Ticket.Run>(state.begin(now = 2, sentEpoch = null))
        assertFalse(state.finish(again, now = 3, manual = false, success = true, epoch = 1, learned = emptyMap(), error = null, triggerUrl = null))
        // A waiter's retry never judges the run; the owner's retry that still fails does.
        assertFalse(state.retried(helped = false, owner = false, error = "still 401"))
        assertTrue(state.retried(helped = false, owner = true, error = "still 401"))
        assertTrue(state.suspended)
        assertSame(MacroRunState.Ticket.Suspended, state.begin(now = 4, sentEpoch = 0))

        val snapshot = state.snapshot()
        assertTrue(snapshot.getValue("suspended").jsonPrimitive.boolean)
        assertEquals(2, snapshot.getValue("consecutive_failures").jsonPrimitive.int)
        assertEquals("did_not_help", snapshot.getValue("last_result").jsonPrimitive.content)

        val manual = assertIs<MacroRunState.Ticket.Run>(state.beginManual())
        state.finish(manual, now = 5, manual = true, success = true, epoch = 2, learned = emptyMap(), error = null, triggerUrl = null)
        assertFalse(state.suspended)
        assertEquals(0, state.snapshot().getValue("consecutive_failures").jsonPrimitive.int)
    }

    @Test
    fun `a retry that helped resets the failure count and max_failures 0 never suspends`() {
        val state = MacroRunState(minIntervalNanos = 0, maxFailures = 0)
        repeat(5) { i ->
            val run = assertIs<MacroRunState.Ticket.Run>(state.begin(now = i.toLong(), sentEpoch = null))
            state.finish(run, now = i.toLong(), manual = false, success = false, epoch = 0, learned = emptyMap(), error = "x", triggerUrl = null)
        }
        assertFalse(state.suspended)
        val run = assertIs<MacroRunState.Ticket.Run>(state.begin(now = 10, sentEpoch = null))
        state.finish(run, now = 10, manual = false, success = true, epoch = 1, learned = emptyMap(), error = null, triggerUrl = null)
        state.retried(helped = true, owner = true, error = null)
        val snapshot = state.snapshot()
        assertEquals(0, snapshot.getValue("consecutive_failures").jsonPrimitive.int)
        assertEquals("reauthenticated", snapshot.getValue("last_result").jsonPrimitive.content)
        assertEquals(6, snapshot.getValue("automatic_runs").jsonPrimitive.int)
        assertEquals(1, snapshot.getValue("retries_helped").jsonPrimitive.int)
    }

    // --- cookies ---

    @Test
    fun `every Set-Cookie value gives its cookie, a deletion gives null`() {
        val now = Instant.parse("2026-11-17T00:00:00Z")
        assertEquals("session" to "abc", SessionMacroCookies.parseSetCookie("session=abc; Path=/; HttpOnly; Secure", now))
        assertEquals("q" to "\"quoted\"", SessionMacroCookies.parseSetCookie("q=\"quoted\"", now))
        assertEquals("empty" to "", SessionMacroCookies.parseSetCookie("empty=; Path=/", now))
        assertEquals("gone" to null, SessionMacroCookies.parseSetCookie("gone=x; Max-Age=0", now))
        assertEquals("gone" to null, SessionMacroCookies.parseSetCookie("gone=x; Expires=Thu, 01 Jan 1970 00:00:00 GMT", now))
        assertEquals("gone" to null, SessionMacroCookies.parseSetCookie("gone=x; expires=Thu, 01-Jan-1970 00:00:00 GMT", now))
        assertEquals("kept" to "x", SessionMacroCookies.parseSetCookie("kept=x; Expires=Fri, 01 Jan 2100 00:00:00 GMT", now))
        // Max-Age wins over Expires.
        assertEquals("kept" to "x", SessionMacroCookies.parseSetCookie("kept=x; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=60", now))
        assertNull(SessionMacroCookies.parseSetCookie("no-equals-sign", now))
        assertNull(SessionMacroCookies.parseSetCookie("=value", now))
        assertNull(SessionMacroCookies.parseSetCookie("bad name=value", now))
    }

    @Test
    fun `learned cookies only replace same-named cookies the request already sends`() {
        val learned = mapOf("session" to "new", "csrf" to "c2")
        assertEquals(mapOf("session" to "new"), SessionMacroCookies.replacements(mapOf("session" to "old", "theme" to "dark"), learned))
        assertEquals(emptyMap(), SessionMacroCookies.replacements(mapOf("theme" to "dark"), learned))
        assertEquals(emptyMap(), SessionMacroCookies.replacements(mapOf("session" to "new"), learned))
        assertEquals(emptyMap(), SessionMacroCookies.replacements(emptyMap(), learned))
    }

    @Test
    fun `a run's cookies are merged into what earlier runs learned`() {
        val merged = SessionMacroCookies.merge(mapOf("session" to "old", "device" to "d1", "tmp" to "t"), mapOf("session" to "new", "tmp" to null))
        assertEquals(mapOf("session" to "new", "device" to "d1"), merged)
    }

    // --- validation ---

    @Test
    fun `validate rejects a macro that could never work`() {
        assertNull(SessionMacroEngine.validate(macro()))
        fun problem(m: SessionMacro) = assertNotNull(SessionMacroEngine.validate(m), m.toString())
        assertTrue("blank" in problem(macro().copy(name = " ")))
        assertTrue("control characters" in problem(macro().copy(name = "a\r\nX-Injected: 1")))
        assertTrue("at least one step" in problem(macro().copy(steps = emptyList())))
        assertTrue("at most ${SessionMacroEngine.MAX_STEPS}" in problem(macro().copy(steps = List(SessionMacroEngine.MAX_STEPS + 1) { login })))
        assertTrue("steps[0] needs a 'url' or a 'raw_request'" in problem(macro().copy(steps = listOf(buildJsonObject { put("method", "GET") }))))
        val badExtract = JsonObject(login + ("extract" to buildJsonArray { add(buildJsonObject { put("name", "t"); put("pattern", "(") }) }))
        assertTrue(problem(macro().copy(steps = listOf(badExtract))).startsWith("steps[0]: extract[0].pattern"))
        assertTrue("scope_pattern" in problem(macro(scope = "custom")))
        assertTrue("scope_pattern" in problem(macro(scope = "custom", scopePattern = "(")))
        assertTrue("trigger_status or trigger_regex" in problem(macro(triggerStatus = emptySet())))
        assertTrue("trigger_regex" in problem(macro(triggerRegex = "[")))
        assertTrue("unknown tool 'BROWSER'" in problem(macro(toolFilter = setOf("BROWSER"))))
        assertTrue("http_mode" in problem(macro().copy(httpMode = "HTTP_3")))
        assertNull(SessionMacroEngine.validate(macro(triggerStatus = emptySet(), triggerRegex = "login")))
    }
}
