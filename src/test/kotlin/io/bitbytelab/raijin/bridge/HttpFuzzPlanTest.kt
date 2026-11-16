package io.bitbytelab.raijin.bridge

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertNull
import kotlin.test.assertNotNull

class HttpFuzzPlanTest {

    // --- FUZZ keyword mode ---

    @Test
    fun `fuzz keyword replaces every occurrence with each payload`() {
        val res = HttpFuzzPlan.plan("GET /a?x=FUZZ HTTP/1.1", null, listOf("1", "2"), null)
        val ok = res as HttpFuzzPlan.Result.Ok
        assertEquals("fuzz_keyword", ok.mode)
        assertEquals(2, ok.requests.size)
        assertEquals("GET /a?x=1 HTTP/1.1", ok.requests[0].request)
        assertEquals("GET /a?x=2 HTTP/1.1", ok.requests[1].request)
    }

    // --- Custom multi-character marker (the no-op bug) ---

    @Test
    fun `custom multi-char marker is detected and substituted`() {
        // Bug: old first-char-only heuristic (count { it == marker[0] }) failed for "MARK".
        val base = "GET /a?id=MARKseedMARK HTTP/1.1"
        val res = HttpFuzzPlan.plan(base, null, listOf("p1", "p2"), "MARK")
        val ok = res as HttpFuzzPlan.Result.Ok
        assertEquals("marker_pairs", ok.mode)
        assertEquals(2, ok.requests.size)
        // The entire MARK...MARK span (including markers) is replaced by the payload.
        assertEquals("GET /a?id=p1 HTTP/1.1", ok.requests[0].request)
        assertEquals("GET /a?id=p2 HTTP/1.1", ok.requests[1].request)
    }

    @Test
    fun `bracket style custom marker pairs are found by whole-marker count`() {
        // "[[" would satisfy the old count-of-'[' heuristic accidentally; ensure whole-marker
        // detection still handles it and produces exactly one injection point.
        val base = "GET /?q=[[x[[ HTTP/1.1"
        val res = HttpFuzzPlan.plan(base, null, listOf("Z"), "[[")
        val ok = res as HttpFuzzPlan.Result.Ok
        assertEquals("marker_pairs", ok.mode)
        assertEquals(1, ok.requests.size)
        assertEquals("GET /?q=Z HTTP/1.1", ok.requests[0].request)
    }

    @Test
    fun `default marker still works when no custom marker supplied`() {
        val base = "GET /?q=§v§ HTTP/1.1" // §v§
        val res = HttpFuzzPlan.plan(base, null, listOf("Z"), null)
        val ok = res as HttpFuzzPlan.Result.Ok
        assertEquals("marker_pairs", ok.mode)
        assertEquals("GET /?q=Z HTTP/1.1", ok.requests[0].request)
    }

    @Test
    fun `blank marker string falls back to default marker`() {
        // An empty marker must not be used verbatim (it would "occur" everywhere).
        val base = "GET /?q=§v§ HTTP/1.1"
        val res = HttpFuzzPlan.plan(base, null, listOf("Z"), "")
        val ok = res as HttpFuzzPlan.Result.Ok
        assertEquals("marker_pairs", ok.mode)
    }

    // --- Astral / multi-byte payloads preserved at String level ---

    @Test
    fun `astral char payload survives substitution unchanged`() {
        val emoji = "💥" // U+1F4A5 (surrogate pair)
        val res = HttpFuzzPlan.plan("GET /?q=FUZZ HTTP/1.1", null, listOf(emoji), null)
        val ok = res as HttpFuzzPlan.Result.Ok
        assertTrue(ok.requests[0].request.contains(emoji))
        assertEquals("GET /?q=$emoji HTTP/1.1", ok.requests[0].request)
    }

    // --- Legacy offset positions + validation ---

    @Test
    fun `valid offset positions substitute payload in range`() {
        val base = "GET /?id=000 HTTP/1.1"
        // Replace the "000" at indices [9, 12)
        val res = HttpFuzzPlan.plan(base, listOf(9 to 12), listOf("X"), null)
        val ok = res as HttpFuzzPlan.Result.Ok
        assertEquals("offset", ok.mode)
        assertEquals("GET /?id=X HTTP/1.1", ok.requests[0].request)
    }

    @Test
    fun `reversed offset pair is rejected with actionable error`() {
        val base = "GET /?id=000 HTTP/1.1"
        val res = HttpFuzzPlan.plan(base, listOf(12 to 9), listOf("X"), null)
        val err = res as HttpFuzzPlan.Result.Error
        assertTrue(err.message.contains("start"))
        assertTrue(err.message.contains("<="))
    }

    @Test
    fun `out of bounds offset pair is rejected`() {
        val base = "short"
        val res = HttpFuzzPlan.plan(base, listOf(0 to 999), listOf("X"), null)
        val err = res as HttpFuzzPlan.Result.Error
        assertTrue(err.message.contains("out of bounds"))
    }

    @Test
    fun `negative offset pair is rejected`() {
        val res = HttpFuzzPlan.plan("hello", listOf(-1 to 2), listOf("X"), null)
        val err = res as HttpFuzzPlan.Result.Error
        assertTrue(err.message.contains("non-negative"))
    }

    @Test
    fun `no injection points yields an error`() {
        val res = HttpFuzzPlan.plan("GET /plain HTTP/1.1", null, listOf("X"), null)
        val err = res as HttpFuzzPlan.Result.Error
        assertTrue(err.message.contains("No injection points"))
    }

    // --- helper unit checks ---

    @Test
    fun `countOccurrences counts non-overlapping whole marker`() {
        assertEquals(2, HttpFuzzPlan.countOccurrences("MARKaMARKb", "MARK"))
        assertEquals(0, HttpFuzzPlan.countOccurrences("abc", ""))
        assertEquals(1, HttpFuzzPlan.countOccurrences("aaa", "aa")) // non-overlapping
    }

    @Test
    fun `validatePositions returns null when all pairs valid`() {
        assertNull(HttpFuzzPlan.validatePositions(listOf(0 to 1, 2 to 5), 10))
    }

    @Test
    fun `validatePositions flags the first bad pair`() {
        val msg = HttpFuzzPlan.validatePositions(listOf(0 to 1, 5 to 3), 10)
        assertNotNull(msg)
        assertTrue(msg.contains("positions[1]"))
    }

    @Test
    fun `sniper marker mode strips inactive markers from other positions`() {
        val base = "GET /?a=§one§&b=§two§ HTTP/1.1"
        val res = HttpFuzzPlan.plan(base, null, listOf("X"), null) as HttpFuzzPlan.Result.Ok
        assertEquals(2, res.requests.size)
        assertEquals("GET /?a=X&b=two HTTP/1.1", res.requests[0].request)
        assertEquals("GET /?a=one&b=X HTTP/1.1", res.requests[1].request)
    }

    @Test
    fun `odd marker count and overlapping offset positions are rejected`() {
        val oddOne = HttpFuzzPlan.plan("GET /?a=§one HTTP/1.1", null, listOf("X"), null)
        assertTrue(oddOne is HttpFuzzPlan.Result.Error)
        assertTrue(oddOne.message.contains("Odd number"), oddOne.message)

        val oddThree = HttpFuzzPlan.plan("GET /?a=§one§&b=§two HTTP/1.1", null, listOf("X"), null)
        assertTrue(oddThree is HttpFuzzPlan.Result.Error)
        assertTrue(oddThree.message.contains("Odd number"), oddThree.message)

        val overlap = HttpFuzzPlan.plan("0123456789", listOf(1 to 5, 3 to 7), listOf("X"), null)
        assertTrue(overlap is HttpFuzzPlan.Result.Error)
        assertTrue(overlap.message.contains("overlaps"), overlap.message)
    }

    @Test
    fun `sniper mode with three marker pairs strips every inactive marker`() {
        val base = "POST /a?x=§1§ HTTP/1.1\r\nX-T: §t§\r\n\r\nb=§2§"
        val ok = HttpFuzzPlan.plan(base, null, listOf("P"), null) as HttpFuzzPlan.Result.Ok
        assertEquals(
            listOf(
                "POST /a?x=P HTTP/1.1\r\nX-T: t\r\n\r\nb=2",
                "POST /a?x=1 HTTP/1.1\r\nX-T: P\r\n\r\nb=2",
                "POST /a?x=1 HTTP/1.1\r\nX-T: t\r\n\r\nb=P",
            ),
            ok.requests.map { it.request }
        )
        assertEquals(listOf(0, 1, 2), ok.requests.map { it.position })
    }

    // --- planRaw: ready-to-send requests ---

    @Test
    fun `planRaw recomputes Content-Length after a payload changes the body length`() {
        val base = "POST /login HTTP/1.1\r\nHost: h\r\nContent-Length: 7\r\n\r\nq=§abc§"
        val ok = HttpFuzzPlan.planRaw(base, null, listOf("much-longer", "é"), null) as HttpFuzzPlan.Result.Ok
        assertEquals("POST /login HTTP/1.1\r\nHost: h\r\nContent-Length: 13\r\n\r\nq=much-longer", ok.requests[0].request)
        // Counted as the UTF-8 bytes fuzz sends: "q=é" is 4 bytes.
        assertTrue(ok.requests[1].request.contains("Content-Length: 4\r\n"), ok.requests[1].request)
    }

    @Test
    fun `planRaw leaves the Content-Length of a CL-TE request alone`() {
        val base = "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nFUZZ\r\n0\r\n\r\n"
        val ok = HttpFuzzPlan.planRaw(base, null, listOf("Z"), null) as HttpFuzzPlan.Result.Ok
        assertEquals(base.replace("FUZZ", "Z"), ok.requests[0].request)
    }

    @Test
    fun `planRaw maps offsets typed against a bare-LF request onto the normalized request`() {
        val raw = "GET /?id=000 HTTP/1.1\nHost: h\n\nbody=XYZ"
        val start = raw.indexOf("XYZ")
        val ok = HttpFuzzPlan.planRaw(raw, listOf(start to start + 3), listOf("P"), null) as HttpFuzzPlan.Result.Ok
        assertEquals("offset", ok.mode)
        assertEquals("GET /?id=000 HTTP/1.1\r\nHost: h\r\n\r\nbody=P", ok.requests[0].request)
    }

    @Test
    fun `planRaw reports a bad offset in the caller's own numbers`() {
        val raw = "GET / HTTP/1.1\nHost: h\n\n"
        val err = HttpFuzzPlan.planRaw(raw, listOf(0 to raw.length + 5), listOf("P"), null) as HttpFuzzPlan.Result.Error
        assertTrue(err.message.contains("end (${raw.length + 5})") && err.message.contains("length (${raw.length})"), err.message)
    }

    @Test
    fun `raceRequests fixes Content-Length per payload or copies the request count times`() {
        val base = "POST /redeem HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\ncode=FUZZ"
        assertEquals(
            listOf(
                "POST /redeem HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\n\r\ncode=A",
                "POST /redeem HTTP/1.1\r\nHost: h\r\nContent-Length: 9\r\n\r\ncode=BBBB",
            ),
            HttpFuzzPlan.raceRequests(base, count = 10, payloads = listOf("A", "BBBB"))
        )
        assertEquals(
            List(3) { "GET / HTTP/1.1\r\nHost: h\r\n\r\n" },
            HttpFuzzPlan.raceRequests("GET / HTTP/1.1\nHost: h\n\n", count = 3, payloads = null)
        )
    }
}
