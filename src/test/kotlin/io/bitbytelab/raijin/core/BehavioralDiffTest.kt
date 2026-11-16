package io.bitbytelab.raijin.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class BehavioralDiffTest {

    @Test
    fun `identical status and body is not changed`() {
        val baseline = ProbeResult(200, "<html>hello world</html>")
        val candidate = ProbeResult(200, "<html>hello world</html>")
        assertFalse(BehavioralDiff.changed(baseline, candidate))
    }

    @Test
    fun `a differing status code is always changed`() {
        val baseline = ProbeResult(404, "not found")
        val candidate = ProbeResult(200, "not found")
        assertTrue(BehavioralDiff.changed(baseline, candidate))
    }

    @Test
    fun `a substantially different body at the same status is changed`() {
        val baseline = ProbeResult(200, "a".repeat(200))
        val candidate = ProbeResult(200, "b".repeat(200))
        assertTrue(BehavioralDiff.changed(baseline, candidate))
    }

    @Test
    fun `minor noise below the similarity threshold is not changed`() {
        val baseline = ProbeResult(200, "the quick brown fox jumps over the lazy dog, request id 1")
        val candidate = ProbeResult(200, "the quick brown fox jumps over the lazy dog, request id 2")
        assertFalse(BehavioralDiff.changed(baseline, candidate))
    }

    @Test
    fun `a byte-length delta beyond the noise threshold is changed even at high similarity`() {
        val baseline = ProbeResult(200, "x".repeat(1000))
        val candidate = ProbeResult(200, "x".repeat(1000) + "y".repeat(50))
        assertTrue(BehavioralDiff.changed(baseline, candidate, noiseThresholdBytes = 10))
    }

    @Test
    fun `TextSimilarity dice returns 0 for single-char non-equal strings and 100 for identical`() {
        assertEquals(0.0, TextSimilarity.dice("a", "b"))
        assertEquals(0.0, TextSimilarity.dice("a", ""))
        assertEquals(100.0, TextSimilarity.dice("a", "a"))
    }

    // --- response headers -------------------------------------------------------------------

    private val page = "<html>" + "same body for everyone ".repeat(20) + "</html>"

    private fun response(vararg headers: Pair<String, String>, status: Int = 200, body: String = page) =
        ProbeResult.of(status, body, headers.toList())

    @Test
    fun `header pairs are stored lower-cased with repeats joined`() {
        val result = ProbeResult.of(200, "", listOf("Set-Cookie" to "a=1", "X-Cache" to "MISS", "set-cookie" to "b=2"))
        assertEquals(mapOf("set-cookie" to "a=1\nb=2", "x-cache" to "MISS"), result.headers)
        assertEquals("MISS", result.header("X-CACHE"))
        assertNull(result.header("location"))
    }

    @Test
    fun `comparing without headers ignores them, as before`() {
        assertFalse(BehavioralDiff.changed(response("Location" to "/a"), response("Location" to "/b")))
    }

    @Test
    fun `a new redirect target or cache answer is a change when headers are compared`() {
        val headers = BehavioralDiff.SIGNAL_HEADERS
        assertTrue(BehavioralDiff.changed(response("Location" to "/home"), response("Location" to "/admin"), headers))
        assertTrue(BehavioralDiff.changed(response(), response("Location" to "/login"), headers))
        assertTrue(BehavioralDiff.changed(response("X-Cache" to "MISS"), response("X-Cache" to "HIT"), headers))
        assertFalse(BehavioralDiff.changed(response("X-Cache" to "MISS", "Date" to "now"), response("X-Cache" to " MISS ", "Date" to "later"), headers))
        assertEquals(listOf("location", "x-cache"), BehavioralDiff.headerDiff(response("Location" to "/a", "X-Cache" to "MISS"), response("Location" to "/b")))
    }

    @Test
    fun `Set-Cookie counts by the cookies set, not by their values`() {
        val headers = listOf("Set-Cookie")
        assertFalse(BehavioralDiff.changed(response("Set-Cookie" to "sid=111; Path=/"), response("Set-Cookie" to "sid=222; Path=/"), headers))
        assertTrue(BehavioralDiff.changed(response("Set-Cookie" to "sid=111"), response("Set-Cookie" to "sid=111", "Set-Cookie" to "admin=1"), headers))
        assertTrue(BehavioralDiff.changed(response(), response("Set-Cookie" to "sid=111"), headers))
    }

    // --- baselines --------------------------------------------------------------------------

    @Test
    fun `a baseline of identical samples accepts the same response and names what differs in another`() {
        val baseline = BehavioralDiff.baseline(listOf(response(), response(), response()))
        assertEquals(200, baseline.status)
        assertEquals(100.0, baseline.similarityFloor)
        assertEquals(0, baseline.lengthTolerance)
        assertEquals(3, baseline.sampleCount)
        assertEquals(BehavioralDiff.SIGNAL_HEADERS, baseline.comparedHeaders)

        assertTrue(BehavioralDiff.diff(baseline, response()).isEmpty())
        assertEquals(listOf("status 200 -> 500"), BehavioralDiff.diff(baseline, response(status = 500)))
        assertEquals(listOf("header location appeared"), BehavioralDiff.diff(baseline, response("Location" to "/login")))
        assertEquals(listOf("header set-cookie appeared"), BehavioralDiff.diff(baseline, response("Set-Cookie" to "admin=1")))
        val longer = "$page<b>debug mode on</b>"
        assertEquals(
            listOf("body length ${longer.length} outside baseline ${page.length}..${page.length}"),
            BehavioralDiff.diff(baseline, response(body = longer)),
        )
        assertEquals(listOf("body differs from every baseline sample"), BehavioralDiff.diff(baseline, response(body = "Z".repeat(page.length))))
    }

    @Test
    fun `what the samples disagree on is not held against a candidate`() {
        val samples = listOf(
            response("Set-Cookie" to "sid=1", "X-Cache" to "MISS", body = page + "token=aaaa1111" + "x".repeat(4)),
            response("Set-Cookie" to "sid=2", "X-Cache" to "HIT", body = page + "token=bbbb2222" + "x".repeat(24)),
            response("Set-Cookie" to "sid=3", "X-Cache" to "MISS", "Location" to "/a", body = page + "token=cccc3333" + "x".repeat(14)),
        )
        val baseline = BehavioralDiff.baseline(samples)
        assertEquals(40, baseline.lengthTolerance)
        assertTrue(baseline.similarityFloor < 100.0)
        // Location comes and goes: not compared. X-Cache changes value: compared by its presence
        // only. Set-Cookie changes value: compared by the cookie names.
        assertEquals(listOf("x-cache", "set-cookie"), baseline.comparedHeaders)

        val alike = response("Set-Cookie" to "sid=9", "X-Cache" to "EXPIRED", "Location" to "/elsewhere", body = page + "token=dddd4444" + "x".repeat(40))
        assertTrue(BehavioralDiff.diff(baseline, alike).isEmpty(), BehavioralDiff.diff(baseline, alike).toString())

        val body = samples[0].body
        assertEquals(
            listOf("header set-cookie changed"),
            BehavioralDiff.diff(baseline, response("X-Cache" to "MISS", "Set-Cookie" to "sid=9", "Set-Cookie" to "role=admin", body = body)),
        )
        assertEquals(listOf("header set-cookie disappeared"), BehavioralDiff.diff(baseline, response("X-Cache" to "MISS", body = body)))
        assertEquals(listOf("header x-cache disappeared"), BehavioralDiff.diff(baseline, response("Set-Cookie" to "sid=9", body = body)))
        assertTrue(BehavioralDiff.diff(baseline, response("X-Cache" to "MISS", "Set-Cookie" to "sid=9", body = page + "x".repeat(200))).single().startsWith("body length"))
    }

    @Test
    fun `samples that disagree on the status leave it out of the comparison`() {
        val baseline = BehavioralDiff.baseline(listOf(response(), response(status = 503, body = "busy")))
        assertNull(baseline.status)
        assertTrue(BehavioralDiff.diff(baseline, response(status = 500, body = "busy")).isEmpty())
    }

    @Test
    fun `a further sample widens the baseline`() {
        val narrow = BehavioralDiff.baseline(listOf(response(), response()))
        val longer = response(body = page + "y".repeat(30))
        assertTrue(BehavioralDiff.diff(narrow, longer).isNotEmpty())

        val widened = narrow.plus(longer)
        assertEquals(3, widened.sampleCount)
        assertEquals(page.length + 30, widened.maxLength)
        assertTrue(BehavioralDiff.diff(widened, longer).isEmpty())
        assertTrue(BehavioralDiff.diff(widened, response(body = page + "y".repeat(60))).isEmpty(), "within twice the spread the samples showed")
        assertEquals(2, narrow.sampleCount, "the baseline it was built from is unchanged")
    }

    @Test
    fun `a candidate is compared with its control within the baseline's noise`() {
        val noisy = BehavioralDiff.baseline(listOf(response(body = page + "x".repeat(5)), response(body = page + "x".repeat(15)), response(body = page)))
        val control = response(body = page + "x".repeat(10))

        assertTrue(BehavioralDiff.diff(noisy, control, response(body = page + "x".repeat(25))).isEmpty())
        assertEquals(listOf("body length ${page.length + 10} -> ${page.length + 80}"), BehavioralDiff.diff(noisy, control, response(body = page + "x".repeat(80))))
        assertEquals(listOf("status 200 -> 302", "header location appeared"), BehavioralDiff.diff(noisy, control, response("Location" to "/login", status = 302, body = control.body)))
        // A known harmless length difference can be allowed for.
        assertTrue(BehavioralDiff.diff(noisy, control, response(body = page + "x".repeat(80)), lengthSlack = 40).isEmpty())

        val exact = BehavioralDiff.baseline(listOf(response(), response()))
        assertEquals(listOf("body length ${page.length} -> ${page.length + 1}"), BehavioralDiff.diff(exact, response(), response(body = "$page!")))
        assertEquals(listOf("body content changed"), BehavioralDiff.diff(exact, response(), response(body = "Q".repeat(page.length))))
    }
}
