package io.bitbytelab.raijin.recon

import io.bitbytelab.raijin.core.ParamMinerWordlists.Entry
import io.bitbytelab.raijin.core.ProbeResult
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The mining engine against in-memory targets. Each fake server reacts to parameter names only
 * (never to the made-up ones), so a run does not depend on the random names the miner picks.
 */
class ParamMinerTest {

    private val page = "<html><body>" + "lorem ipsum dolor sit amet ".repeat(40) + "</body></html>"

    private fun names(count: Int): List<Entry> = List(count) { Entry("p" + it.toString().padStart(4, '0')) }

    private class Run(val outcome: ParamMiner.Outcome, val requests: List<List<Pair<String, String>>>, val sleeps: List<Long>)

    private fun mine(
        candidates: List<Entry>,
        reflection: Boolean,
        diff: Boolean,
        bucketSize: Int = 64,
        maxRequests: Int = 2000,
        ignoreNameCase: Boolean = false,
        server: (List<Pair<String, String>>) -> ProbeResult?,
    ): Run {
        val requests = ArrayList<List<Pair<String, String>>>()
        val sleeps = ArrayList<Long>()
        val config = ParamMiner.Config(
            host = "t.example",
            reflection = reflection,
            diff = diff,
            bucketSize = bucketSize,
            maxRequests = maxRequests,
            ignoreNameCase = ignoreNameCase,
            random = Random(7),
            sleep = { sleeps.add(it) },
        )
        val outcome = ParamMiner(candidates, config) { params ->
            requests.add(params)
            server(params)
        }.run()
        return Run(outcome, requests, sleeps)
    }

    private fun List<Pair<String, String>>.value(name: String): String? = firstOrNull { it.first == name }?.second

    // 6000 names at 64 per request.
    private val buckets = 94

    // Requests before the first bucket: one without names, two with one made-up name, three baseline samples.
    private val setup = 6

    // log2(64): the depth of the search inside one bucket.
    private val depth = 6

    @Test
    fun `one reflected parameter among 6000 names costs about one request per bucket`() {
        val run = mine(names(6000), reflection = true, diff = false) { params ->
            ProbeResult(200, page + "<input name=\"q\" value=\"" + (params.value("p4321") ?: "") + "\">")
        }

        assertNull(run.outcome.error)
        assertNull(run.outcome.stopped)
        assertEquals(listOf("p4321"), run.outcome.hits.map { it.candidate.name })
        assertEquals(listOf("body"), run.outcome.hits.single().reflectedIn)
        assertEquals(6000, run.outcome.tested)
        assertEquals(64, run.outcome.bucketSize)
        assertTrue(run.requests.size <= buckets + setup + 2 * depth, "took ${run.requests.size} requests")
        assertTrue(run.requests.all { it.size <= 64 }, "a request carried more names than the bucket size")
    }

    @Test
    fun `a parameter that changes the status without being echoed is found by a search inside its bucket`() {
        val run = mine(names(6000), reflection = false, diff = true) { params ->
            if (params.value("p1234") != null) ProbeResult(500, "error") else ProbeResult(200, page)
        }

        assertNull(run.outcome.stopped)
        val hit = run.outcome.hits.single()
        assertEquals("p1234", hit.candidate.name)
        assertTrue(hit.reflectedIn.isEmpty())
        assertTrue(hit.diff.any { it.startsWith("status 200 -> 500") }, hit.diff.toString())
        // One request per bucket, plus a number of requests logarithmic in the bucket size for the one that stood out.
        assertTrue(run.requests.size <= buckets + setup + 4 * depth + 8, "took ${run.requests.size} requests")
    }

    @Test
    fun `a parameter that only changes a response header is a behavior change`() {
        val run = mine(names(300), reflection = false, diff = true) { params ->
            val cookies = "sid=" + params.hashCode() + (if (params.value("p0150") != null) "\nadmin=1" else "")
            ProbeResult(200, page, mapOf("set-cookie" to cookies))
        }

        val hit = run.outcome.hits.single()
        assertEquals("p0150", hit.candidate.name)
        assertEquals(listOf("header set-cookie changed"), hit.diff)
    }

    @Test
    fun `an endpoint that varies on its own but ignores every parameter yields no hit`() {
        // A token that changes with every request and a body length that moves around.
        val filler = listOf(0, 40, 20, 10, 30, 5, 35)
        var count = 0
        val run = mine(names(6000), reflection = true, diff = true) {
            count++
            val token = ((count * 2654435761L) % 4294967296L).toString(16).padStart(8, '0')
            ProbeResult(200, page + "<input name=csrf value=$token>" + "x".repeat(filler[count % 7]))
        }

        assertNull(run.outcome.error)
        assertNull(run.outcome.stopped)
        assertTrue(run.outcome.hits.isEmpty(), run.outcome.hits.toString())
        assertTrue(run.outcome.responseChanging.isEmpty())
        assertEquals(6000, run.outcome.tested)
        assertTrue(run.requests.size <= 2 * buckets + setup, "took ${run.requests.size} requests")
    }

    @Test
    fun `a banner that comes and goes is not a parameter's doing`() {
        var count = 0
        val run = mine(names(6000), reflection = true, diff = true) {
            count++
            val banner = if (count % 5 == 0) "<div class=banner>special offer today only</div>" else ""
            ProbeResult(200, "$page$banner<!-- request $count -->")
        }

        assertTrue(run.outcome.hits.isEmpty(), run.outcome.hits.toString())
        assertEquals(6000, run.outcome.tested)
    }

    @Test
    fun `sporadic errors and a cookie set every other time yield no hit`() {
        var count = 0
        val run = mine(names(1500), reflection = true, diff = true) {
            count++
            when {
                count % 17 == 0 -> ProbeResult(503, "busy")
                count % 2 == 1 -> ProbeResult(200, page, mapOf("set-cookie" to "sid=$count"))
                else -> ProbeResult(200, page)
            }
        }

        assertNull(run.outcome.stopped)
        assertTrue(run.outcome.hits.isEmpty(), run.outcome.hits.toString())
        assertEquals(1500, run.outcome.tested)
    }

    @Test
    fun `a page that echoes the whole query string credits only the parameter echoed beyond that`() {
        val candidates = listOf(Entry("q")) + names(1499)
        val server: (List<Pair<String, String>>) -> ProbeResult? = { params ->
            val query = params.joinToString("&") { "${it.first}=${it.second}" }
            ProbeResult(200, "$page<link rel=canonical href='/x?$query'><a href='/x?$query&page=2'>next</a><input name=q value='${params.value("q") ?: ""}'>")
        }

        for (diff in listOf(false, true)) {
            val run = mine(candidates, reflection = true, diff = diff, server = server)
            assertEquals(listOf("q"), run.outcome.hits.map { it.candidate.name }, "diff=$diff")
            assertEquals(listOf("body"), run.outcome.hits.single().reflectedIn)
            assertTrue(run.outcome.hits.single().diff.isEmpty(), "an echo alone is not a behavior change")
            assertTrue(run.outcome.echoesValues)
            assertTrue(run.outcome.echoesPairs)
            // The echoed query string is recognised as such: no bucket is taken apart for it.
            assertTrue(run.requests.size <= 24 + setup + 2, "took ${run.requests.size} requests")
        }
    }

    @Test
    fun `a parameter that breaks the page does not hide the echo of another one in its bucket`() {
        val candidates = names(200).toMutableList()
        candidates[10] = Entry("id")
        candidates[20] = Entry("q")
        val server: (List<Pair<String, String>>) -> ProbeResult? = { params ->
            if (params.value("id") != null) ProbeResult(500, "invalid id")
            else ProbeResult(200, page.replace("<body>", "<body><h1>" + (params.value("q") ?: "") + "</h1>"))
        }

        val echoes = mine(candidates, reflection = true, diff = false, server = server)
        assertEquals(listOf("q"), echoes.outcome.hits.map { it.candidate.name })
        assertEquals(listOf("id"), echoes.outcome.responseChanging.map { it.name })

        val both = mine(candidates, reflection = true, diff = true, server = server)
        assertEquals(listOf("id", "q"), both.outcome.hits.map { it.candidate.name })
        assertTrue(both.outcome.hits[0].diff.isNotEmpty() && both.outcome.hits[0].reflectedIn.isEmpty())
        assertTrue(both.outcome.hits[1].reflectedIn.isNotEmpty() && both.outcome.hits[1].diff.isEmpty())
        assertTrue(both.outcome.responseChanging.isEmpty())
    }

    @Test
    fun `the bucket shrinks until the target stops rejecting the request for its size`() {
        val run = mine(names(300), reflection = true, diff = true) { params ->
            if (params.size > 20) ProbeResult(414, "URI too long") else ProbeResult(200, page + (params.value("p0077") ?: ""))
        }

        assertEquals(16, run.outcome.bucketSize)
        assertEquals(listOf("p0077"), run.outcome.hits.map { it.candidate.name })
        assertEquals(300, run.outcome.tested)
    }

    @Test
    fun `a target that rejects unknown names is mined one name per request`() {
        val candidates = names(40).toMutableList()
        candidates[17] = Entry("limit")
        val run = mine(candidates, reflection = true, diff = true) { params ->
            if (params.any { it.first != "limit" }) ProbeResult(400, "{\"error\":\"unknown field\"}") else ProbeResult(200, "{\"items\":[]}")
        }

        assertTrue(run.outcome.rejectsUnknownNames)
        assertEquals(1, run.outcome.bucketSize)
        assertEquals(listOf("limit"), run.outcome.hits.map { it.candidate.name })
        assertTrue(run.outcome.hits.single().diff.any { it.startsWith("status 400 -> 200") })
        assertTrue(run.requests.all { it.size <= 1 })
    }

    @Test
    fun `value templates are filled with the canary and the target host, and a name listed twice is never sent twice at once`() {
        // "Host" right after "host": the bucket has to close before it rather than carry the header twice.
        val candidates = buildList {
            add(Entry("accept"))
            add(Entry("host", "%h:%s"))
            add(Entry("origin", "https://%s.%h"))
            add(Entry("x-forwarded-host", "%s.%h"))
            add(Entry("x-original-url", "/%s"))
            add(Entry("Host"))
            repeat(60) { add(Entry("h" + it.toString().padStart(3, '0'))) }
        }
        val seen = HashMap<String, String>()
        val run = mine(candidates, reflection = true, diff = true, bucketSize = 20, ignoreNameCase = true) { params ->
            val headers = params.associate { it.first.lowercase() to it.second }
            for (name in listOf("host", "origin", "x-forwarded-host", "x-original-url")) headers[name]?.let { seen.putIfAbsent(name, it) }
            when {
                "x-original-url" in headers -> ProbeResult(404, "not found")
                else -> ProbeResult(200, page + (headers["x-forwarded-host"]?.let { "<script src='//$it/app.js'></script>" } ?: ""))
            }
        }

        val prefix = run.outcome.canaryPrefix
        assertTrue(seen.getValue("host").startsWith("t.example:$prefix"), seen.toString())
        assertTrue(seen.getValue("origin").startsWith("https://$prefix") && seen.getValue("origin").endsWith(".t.example"))
        assertTrue(seen.getValue("x-forwarded-host").startsWith(prefix) && seen.getValue("x-forwarded-host").endsWith(".t.example"))
        assertTrue(seen.getValue("x-original-url").startsWith("/$prefix"))

        assertEquals(listOf("x-forwarded-host", "x-original-url"), run.outcome.hits.map { it.candidate.name })
        assertEquals(listOf("body"), run.outcome.hits[0].reflectedIn)
        assertTrue(run.outcome.hits[1].diff.any { it.startsWith("status 200 -> 404") })
        for (request in run.requests) {
            val lower = request.map { it.first.lowercase() }
            assertEquals(lower.size, lower.toSet().size, "a request carried one header name twice: $lower")
        }
    }

    @Test
    fun `the request budget ends the run and says how far it got`() {
        val run = mine(names(6000), reflection = true, diff = true, maxRequests = 30) { params ->
            ProbeResult(200, page + (params.value("p4321") ?: ""))
        }

        assertEquals(ParamMiner.STOP_BUDGET, run.outcome.stopped)
        assertEquals(30, run.requests.size)
        assertEquals((30 - setup) * 64, run.outcome.tested)
        assertTrue(run.outcome.hits.isEmpty())
    }

    @Test
    fun `a budget too small for the baseline is an error, not an empty result`() {
        val run = mine(names(100), reflection = true, diff = true, maxRequests = 3) { ProbeResult(200, page) }
        val error = run.outcome.error
        assertNotNull(error)
        assertTrue("budget" in error, error)
    }

    @Test
    fun `a rate limit that does not pass stops the run after backing off`() {
        var count = 0
        val run = mine(names(6000), reflection = true, diff = true) {
            count++
            if (count > 12) ProbeResult(429, "slow down", mapOf("retry-after" to "2")) else ProbeResult(200, page)
        }

        assertEquals(ParamMiner.STOP_RATE_LIMITED, run.outcome.stopped)
        assertTrue(run.outcome.hits.isEmpty())
        assertEquals(listOf(2000L), run.sleeps)
        assertTrue(run.outcome.tested < 6000)
        assertTrue(run.requests.size < 30, "kept sending after the rate limit: ${run.requests.size} requests")
    }

    @Test
    fun `a target that never answers is an error`() {
        val run = mine(names(100), reflection = true, diff = true) { null }
        assertNotNull(run.outcome.error)
        assertTrue(run.requests.size <= 3)
    }

    @Test
    fun `an empty candidate list sends nothing`() {
        val run = mine(emptyList(), reflection = true, diff = true) { ProbeResult(200, page) }
        assertNull(run.outcome.error)
        assertTrue(run.requests.isEmpty())
        assertEquals(0, run.outcome.tested)
    }

    // --- canaries ---------------------------------------------------------------------------

    @Test
    fun `every canary is unique and of the same length`() {
        val canaries = Canaries(Random(1))
        val issued = List(2000) { canaries.next() }
        assertEquals(2000, issued.toSet().size)
        assertTrue(issued.all { it.length == Canaries.LENGTH && it.startsWith(canaries.prefix) })
        assertNotEquals(canaries.prefix, Canaries(Random(2)).prefix, "two runs share a prefix")
    }

    @Test
    fun `canaries are counted and stripped whatever case they come back in`() {
        val canaries = Canaries(Random(1))
        val first = canaries.next()
        val second = canaries.next()
        val text = "a=$first b=${first.uppercase()} c=$second end"

        assertEquals(mapOf(first to 2, second to 1), canaries.counts(text))
        assertEquals("a= b= c= end", canaries.strip(text))
        assertEquals("no canary here", canaries.strip("no canary here"))
        assertTrue(canaries.counts("no canary here").isEmpty())
    }

    @Test
    fun `an echoed name=value pair is stripped whole, a name elsewhere is kept`() {
        val canaries = Canaries(Random(1))
        val canary = canaries.next()
        val names = mapOf(canary to "page")

        assertEquals("/x?&y=1", canaries.strip("/x?page=$canary&y=1", names))
        assertEquals("{\"\"}", canaries.strip("{\"page\":\"$canary\"}", names))
        // Too far from its value to be an echo of the pair: a form field of that name stays.
        assertEquals("<input name=page value=''>", canaries.strip("<input name=page value='$canary'>", names))
        assertTrue(canaries.echoesPairs("?page=$canary", names))
        assertFalse(canaries.echoesPairs("<input name=page value='$canary'>", names))
        assertFalse(canaries.echoesPairs("value $canary alone", names))
    }
}
