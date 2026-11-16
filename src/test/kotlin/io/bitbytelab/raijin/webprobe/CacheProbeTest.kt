package io.bitbytelab.raijin.webprobe

import io.bitbytelab.raijin.core.ProbeResult
import io.bitbytelab.raijin.recon.ProbeRequest
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The cache probe against an in-memory cache in front of an in-memory origin. */
class CacheProbeTest {

    private val base = ProbeRequest("GET", "/home", listOf("Host" to "t.example", "User-Agent" to "ua"))
    private val filler = "<p>welcome to the shop</p>".repeat(20)

    /**
     * A cache: stores what [stores] allows under [keyOf], says MISS when it stores and HIT when
     * it serves, and passes everything else through untouched.
     */
    private class FakeCache(
        private val origin: (ProbeRequest) -> ProbeResult,
        private val keyOf: (ProbeRequest) -> String = { it.target },
        private val stores: (ProbeRequest, ProbeResult) -> Boolean = { _, response -> response.status == 200 },
    ) {
        val log = ArrayList<Pair<ProbeRequest, Boolean>>()
        private val store = HashMap<String, ProbeResult>()

        fun send(request: ProbeRequest, anonymous: Boolean): ProbeResult {
            log.add(request to anonymous)
            val key = keyOf(request)
            store[key]?.let { return it.copy(headers = it.headers + ("x-cache" to "HIT")) }
            val response = origin(request)
            if (!stores(request, response)) return response
            store[key] = response
            return response.copy(headers = response.headers + ("x-cache" to "MISS"))
        }
    }

    private fun probe(
        cache: FakeCache,
        request: ProbeRequest = base,
        identity: List<Pair<String, String>> = emptyList(),
        poisoning: Boolean = true,
        deception: Boolean = true,
        maxRequests: Int = 400,
        extraHeaders: List<String> = emptyList(),
        extraCookies: List<String> = emptyList(),
    ): CacheProbe.Report {
        val config = CacheProbe.Config("t.example", poisoning, deception, maxRequests, extraHeaders, extraCookies, Random(5))
        return CacheProbe(request, identity, config) { sent, anonymous -> cache.send(sent, anonymous) }.run()
    }

    /** What a request carries beyond the plain request: the inputs a poisoning attempt adds. */
    private fun inputsOf(request: ProbeRequest, plain: ProbeRequest = base): List<Pair<String, String>> =
        request.headers.filter { header -> plain.headers.none { it.first.equals(header.first, ignoreCase = true) && it.second == header.second } }

    private fun busterOf(request: ProbeRequest, param: String): String? =
        request.query.orEmpty().split('&').firstOrNull { it.startsWith("$param=") }?.substringAfter('=')

    /** An origin that builds a script URL from X-Forwarded-Host, as frameworks behind a proxy do. */
    private val reflectingOrigin: (ProbeRequest) -> ProbeResult = { request ->
        val host = request.header("X-Forwarded-Host") ?: "t.example"
        ProbeResult(200, "<html><script src=\"//$host/static/app.js\"></script>$filler</html>")
    }

    @Test
    fun `an unkeyed header that ends up in a cached response is a confirmed poisoning`() {
        val cache = FakeCache(reflectingOrigin)
        val report = probe(cache)

        assertNull(report.error)
        assertTrue(report.cached)
        assertEquals(true, report.busterEffective)
        assertEquals(CacheSignals.State.MISS, report.first?.state)
        assertEquals(CacheSignals.State.HIT, report.repeat?.state)

        val finding = report.poisoning.single()
        assertEquals(CacheProbe.HEADER, finding.input.kind)
        assertEquals("X-Forwarded-Host", finding.input.name)
        assertEquals(CacheProbe.CONFIRMED, finding.verdict)
        assertEquals("high", finding.severity)
        assertEquals(listOf("reflected in body"), finding.effects)
        assertTrue(finding.value.endsWith("." + CacheProbe.PROBE_DOMAIN))
        assertTrue(finding.cacheKey.startsWith(report.busterParam + "="))
        assertEquals(CacheProbe.DEFAULT_HEADERS.size + CacheProbe.DEFAULT_COOKIES.size, report.poisoningTested)
        // The target itself is served from the cache: deception has nothing to add.
        assertNotNull(report.deceptionSkipped)
        assertTrue(report.deception.isEmpty())
    }

    @Test
    fun `no poisoning attempt goes out without a cache-buster of its own`() {
        val cache = FakeCache(reflectingOrigin)
        val report = probe(cache)

        val attempts = cache.log.map { it.first }.filter { inputsOf(it).isNotEmpty() }
        assertTrue(attempts.size >= CacheProbe.DEFAULT_HEADERS.size, "only ${attempts.size} attempts were sent")
        val inputsPerBuster = HashMap<String, MutableSet<String>>()
        for (attempt in attempts) {
            val buster = assertNotNull(busterOf(attempt, report.busterParam), "an attempt without a cache-buster: ${attempt.render()}")
            assertTrue(buster.length >= 8, "a cache-buster too short to be unique: $buster")
            inputsPerBuster.getOrPut(buster) { HashSet() }.add(inputsOf(attempt).toString())
        }
        assertTrue(inputsPerBuster.values.all { it.size == 1 }, "two different inputs shared one cache key")
        // No cache-buster of an attempt was used by the requests that look at the cache itself.
        val detection = cache.log.map { it.first }.takeWhile { inputsOf(it).isEmpty() }.mapNotNull { busterOf(it, report.busterParam) }
        assertTrue(detection.none { it in inputsPerBuster })
    }

    @Test
    fun `nothing is sent when the cache does not key on the cache-buster`() {
        // The cache keys on the path alone, so every cache-buster value hits the same entry.
        val cache = FakeCache(reflectingOrigin, keyOf = { it.path })
        val report = probe(cache)

        assertEquals(false, report.busterEffective)
        assertTrue(report.cached)
        assertEquals(0, report.poisoningTested)
        assertTrue(report.poisoning.isEmpty())
        assertTrue("does not key" in report.poisoningSkipped.orEmpty(), report.poisoningSkipped)
        assertTrue(cache.log.none { inputsOf(it.first).isNotEmpty() }, "an input was sent to a cache shared with everyone")
    }

    @Test
    fun `an input that changes the response without a cache in between is reported as unconfirmed`() {
        val cache = FakeCache(reflectingOrigin, stores = { _, _ -> false })
        val report = probe(cache)

        assertFalse(report.cached)
        assertNull(report.busterEffective)
        assertEquals(CacheSignals.State.UNKNOWN, report.first?.state)
        val finding = report.poisoning.single()
        assertEquals("X-Forwarded-Host", finding.input.name)
        assertEquals(CacheProbe.UNCONFIRMED, finding.verdict)
        assertEquals("info", finding.severity)
        // Even so, every attempt carried its own cache-buster.
        assertTrue(cache.log.map { it.first }.filter { inputsOf(it).isNotEmpty() }.all { busterOf(it, report.busterParam) != null })
        assertTrue(report.deception.isEmpty())
    }

    @Test
    fun `an input the cache keys on through Vary is not a poisoning`() {
        val cache = FakeCache(
            origin = { request -> reflectingOrigin(request).copy(headers = mapOf("vary" to "Accept-Encoding, X-Forwarded-Host")) },
            keyOf = { it.target + "|" + (it.header("X-Forwarded-Host") ?: "") },
        )
        val finding = probe(cache, deception = false).poisoning.single()

        assertEquals(CacheProbe.UNCONFIRMED, finding.verdict)
        assertTrue(finding.keyedByVary)
        assertEquals("info", finding.severity)
    }

    @Test
    fun `an error an unkeyed header provokes and the cache keeps is a confirmed poisoning`() {
        val cache = FakeCache(
            origin = { request ->
                if (request.header("X-HTTP-Method-Override") != null) ProbeResult(405, "Method Not Allowed") else ProbeResult(200, "<html>$filler</html>")
            },
            stores = { _, _ -> true },
        )
        val finding = probe(cache, deception = false).poisoning.single()

        assertEquals("X-HTTP-Method-Override", finding.input.name)
        assertEquals(CacheProbe.CONFIRMED, finding.verdict)
        assertEquals(listOf("status 200 -> 405"), finding.effects)
        assertEquals("medium", finding.severity)
    }

    @Test
    fun `a cookie the target hands out is tried as an unkeyed input`() {
        val cache = FakeCache({ request ->
            val frontend = request.header("Cookie")?.substringAfter("fehost=", "")?.substringBefore(';')?.takeIf { it.isNotEmpty() } ?: "prod-cache-01"
            ProbeResult(200, "<html><script>data = {\"host\":\"$frontend\"}</script>$filler</html>", mapOf("set-cookie" to "fehost=prod-cache-01; Path=/"))
        })
        val report = probe(cache, deception = false)

        val finding = report.poisoning.single()
        assertEquals(CacheProbe.COOKIE, finding.input.kind)
        assertEquals("fehost", finding.input.name)
        assertEquals(CacheProbe.CONFIRMED, finding.verdict)
        assertEquals(CacheProbe.DEFAULT_HEADERS.size + CacheProbe.DEFAULT_COOKIES.size + 1, report.poisoningTested)
    }

    @Test
    fun `inputs the caller names are tried first, with their own value`() {
        val cache = FakeCache({ request -> ProbeResult(200, "<html>" + (request.header("X-Debug-Host") ?: "") + filler + "</html>") })
        val report = probe(cache, deception = false, maxRequests = 12, extraHeaders = listOf("X-Debug-Host~%s.%h"))

        // Four requests look at the cache, the next ones go to the caller's input.
        val finding = report.poisoning.single()
        assertEquals("X-Debug-Host", finding.input.name)
        assertTrue(finding.value.endsWith(".t.example"), finding.value)
        assertEquals(CacheProbe.CONFIRMED, finding.verdict)
        assertEquals(CacheProbe.STOP_BUDGET, report.stopped)
        assertEquals(12, report.requests)
    }

    // --- deception --------------------------------------------------------------------------

    /** An account page for whoever the session cookie names, also under /account/anything and /account;anything. */
    private fun accountOrigin(perUser: Boolean): (ProbeRequest) -> ProbeResult = { request ->
        val user = request.header("Cookie")?.substringAfter("session=", "")?.substringBefore(';')?.takeIf { it.isNotEmpty() }
        val isAccount = request.path == "/account" || request.path.startsWith("/account/") || request.path.startsWith("/account;")
        when {
            !isAccount -> ProbeResult(404, "not found")
            !perUser -> ProbeResult(200, "<html><h1>Account</h1>" + "<p>public help text</p>".repeat(20) + "</html>")
            user == null -> ProbeResult(200, "<html>Please log in</html>")
            else -> ProbeResult(200, "<html><h1>Account of $user</h1>" + "<p>card ending 4242</p>".repeat(20) + "</html>")
        }
    }

    /** A cache that stores what looks like a stylesheet or script, whoever asked for it. */
    private fun staticFileCache(origin: (ProbeRequest) -> ProbeResult) =
        FakeCache(origin, stores = { request, response -> response.status == 200 && (request.path.endsWith(".css") || request.path.endsWith(".js")) })

    @Test
    fun `a user's page stored under a static-looking URL and served without a session is a confirmed deception`() {
        val cache = staticFileCache(accountOrigin(perUser = true))
        val report = probe(cache, request = base.copy(target = "/account"), identity = listOf("Cookie" to "session=alice"), poisoning = false)

        assertFalse(report.cached)
        assertEquals(true, report.sessionDependent)
        assertNull(report.deceptionSkipped)
        assertEquals(listOf("path_suffix", "path_suffix", "delimiter_semicolon"), report.deception.map { it.technique })
        assertTrue(report.deception.all { it.verdict == CacheProbe.CONFIRMED && it.severity == "high" && it.state == CacheSignals.State.HIT })
        assertTrue(Regex("/account/[a-z][a-z0-9]{9}\\.css").matches(report.deception[0].target), report.deception[0].target)
        assertTrue(Regex("/account;[a-z][a-z0-9]{9}\\.css").matches(report.deception[2].target), report.deception[2].target)

        // The requests made as a visitor carried no session; the others carried the user's.
        assertTrue(cache.log.filter { it.second }.none { it.first.header("Cookie") != null })
        assertTrue(cache.log.filter { !it.second }.all { it.first.header("Cookie") == "session=alice" })
        assertTrue(cache.log.any { it.second })
    }

    @Test
    fun `without a session to tell apart, a dynamic page that becomes cacheable is reported as likely`() {
        val cache = staticFileCache(accountOrigin(perUser = false))
        val report = probe(cache, request = base.copy(target = "/account"), poisoning = false)

        assertEquals(false, report.sessionDependent)
        assertEquals(listOf("path_suffix", "path_suffix", "delimiter_semicolon"), report.deception.map { it.technique })
        assertTrue(report.deception.all { it.verdict == CacheProbe.LIKELY && it.severity == "low" })
    }

    @Test
    fun `an origin that does not answer the variants with the page yields no deception finding`() {
        val strict: (ProbeRequest) -> ProbeResult = { request ->
            if (request.path == "/account") ProbeResult(200, "<html><h1>Account</h1>$filler</html>") else ProbeResult(404, "not found")
        }
        val report = probe(staticFileCache(strict), request = base.copy(target = "/account"), identity = listOf("Cookie" to "session=alice"), poisoning = false)

        assertTrue(report.deception.isEmpty())
        assertTrue(report.deceptionTested >= 9)
    }

    @Test
    fun `deception variants cover suffixes, delimiters, an appended extension and static directories`() {
        val variants = CacheProbe.variants("/account/", listOf("/assets", "/img"), Random(1))
        val name = "[a-z][a-z0-9]{9}"
        val expected = listOf(
            "path_suffix" to "/account/$name\\.css",
            "path_suffix" to "/account/$name\\.js",
            "delimiter_semicolon" to "/account;$name\\.css",
            "delimiter_encoded_hash" to "/account%23$name\\.css",
            "delimiter_encoded_question" to "/account%3f$name\\.css",
            "delimiter_null_byte" to "/account%00$name\\.css",
            "delimiter_newline" to "/account%0a$name\\.css",
            "delimiter_exclamation" to "/account!$name\\.css",
            "extension_suffix" to "/account\\.css",
            "static_directory_traversal" to "/assets/\\.\\.%2faccount",
            "static_directory_traversal" to "/img/\\.\\.%2faccount",
        )
        assertEquals(expected.map { it.first }, variants.map { it.technique })
        for ((variant, pattern) in variants.zip(expected.map { it.second })) {
            assertTrue(Regex(pattern).matches(variant.path), "${variant.technique}: ${variant.path}")
        }
        // A variant whose path holds no random name needs a cache-buster of its own.
        assertEquals(listOf(true, true, true, true, true, true, true, true, false, false, false), variants.map { it.unique })
        assertEquals(variants.size, variants.map { it.path }.toSet().size)

        // At the site root there is no page name to append to or to reach from a static directory.
        val root = CacheProbe.variants("/", listOf("/assets"), Random(1))
        assertEquals(8, root.size)
        assertTrue(root.all { it.unique && it.path.startsWith("/") })
        assertTrue(Regex("/;$name\\.css").matches(root[2].path), root[2].path)
    }

    @Test
    fun `static directories are read from what the page loads`() {
        val body = """
            <link href="/assets/css/site.css" rel="stylesheet">
            <script src="/assets/js/app.js"></script>
            <img src='/img/logo.png'>
            <a href="/account/settings">settings</a>
        """.trimIndent()
        assertEquals(listOf("/assets", "/img"), CacheProbe.staticDirectories(body))
        assertEquals(listOf("/static", "/assets"), CacheProbe.staticDirectories("<html>no static files</html>"))
    }

    @Test
    fun `inputs come in order and once each`() {
        val inputs = CacheProbe.inputs(
            targetCookies = listOf("fehost", "lang"),
            extraHeaders = listOf("X-Custom", "X-Other~/%s", " ", "x-forwarded-host~%s.${CacheProbe.PROBE_DOMAIN}"),
            extraCookies = listOf("region~eu-%s"),
        )
        assertEquals(CacheProbe.Input(CacheProbe.HEADER, "X-Custom", "%s"), inputs[0])
        assertEquals(CacheProbe.Input(CacheProbe.HEADER, "X-Other", "/%s"), inputs[1])
        assertEquals(CacheProbe.Input(CacheProbe.HEADER, "x-forwarded-host", "%s.${CacheProbe.PROBE_DOMAIN}"), inputs[2])
        assertEquals(CacheProbe.Input(CacheProbe.COOKIE, "region", "eu-%s"), inputs[3])
        // The default X-Forwarded-Host is the caller's third input again: tried once.
        assertEquals(1, inputs.count { it.name.equals("x-forwarded-host", ignoreCase = true) })
        assertEquals(CacheProbe.DEFAULT_HEADERS.size - 1, inputs.count { it.kind == CacheProbe.HEADER } - 3)
        val cookies = inputs.filter { it.kind == CacheProbe.COOKIE }.map { it.name to it.template }
        assertEquals(listOf("region" to "eu-%s", "fehost" to "%s", "lang" to "%s"), cookies.take(3))
        assertEquals(1, cookies.count { it == "lang" to "%s" }, "a cookie the target sets and a default of the same name are one input")
        assertTrue("region" to "%s" in cookies, "the default region cookie differs from the caller's by its value")
    }

    @Test
    fun `a target that never answers is an error`() {
        val config = CacheProbe.Config(host = "t.example", poisoning = true, deception = true, maxRequests = 50, random = Random(5))
        val report = CacheProbe(base, emptyList(), config) { _, _ -> null }.run()
        assertNotNull(report.error)
        assertEquals(1, report.requests)
    }
}
