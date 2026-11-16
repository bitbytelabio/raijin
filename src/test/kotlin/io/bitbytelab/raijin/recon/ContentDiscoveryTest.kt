package io.bitbytelab.raijin.recon

import io.bitbytelab.raijin.core.ProbeResult
import java.net.URLEncoder
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The discovery engine against in-memory hosts; the hosts decide by path, so runs do not depend on the made-up names. */
class ContentDiscoveryTest {

    private val wordlist = listOf(
        "admin", "login", "api/users", "robots.txt", "backup.zip", "config.php", "index.php", "assets/", ".git/config", ".env",
        "old", "test", "dev", "tmp", "private/a", "private/b", "private/c", "private/d", "private/e", "private/f",
        "health.json", "missing1", "missing2",
    )
    private val targets = wordlist.map { "/$it" }.toSet()

    private val login = "<html><form action=/login>" + "<p>please sign in</p>\n".repeat(20) + "</form></html>"
    private val real = mapOf(
        "/admin" to ProbeResult(403, "Forbidden"),
        "/login" to ProbeResult(200, login),
        "/robots.txt" to ProbeResult(200, "User-agent: *\nDisallow: /admin\n"),
        "/api/users" to ProbeResult(401, "{\"error\":\"unauthorized\"}"),
        "/assets/" to ProbeResult(200, "<html>Index of /assets/\n<a href=app.js>app.js</a>\n</html>"),
        "/.env" to ProbeResult(200, "DB_PASSWORD=hunter2\nSECRET_KEY=abc\n"),
        "/health.json" to ProbeResult(200, "{\"ok\":true}"),
    )
    private val realPaths = listOf("/admin", "/login", "/api/users", "/robots.txt", "/assets/", "/.env", "/health.json")
    private val blockPage = "<html><head><title>Attention Required! | Cloudflare</title></head><body>Sorry, you have been blocked</body></html>"

    private fun notFound(path: String) =
        ProbeResult(404, "<html><h1>Not Found</h1><p>The requested URL $path was not found on this server.</p></html>")

    private fun normal(path: String): ProbeResult = real[path] ?: notFound(path)

    private class Run(val outcome: ContentDiscovery.Outcome, val requested: List<String>, val sleeps: List<Long>) {
        val found: List<String> get() = outcome.found.map { it.path }
    }

    private fun scan(paths: List<String> = wordlist, host: (String) -> ProbeResult?): Run {
        val requested = ArrayList<String>()
        val sleeps = ArrayList<Long>()
        val engine = ContentDiscovery({ path ->
            requested.add(path)
            host(path)
        }, Random(3), { sleeps.add(it) })
        return Run(engine.run(paths), requested, sleeps)
    }

    @Test
    fun `on a host with real 404s the existing paths are found, whatever their status`() {
        val run = scan { normal(it) }

        assertNull(run.outcome.error)
        assertNull(run.outcome.stopped)
        assertEquals(realPaths, run.found)
        assertEquals(23, run.outcome.tested)
        assertEquals(false, run.outcome.wildcard)
        assertEquals(listOf(0, 1, 2, 3, 7, 9, 20), run.outcome.found.map { it.index })
        assertEquals(403, run.outcome.found.first().status)
        assertTrue(run.sleeps.isEmpty())
        // Every candidate was asked for once, after the made-up calibration paths.
        assertEquals(wordlist.map { "/$it" }, run.requested.filter { it in targets })
        assertTrue(run.outcome.calibration.size >= 6 && run.outcome.calibration.none { it.path in targets })
    }

    @Test
    fun `a host that answers 200 to everything and repeats the path yields no finds`() {
        val page = "<p>content</p>\n".repeat(30)
        val hosts: List<(String) -> ProbeResult?> = listOf(
            { path -> ProbeResult(200, "<html><body><h1>Welcome</h1>\n<p>You asked for $path</p>\n$page</body></html>") },
            { _ -> ProbeResult(200, "<html><body>" + "<p>app shell</p>\n".repeat(30) + "</body></html>") },
            { path -> ProbeResult(200, "<html><link rel=canonical href='$path'><body>\n<p>You asked for $path</p>\n$page</body></html>") },
        )
        for ((number, host) in hosts.withIndex()) {
            val run = scan(host = host)
            assertTrue(run.found.isEmpty(), "host $number: ${run.found}")
            assertEquals(true, run.outcome.wildcard)
            assertEquals(23, run.outcome.tested)
            assertNull(run.outcome.stopped)
        }
    }

    @Test
    fun `on a host that answers 200 to everything a different page and a 404 still stand out`() {
        val run = scan { path ->
            when (path) {
                "/robots.txt" -> real.getValue(path)
                "/api/users" -> ProbeResult(404, "{\"error\":\"no such route\"}")
                else -> ProbeResult(200, "<html><body>\n<p>You asked for $path</p>\n" + "<p>content</p>\n".repeat(30) + "</body></html>")
            }
        }
        assertEquals(listOf("/api/users", "/robots.txt"), run.found)
    }

    @Test
    fun `a redirect every unknown path gets is not a find, a redirect elsewhere is`() {
        val run = scan { path ->
            when (path) {
                "/admin" -> ProbeResult(302, "", mapOf("location" to "/admin/dashboard"))
                "/login" -> ProbeResult(200, login)
                else -> ProbeResult(302, "", mapOf("location" to "/login?next=" + URLEncoder.encode(path, Charsets.UTF_8)))
            }
        }
        assertEquals(listOf("/admin", "/login"), run.found)
        assertEquals("/admin/dashboard", run.outcome.found.first().location)
    }

    @Test
    fun `what a handler answers for every path of one shape is learned per shape`() {
        // Every .php and every dotfile is refused, whether it exists or not; /admin is refused because it exists.
        val run = scan { path ->
            val name = path.substringAfterLast('/')
            when {
                path == "/admin" -> ProbeResult(403, "Forbidden")
                name.endsWith(".php") -> ProbeResult(403, "<html>PHP is disabled on this host</html>")
                name.startsWith(".") -> ProbeResult(403, "Forbidden")
                else -> notFound(path)
            }
        }
        assertEquals(listOf("/admin"), run.found)
    }

    @Test
    fun `a rate limit that passes is waited out and the scan completes`() {
        var count = 0
        val run = scan { path ->
            count++
            if (count % 4 == 0) ProbeResult(429, "slow down", mapOf("retry-after" to "1")) else normal(path)
        }

        assertNull(run.outcome.stopped)
        assertEquals(realPaths, run.found)
        assertEquals(23, run.outcome.tested)
        assertTrue(run.outcome.throttled > 0)
        assertEquals(1000L, run.sleeps.first(), "the Retry-After of the first 429")
        assertTrue(run.sleeps.size > run.outcome.throttled, "no pause between requests after being rate limited")
    }

    @Test
    fun `a rate limit that persists stops the scan where it was`() {
        var asked = 0
        val run = scan { path ->
            if (path in targets) asked++
            if (asked > 6) ProbeResult(429, "slow down") else normal(path)
        }

        assertEquals(ContentDiscovery.STOP_RATE_LIMITED, run.outcome.stopped)
        assertEquals(6, run.outcome.tested)
        assertEquals(listOf("/admin", "/login", "/api/users", "/robots.txt"), run.found)
        // Back off longer each time, and keep a growing pause before the next try.
        assertEquals(listOf(1000L, 250L, 3000L, 500L, 6000L, 1000L), run.sleeps)
        assertEquals(4, run.outcome.throttled)
    }

    @Test
    fun `paths a WAF refuses are reported as blocked, not as found`() {
        val run = scan { path ->
            if (path in setOf("/.git/config", "/.env", "/backup.zip")) ProbeResult(403, blockPage) else normal(path)
        }

        assertNull(run.outcome.stopped)
        assertEquals(realPaths - "/.env", run.found)
        assertEquals(listOf("/backup.zip", "/.git/config", "/.env"), run.outcome.blocked)
        assertEquals("cloudflare", run.outcome.blockedBy)
    }

    @Test
    fun `a WAF that starts answering for everything stops the scan`() {
        var asked = 0
        val run = scan { path ->
            if (path in targets) asked++
            if (asked > 6) ProbeResult(403, blockPage) else normal(path)
        }

        assertEquals(ContentDiscovery.STOP_BLOCKED, run.outcome.stopped)
        assertEquals("cloudflare", run.outcome.blockedBy)
        assertEquals(listOf("/admin", "/login", "/api/users", "/robots.txt"), run.found)
        assertEquals(5, run.outcome.blocked.size)
        assertEquals(6, run.outcome.tested, "the scan is to continue from the first path the block answered for")
        assertEquals(listOf(5000L), run.sleeps)
    }

    @Test
    fun `a refusal without a WAF signature that starts mid-scan is recognised by a made-up path`() {
        var asked = 0
        val run = scan { path ->
            if (path in targets) asked++
            if (asked > 6) ProbeResult(403, "Forbidden") else normal(path)
        }

        assertEquals(ContentDiscovery.STOP_BLOCKED, run.outcome.stopped)
        // The five refusals seen before the check are withdrawn; what was found before stays.
        assertEquals(listOf("/admin", "/login", "/api/users", "/robots.txt"), run.found)
        assertEquals(5, run.outcome.droppedAsCatchAll)
        assertEquals(6, run.outcome.tested, "the scan is to continue from the first refused path")
        assertEquals(listOf(5000L), run.sleeps)
    }

    @Test
    fun `a refusal that passes is waited out and the refused paths are asked for again`() {
        var asked = 0
        var refused = 0
        val run = scan { path ->
            if (path in targets) asked++
            if (asked > 6 && refused < 6) {
                refused++
                ProbeResult(403, "Forbidden")
            } else {
                normal(path)
            }
        }

        assertNull(run.outcome.stopped)
        assertEquals(realPaths, run.found)
        assertEquals(23, run.outcome.tested)
        assertEquals(listOf(5000L), run.sleeps)
        assertEquals(2, run.requested.count { it == "/index.php" }, "the first refused path was not asked for again")
    }

    @Test
    fun `a directory that answers alike for anything under it is learned and its paths withdrawn`() {
        val run = scan { path -> if (path.startsWith("/private/")) ProbeResult(403, "Forbidden") else normal(path) }

        assertNull(run.outcome.stopped)
        assertEquals(realPaths, run.found)
        assertEquals(listOf("/private/"), run.outcome.catchAllDirectories)
        assertEquals(5, run.outcome.droppedAsCatchAll)
    }

    @Test
    fun `a target that never answers is an error`() {
        val run = scan { null }
        assertNotNull(run.outcome.error)
        assertTrue(run.found.isEmpty())
    }

    @Test
    fun `block pages for every made-up path mean nothing can be told apart`() {
        val run = scan { ProbeResult(403, blockPage) }
        assertEquals(ContentDiscovery.STOP_BLOCKED, run.outcome.stopped)
        assertEquals(0, run.outcome.tested)
        assertTrue(run.found.isEmpty())
        assertTrue(run.requested.none { it in targets }, "candidates were sent although every calibration request was blocked")
    }
}
