package io.bitbytelab.raijin.injection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class InjectionOracleTest {

    private fun page(
        body: String,
        status: Int = 200,
        elapsedMs: Long = 100,
        headers: List<Pair<String, String>> = emptyList(),
    ) = Observation(status, headers, body, elapsedMs)

    private val timeout = Observation(status = 0, elapsedMs = 30_000)

    private val mysqlError = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
    private val passwd = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    private val winIni = "; for 16-bit app support\r\n[fonts]\r\n[extensions]\r\n[mci extensions]\r\n[files]\r\n"

    // ---------------------------------------------------------------
    // Signatures
    // ---------------------------------------------------------------

    @Test
    fun `detects SQL error signatures by dbms`() {
        assertEquals("mysql", InjectionOracle.sqlError(mysqlError))
        assertEquals("oracle", InjectionOracle.sqlError("ORA-00933: SQL command not properly ended"))
        assertEquals("postgresql", InjectionOracle.sqlError("PostgreSQL query failed: ERROR: unterminated quoted string"))
        assertEquals("mssql", InjectionOracle.sqlError("Unclosed quotation mark after the character string 'x'."))
        assertEquals("sqlite", InjectionOracle.sqlError("sqlite3.OperationalError: near \"'\": syntax error"))
        assertNull(InjectionOracle.sqlError("a perfectly normal response body"))
    }

    @Test
    fun `an SQL error the baseline already shows is not a hit`() {
        val hit = InjectionOracle.novelSqlError(listOf("a normal page", "a normal page"), "Query failed: $mysqlError")
        assertEquals("mysql", hit?.kind)
        assertTrue("SQL syntax" in hit!!.excerpt, hit.excerpt)
        assertNull(InjectionOracle.novelSqlError(listOf("a normal page", mysqlError), mysqlError))
    }

    @Test
    fun `NoSQL errors are recognised and a JSON parse error is not one`() {
        assertEquals("mongodb", InjectionOracle.nosqlErrorMatch("MongoServerError: unknown operator: \$foo")?.kind)
        assertEquals("script-error", InjectionOracle.nosqlErrorMatch("SyntaxError: unterminated string literal")?.kind)
        assertNull(InjectionOracle.nosqlErrorMatch("SyntaxError: Unexpected token ' in JSON at position 9"))
        assertNull(InjectionOracle.nosqlErrorMatch("No users found"))

        val error = "MongoServerError: \$where got a bad expression"
        assertEquals("mongodb", InjectionOracle.novelNosqlError(listOf("No users found"), error)?.kind)
        assertNull(InjectionOracle.novelNosqlError(listOf(error), error))
    }

    @Test
    fun `fileMarker detects etc-passwd and win-ini`() {
        assertEquals("unix-passwd", InjectionOracle.fileMarker(passwd))
        assertEquals("windows-ini", InjectionOracle.fileMarker("; for 16-bit app support\r\n[fonts]\r\n[extensions]"))
        assertNull(InjectionOracle.fileMarker("hello world, nothing to see"))
    }

    @Test
    fun `one win-ini section name alone is ordinary page text`() {
        assertNull(InjectionOracle.fileMarker("<p>Pick one of the [fonts] below</p>"))
        assertNull(InjectionOracle.fileMarker("<p>Supported [extensions]: png, jpg</p>"))
    }

    @Test
    fun `file markers already in the baseline are not a hit`() {
        val docs = "<p>To change this, edit the [fonts] and [extensions] sections of win.ini</p>"
        assertNull(InjectionOracle.novelFileMarker(listOf(docs, docs), docs + winIni))
        assertEquals("windows-ini", InjectionOracle.novelFileMarker(listOf("a normal page"), winIni)?.kind)

        assertNull(InjectionOracle.novelFileMarker(listOf(passwd), passwd))
        assertEquals("unix-passwd", InjectionOracle.novelFileMarker(listOf("a normal page"), passwd)?.kind)
        // A different marker family than the one the baseline has is still new.
        assertEquals("unix-passwd", InjectionOracle.novelFileMarker(listOf(docs), passwd)?.kind)
    }

    @Test
    fun `command output is the id format and must be new`() {
        val output = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
        assertEquals("id-output", InjectionOracle.novelCommandOutput(listOf("ping ok"), "ping ok\n$output")?.kind)
        assertNull(InjectionOracle.novelCommandOutput(listOf("man page: $output"), "man page: $output"))
        assertNull(InjectionOracle.commandOutput("you sent: 1;id"))
    }

    @Test
    fun `internal content needs several metadata keys, a banner or a file, and must be new`() {
        val metadata = "ami-id\nami-launch-index\nhostname\ninstance-id\ninstance-type\nlocal-ipv4\n"
        assertEquals("cloud-metadata", InjectionOracle.novelInternalContent(listOf("fetch failed"), metadata)?.kind)
        assertEquals("ssh-banner", InjectionOracle.novelInternalContent(listOf("fetch failed"), "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")?.kind)
        assertEquals("unix-passwd", InjectionOracle.novelInternalContent(listOf("fetch failed"), passwd)?.kind)
        assertNull(InjectionOracle.internalContent("Your instance-id is shown in the console"))
        assertNull(InjectionOracle.novelInternalContent(listOf(metadata), metadata))
    }

    // ---------------------------------------------------------------
    // Computed values
    // ---------------------------------------------------------------

    @Test
    fun `evaluatedTo detects template math evaluation`() {
        assertTrue(InjectionOracle.evaluatedTo("the answer is 1787569 today", "1787569"))
        assertFalse(InjectionOracle.evaluatedTo("the answer is {{1337*1337}} today", "1787569"))
        assertFalse(InjectionOracle.evaluatedTo("order 917875690 shipped", "1787569"), "digits of a longer number")
    }

    @Test
    fun `a computed value the baseline already contains is not a hit`() {
        assertTrue(InjectionOracle.novelEvaluation(listOf("Hello"), "Hello 1787569", "1787569"))
        assertFalse(InjectionOracle.novelEvaluation(listOf("Stock: 1787569 units"), "Stock: 1787569 units", "1787569"))
        assertTrue(InjectionOracle.novelText(listOf("Invalid product"), "Invalid product: abczabc", "abczabc"))
        assertFalse(InjectionOracle.novelText(listOf("abczabc"), "abczabc", "abczabc"))
        assertFalse(InjectionOracle.novelText(listOf("Invalid product"), "Invalid product: &a;z&a;", "abczabc"))
    }

    // ---------------------------------------------------------------
    // Response time
    // ---------------------------------------------------------------

    @Test
    fun `timeDelayed flags a clear delay and ignores a fast response`() {
        assertTrue(InjectionOracle.timeDelayed(baselineMs = 120, probeMs = 5300, expectedDelaySec = 5))
        assertFalse(InjectionOracle.timeDelayed(baselineMs = 120, probeMs = 350, expectedDelaySec = 5))
        assertFalse(InjectionOracle.timeDelayed(baselineMs = 120, probeMs = 4000, expectedDelaySec = 5), "a 5s sleep cannot finish in 4s")
        assertFalse(InjectionOracle.timeDelayed(baselineMs = 3000, probeMs = 5200, expectedDelaySec = 5), "a slow baseline explains it")
    }

    @Test
    fun `a request that got no response is never a delay`() {
        assertFalse(InjectionOracle.delayed(100, timeout, 5))
        assertTrue(InjectionOracle.delayed(100, page("ok", elapsedMs = 5200), 5))
        assertFalse(InjectionOracle.fastControl(100, timeout, 5))
    }

    @Test
    fun `a delay is confirmed only when it repeats and the zero-delay control stays fast`() {
        val slow = page("ok", elapsedMs = 5200)
        val fast = page("ok", elapsedMs = 110)
        assertTrue(InjectionOracle.timingVerdict(100, slow, fast, page("ok", elapsedMs = 5150), 5).confirmed)

        val lag = InjectionOracle.timingVerdict(100, slow, page("ok", elapsedMs = 5100), slow, 5)
        assertFalse(lag.confirmed)
        assertTrue("control" in lag.reason, lag.reason)

        val once = InjectionOracle.timingVerdict(100, slow, fast, fast, 5)
        assertFalse(once.confirmed)
        assertTrue("did not repeat" in once.reason, once.reason)

        assertFalse(InjectionOracle.timingVerdict(100, timeout, fast, slow, 5).confirmed)
        assertFalse(InjectionOracle.timingVerdict(100, slow, timeout, slow, 5).confirmed)
        assertFalse(InjectionOracle.timingVerdict(100, slow, fast, timeout, 5).confirmed)
    }

    // ---------------------------------------------------------------
    // Boolean differential
    // ---------------------------------------------------------------

    private val welcome = "<html><body><h1>Shop</h1><p>Welcome back!</p><p>Item 1</p></body></html>"
    private val anonymous = "<html><body><h1>Shop</h1><p>Item 1</p></body></html>"

    @Test
    fun `a difference that follows the condition over every round is a verdict`() {
        val verdict = InjectionOracle.booleanDifferential(
            baselines = listOf(page(welcome), page(welcome)),
            trues = List(3) { page(welcome) },
            falses = List(3) { page(anonymous) },
        )
        assertNotNull(verdict)
        assertEquals("false_diverges", verdict.polarity)
        assertTrue("-Welcome" in verdict.tokens, verdict.tokens.toString())

        val reversed = InjectionOracle.booleanDifferential(
            baselines = listOf(page(anonymous), page(anonymous)),
            trues = List(3) { page(welcome) },
            falses = List(3) { page(anonymous) },
        )
        assertEquals("true_diverges", reversed?.polarity)
    }

    @Test
    fun `a status that follows the condition is a verdict`() {
        val verdict = InjectionOracle.booleanDifferential(
            baselines = listOf(page("item"), page("item")),
            trues = List(3) { page("item") },
            falses = List(3) { page("item", status = 404) },
        )
        assertTrue("+status:404" in verdict!!.tokens, verdict.tokens.toString())
    }

    @Test
    fun `an unanswered request on either side gives no verdict`() {
        val baselines = listOf(page(welcome), page(welcome))
        assertNull(InjectionOracle.booleanDifferential(baselines, List(3) { page(welcome) }, listOf(page(anonymous), timeout, page(anonymous))))
        assertNull(InjectionOracle.booleanDifferential(baselines, listOf(page(welcome), timeout, page(welcome)), List(3) { page(anonymous) }))
        assertNull(InjectionOracle.booleanDifferential(listOf(page(welcome), timeout), List(3) { page(welcome) }, List(3) { page(anonymous) }))
        assertNull(InjectionOracle.booleanDifferential(baselines, List(3) { page(welcome) }, List(2) { page(anonymous) }))
    }

    @Test
    fun `content that changes on every request gives no verdict`() {
        fun dynamic(n: Int) = page("<html><input name=csrf value=tok$n><p>Item 1</p></html>")
        assertNull(
            InjectionOracle.booleanDifferential(
                baselines = listOf(dynamic(1), dynamic(2)),
                trues = listOf(dynamic(3), dynamic(5), dynamic(7)),
                falses = listOf(dynamic(4), dynamic(6), dynamic(8)),
            )
        )
    }

    @Test
    fun `an echoed payload gives no verdict because both sides carry the same words`() {
        fun echo(value: String) = page("<html><p>No results for $value</p></html>")
        val trues = InjectionPayloads.booleanRounds.indices.map { echo(InjectionPayloads.boolean("{base} AND {x}<{y}", "1", it, true)) }
        val falses = InjectionPayloads.booleanRounds.indices.map { echo(InjectionPayloads.boolean("{base} AND {x}<{y}", "1", it, false)) }
        assertNull(InjectionOracle.booleanDifferential(listOf(echo("1"), echo("1")), trues, falses))
    }

    @Test
    fun `a difference seen in one round only gives no verdict`() {
        val verdict = InjectionOracle.booleanDifferential(
            baselines = listOf(page(welcome), page(welcome)),
            trues = List(3) { page(welcome) },
            falses = listOf(page(anonymous), page(welcome), page(welcome)),
        )
        assertNull(verdict)
    }

    // ---------------------------------------------------------------
    // Redirects and headers
    // ---------------------------------------------------------------

    @Test
    fun `targetsHost follows the browser's reading of a URL`() {
        val host = "canary.test"
        listOf(
            "https://canary.test/x", "HTTPS://CANARY.TEST/", "//canary.test/", "/\\canary.test/", "\\\\canary.test",
            "https://target.test@canary.test/", "https://sub.canary.test/", "/\t/canary.test/", "  https://canary.test:8443/a",
        ).forEach { assertTrue(InjectionOracle.targetsHost(it, host), it) }
        listOf(
            "/login?next=https://canary.test/", "https://target.test/?u=canary.test", "https://canary.test.evil.example/",
            "/canary.test/", "/%09/canary.test/", "canary.test", "",
        ).forEach { assertFalse(InjectionOracle.targetsHost(it, host), it) }
    }

    @Test
    fun `a redirect to the supplied host is a hit through each mechanism`() {
        val baselines = listOf(page("", status = 302, headers = listOf("Location" to "/home")))
        val host = "canary.test"

        val location = page("", status = 302, headers = listOf("Location" to "https://canary.test/"))
        assertEquals("location_header", InjectionOracle.novelRedirect(baselines, location, host)?.via)

        val refresh = page("", headers = listOf("Refresh" to "0; url=https://canary.test/"))
        assertEquals("refresh_header", InjectionOracle.novelRedirect(baselines, refresh, host)?.via)

        val meta = page("<html><head><meta http-equiv=\"refresh\" content=\"0;url=https://canary.test/\"></head></html>")
        assertEquals("meta_refresh", InjectionOracle.novelRedirect(baselines, meta, host)?.via)

        val script = page("<script>window.location = \"https://canary.test/\";</script>")
        assertEquals("script", InjectionOracle.novelRedirect(baselines, script, host)?.via)
        val replace = page("<script>location.replace('//canary.test/next')</script>")
        assertEquals("//canary.test/next", InjectionOracle.novelRedirect(baselines, replace, host)?.target)
    }

    @Test
    fun `a host that is only a parameter of the redirect, or already the baseline's target, is not a hit`() {
        val host = "canary.test"
        val home = listOf(page("", status = 302, headers = listOf("Location" to "/home")))
        val login = page("", status = 302, headers = listOf("Location" to "/login?next=https%3A%2F%2Fcanary.test%2F"))
        assertNull(InjectionOracle.novelRedirect(home, login, host))

        val notRedirect = page("ok", status = 200, headers = listOf("Location" to "https://canary.test/"))
        assertNull(InjectionOracle.novelRedirect(home, notRedirect, host), "Location on a 200 does not redirect")

        val toCanary = page("", status = 302, headers = listOf("Location" to "https://canary.test/"))
        assertNull(InjectionOracle.novelRedirect(listOf(toCanary), toCanary, host))
        assertNull(InjectionOracle.novelRedirect(home, Observation(status = 0, headers = listOf("Location" to "https://canary.test/")), host))
    }

    @Test
    fun `an injected header counts only as a header line of its own that the baseline lacks`() {
        val baselines = listOf(page("", headers = listOf("Location" to "/set?lang=en")))
        val split = page("", headers = listOf("Location" to "/set?lang=en", "X-rjn1" to "1"))
        assertEquals("1", InjectionOracle.novelHeader(baselines, split, "x-rjn1"))

        val inValue = page("", headers = listOf("Location" to "/set?lang=en%0d%0aX-rjn1: 1"))
        assertNull(InjectionOracle.novelHeader(baselines, inValue, "X-rjn1"))
        assertNull(InjectionOracle.novelHeader(listOf(split), split, "X-rjn1"))
        assertNull(InjectionOracle.novelHeader(baselines, Observation(status = 0, headers = listOf("X-rjn1" to "1")), "X-rjn1"))
    }
}
