package io.bitbytelab.raijin.injection

import io.bitbytelab.raijin.core.BodyText

/** What an oracle matched: the signature family ([kind]) and the response text around it. */
data class OracleMatch(val kind: String, val excerpt: String)

/**
 * Pure detection oracles for the injection probe. Every oracle that reads a response compares it
 * with the baseline (the same request carrying a benign value), so content the page shows anyway
 * is never evidence, and none of them accepts an unanswered request ([Observation.answered]):
 *  - signatures that must be new: SQL / NoSQL errors, file contents, command output, cloud metadata
 *  - a computed value that must be new: template or shell arithmetic, an expanded XML entity
 *  - response time against a zero-delay control and a repeat ([timingVerdict])
 *  - TRUE/FALSE payload pairs that differ in the same way over several rounds ([booleanDifferential])
 *  - a redirect target or response header only the payload can explain
 */
object InjectionOracle {

    private const val MAX_SCAN = 200_000
    private val WHITESPACE = Regex("\\s+")

    private fun sample(body: String): String = if (body.length > MAX_SCAN) body.substring(0, MAX_SCAN) else body

    private fun excerpt(text: String, range: IntRange): String {
        val from = (range.first - 60).coerceAtLeast(0)
        val to = (range.last + 101).coerceAtMost(text.length)
        return BodyText.stripLoneSurrogates(text.substring(from, to)).replace(WHITESPACE, " ").trim()
    }

    private fun firstSignature(signatures: List<Pair<String, Regex>>, body: String): OracleMatch? {
        val text = sample(body)
        for ((kind, regex) in signatures) {
            val match = regex.find(text) ?: continue
            return OracleMatch(kind, excerpt(text, match.range))
        }
        return null
    }

    /** [detect] on [probeBody], unless a baseline already shows the same kind of match. */
    private fun novel(baselineBodies: List<String>, probeBody: String, detect: (String) -> OracleMatch?): OracleMatch? {
        val match = detect(probeBody) ?: return null
        return match.takeIf { baselineBodies.none { detect(it)?.kind == match.kind } }
    }

    // ---------------------------------------------------------------
    // Signatures
    // ---------------------------------------------------------------

    private val sqlErrors: List<Pair<String, Regex>> = listOf(
        "mysql" to Regex(
            """(?i)SQL syntax[^\n]{0,200}(MySQL|MariaDB)|valid MySQL result|MySqlClient\.|com\.mysql\.(cj\.)?jdbc|MySQL server version|MySqlException|check the manual that (corresponds to|fits) your (MySQL|MariaDB)"""
        ),
        "postgresql" to Regex(
            """(?i)PostgreSQL[^\n]{0,200}ERROR|pg_(query|exec)\(\)|PSQLException|org\.postgresql\.|unterminated quoted string|syntax error at or near|Npgsql\."""
        ),
        "mssql" to Regex(
            """(?i)Microsoft SQL Server|ODBC SQL Server Driver|SQLServerException|Unclosed quotation mark after the character string|Incorrect syntax near|System\.Data\.SqlClient\.|OLE DB Provider for SQL Server"""
        ),
        "oracle" to Regex("""(?i)\bORA-[0-9]{5}\b|Oracle error|quoted string not properly terminated|oracle\.jdbc\.|\bPLS-[0-9]{5}\b"""),
        "sqlite" to Regex(
            """(?i)SQLite/JDBCDriver|SQLite\.Exception|SQLiteException|sqlite3\.OperationalError|SQLITE_ERROR|unrecognized token: "|near "[^"\n]{0,60}": syntax error"""
        ),
        "db2" to Regex("""(?i)DB2 SQL error|\bSQLCODE[=: ]+-?[0-9]+|com\.ibm\.db2\.jcc"""),
        "generic" to Regex(
            """(?i)SQLSTATE\[[0-9A-Z]{5}\]|java\.sql\.SQL(SyntaxError)?Exception|PDOException|SQLGrammarException|SQL command not properly ended|unexpected end of SQL command"""
        ),
    )

    private val nosqlErrors: List<Pair<String, Regex>> = listOf(
        "mongodb" to Regex(
            """(?i)Mongo(Server|Parse|Runtime)?Error|com\.mongodb\.|MongoDB\\Driver\\Exception|pymongo\.errors|unknown (top level )?operator: [$]|[$]where|Can't canonicalize query|BSON(Type)?Error|Cast to ObjectId failed|CastError: Cast to"""
        ),
        // A script engine choking on the payload (server-side JavaScript in `$where`, mapReduce, eval).
        // A JSON parser's SyntaxError is a malformed document, not injected code.
        "script-error" to Regex("""SyntaxError: (?![^\n]{0,80}JSON)|ReferenceError: [A-Za-z_$][\w$]{0,60} is not defined"""),
    )

    private val PASSWD = Regex("""root:[^:\n]{0,40}:0:0:""")
    private val WIN_INI = listOf("[fonts]", "[extensions]", "[mci extensions]", "[files]", "for 16-bit app support")
    private val ID_OUTPUT = Regex("""uid=[0-9]+\([^)\s]{1,64}\) gid=[0-9]+""")
    private val SSH_BANNER = Regex("""SSH-2\.0-[A-Za-z0-9_.-]{3,}""")
    private val AWS_METADATA = listOf(
        "ami-id", "ami-launch-index", "instance-id", "instance-type", "local-hostname",
        "local-ipv4", "public-keys", "reservation-id", "security-groups",
    )

    /** DBMS whose error signature appears in [body], or null. */
    fun sqlError(body: String): String? = sqlErrorMatch(body)?.kind

    fun sqlErrorMatch(body: String): OracleMatch? = firstSignature(sqlErrors, body)

    fun novelSqlError(baselineBodies: List<String>, probeBody: String): OracleMatch? =
        novel(baselineBodies, probeBody, ::sqlErrorMatch)

    fun nosqlErrorMatch(body: String): OracleMatch? = firstSignature(nosqlErrors, body)

    fun novelNosqlError(baselineBodies: List<String>, probeBody: String): OracleMatch? =
        novel(baselineBodies, probeBody, ::nosqlErrorMatch)

    /** Marker family (`unix-passwd`, `windows-ini`) when [body] looks like the contents of a system file. */
    fun fileMarker(body: String): String? = fileMarkerMatch(body)?.kind

    /**
     * `/etc/passwd` needs its root entry; `win.ini` needs two of its section names, because one
     * alone (`[fonts]`, `[extensions]`) is ordinary page text.
     */
    fun fileMarkerMatch(body: String): OracleMatch? {
        val text = sample(body)
        PASSWD.find(text)?.let { return OracleMatch("unix-passwd", excerpt(text, it.range)) }
        val sections = WIN_INI.filter { text.contains(it, ignoreCase = true) }
        if (sections.size < 2) return null
        val at = text.indexOf(sections.first(), ignoreCase = true)
        return OracleMatch("windows-ini", excerpt(text, at until at + sections.first().length))
    }

    /** [fileMarkerMatch] for [probeBody], unless a baseline already carries the same marker family. */
    fun novelFileMarker(baselineBodies: List<String>, probeBody: String): OracleMatch? =
        novel(baselineBodies, probeBody, ::fileMarkerMatch)

    /** Output of the `id` command (`uid=33(www-data) gid=33(www-data)`). */
    fun commandOutput(body: String): OracleMatch? {
        val text = sample(body)
        return ID_OUTPUT.find(text)?.let { OracleMatch("id-output", excerpt(text, it.range)) }
    }

    fun novelCommandOutput(baselineBodies: List<String>, probeBody: String): OracleMatch? =
        novel(baselineBodies, probeBody, ::commandOutput)

    /** Content only an internal fetch returns: a cloud metadata listing, an SSH banner, a local file. */
    fun internalContent(body: String): OracleMatch? {
        val text = sample(body)
        val keys = AWS_METADATA.filter { text.contains(it) }
        if (keys.size >= 3) {
            val at = text.indexOf(keys.first())
            return OracleMatch("cloud-metadata", excerpt(text, at until at + keys.first().length))
        }
        SSH_BANNER.find(text)?.let { return OracleMatch("ssh-banner", excerpt(text, it.range)) }
        return fileMarkerMatch(text)
    }

    fun novelInternalContent(baselineBodies: List<String>, probeBody: String): OracleMatch? =
        novel(baselineBodies, probeBody, ::internalContent)

    // ---------------------------------------------------------------
    // Computed values
    // ---------------------------------------------------------------

    /** True if [expected] (the result of injected arithmetic) appears in [body] as a number of its own. */
    fun evaluatedTo(body: String, expected: String): Boolean {
        var at = body.indexOf(expected)
        while (at >= 0) {
            val end = at + expected.length
            val digitBefore = at > 0 && body[at - 1].isDigit()
            val digitAfter = end < body.length && body[end].isDigit()
            if (!digitBefore && !digitAfter) return true
            at = body.indexOf(expected, at + 1)
        }
        return false
    }

    /** [evaluatedTo] for the probe and for no baseline. */
    fun novelEvaluation(baselineBodies: List<String>, probeBody: String, expected: String): Boolean =
        evaluatedTo(probeBody, expected) && baselineBodies.none { evaluatedTo(it, expected) }

    /** True if [text] is in [probeBody] and in no baseline. */
    fun novelText(baselineBodies: List<String>, probeBody: String, text: String): Boolean =
        text.isNotEmpty() && probeBody.contains(text) && baselineBodies.none { it.contains(text) }

    // ---------------------------------------------------------------
    // Response time
    // ---------------------------------------------------------------

    /**
     * True if [probeMs] is late by the injected sleep. An injected sleep cannot finish early, so
     * the response must take at least 90% of [expectedDelaySec] (timer granularity) and exceed
     * the baseline by 70% of it.
     */
    fun timeDelayed(baselineMs: Long, probeMs: Long, expectedDelaySec: Int): Boolean {
        if (expectedDelaySec <= 0 || baselineMs < 0 || probeMs <= 0) return false
        val delayMs = expectedDelaySec * 1000L
        return probeMs >= delayMs * 9 / 10 && probeMs - baselineMs >= delayMs * 7 / 10
    }

    /** [timeDelayed] for an answered [probe]; a timeout is slow too, and is never a hit. */
    fun delayed(baselineMs: Long, probe: Observation, expectedDelaySec: Int): Boolean =
        probe.answered && timeDelayed(baselineMs, probe.elapsedMs, expectedDelaySec)

    /** True if the zero-delay [control] came back about as fast as the baseline. */
    fun fastControl(baselineMs: Long, control: Observation, expectedDelaySec: Int): Boolean =
        control.answered && control.elapsedMs - baselineMs < expectedDelaySec * 500L

    data class TimingVerdict(val confirmed: Boolean, val reason: String)

    /**
     * Double check for a time-based hit: the delayed payload must be late twice ([first],
     * [repeat]) while the same payload asking for no delay ([control]) is not. A slow network
     * delays the control as well, so lag alone never confirms.
     */
    fun timingVerdict(
        baselineMs: Long,
        first: Observation,
        control: Observation,
        repeat: Observation,
        expectedDelaySec: Int,
    ): TimingVerdict = when {
        !delayed(baselineMs, first, expectedDelaySec) ->
            TimingVerdict(false, "the delayed payload was not late (${describe(first)})")
        !control.answered ->
            TimingVerdict(false, "the zero-delay control got no response")
        !fastControl(baselineMs, control, expectedDelaySec) ->
            TimingVerdict(false, "the zero-delay control was slow too (${control.elapsedMs}ms): network or server lag")
        !delayed(baselineMs, repeat, expectedDelaySec) ->
            TimingVerdict(false, "the delay did not repeat (${describe(repeat)})")
        else ->
            TimingVerdict(true, "late twice (${first.elapsedMs}ms, ${repeat.elapsedMs}ms) while the zero-delay control took ${control.elapsedMs}ms")
    }

    private fun describe(o: Observation): String = if (o.answered) "${o.elapsedMs}ms" else "no response"

    // ---------------------------------------------------------------
    // Boolean differential
    // ---------------------------------------------------------------

    private val WORD = Regex("[A-Za-z0-9_]+")

    /** Word counts of the response body, with the status and redirect target as tokens of their own. */
    internal fun signature(o: Observation): Map<String, Int> {
        val counts = HashMap<String, Int>()
        counts["status:${o.status}"] = 1
        o.header("Location")?.let { location ->
            for (word in WORD.findAll(location)) counts["location:${word.value}"] = (counts["location:${word.value}"] ?: 0) + 1
        }
        for (word in WORD.findAll(sample(o.body))) counts[word.value] = (counts[word.value] ?: 0) + 1
        return counts
    }

    /** Tokens whose count differs, signed: `+token` occurs more often in [other] than in [base], `-token` less. */
    internal fun changed(base: Map<String, Int>, other: Map<String, Int>): Set<String> {
        val out = HashSet<String>()
        for ((token, count) in other) if (count > (base[token] ?: 0)) out += "+$token"
        for ((token, count) in base) if (count > (other[token] ?: 0)) out += "-$token"
        return out
    }

    /** Which side stands apart from the baseline ([polarity]: `false_diverges` or `true_diverges`) and the [tokens] that show it. */
    data class BooleanVerdict(val polarity: String, val tokens: List<String>)

    /**
     * Blind boolean oracle. [trues] and [falses] are the responses to TRUE and FALSE conditions,
     * one pair per round. A verdict needs tokens that changed against the baseline in every
     * response of one side and in no response of the other, and that do not vary between the
     * [baselines] themselves.
     *
     * Per-request noise (CSRF tokens, timestamps, counters) differs in every response and so is
     * in no intersection. The payload echoed back cancels out when each pair is the same text
     * with two literals swapped (see [InjectionPayloads.booleanRounds]), since both sides then
     * carry the same words. A caller should run at least three rounds with different literals.
     */
    fun booleanDifferential(
        baselines: List<Observation>,
        trues: List<Observation>,
        falses: List<Observation>,
    ): BooleanVerdict? {
        if (baselines.isEmpty() || trues.isEmpty() || trues.size != falses.size) return null
        if (baselines.any { !it.answered } || trues.any { !it.answered } || falses.any { !it.answered }) return null
        val base = signature(baselines.first())
        val noise = HashSet<String>()
        for (other in baselines.drop(1)) noise += changed(base, signature(other))
        val trueDeltas = trues.map { changed(base, signature(it)) }
        val falseDeltas = falses.map { changed(base, signature(it)) }
        val falseOnly = exclusive(falseDeltas, trueDeltas, noise)
        if (falseOnly.isNotEmpty()) return BooleanVerdict("false_diverges", falseOnly)
        val trueOnly = exclusive(trueDeltas, falseDeltas, noise)
        if (trueOnly.isNotEmpty()) return BooleanVerdict("true_diverges", trueOnly)
        return null
    }

    private fun exclusive(side: List<Set<String>>, other: List<Set<String>>, noise: Set<String>): List<String> =
        side.reduce { common, delta -> common intersect delta }
            .filter { token -> token !in noise && other.none { token in it } }
            .sorted()
            .take(12)

    // ---------------------------------------------------------------
    // Redirects and response headers
    // ---------------------------------------------------------------

    /** Where a response sends the browser ([target]) and by which mechanism ([via]). */
    data class Redirect(val via: String, val target: String)

    private val REFRESH_URL = Regex("""(?i)^\s*\d+\s*[;,]\s*(?:url\s*=\s*)?["']?([^"'\s]+)""")
    private val META_TAG = Regex("""(?i)<meta\b[^>]{0,400}>""")
    private val META_URL = Regex("""(?i)url\s*=\s*["']?\s*([^"'>\s]+)""")
    private val SCRIPT_LOCATION = Regex(
        """\blocation(?:\.href)?\s*=\s*["']([^"'\\\s]{1,400})["']|\blocation\.(?:replace|assign)\(\s*["']([^"'\\\s]{1,400})["']"""
    )
    private val URL_SCHEME = Regex("""^[A-Za-z][A-Za-z0-9+.-]*:/{2,}""")

    /** Every redirect [o] performs: `Location` on a 3xx, a `Refresh` header, a meta refresh, a script assigning `location`. */
    fun redirects(o: Observation): List<Redirect> {
        val out = ArrayList<Redirect>()
        if (o.status in 300..399) o.header("Location")?.let { out += Redirect("location_header", it.trim()) }
        o.header("Refresh")?.let { value -> REFRESH_URL.find(value)?.let { out += Redirect("refresh_header", it.groupValues[1]) } }
        val text = sample(o.body)
        for (tag in META_TAG.findAll(text)) {
            if (!tag.value.contains("refresh", ignoreCase = true)) continue
            META_URL.find(tag.value)?.let { out += Redirect("meta_refresh", it.groupValues[1]) }
        }
        for (assignment in SCRIPT_LOCATION.findAll(text)) {
            out += Redirect("script", assignment.groupValues[1].ifEmpty { assignment.groupValues[2] })
        }
        return out
    }

    /**
     * True when a browser following [url] lands on [host] or a subdomain of it. Mirrors the
     * leniency of browser URL parsing that redirect filters miss: backslashes read as slashes,
     * tabs and newlines dropped, extra slashes and userinfo ignored. A host that only appears in
     * the path or query of [url] does not count.
     */
    fun targetsHost(url: String, host: String): Boolean {
        val cleaned = url.filter { it != '\t' && it != '\n' && it != '\r' }.trim { it <= ' ' }.replace('\\', '/')
        val afterScheme = when {
            cleaned.startsWith("//") -> cleaned.trimStart('/')
            else -> cleaned.substring((URL_SCHEME.find(cleaned) ?: return false).range.last + 1)
        }
        val authority = afterScheme.takeWhile { it != '/' && it != '?' && it != '#' }.substringAfterLast('@')
        val name = authority.substringBefore(':').trimEnd('.').lowercase()
        val wanted = host.lowercase()
        return wanted.isNotEmpty() && (name == wanted || name.endsWith(".$wanted"))
    }

    /** The redirect of [probe] that points at [host], unless a baseline already redirects there. */
    fun novelRedirect(baselines: List<Observation>, probe: Observation, host: String): Redirect? {
        if (!probe.answered) return null
        val hit = redirects(probe).firstOrNull { targetsHost(it.target, host) } ?: return null
        return hit.takeIf { baselines.none { b -> redirects(b).any { targetsHost(it.target, host) } } }
    }

    /**
     * Value of response header [name] when [probe] has it and no baseline does: the payload ended
     * a header line and started this one. The name inside another header's value is not a hit.
     */
    fun novelHeader(baselines: List<Observation>, probe: Observation, name: String): String? {
        if (!probe.answered) return null
        val value = probe.header(name) ?: return null
        return value.takeIf { baselines.none { it.header(name) != null } }
    }
}
