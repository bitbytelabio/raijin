package io.bitbytelab.raijin.injection

/**
 * Pure detection oracles for the injection probe — turn raw fuzz responses into
 * confirmed/likely findings:
 *  - SQL error signatures (DBMS fingerprint) for error-based SQLi
 *  - template math-evaluation for SSTI
 *  - file-content markers for path traversal / LFI
 *  - response-time delta for time-based (blind) SQLi / cmdi
 *  - boolean-differential (TRUE/FALSE payload pair divergence) for blind SQLi with no error
 *    text and no observable delay — the only oracle that can confirm this, since the other
 *    three all need something to detect (an error, a delay, or an echoed value).
 */
object InjectionOracle {

    private val sqlErrors: List<Pair<String, Regex>> = listOf(
        "mysql" to Regex("(?i)(SQL syntax.*MySQL|valid MySQL result|MySqlClient\\.|com\\.mysql\\.jdbc|MySQL server version)"),
        "postgresql" to Regex("(?i)(PostgreSQL.*ERROR|pg_query\\(\\)|PSQLException|org\\.postgresql|unterminated quoted string)"),
        "mssql" to Regex("(?i)(Microsoft SQL Server|ODBC SQL Server Driver|SQLServerException|Unclosed quotation mark after the character string)"),
        "oracle" to Regex("(?i)(ORA-[0-9]{5}|Oracle error|quoted string not properly terminated)"),
        "sqlite" to Regex("(?i)(SQLite/JDBCDriver|SQLite\\.Exception|sqlite3\\.OperationalError|\\[SQLITE_ERROR\\])")
    )

    /** Returns the DBMS whose error signature appears in [body], or null. Body is length-capped for safety. */
    fun sqlError(body: String): String? {
        val sample = body.take(200_000)
        return sqlErrors.firstOrNull { it.second.containsMatchIn(sample) }?.first
    }

    /** True if a unique math result [expected] (e.g. 1337*1337=1787569) appears — template/expression was evaluated. */
    fun evaluatedTo(body: String, expected: String): Boolean = body.contains(expected)

    /** Returns a file-read marker family if [body] looks like /etc/passwd or win.ini contents, else null. */
    fun fileMarker(body: String): String? = when {
        body.contains("root:x:0:0:") || Regex("root:[^:]*:0:0:").containsMatchIn(body.take(200_000)) -> "unix-passwd"
        body.contains("[fonts]", ignoreCase = true) || body.contains("[extensions]", ignoreCase = true) -> "windows-ini"
        else -> null
    }

    /**
     * True if [probeMs] is delayed relative to [baselineMs] by roughly the
     * injected sleep ([expectedDelaySec]). Uses a 0.7 slack factor to tolerate
     * jitter while rejecting normal responses.
     */
    fun timeDelayed(baselineMs: Long, probeMs: Long, expectedDelaySec: Int): Boolean {
        if (expectedDelaySec <= 0) return false
        val threshold = (expectedDelaySec * 1000L * 0.7).toLong()
        return (probeMs - baselineMs) >= threshold && probeMs >= threshold
    }

    /**
     * True if a `TRUE`-condition payload's response resembles [baselineBody] (>=95 similar)
     * while a `FALSE`-condition payload's response diverges from it (<70 similar) — or the
     * reverse polarity (the app renders the FALSE case as "normal" and TRUE as different) —
     * and the two probe bodies differ from each other. This is the fallback oracle for blind
     * SQLi when error text is suppressed (WAF/custom error pages) and a sleep-based payload is
     * clamped, rate-limited, or simply never reaches the vulnerable sink in this insertion
     * context (e.g. a payload shaped for comment-truncation never executes in a
     * string-concatenation context) — a true/false divergence survives all three cases.
     *
     * @param similarity 0..100 body similarity (bigram-Dice via [io.bitbytelab.raijin.core.TextSimilarity.dice] in production; tests may stub it).
     */
    fun booleanDifferential(
        baselineBody: String,
        trueBody: String,
        falseBody: String,
        similarity: (String, String) -> Double
    ): Boolean {
        if (trueBody == falseBody) return false // payload had no effect at all — not a signal
        val trueVsBase = similarity(baselineBody, trueBody)
        val falseVsBase = similarity(baselineBody, falseBody)
        val trueVsFalse = similarity(trueBody, falseBody)
        if (trueVsFalse >= 95.0) return false // TRUE and FALSE look the same — no divergence
        return (trueVsBase >= 95.0 && falseVsBase < 70.0) || (falseVsBase >= 95.0 && trueVsBase < 70.0)
    }
}
