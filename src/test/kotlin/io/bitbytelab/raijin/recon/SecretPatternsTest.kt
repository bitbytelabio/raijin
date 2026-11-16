package io.bitbytelab.raijin.recon

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SecretPatternsTest {

    private val farFuture: Long get() = System.nanoTime() + 60_000_000_000L

    /** Values the named pattern finds in [text]. */
    private fun found(pattern: String, text: String): List<String> =
        SecretPatterns.scan(text, mapOf(pattern to SecretPatterns.ALL.getValue(pattern)), farFuture).matches.map { it.value }

    /** Names of the default patterns that find something in [text]. */
    private fun defaults(text: String): Set<String> =
        SecretPatterns.scan(text, SecretPatterns.select(null).patterns, farFuture).matches.map { it.pattern }.toSet()

    @Test
    fun `the newer token formats are recognised`() {
        val githubPat = "github_pat_11ABCDEFG0abcdefghijkl_mnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijk"
        assertEquals(listOf(githubPat), found("github_fine_grained_token", "Authorization: token $githubPat\r\n"))
        assertEquals(listOf("glpat-AbCdEfGhIjKlMnOpQrSt"), found("gitlab_token", "PRIVATE-TOKEN: glpat-AbCdEfGhIjKlMnOpQrSt end"))
        assertEquals(listOf("sk-proj-abcDEF123456_ghiJKL7890mnop"), found("openai_api_key", "{\"key\":\"sk-proj-abcDEF123456_ghiJKL7890mnop\"}"))
        assertEquals(listOf("sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz"), found("anthropic_api_key", "x-api-key: sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz"))
    }

    @Test
    fun `look-alikes of the newer token formats are not reported`() {
        assertTrue(found("github_fine_grained_token", "github_pat_short and my_github_pat_variable").isEmpty())
        assertTrue(found("gitlab_token", "glpat-short, glpat-").isEmpty())
        assertTrue(found("openai_api_key", "task-proj-abcdefghijklmnopqrstuvwx sk-proj-short").isEmpty())
        assertTrue(found("anthropic_api_key", "risk-ant-abcdefghijklmnopqrstuv sk-ant-x").isEmpty())
    }

    @Test
    fun `source map references are found in comments and headers`() {
        assertEquals(listOf("# sourceMappingURL=app.js.map"), found("source_map_url", "x()\n//# sourceMappingURL=app.js.map\n"))
        assertEquals(listOf("SourceMap: /static/app.js.map"), found("source_map_url", "HTTP/1.1 200 OK\r\nSourceMap: /static/app.js.map\r\n\r\n"))
        assertEquals(listOf("X-SourceMap: old.map"), found("source_map_url", "HTTP/1.1 200 OK\r\nX-SourceMap: old.map\r\n\r\n"))
        assertTrue(found("source_map_url", "the sourceMappingURL= option, and a line about SourceMap: support").isEmpty())
    }

    @Test
    fun `the noisy patterns are gone`() {
        assertFalse("debug_info" in SecretPatterns.ALL)
        assertFalse("heroku_api_key" in SecretPatterns.ALL)
        // What they used to flag in almost every response no longer produces a finding.
        assertTrue(defaults("X-Request-Id: 123e4567-e89b-12d3-a456-426614174000\r\nlevel=DEBUG trace enabled").isEmpty())
    }

    @Test
    fun `AWS access keys are matched as issued, not in lower case or inside longer strings`() {
        assertEquals(listOf("AKIAIOSFODNN7EXAMPLE"), found("aws_access_key", "aws_access_key_id=AKIAIOSFODNN7EXAMPLE;"))
        assertEquals(listOf("ASIAABCDEFGHIJKLMNOP"), found("aws_access_key", "ASIAABCDEFGHIJKLMNOP"))
        assertTrue(found("aws_access_key", "akiaiosfodnn7example XAKIAIOSFODNN7EXAMPLEX").isEmpty())
    }

    @Test
    fun `established patterns still match`() {
        assertEquals(listOf("alice@example.com"), found("email_address", "contact: alice@example.com."))
        assertEquals(listOf("https://my-bucket.s3.us-east-1.amazonaws.com"), found("s3_bucket", "src=\"https://my-bucket.s3.us-east-1.amazonaws.com/x.png\""))
        assertEquals(listOf("acct01.blob.core.windows.net"), found("azure_storage", "https://acct01.blob.core.windows.net/c"))
        assertEquals(listOf("192.168.1.20"), found("ipv4_internal", "upstream 192.168.1.20:8080"))
        assertEquals(setOf("jwt_token"), defaults("token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlMTIz"))
    }

    @Test
    fun `low-entropy bearer values are dropped, real ones kept`() {
        assertTrue(found("bearer_token", "Authorization: Bearer test").isEmpty())
        assertEquals(1, found("bearer_token", "Authorization: Bearer 9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c").size)
    }

    @Test
    fun `a text reports each distinct match once and long matches cut short`() {
        val text = "a@example.com b@example.com a@example.com " + "sk-ant-" + "A1b2".repeat(100)
        assertEquals(listOf("a@example.com", "b@example.com"), found("email_address", text))
        assertEquals(200, found("anthropic_api_key", text).single().length)
    }

    @Test
    fun `the default selection leaves out what matches everywhere`() {
        val default = SecretPatterns.select(null)
        assertTrue(default.unknown.isEmpty())
        assertFalse("email_address" in default.patterns)
        assertFalse("phone_number" in default.patterns)
        assertEquals(SecretPatterns.ALL.keys - SecretPatterns.OPT_IN, default.patterns.keys)
        assertEquals(default.patterns.keys, SecretPatterns.select(emptyList()).patterns.keys)
        assertEquals(default.patterns.keys, SecretPatterns.select(listOf(" ")).patterns.keys)
    }

    @Test
    fun `categories select by name or part of a name, and unknown ones are reported`() {
        assertEquals(setOf("aws_access_key", "aws_secret_key"), SecretPatterns.select(listOf("AWS")).patterns.keys)
        assertEquals(setOf("email_address"), SecretPatterns.select(listOf("email_address")).patterns.keys)
        assertEquals(setOf("github_token", "github_fine_grained_token", "jwt_token"), SecretPatterns.select(listOf("github", "jwt")).patterns.keys)

        val mixed = SecretPatterns.select(listOf("jwt_token", "debug_info", "heroku_api_key"))
        assertEquals(listOf("debug_info", "heroku_api_key"), mixed.unknown)
        assertEquals(setOf("jwt_token"), mixed.patterns.keys)
    }

    @Test
    fun `a scan past its deadline matches nothing and names the patterns it skipped`() {
        val result = SecretPatterns.scan("alice@example.com AKIAIOSFODNN7EXAMPLE", SecretPatterns.ALL, System.nanoTime() - 1)
        assertTrue(result.matches.isEmpty())
        assertEquals(SecretPatterns.ALL.keys.toList(), result.timedOut)
    }

    @Test
    fun `a long run of name characters does not exhaust a pattern's time`() {
        // Entered once per character, as these patterns were before being anchored, such a run
        // costs billions of steps and the pattern times out; entered once, it costs thousands.
        val text = "a".repeat(60_000) + " " + "b.c-".repeat(15_000)
        val result = SecretPatterns.scan(text, SecretPatterns.ALL.filterKeys { it in setOf("email_address", "s3_bucket", "azure_storage") }, farFuture)
        assertTrue(result.timedOut.isEmpty(), "timed out: ${result.timedOut}")
        assertTrue(result.matches.isEmpty())
    }
}
