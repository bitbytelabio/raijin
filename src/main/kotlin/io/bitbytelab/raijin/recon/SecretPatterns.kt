package io.bitbytelab.raijin.recon

import io.bitbytelab.raijin.core.Entropy
import io.bitbytelab.raijin.safety.InterruptibleCharSequence
import io.bitbytelab.raijin.safety.RegexTimeoutException

/**
 * The patterns passive intel looks for in captured traffic, and the bounded scan that applies
 * them. Each pattern runs in time linear in the text: a name that starts with a character class
 * is anchored with a lookbehind, so a long token is entered once instead of once per character.
 */
object SecretPatterns {

    val ALL: Map<String, Regex> = linkedMapOf(
        // Cloud credentials
        "aws_access_key" to Regex("\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b"),
        "aws_secret_key" to Regex("(?i)(aws_secret_access_key|aws_secret_key|secret_access_key)[\\s]*[=:][\\s]*['\"]?([A-Za-z0-9/+=]{40})"),
        "google_api_key" to Regex("AIza[0-9A-Za-z\\-_]{35}"),
        "google_oauth_token" to Regex("ya29\\.[0-9A-Za-z\\-_]+"),
        "github_token" to Regex("(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}"),
        "github_fine_grained_token" to Regex("\\bgithub_pat_[A-Za-z0-9_]{36,255}"),
        "gitlab_token" to Regex("\\bglpat-[A-Za-z0-9_\\-]{20,}(?:\\.[A-Za-z0-9_\\-]+)*"),
        "openai_api_key" to Regex("\\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\\-]{20,}"),
        "anthropic_api_key" to Regex("\\bsk-ant-[A-Za-z0-9_\\-]{20,}"),
        "slack_token" to Regex("xox[bpors]-[0-9a-zA-Z]{10,}"),
        "stripe_key" to Regex("(sk|pk)_(live|test)_[0-9a-zA-Z]{24,}"),

        // Tokens and secrets
        "jwt_token" to Regex("eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+"),
        "bearer_token" to Regex("(?i)bearer\\s+[a-zA-Z0-9_\\-\\.]+"),
        "basic_auth" to Regex("(?i)basic\\s+[A-Za-z0-9+/=]{10,}"),
        "private_key" to Regex("-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"),

        // Personal data
        "email_address" to Regex("(?<![a-zA-Z0-9._%+-])[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"),
        "ipv4_internal" to Regex("(?:10\\.|172\\.(?:1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)[0-9]+\\.[0-9]+"),
        "phone_number" to Regex("(?:\\+?1[-.\\s]?)?\\(?[0-9]{3}\\)?[-.\\s]?[0-9]{3}[-.\\s]?[0-9]{4}"),

        // Cloud resources
        "s3_bucket" to Regex("(?i)(?:https?://)?(?<![a-z0-9.-])[a-z0-9][a-z0-9.-]+\\.s3[.-](?:us|eu|ap|sa|ca|me|af)-[a-z]+-[0-9]+\\.amazonaws\\.com|s3://[a-z0-9][a-z0-9.-]+"),
        "azure_storage" to Regex("(?i)(?<![a-z0-9])[a-z0-9]+\\.blob\\.core\\.windows\\.net"),
        "gcs_bucket" to Regex("(?i)storage\\.googleapis\\.com/[a-z0-9][a-z0-9._-]+"),

        // URLs and endpoints
        "internal_url" to Regex("(?i)https?://(?:localhost|127\\.0\\.0\\.1|10\\.[0-9.]+|172\\.(?:1[6-9]|2[0-9]|3[01])\\.[0-9.]+|192\\.168\\.[0-9.]+)[:/][^\\s'\"<>]+"),
        "graphql_endpoint" to Regex("(?i)/graphql(?:/|\\?|$)"),
        "api_endpoint" to Regex("(?i)/api/(?:v[0-9]+/)?[a-z_-]+"),
        "source_map_url" to Regex("(?im)(?:[#@][ \\t]*sourceMappingURL=|^(?:X-)?SourceMap:[ \\t]*)[^\\s'\"*]+"),

        // Error patterns
        "stack_trace" to Regex("(?i)(?:at\\s+[a-z]+\\.[a-z]+\\.[a-z]+|Traceback \\(most recent|Exception in thread|Fatal error:|SQLSTATE\\[)"),
        "sql_error" to Regex("(?i)(?:mysql_|pg_|sqlite_|ORA-[0-9]+|SQL syntax|syntax error at|unterminated quoted string)"),

        // Version/technology fingerprints
        "server_version" to Regex("(?i)(?:apache|nginx|iis|tomcat|express|flask|django|spring|rails)[/\\s-]+[0-9]+\\.[0-9]+"),
        "framework_version" to Regex("(?i)(?:x-powered-by|x-aspnet-version|x-runtime|x-generator)[:\\s]+[^\\r\\n]+"),
        "php_version" to Regex("(?i)PHP/[0-9]+\\.[0-9]+\\.[0-9]+"),

        // Sensitive paths
        "sensitive_path" to Regex("(?i)/(?:admin|debug|test|staging|internal|backup|config|setup|install|phpinfo|server-status|server-info|\\.env|\\.git|wp-admin|actuator)(?:/|$)"),
    )

    /**
     * High-false-positive patterns excluded from the default scan; reported only
     * when explicitly named in `categories` (emails and phone numbers appear
     * everywhere and are rarely the secret you're hunting).
     */
    val OPT_IN: Set<String> = setOf("email_address", "phone_number")

    /**
     * Patterns whose match must clear a Shannon-entropy bar (bits/char) to be
     * reported — kills "bearer test" / "basic dGVzdA==" style noise while keeping
     * real high-entropy tokens.
     */
    private val ENTROPY_GATE: Map<String, Double> = mapOf("bearer_token" to 3.0, "basic_auth" to 3.0)

    /** Time one pattern may spend on one text. */
    private const val PATTERN_BUDGET_MS = 500L

    /** Matches reported per pattern and text; a page listing thousands of addresses says no more than its first few. */
    private const val MAX_MATCHES_PER_TEXT = 50
    private const val MAX_MATCH_CHARS = 200

    /** @param unknown requested categories that name no pattern. */
    class Selection(val patterns: Map<String, Regex>, val unknown: List<String>)

    /**
     * The patterns to run: every pattern whose name contains one of [categories] (so `aws` selects
     * both AWS patterns), or all but [OPT_IN] when no category is given.
     */
    fun select(categories: List<String>?): Selection {
        val wanted = categories.orEmpty().map { it.trim() }.filter { it.isNotEmpty() }
        if (wanted.isEmpty()) return Selection(ALL.filterKeys { it !in OPT_IN }, emptyList())
        val unknown = wanted.filter { category -> ALL.keys.none { it.contains(category, ignoreCase = true) } }
        return Selection(ALL.filter { (name, _) -> wanted.any { name.contains(it, ignoreCase = true) } }, unknown)
    }

    data class Match(val pattern: String, val value: String)

    /** @param timedOut patterns that ran out of time on this text; their matches may be missing. */
    class Result(val matches: List<Match>, val timedOut: List<String>)

    /**
     * Runs [patterns] over [text], each for at most [PATTERN_BUDGET_MS] and none past
     * [deadlineNanos] (a [System.nanoTime] instant). Matches are cut to [MAX_MATCH_CHARS] and
     * de-duplicated per pattern.
     */
    fun scan(text: String, patterns: Map<String, Regex>, deadlineNanos: Long): Result {
        val matches = ArrayList<Match>()
        val timedOut = ArrayList<String>()
        if (text.isEmpty()) return Result(matches, timedOut)
        for ((name, regex) in patterns) {
            val now = System.nanoTime()
            if (now >= deadlineNanos) {
                timedOut.add(name)
                continue
            }
            val until = minOf(deadlineNanos, now + PATTERN_BUDGET_MS * 1_000_000)
            val guarded = InterruptibleCharSequence(text) { System.nanoTime() > until }
            val threshold = ENTROPY_GATE[name]
            val seen = HashSet<String>()
            try {
                for (match in regex.findAll(guarded)) {
                    val value = match.value
                    if (threshold != null && Entropy.shannon(value) < threshold) continue
                    if (seen.add(value)) matches.add(Match(name, value.take(MAX_MATCH_CHARS)))
                    if (seen.size >= MAX_MATCHES_PER_TEXT) break
                }
            } catch (_: RegexTimeoutException) {
                timedOut.add(name)
            }
        }
        return Result(matches, timedOut)
    }
}
