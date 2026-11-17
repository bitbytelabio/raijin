package io.bitbytelab.raijin.safety

import java.util.Collections

/**
 * Hardened facade for agent/operator-supplied regexes applied on Burp's hot
 * paths (proxy / HTTP / session rules). Replaces raw `Regex(...)` / `Pattern.compile(...)`
 * calls with a bounded LRU compile cache, an input-length cap, and a wall-clock
 * deadline via [InterruptibleCharSequence].
 *
 * Invalid patterns never propagate `PatternSyntaxException` to [containsMatchIn],
 * [matches], [find], or [replace]; callers that accept user/agent patterns at
 * registration/query time can call [validate] upfront to surface syntax errors.
 */
object SafeRegex {
    const val DEFAULT_MAX_INPUT_LEN = 200_000
    const val DEFAULT_TIMEOUT_MS = 1_000L
    private const val MAX_CACHE = 256

    private val cache: MutableMap<String, Regex> = Collections.synchronizedMap(
        object : LinkedHashMap<String, Regex>(64, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Regex>): Boolean = size > MAX_CACHE
        }
    )

    /** Validates [pattern] syntax, returning null if valid or an error message if invalid. */
    fun validate(pattern: String, ignoreCase: Boolean = false): String? = try {
        compile(pattern, ignoreCase)
        null
    } catch (e: Exception) {
        e.message ?: "Invalid regex pattern"
    }

    /** Returns a cached compiled [Regex]; throws [java.util.regex.PatternSyntaxException] on an invalid pattern. */
    fun compile(pattern: String, ignoreCase: Boolean = false): Regex {
        val key = (if (ignoreCase) "i " else " ") + pattern
        cache[key]?.let { return it }
        val compiled = if (ignoreCase) Regex(pattern, RegexOption.IGNORE_CASE) else Regex(pattern)
        cache[key] = compiled
        return compiled
    }

    /** True if [pattern] matches anywhere in [input]; false on oversize input, invalid pattern, or timeout. */
    fun containsMatchIn(
        pattern: String,
        input: CharSequence,
        ignoreCase: Boolean = false,
        maxInputLen: Int = DEFAULT_MAX_INPUT_LEN,
        timeoutMs: Long = DEFAULT_TIMEOUT_MS
    ): Boolean {
        if (input.length > maxInputLen) return false
        val regex = try { compile(pattern, ignoreCase) } catch (_: Exception) { return false }
        return try { regex.containsMatchIn(guard(input, timeoutMs)) } catch (_: RegexTimeoutException) { false }
    }

    /** True if [pattern] matches the ENTIRE [input]; false on oversize input, invalid pattern, or timeout. */
    fun matches(
        pattern: String,
        input: CharSequence,
        ignoreCase: Boolean = false,
        maxInputLen: Int = DEFAULT_MAX_INPUT_LEN,
        timeoutMs: Long = DEFAULT_TIMEOUT_MS
    ): Boolean {
        if (input.length > maxInputLen) return false
        val regex = try { compile(pattern, ignoreCase) } catch (_: Exception) { return false }
        return try { regex.matches(guard(input, timeoutMs)) } catch (_: RegexTimeoutException) { false }
    }

    /**
     * Finds the first match of [pattern] in [input] in a single pass, or null on
     * oversize input, invalid pattern, no match, or timeout. The guard is disarmed
     * immediately after matching succeeds so capture-group access cannot throw.
     */
    fun find(
        pattern: String,
        input: CharSequence,
        ignoreCase: Boolean = false,
        maxInputLen: Int = DEFAULT_MAX_INPUT_LEN,
        timeoutMs: Long = DEFAULT_TIMEOUT_MS
    ): MatchResult? {
        if (input.length > maxInputLen) return null
        val regex = try { compile(pattern, ignoreCase) } catch (_: Exception) { return null }
        val guarded = guard(input, timeoutMs)
        val result = try { regex.find(guarded) } catch (_: RegexTimeoutException) { return null }
        guarded.disarm()
        return result
    }

    /**
     * Collects all matches of a precompiled [regex] in [input], stopping cleanly on timeout.
     * Returns an empty list on oversize input.
     */
    fun findAll(
        regex: Regex,
        input: CharSequence,
        maxInputLen: Int = DEFAULT_MAX_INPUT_LEN,
        timeoutMs: Long = DEFAULT_TIMEOUT_MS
    ): List<MatchResult> {
        if (input.length > maxInputLen) return emptyList()
        val guarded = guard(input, timeoutMs)
        val matches = ArrayList<MatchResult>()
        try {
            val iter = regex.findAll(guarded).iterator()
            while (iter.hasNext()) {
                matches.add(iter.next())
            }
        } catch (_: RegexTimeoutException) {
            // Keep matches collected before the deadline.
        } finally {
            guarded.disarm()
        }
        return matches
    }

    /**
     * Replaces all matches of [pattern] in [input] using [transform], returning null on oversize
     * input, invalid pattern, or timeout.
     */
    fun replaceOrNull(
        pattern: String,
        input: CharSequence,
        ignoreCase: Boolean = false,
        maxInputLen: Int = DEFAULT_MAX_INPUT_LEN,
        timeoutMs: Long = DEFAULT_TIMEOUT_MS,
        transform: (MatchResult) -> CharSequence
    ): String? {
        if (input.length > maxInputLen) return null
        val regex = try { compile(pattern, ignoreCase) } catch (_: Exception) { return null }
        val guarded = guard(input, timeoutMs)
        return try {
            regex.replace(guarded, transform)
        } catch (_: RegexTimeoutException) {
            null
        } catch (_: Exception) {
            null
        } finally {
            guarded.disarm()
        }
    }

    /**
     * Replaces all matches of [pattern] in [input] with [replacement]. On oversize
     * input, an invalid pattern, an invalid replacement reference (`$10`, `$foo`),
     * or a timeout, returns the input unchanged (so a bad rule never crashes or
     * hangs live traffic).
     */
    fun replace(
        pattern: String,
        input: CharSequence,
        replacement: String,
        ignoreCase: Boolean = false,
        maxInputLen: Int = DEFAULT_MAX_INPUT_LEN,
        timeoutMs: Long = DEFAULT_TIMEOUT_MS
    ): String {
        if (input.length > maxInputLen) return input.toString()
        val regex = try { compile(pattern, ignoreCase) } catch (_: Exception) { return input.toString() }
        return try {
            regex.replace(guard(input, timeoutMs), replacement)
        } catch (_: RegexTimeoutException) {
            input.toString()
        } catch (_: Exception) {
            input.toString()
        }
    }

    /** Matches a hostname against a wildcard glob (e.g. `*.example.com`) or regex (e.g. `.*`). */
    fun matchesHostPattern(pattern: String, host: String): Boolean {
        if (pattern == "*") return true
        val regexPattern = if (looksLikeRegex(pattern)) {
            pattern
        } else {
            pattern.split('*').joinToString(".*") { Regex.escape(it) }
        }
        return matches(regexPattern, host, ignoreCase = true)
    }

    private fun looksLikeRegex(pattern: String): Boolean =
        pattern.contains(".*") || pattern.contains(".+") || pattern.contains("\\") ||
            pattern.contains('[') || pattern.contains('(') || pattern.contains('^') ||
            pattern.contains('$') || pattern.contains('+') || pattern.contains('?') ||
            pattern.contains('|') || pattern.contains('{')

    private fun guard(input: CharSequence, timeoutMs: Long): InterruptibleCharSequence {
        val deadlineNs = System.nanoTime() + timeoutMs * 1_000_000
        return InterruptibleCharSequence(input) { System.nanoTime() > deadlineNs }
    }
}
