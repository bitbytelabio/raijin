package io.bitbytelab.raijin.recon

import io.bitbytelab.raijin.safety.InterruptibleCharSequence
import io.bitbytelab.raijin.safety.RegexTimeoutException

/**
 * Extracts endpoint paths and URLs from JavaScript source. SPAs expose much of
 * their API surface in JS, so harvesting it from proxy history surfaces routes
 * the agent was never explicitly handed.
 */
object JsEndpoints {
    /** Characters scanned per script; the rest of a larger bundle is left out. */
    const val MAX_SCAN_CHARS = 4_000_000

    /** Time one script may take: these patterns are linear, the bound is for input built to defeat them. */
    const val DEFAULT_BUDGET_MS = 2_000L

    private val quotedPath = Regex("""["'`](/[A-Za-z0-9_\-./:~@{}]+(?:\?[A-Za-z0-9_\-.=&%{}]*)?)["'`]""")
    private val urlPattern = Regex("""https?://[A-Za-z0-9._\-]+(?::[0-9]+)?(?:/[A-Za-z0-9_\-./?=&%#:~@]*)?""")

    // A template literal that is a path or URL with interpolations: `/users/${id}`, `${base}/items/${id}?x=1`.
    private val templateLiteral = Regex(
        """`((?:\$\{[^`{}]{1,80}\})?(?:https?://(?:[A-Za-z0-9._\-:]|\$\{[^`{}]{1,80}\})*)?/(?:[A-Za-z0-9_\-./:~@%?=&#]|\$\{[^`{}]{1,80}\})*)`"""
    )
    private val interpolation = Regex("""\$\{([^`{}]{1,80})\}""")

    /** @param complete false when the text was cut at [MAX_SCAN_CHARS] or the time ran out. */
    data class Scan(val endpoints: Set<String>, val complete: Boolean)

    fun extract(text: String): Set<String> = scan(text).endpoints

    /**
     * Endpoints in [text]: quoted absolute paths, full URLs, and template literals, whose
     * `${expr}` parts come back as `{expr}` (`/users/${id}` gives `/users/{id}`).
     */
    fun scan(text: String, budgetMs: Long = DEFAULT_BUDGET_MS): Scan {
        val limited = if (text.length > MAX_SCAN_CHARS) text.substring(0, MAX_SCAN_CHARS) else text
        val deadline = System.nanoTime() + budgetMs * 1_000_000
        val guarded = InterruptibleCharSequence(limited) { System.nanoTime() > deadline }
        val out = linkedSetOf<String>()
        var complete = text.length <= MAX_SCAN_CHARS
        try {
            for (match in quotedPath.findAll(guarded)) {
                val path = match.groupValues[1]
                if (!path.startsWith("//")) out.add(path) // drop protocol-relative noise
            }
            for (match in templateLiteral.findAll(guarded)) {
                val literal = match.groupValues[1]
                if (literal.contains("\${")) out.add(interpolation.replace(literal) { "{" + it.groupValues[1].trim() + "}" })
            }
            for (match in urlPattern.findAll(guarded)) out.add(match.value)
        } catch (_: RegexTimeoutException) {
            complete = false
        }
        return Scan(out, complete)
    }
}
