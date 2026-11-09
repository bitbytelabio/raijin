package io.bitbytelab.raijin.graphql

/**
 * Expands a GraphQL query containing a `$[INT:first:last]` or `$[LIST]` placeholder into N
 * aliased sub-operations inside one selection set — the batching/alias-attack shape used for
 * 2FA brute force, IDOR enumeration, and rate-limit-bypass testing (many "requests" riding
 * inside one HTTP request). Ported from InQL's `Attacker.generateAttackRequest()` (same
 * brace-peeling + placeholder regex approach).
 *
 * Differs from InQL's `$[FILE:path[:first:last]]` variant: rather than reading a path on the
 * MCP server's filesystem, [values] is supplied directly by the caller via `$[LIST]` — strictly
 * more composable for an agent, and avoids giving an MCP tool a new local-file-read capability.
 */
object BatchAttack {
    data class Result(val query: String, val count: Int)

    private val outerBraces = Regex("^([^{]*?)\\{(.+)}([^}]*?)$", RegexOption.DOT_MATCHES_ALL)
    private val intPlaceholder = Regex("^(.*?)\\$\\[INT:(\\d+):(\\d+)](.*)$", RegexOption.DOT_MATCHES_ALL)
    private val listPlaceholder = Regex("^(.*?)\\$\\[LIST](.*)$", RegexOption.DOT_MATCHES_ALL)

    /**
     * Expands the outermost `$[INT:...]`/`$[LIST]` placeholder found in [query] (peeling one
     * `{...}` layer at a time until one is found immediately before an opening brace, matching
     * InQL's original descent). Returns null if no placeholder is found, or (for `$[LIST]`)
     * [values] is null/empty.
     */
    fun expand(query: String, values: List<String>? = null): Result? {
        var remaining = query.trim()
        var prefix = ""
        var suffix = ""

        while (true) {
            val m = outerBraces.matchEntire(remaining) ?: return null
            val pfx = m.groupValues[1]
            val inner = m.groupValues[2]
            val sfx = m.groupValues[3]

            val intMatch = intPlaceholder.matchEntire(pfx)
            val listMatch = if (intMatch == null) listPlaceholder.matchEntire(pfx) else null

            if (intMatch == null && listMatch == null) {
                prefix += "$pfx{"
                suffix = "}$sfx$suffix"
                remaining = inner
                continue
            }

            val sb = StringBuilder()
            var count = 0
            if (intMatch != null) {
                val leading = intMatch.groupValues[1]
                val start = intMatch.groupValues[2].toInt()
                val end = intMatch.groupValues[3].toInt()
                val trailing = intMatch.groupValues[4]
                for (n in start until end) {
                    sb.append("op$n: $leading$trailing{$inner}$sfx".replace("\$INT", n.toString()))
                    count++
                }
            } else if (listMatch != null) {
                val leading = listMatch.groupValues[1]
                val trailing = listMatch.groupValues[2]
                for ((n, value) in (values ?: emptyList()).withIndex()) {
                    sb.append("op$n: $leading$trailing{$inner}$sfx".replace("\$LIST", value))
                    count++
                }
            }
            if (count == 0) return null
            return Result(prefix + sb.toString() + suffix, count)
        }
    }
}
