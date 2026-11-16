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

    /** A template that cannot be expanded: an unusable range, or a result past [MAX_OPERATIONS] / [MAX_QUERY_CHARS]. */
    class ExpansionException(message: String) : IllegalArgumentException(message)

    /**
     * Most sub-operations one expansion may produce. The whole query is built in memory (and again
     * as a JSON body and a request), so `$[INT:0:2000000000]` would exhaust the heap long before a
     * server saw it; a larger run is split over several requests.
     */
    const val MAX_OPERATIONS = 10_000

    /** Most characters one expanded query may reach, whatever its operation count. */
    const val MAX_QUERY_CHARS = 8_000_000

    private val outerBraces = Regex("^([^{]*?)\\{(.+)}([^}]*?)$", RegexOption.DOT_MATCHES_ALL)
    private val intPlaceholder = Regex("^(.*?)\\$\\[INT:(\\d+):(\\d+)](.*)$", RegexOption.DOT_MATCHES_ALL)
    private val listPlaceholder = Regex("^(.*?)\\$\\[LIST](.*)$", RegexOption.DOT_MATCHES_ALL)

    /**
     * Expands the outermost `$[INT:...]`/`$[LIST]` placeholder found in [query] (peeling one
     * `{...}` layer at a time until one is found immediately before an opening brace, matching
     * InQL's original descent). Returns null if no placeholder is found, or (for `$[LIST]`)
     * [values] is null/empty.
     *
     * @throws ExpansionException when the range is empty or malformed, or the expansion would
     *   produce more than [maxOperations] sub-operations or more than [MAX_QUERY_CHARS] characters.
     */
    fun expand(query: String, values: List<String>? = null, maxOperations: Int = MAX_OPERATIONS): Result? {
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

            val sb = StringBuilder(prefix)
            val tail = suffix
            fun add(operation: String) {
                sb.append(operation)
                if (sb.length + tail.length > MAX_QUERY_CHARS) {
                    throw ExpansionException(
                        "The expanded query would exceed $MAX_QUERY_CHARS characters. " +
                            "Split the range or value list over several calls."
                    )
                }
            }
            var count = 0
            if (intMatch != null) {
                val leading = intMatch.groupValues[1]
                val first = intMatch.groupValues[2].toLongOrNull()
                val last = intMatch.groupValues[3].toLongOrNull()
                val trailing = intMatch.groupValues[4]
                if (first == null || last == null) {
                    throw ExpansionException(
                        "\$[INT:${intMatch.groupValues[2]}:${intMatch.groupValues[3]}]: both bounds must fit a 64-bit integer."
                    )
                }
                if (last <= first) {
                    throw ExpansionException(
                        "\$[INT:$first:$last] is an empty range: 'last' is exclusive and must be greater than 'first'."
                    )
                }
                requireWithinLimit(last - first, maxOperations)
                for (n in first until last) {
                    add("op$n: $leading$trailing{$inner}$sfx".replace("\$INT", n.toString()))
                    count++
                }
            } else if (listMatch != null) {
                val leading = listMatch.groupValues[1]
                val trailing = listMatch.groupValues[2]
                val items = values ?: emptyList()
                requireWithinLimit(items.size.toLong(), maxOperations)
                for ((n, value) in items.withIndex()) {
                    add("op$n: $leading$trailing{$inner}$sfx".replace("\$LIST", value))
                    count++
                }
            }
            if (count == 0) return null
            return Result(sb.append(tail).toString(), count)
        }
    }

    private fun requireWithinLimit(operations: Long, maxOperations: Int) {
        if (operations > maxOperations) {
            throw ExpansionException(
                "The template expands to $operations sub-operations; the limit is $maxOperations per request. " +
                    "Split the range or value list over several calls."
            )
        }
    }
}
