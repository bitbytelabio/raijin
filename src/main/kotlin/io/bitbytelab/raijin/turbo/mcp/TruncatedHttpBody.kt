package io.bitbytelab.raijin.turbo.mcp

/**
 * A response body cut to its first [limit] lines (`\n` or `\r\n` terminated); [limit] 0 or less
 * keeps it whole. Lines rather than characters, as `turbo_run_result`'s `body_limit` promises:
 * a cut never lands mid-line.
 */
data class TruncatedHttpBody(
    val fullBody: String,
    val limit: Int
) {
    /** Index of the `\n` ending line [limit] when more of the body follows it, else null. */
    private val cutAt: Int? = run {
        if (limit <= 0) return@run null
        var newline = -1
        repeat(limit) {
            newline = fullBody.indexOf('\n', newline + 1)
            if (newline < 0) return@run null
        }
        newline.takeIf { it < fullBody.lastIndex }
    }

    val content: String
        get() = cutAt?.let { fullBody.substring(0, it).removeSuffix("\r") } ?: fullBody

    val truncated: Boolean
        get() = cutAt != null

    /** Characters in the whole body. */
    val totalLength: Int
        get() = fullBody.length

    /** Lines in the whole body; a final line without a terminator counts. */
    val totalLines: Int
        get() = if (fullBody.isEmpty()) 0 else fullBody.count { it == '\n' } + if (fullBody.endsWith('\n')) 0 else 1

    fun toResponseFields(): Map<String, Any> = mapOf(
        "response_body" to content,
        "response_body_truncated" to truncated,
        "response_body_total_length" to totalLength,
        "response_body_total_lines" to totalLines
    )
}
