package io.bitbytelab.raijin.turbo.mcp

import io.bitbytelab.raijin.core.BodyText

/**
 * A response body cut to its first [limit] lines (`\n` or `\r\n` terminated); [limit] 0 or less
 * keeps it whole. Lines rather than characters, as `turbo_run_result`'s `body_limit` promises,
 * so a cut normally lands on a line boundary. A limited body is also capped at [MAX_CHARS]
 * characters, so one huge line (minified JS, a JSON blob) cannot flood the result.
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

    private val byLines: String
        get() = cutAt?.let { fullBody.substring(0, it).removeSuffix("\r") } ?: fullBody

    private val overCharCap: Boolean
        get() = limit > 0 && byLines.length > MAX_CHARS

    val content: String
        get() = if (overCharCap) BodyText.truncate(byLines, MAX_CHARS) else byLines

    val truncated: Boolean
        get() = cutAt != null || overCharCap

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

    companion object {
        /** Character cap on a line-limited body. */
        const val MAX_CHARS = BodyText.DEFAULT_MAX_LENGTH
    }
}
