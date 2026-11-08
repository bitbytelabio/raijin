package io.bitbytelab.raijin.turbo.mcp

data class TruncatedHttpBody(
    val fullBody: String,
    val limit: Int
) {
    val content: String
        get() = if (limit > 0 && fullBody.length > limit) fullBody.take(limit) else fullBody

    val truncated: Boolean
        get() = limit > 0 && fullBody.length > limit

    val totalLength: Int
        get() = fullBody.length

    fun toResponseFields(): Map<String, Any> = mapOf(
        "response_body" to content,
        "response_body_truncated" to truncated,
        "response_body_total_length" to totalLength
    )
}
