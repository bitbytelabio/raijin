package io.bitbytelab.raijin.core

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive

/**
 * Truncates a [JsonElement] for display/logging (the MCP Activity tab's argument summary),
 * keeping it valid JSON rather than double-encoding it.
 *
 * The previous call site ([io.bitbytelab.raijin.transport.ToolCallTracker]) called
 * `value.toString()` on each argument — which for a string [JsonPrimitive] already returns
 * *quoted* JSON text (e.g. the 7 characters `"start"`) — and stored that text as a **new**
 * string value. The outer object's own `.toString()` then re-escaped those embedded quotes and
 * backslashes, corrupting every argument into unreadable double-encoded JSON (`\"start\"`,
 * doubled `\\r\\n`) in the Activity tab, the persisted `.raijin-activity.jsonl` history, and the
 * web dashboard's `tool.called` event payload alike. This truncates the *content* of a string
 * primitive instead of its re-quoted form, so the result stays single-encoded.
 */
fun truncateJsonForSummary(value: JsonElement, maxLen: Int): JsonElement = when {
    value is JsonPrimitive && !value.isString -> value // numbers/booleans/null: short, pass through
    value is JsonPrimitive -> {
        val c = value.content
        JsonPrimitive(if (c.length > maxLen) c.take(maxLen) + "…" else c)
    }
    else -> {
        // Object/array: keep the real structure (so it stays a real nested object in the
        // Activity view, not a mangled string) unless its serialized form is itself huge.
        val s = value.toString()
        if (s.length <= maxLen) value else JsonPrimitive(s.take(maxLen) + "… [truncated ${s.length} chars]")
    }
}
