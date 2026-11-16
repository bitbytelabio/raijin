package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.core.BodyText

/**
 * Output shaping shared by the proxy and Autorize tools: caller-supplied limits brought into the
 * range a tool supports, and raw HTTP messages made safe for a JSON result.
 */
internal object ProxyLimits {

    /**
     * [value] within [min]..[max]. An out-of-range value is served at the nearest bound and a note
     * is added to [notes] (returned in the result's `notes`) instead of failing the call.
     */
    fun clamp(name: String, value: Int, min: Int, max: Int, notes: MutableList<String>): Int {
        val clamped = value.coerceIn(min, max)
        if (clamped != value) notes += "$name $value is outside $min..$max; used $clamped"
        return clamped
    }

    /**
     * A raw HTTP message for a tool result: the head (request or status line and headers) as it
     * is, the body through [BodyText], so a binary body becomes a placeholder and a long one is cut
     * at [maxLength] characters without losing the head. A [maxLength] of null or below 1 uses
     * [BodyText.DEFAULT_MAX_LENGTH].
     */
    fun renderMessage(raw: String, maxLength: Int?, label: String): BodyText.Rendered {
        val boundary = raw.indexOf("\r\n\r\n")
        if (boundary < 0) return BodyText.render(raw, maxLength, label = label)
        val head = BodyText.stripLoneSurrogates(raw.substring(0, boundary + 4))
        val body = BodyText.render(raw.substring(boundary + 4), maxLength, label = "$label body")
        return BodyText.Rendered(head + body.text, body.binary, body.truncated, raw.length)
    }
}
