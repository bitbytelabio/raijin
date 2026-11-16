package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.core.BodyText
import io.bitbytelab.raijin.state.WebSocketMessage
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.util.Base64

/**
 * Frame conventions of the WebSocket tools. A binary frame travels as base64 in tool arguments and
 * results, and is seen by regexes (intercept rules, wait and fuzz filters) as ISO-8859-1 text: one
 * char per byte, so `\xNN` in a pattern addresses a raw byte and the way back to bytes is exact.
 */
internal object WebSocketFrames {

    /** The frame kinds a `message_type` parameter accepts. */
    val MESSAGE_TYPES = listOf("TEXT", "BINARY")

    /** [messageType] upper-cased; null when absent or blank. */
    fun normalizeMessageType(messageType: String?): String? =
        messageType?.trim()?.uppercase()?.takeIf { it.isNotEmpty() }

    /** The error for a [messageType] that is neither TEXT nor BINARY (case-insensitive), else null. */
    fun messageTypeError(messageType: String?): String? {
        val normalized = normalizeMessageType(messageType)
        if (normalized == null || normalized in MESSAGE_TYPES) return null
        return "Invalid message_type: '$messageType'. Must be 'TEXT' or 'BINARY'"
    }

    /** True for the recorded type of a binary frame ("BINARY", "BINARY_DROPPED", "BINARY_UNSENT"). */
    fun isBinary(type: String): Boolean = type.startsWith("BINARY")

    fun encodeBase64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    /**
     * Decodes base64 the way a caller is likely to supply it: standard or URL-safe alphabet, with or
     * without padding, whitespace and line breaks ignored. Null when [data] is not base64.
     */
    fun decodeBase64(data: String): ByteArray? {
        try {
            return Base64.getDecoder().decode(data)
        } catch (_: IllegalArgumentException) {
            // Not canonical: try the lenient reading below.
        }
        val cleaned = StringBuilder(data.length)
        for (ch in data) {
            when {
                ch == '-' -> cleaned.append('+')
                ch == '_' -> cleaned.append('/')
                ch.isWhitespace() -> Unit
                else -> cleaned.append(ch)
            }
        }
        var end = cleaned.length
        while (end > 0 && cleaned[end - 1] == '=') end--
        return try {
            Base64.getDecoder().decode(cleaned.substring(0, end))
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    /** [bytes] as text with one char per byte. */
    fun latin1(bytes: ByteArray): String = String(bytes, Charsets.ISO_8859_1)

    /** Inverse of [latin1]. A char above U+00FF has no byte and becomes `?`. */
    fun latin1Bytes(text: String): ByteArray = text.toByteArray(Charsets.ISO_8859_1)

    /** What a regex is matched against for [message]: a text frame's payload, a binary frame's bytes as [latin1]. */
    fun matchText(message: WebSocketMessage): String {
        if (!isBinary(message.type)) return message.payload
        return decodeBase64(message.payload)?.let { latin1(it) } ?: message.payload
    }

    /**
     * Byte length of [text] in UTF-8, computed without encoding it. An unpaired surrogate counts as
     * the single `?` the encoder writes for it, so this equals `text.toByteArray().size`.
     */
    fun utf8Length(text: String): Int {
        var bytes = 0
        var i = 0
        val length = text.length
        while (i < length) {
            val c = text[i]
            when {
                c.code < 0x80 -> bytes += 1
                c.code < 0x800 -> bytes += 2
                !c.isSurrogate() -> bytes += 3
                c.isHighSurrogate() && i + 1 < length && text[i + 1].isLowSurrogate() -> {
                    bytes += 4
                    i++
                }
                else -> bytes += 1
            }
            i++
        }
        return bytes
    }

    /**
     * [text] made safe for a JSON result (unpaired surrogates replaced) and, when [max] > 0, cut to at
     * most [max] chars without splitting a surrogate pair. A [base64] payload is cut on a 4-char
     * boundary instead (at least 4 chars), so the part that is kept still decodes.
     */
    fun clip(text: String, max: Int, base64: Boolean = false): String {
        if (base64) {
            if (max <= 0 || text.length <= max) return text
            return text.substring(0, minOf(text.length, maxOf(4, max - max % 4)))
        }
        val cut = if (max <= 0 || text.length <= max) text else BodyText.truncate(text, max)
        return BodyText.stripLoneSurrogates(cut)
    }

    /**
     * [message] as an entry of a tool result. [maxPayloadChars] > 0 cuts the payload (see [clip]) and
     * marks the entry `truncated`; `length` is always the full frame length in bytes. [brief] leaves
     * out the direction and the timestamp.
     */
    fun toJson(message: WebSocketMessage, maxPayloadChars: Int = 0, brief: Boolean = false): JsonObject = buildJsonObject {
        val payload = clip(message.payload, maxPayloadChars, isBinary(message.type))
        put("index", message.index)
        if (!brief) put("direction", message.direction)
        put("type", message.type)
        put("payload", payload)
        put("length", message.length)
        if (payload.length < message.payload.length) put("truncated", true)
        if (!brief) put("timestamp", message.timestamp)
    }
}
