package io.bitbytelab.raijin.turbo.http

import io.bitbytelab.raijin.turbo.hp3.h3.qpack.FieldLine
import io.bitbytelab.raijin.turbo.hp3.translate.KettleEscapes
import java.util.Locale

data class BinaryHttpRequest(
    val fields: List<FieldLine>,
    val body: ByteArray,
    val authoredVersion: String,
)

object BinaryHttpRequestTranslator {
    private val prohibitedNormalFields = setOf(
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
    )

    /**
     * Turns an HTTP/1-style request into binary HTTP field lines. With [kettled], [KettleEscapes]
     * are decoded in the method, the path, every field name (where a backtick is a colon) and every
     * value, and fields are otherwise kept exactly as written.
     */
    fun translate(
        raw: String,
        scheme: String,
        defaultAuthority: String,
        kettled: Boolean,
    ): BinaryHttpRequest {
        val usesCrLf = raw.contains("\r\n")
        val headerTerminator = if (usesCrLf) "\r\n\r\n" else "\n\n"
        val lineSeparator = if (usesCrLf) "\r\n" else "\n"
        val sections = raw.split(headerTerminator, limit = 2)
        val headLines = sections[0].split(lineSeparator)
        require(headLines.isNotEmpty() && headLines[0].isNotBlank()) { "HTTP request line is missing" }

        val requestLine = headLines[0].split(" ", limit = 3)
        require(requestLine.size >= 2) { "Invalid HTTP request line: ${headLines[0]}" }
        val method = if (kettled) KettleEscapes.decode(requestLine[0]) else requestLine[0]
        val path = if (kettled) KettleEscapes.decode(requestLine[1]) else requestLine[1]
        val authoredVersion = requestLine.getOrElse(2) { "HTTP/1.1" }
        val parsedFields = headLines.drop(1).filter { it.isNotEmpty() }.map { parseField(it, kettled) }
        val decodedFields = parsedFields.map { field ->
            if (kettled) {
                FieldLine.of(KettleEscapes.decodeName(field.name), KettleEscapes.decode(field.value))
            } else {
                FieldLine.of(field.name.lowercase(Locale.ROOT), field.value)
            }
        }

        val pseudoHeaders = if (kettled) {
            decodedFields.filter { it.isPseudoHeader() }.toMutableList()
        } else {
            mutableListOf()
        }
        val suppliedPseudoHeaders = pseudoHeaders.mapTo(linkedSetOf()) { it.name() }
        val explicitAuthority = suppliedPseudoHeaders.contains(":authority")
        val firstHostIndex = decodedFields.indexOfFirst { it.name().equals("host", ignoreCase = true) }
        val derivedAuthority = if (firstHostIndex >= 0) decodedFields[firstHostIndex].value() else defaultAuthority

        addIfMissing(pseudoHeaders, suppliedPseudoHeaders, ":method", method)
        addIfMissing(pseudoHeaders, suppliedPseudoHeaders, ":scheme", scheme)
        addIfMissing(pseudoHeaders, suppliedPseudoHeaders, ":authority", derivedAuthority)
        addIfMissing(pseudoHeaders, suppliedPseudoHeaders, ":path", path)

        val regularFields = decodedFields.mapIndexedNotNull { index, field ->
            if (kettled && field.isPseudoHeader()) return@mapIndexedNotNull null
            if (!explicitAuthority && index == firstHostIndex) return@mapIndexedNotNull null
            if (!kettled && prohibitedNormalFields.contains(field.name())) return@mapIndexedNotNull null
            field
        }

        return BinaryHttpRequest(
            pseudoHeaders + regularFields,
            sections.getOrElse(1) { "" }.toByteArray(Charsets.ISO_8859_1),
            authoredVersion,
        )
    }

    /**
     * Splits a header line at its first colon, as an HTTP/1 parser does, so `Name:value` needs no
     * space; a pseudo-header's own leading colon belongs to its name. A kettled value loses only the
     * single space after the colon, keeping any deliberate whitespace; an ordinary value is trimmed
     * of optional whitespace.
     */
    private fun parseField(line: String, kettled: Boolean): FieldLine {
        val separator = line.indexOf(':', if (line.startsWith(':')) 1 else 0)
        if (separator < 0) {
            return FieldLine.of(line, "")
        }
        val value = line.substring(separator + 1)
        return FieldLine.of(
            line.substring(0, separator),
            if (kettled) value.removePrefix(" ") else value.trim(' ', '\t'),
        )
    }

    private fun addIfMissing(
        fields: MutableList<FieldLine>,
        supplied: MutableSet<String>,
        name: String,
        value: String,
    ) {
        if (supplied.add(name)) fields.add(FieldLine.of(name, value))
    }
}
