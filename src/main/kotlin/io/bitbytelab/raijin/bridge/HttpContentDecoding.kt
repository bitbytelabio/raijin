package io.bitbytelab.raijin.bridge

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.util.zip.GZIPInputStream
import java.util.zip.Inflater
import java.util.zip.InflaterInputStream

/**
 * Undoes the `Content-Encoding` of a response body read off one of Raijin's own sockets, where
 * Burp is not there to do it, and renders raw bytes for a tool result.
 */
internal object HttpContentDecoding {

    const val DEFAULT_MAX_BYTES = 10_000_000

    private const val HEX = "0123456789abcdef"

    /**
     * @param body the body as received when nothing was undone, else the decoded bytes; when
     *   [error] is set they stop where a broken stream broke off or at the size cap.
     * @param applied codings undone, in the order they were undone (the last listed first).
     * @param error why decoding stopped short of a complete body: an unknown or unavailable
     *   coding, a broken stream, or the size cap.
     */
    class Decoded(val body: ByteArray, val applied: List<String>, val error: String? = null)

    /**
     * Output of undoing one coding: [bytes] decoded before [error] (null when the whole stream
     * decoded); [capped] when decoding stopped at the size cap rather than on a broken stream.
     */
    private class Inflated(val bytes: ByteArray, val error: String?, val capped: Boolean = false)

    /**
     * Decodes [body] per a `Content-Encoding` header value (`gzip`, `x-gzip`, `deflate`, `br`;
     * several codings are undone last to first, `identity` is skipped). `deflate` is tried as zlib
     * and then as a raw deflate stream, since servers send both.
     *
     * @param brotli decoder for `br`, which the JDK does not have (Burp's, when running in Burp);
     *   it fails by throwing.
     * @param maxBytes cap on the decoded size of each coding.
     */
    fun decode(
        body: ByteArray,
        contentEncoding: String?,
        brotli: ((ByteArray) -> ByteArray)? = null,
        maxBytes: Int = DEFAULT_MAX_BYTES,
    ): Decoded {
        val codings = contentEncoding.orEmpty().split(',').map { it.trim().lowercase() }
            .filter { it.isNotEmpty() && it != "identity" }
        if (codings.isEmpty() || body.isEmpty()) return Decoded(body, emptyList())
        var current = body
        val applied = ArrayList<String>(codings.size)
        for (coding in codings.asReversed()) {
            val input = current
            val step = when (coding) {
                "gzip", "x-gzip" -> inflate(maxBytes) { GZIPInputStream(ByteArrayInputStream(input)) }
                "deflate" -> inflateDeflate(input, maxBytes)
                "br" -> brotli?.let { decodeWith(it, input, maxBytes) }
                    ?: return Decoded(input, applied, "br decoding is not available here")
                else -> return Decoded(input, applied, "unknown content coding '$coding'")
            }
            if (step.error == null) {
                current = step.bytes
                applied += coding
                continue
            }
            if (step.capped) return Decoded(step.bytes, applied + coding, "${step.error}; decoding stopped there")
            // A stream that broke off part way still yields what came before the break.
            if (step.bytes.isEmpty()) return Decoded(input, applied, "$coding decoding failed: ${step.error}")
            return Decoded(step.bytes, applied + coding, "$coding stream is broken (${step.error}); the body is what decoded before that")
        }
        return Decoded(current, applied)
    }

    private fun decodeWith(decoder: (ByteArray) -> ByteArray, data: ByteArray, maxBytes: Int): Inflated {
        val decoded = try {
            decoder(data)
        } catch (e: Exception) {
            return Inflated(ByteArray(0), e.message ?: e.javaClass.simpleName)
        }
        if (decoded.size > maxBytes) return Inflated(decoded.copyOf(maxBytes), "decoded body exceeds $maxBytes bytes", capped = true)
        return Inflated(decoded, null)
    }

    /**
     * zlib first (what `deflate` means, RFC 9110 §8.4.1.2), then a raw deflate stream. A clean
     * decode wins; when both break, the one that got further.
     */
    private fun inflateDeflate(data: ByteArray, maxBytes: Int): Inflated {
        val zlib = inflateWith(Inflater(false), data, maxBytes)
        if (zlib.error == null || zlib.capped) return zlib
        val raw = inflateWith(Inflater(true), data, maxBytes)
        if (raw.error == null || raw.capped) return raw
        return if (raw.bytes.size > zlib.bytes.size) raw else zlib
    }

    private fun inflateWith(inflater: Inflater, data: ByteArray, maxBytes: Int): Inflated = try {
        inflate(maxBytes) { InflaterInputStream(ByteArrayInputStream(data), inflater) }
    } finally {
        inflater.end()
    }

    /** Reads the stream [open] returns to its end or to [maxBytes]; a stream that breaks keeps what it gave before. */
    private fun inflate(maxBytes: Int, open: () -> InputStream): Inflated {
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        return try {
            open().use { stream ->
                while (true) {
                    val read = stream.read(buffer)
                    if (read < 0) break
                    if (out.size() + read > maxBytes) {
                        out.write(buffer, 0, maxBytes - out.size())
                        return Inflated(out.toByteArray(), "decoded body exceeds $maxBytes bytes", capped = true)
                    }
                    out.write(buffer, 0, read)
                }
            }
            Inflated(out.toByteArray(), null)
        } catch (e: Exception) {
            Inflated(out.toByteArray(), e.message ?: e.javaClass.simpleName)
        }
    }

    /** [bytes] as text: UTF-8 when they are valid UTF-8, else ISO-8859-1 (one char per byte). */
    fun text(bytes: ByteArray): String = try {
        Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    } catch (_: CharacterCodingException) {
        String(bytes, Charsets.ISO_8859_1)
    }

    /** Lowercase hex of [bytes]. */
    fun hex(bytes: ByteArray): String {
        val out = StringBuilder(bytes.size * 2)
        for (byte in bytes) {
            val value = byte.toInt() and 0xFF
            out.append(HEX[value shr 4]).append(HEX[value and 0x0F])
        }
        return out.toString()
    }

    /**
     * Lowercase hex of the first [limit] bytes of [wire], a byte string held as ISO-8859-1 chars
     * (how [HttpPipelineFraming] keeps what it reads).
     */
    fun hex(wire: CharSequence, limit: Int = Int.MAX_VALUE): String {
        val count = minOf(wire.length, limit)
        val out = StringBuilder(count * 2)
        for (i in 0 until count) {
            val value = wire[i].code and 0xFF
            out.append(HEX[value shr 4]).append(HEX[value and 0x0F])
        }
        return out.toString()
    }
}
