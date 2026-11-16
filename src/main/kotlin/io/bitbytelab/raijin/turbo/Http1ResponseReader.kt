package io.bitbytelab.raijin.turbo

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.ConnectException
import java.net.Socket
import java.net.SocketTimeoutException
import javax.net.ssl.SSLProtocolException

/** Where [Http1ResponseReader] gets its bytes: a connection's input and its read timeout. */
internal interface Http1Source {
    /** Reads up to [length] bytes into [buffer] at [offset]; -1 at the end of the stream. */
    fun read(buffer: ByteArray, offset: Int, length: Int): Int

    /** The read timeout in milliseconds (`Socket.soTimeout`). */
    var readTimeoutMillis: Int
}

internal class SocketHttp1Source(private val socket: Socket) : Http1Source {
    private val input = socket.getInputStream()

    override fun read(buffer: ByteArray, offset: Int, length: Int): Int = input.read(buffer, offset, length)

    override var readTimeoutMillis: Int
        get() = socket.soTimeout
        set(value) {
            socket.soTimeout = value
        }
}

/** One framed response. [interim] holds the 1xx responses that came before [head], in order. */
internal class Http1Response(
    val interim: String,
    /** The status line and headers, up to and including the blank line. */
    val head: String,
    /** The body as received; de-chunked when the response was chunked. */
    val body: ByteArray,
    /** When the bytes that completed [head] arrived (System.nanoTime). */
    val headCompletedAt: Long,
    /** When the last byte of the response arrived (System.nanoTime). */
    val lastByteAt: Long,
    /** The response ran to the end of the connection, or was cut short: nothing more can follow it. */
    val closeConnection: Boolean,
)

/**
 * Frames HTTP/1.1 responses off one connection for [ThreadedRequestEngine]. Bytes stay bytes
 * until a response is complete (bodies are never decoded before decompression), the buffer grows
 * by doubling instead of by string concatenation, and every read is stamped with its arrival
 * time, so each response in a pipelined batch is timed by when its own bytes came in.
 */
internal class Http1ResponseReader(
    private val source: Http1Source,
    readSize: Int,
    private val onRead: (String) -> Unit = {},
    private val shouldAbandon: () -> Boolean = { false },
    private val clock: () -> Long = System::nanoTime,
) {
    private class Arrival(val endOffset: Long, val atNanos: Long)

    private val readSize = readSize.coerceAtLeast(1)
    private var buffer = ByteArray(maxOf(INITIAL_CAPACITY, this.readSize * 2))
    private var start = 0
    private var end = 0
    /** Stream offset of buffer[0]: arrivals are kept by stream offset, so compaction leaves them valid. */
    private var origin = 0L
    private val arrivals = ArrayDeque<Arrival>()
    /** Bytes after [start] already searched for the end of a header block. */
    private var headScanned = 0
    /** When the most recently consumed byte arrived. */
    private var lastTakenAt = 0L

    private val buffered: Int get() = end - start

    /** Drops everything buffered; the engine starts every batch on a clean buffer. */
    fun discard() {
        origin += end
        start = 0
        end = 0
        headScanned = 0
        arrivals.clear()
    }

    /**
     * One read bounded by [timeoutMillis], for whatever arrives while a request is held part-sent.
     * The bytes join the buffer, ahead of the response they belong to. Returns how many arrived.
     */
    fun readWithin(timeoutMillis: Int): Int {
        val before = buffered
        val previous = source.readTimeoutMillis
        source.readTimeoutMillis = timeoutMillis
        try {
            fill()
        } catch (_: IOException) {
            // Nothing in time, or the connection failed: the send carries on and finds out.
        } finally {
            restoreReadTimeout(previous)
        }
        return buffered - before
    }

    /**
     * Reads the next response. With [ignoreLength] the length headers are ignored, and so are
     * interim responses: whatever arrives until the connection goes quiet is the response.
     * Returns null when the run is abandoned before the response is complete.
     */
    fun readResponse(ignoreLength: Boolean): Http1Response? {
        val interim = StringBuilder()
        var headEnd: Int
        while (true) {
            headEnd = findHeadEnd()
            if (headEnd != -1) {
                if (!ignoreLength && isInterim(headEnd)) {
                    interim.append(takeString(headEnd - start))
                    continue
                }
                break
            }
            if (shouldAbandon()) return null
            if (buffered >= MAX_RESPONSE_BYTES) {
                throw ConnectException("Response headers too large - 10mb max")
            }
            val more = try {
                fill()
            } catch (timeout: SocketTimeoutException) {
                // After an interim response, silence means no final one is coming.
                if (interim.isEmpty()) throw timeout
                false
            }
            if (!more) break
        }

        if (headEnd == -1) {
            if (buffered > 0) throw ConnectException("Unterminated response: '${bufferedString()}'")
            if (interim.isEmpty()) throw ConnectException("No response")
            // Only an interim response arrived: it is all there is to report. The final one may
            // still turn up, so the connection is not used again.
            return Http1Response("", interim.toString(), EMPTY_BODY, lastTakenAt, lastTakenAt, closeConnection = true)
        }

        val head = takeString(headEnd - start)
        val headCompletedAt = lastTakenAt
        val contentLength = contentLength(head)
        if (contentLength > MAX_RESPONSE_BYTES) {
            throw ConnectException("Response too large - 10mb max")
        }

        var closeConnection = false
        val body: ByteArray
        if (!ignoreLength && contentLength != -1) {
            while (buffered < contentLength) {
                if (shouldAbandon()) return null
                if (!fill()) {
                    // Closed early: keep what arrived.
                    closeConnection = true
                    break
                }
            }
            body = takeBytes(minOf(contentLength, buffered))
        } else if (!ignoreLength && isChunked(head)) {
            body = readChunkedBody() ?: return null
        } else {
            val quietMillis = when {
                ignoreLength -> 5000
                interim.isNotEmpty() -> 100
                else -> {
                    Utils.err("Response has no content-length - doing a one-second socket read instead. This is slow!")
                    closeConnection = true
                    1000
                }
            }
            if (!readUntilQuiet(quietMillis)) return null
            if (buffered > MAX_RESPONSE_BYTES) {
                Utils.err("Response without a length passed 10mb: keeping the first 10mb")
                closeConnection = true
            }
            body = takeBytes(minOf(buffered, MAX_RESPONSE_BYTES))
        }

        return Http1Response(interim.toString(), head, body, headCompletedAt, lastTakenAt, closeConnection)
    }

    /** Reads until the connection closes or stays quiet for [quietMillis]; false if the run was abandoned. */
    private fun readUntilQuiet(quietMillis: Int): Boolean {
        val previous = source.readTimeoutMillis
        source.readTimeoutMillis = quietMillis
        try {
            while (!shouldAbandon() && buffered <= MAX_RESPONSE_BYTES) {
                if (!fill()) break
            }
        } catch (_: SocketTimeoutException) {
        } catch (_: SSLProtocolException) {
        } catch (ex: Exception) {
            Utils.err("Exception during timed read: $ex")
        } finally {
            // The connection may carry more requests, at the timeout they were sent with.
            restoreReadTimeout(previous)
        }
        return !shouldAbandon()
    }

    private fun readChunkedBody(): ByteArray? {
        val body = ByteArrayOutputStream()
        while (true) {
            val sizeLineEnd = awaitLineEnd() ?: return null
            val size = chunkSize(sizeLineEnd)
            skip(sizeLineEnd + 2 - start)
            if (size == 0) {
                // Trailer fields, then the blank line that ends the message. Skipping just two bytes
                // left any trailer in front of the next response.
                while (true) {
                    val lineEnd = awaitLineEnd() ?: return null
                    val blank = lineEnd == start
                    skip(lineEnd + 2 - start)
                    if (blank) return body.toByteArray()
                }
            }
            if (body.size() + size > MAX_RESPONSE_BYTES) {
                throw ConnectException("Response too large - 10mb max")
            }
            if (!awaitBuffered(size + 2)) return null
            body.write(buffer, start, size)
            skip(size + 2)
        }
    }

    /** The index of the CRLF ending the line at [start]; null if the run was abandoned first. */
    private fun awaitLineEnd(): Int? {
        var scanned = 0
        while (true) {
            val crlf = Utils.indexOf(buffer, CRLF, start + scanned, end)
            if (crlf != -1) return crlf
            scanned = maxOf(0, buffered - 1)
            if (shouldAbandon()) return null
            if (buffered >= MAX_RESPONSE_BYTES) throw ConnectException("Response too large - 10mb max")
            if (!fill()) throw RuntimeException("Chunked response finished unexpectedly")
        }
    }

    private fun awaitBuffered(count: Int): Boolean {
        while (buffered < count) {
            if (shouldAbandon()) return false
            if (!fill()) throw RuntimeException("Chunked response finished unexpectedly")
        }
        return true
    }

    private fun chunkSize(lineEnd: Int): Int {
        val line = String(buffer, start, lineEnd - start, Charsets.ISO_8859_1)
        // Chunk extensions (";name=value") carry nothing the body needs.
        val size = line.substringBefore(';').trim().toIntOrNull(16)
        if (size == null || size < 0) {
            throw RuntimeException("Can't parse followup chunk length '$line'")
        }
        return size
    }

    /** The index just past the next header block's blank line, or -1 while it is incomplete. */
    private fun findHeadEnd(): Int {
        val at = Utils.indexOf(buffer, HEAD_END, start + headScanned, end)
        if (at != -1) return at + HEAD_END.size
        headScanned = maxOf(0, buffered - (HEAD_END.size - 1))
        return -1
    }

    /** `HTTP/x 1xx` other than 101 (which switches protocols): a final response follows it. */
    private fun isInterim(headEnd: Int): Boolean {
        if (!startsWith(HTTP_PREFIX)) return false
        var space = start + HTTP_PREFIX.size
        while (space < headEnd && buffer[space] != SPACE) space++
        if (space + 3 >= headEnd) return false
        val first = buffer[space + 1]
        val second = buffer[space + 2]
        val third = buffer[space + 3]
        return first == ONE && isDigit(second) && isDigit(third) && !(second == ZERO && third == ONE)
    }

    private fun startsWith(prefix: ByteArray): Boolean {
        if (buffered < prefix.size) return false
        for (i in prefix.indices) {
            if (buffer[start + i] != prefix[i]) return false
        }
        return true
    }

    /** Reads once into the buffer; false at the end of the stream. */
    private fun fill(): Boolean {
        ensureRoom(readSize)
        val read = source.read(buffer, end, readSize)
        if (read < 0) return false
        val chunkStart = end
        end += read
        arrivals.addLast(Arrival(origin + end, clock()))
        onRead(String(buffer, chunkStart, read, Charsets.ISO_8859_1))
        return true
    }

    private fun ensureRoom(extra: Int) {
        if (buffer.size - end >= extra) return
        val live = buffered
        if (start >= live && buffer.size - live >= extra) {
            // Moves no more bytes than it frees, so compaction stays linear overall.
            System.arraycopy(buffer, start, buffer, 0, live)
        } else {
            var capacity = buffer.size * 2
            while (capacity - live < extra) capacity *= 2
            val grown = ByteArray(capacity)
            System.arraycopy(buffer, start, grown, 0, live)
            buffer = grown
        }
        origin += start
        end = live
        start = 0
    }

    /** Consumes [count] bytes, noting when the last of them arrived. */
    private fun skip(count: Int) {
        if (count <= 0) return
        val lastOffset = origin + start + count - 1
        lastTakenAt = arrivals.first { it.endOffset > lastOffset }.atNanos
        start += count
        headScanned = 0
        val consumedTo = origin + start
        while (arrivals.isNotEmpty() && arrivals.first().endOffset <= consumedTo) arrivals.removeFirst()
    }

    private fun takeString(count: Int): String =
        String(buffer, start, count, Charsets.ISO_8859_1).also { skip(count) }

    private fun takeBytes(count: Int): ByteArray =
        buffer.copyOfRange(start, start + count).also { skip(count) }

    private fun bufferedString(): String = String(buffer, start, buffered, Charsets.ISO_8859_1)

    private fun restoreReadTimeout(previous: Int) {
        try {
            source.readTimeoutMillis = previous
        } catch (_: IOException) {
            // The connection is already closed; nothing will read with it again.
        }
    }

    companion object {
        const val MAX_RESPONSE_BYTES = 10_000_000
        private const val INITIAL_CAPACITY = 8192
        private val EMPTY_BODY = ByteArray(0)
        private val HEAD_END = Utils.stringToBytes("\r\n\r\n")
        private val CRLF = Utils.stringToBytes("\r\n")
        private val HTTP_PREFIX = Utils.stringToBytes("HTTP/")
        private const val SPACE = ' '.code.toByte()
        private const val ZERO = '0'.code.toByte()
        private const val ONE = '1'.code.toByte()
        private const val NINE = '9'.code.toByte()

        private fun isDigit(value: Byte): Boolean = value >= ZERO && value <= NINE

        /** The first [name] field's value in [head] (status line first), matched case-insensitively. */
        fun headerValue(head: String, name: String): String? {
            var lineStart = head.indexOf('\n') + 1
            while (lineStart in 1 until head.length) {
                val lineEnd = head.indexOf('\n', lineStart).let { if (it == -1) head.length else it }
                val colon = lineStart + name.length
                if (colon < lineEnd && head[colon] == ':' && head.regionMatches(lineStart, name, 0, name.length, ignoreCase = true)) {
                    return head.substring(colon + 1, lineEnd).trim()
                }
                lineStart = lineEnd + 1
            }
            return null
        }

        /**
         * The Content-Length of a response [head], or -1 without one. Only the head is searched,
         * and the name matches in any case: searching the whole buffer for `Content-Length: `
         * missed `content-length` and could take a length from a body or from the next response.
         */
        fun contentLength(head: String): Int {
            val value = headerValue(head, "Content-Length") ?: return -1
            val length = value.toIntOrNull()
            if (length == null || length < 0) {
                throw RuntimeException("Can't parse content length '$value'")
            }
            return length
        }

        /** True when the last transfer coding of [head] is chunked. */
        fun isChunked(head: String): Boolean {
            val value = headerValue(head, "Transfer-Encoding") ?: return false
            return value.substringAfterLast(',').trim().equals("chunked", ignoreCase = true)
        }
    }
}
