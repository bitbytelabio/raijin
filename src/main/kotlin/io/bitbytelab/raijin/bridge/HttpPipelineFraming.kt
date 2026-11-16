package io.bitbytelab.raijin.bridge

import java.io.IOException
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException

/**
 * Dependency-free HTTP/1.1 response framing reader. A [Reader] reads the responses on one socket
 * one [Reader.next] call at a time, so [HttpPipelineBridge] can pipeline several raw requests over
 * one connection and read the responses back in order; [readOne] reads a single response.
 *
 * Uses the same byte<->ISO-8859-1-String bijection Turbo's
 * [io.bitbytelab.raijin.turbo.ThreadedRequestEngine] uses for its own HTTP/1.1 parsing, so no byte
 * is ever lost or corrupted.
 *
 * Framing is strict, because a framing disagreement with the target is the finding this tool exists
 * to surface: anything it cannot frame unambiguously (bad or conflicting Content-Length, bad chunk
 * size, chunk data without its CRLF) ends in [Outcome.Malformed] instead of a guess or an exception.
 *
 * Every outcome also says what arrived on the wire for its response ([Received]): the bytes exactly
 * as read and when the first and the last of them were read off the socket.
 */
internal object HttpPipelineFraming {

    const val DEFAULT_MAX_RESPONSE_BYTES = 10_000_000

    /** Consumed bytes are dropped from the read buffer in bulk once there are at least this many. */
    private const val COMPACT_AFTER = 65_536

    data class Response(
        val statusLine: String,
        val statusCode: Int,
        val headers: List<Pair<String, String>>,
        val body: String,
        val framing: String, // "content-length" | "chunked" | "close-delimited" | "no-body" | "switching-protocols"
        val connectionCloseHeader: Boolean,
        val warnings: List<String>,
        val trailers: List<Pair<String, String>> = emptyList(),
    ) {
        /**
         * Whether the connection can carry another request after this response: not after
         * `Connection: close`, a close-delimited body, a protocol switch (101), or an HTTP/1.0
         * response without `Connection: keep-alive` (RFC 9112 §9.3).
         */
        val persistent: Boolean
            get() = !connectionCloseHeader && statusCode != 101 &&
                (!statusLine.startsWith("HTTP/1.0") ||
                    headers.any { it.first.equals("Connection", ignoreCase = true) && it.second.contains("keep-alive", ignoreCase = true) })
    }

    /**
     * What arrived on the wire for one response: everything from its first byte (that of any 1xx
     * absorbed before it) through its last (chunk framing and trailers included), or, when reading
     * failed, through the last byte that arrived.
     *
     * @param bytes the first of those bytes as ISO-8859-1 chars, up to the reader's capture cap
     *   (empty when capture is off).
     * @param length how many bytes arrived for the response.
     * @param firstByteAtNanos [System.nanoTime] after the read that delivered the first byte (for
     *   bytes carried over from an earlier read, that read). Meaningless when [length] is 0.
     * @param lastByteAtNanos the same for the last byte.
     */
    class Received(val bytes: String, val length: Int, val firstByteAtNanos: Long, val lastByteAtNanos: Long) {
        /** [bytes] holds fewer bytes than arrived. */
        val truncated: Boolean get() = bytes.length < length

        companion object {
            val NONE = Received("", 0, 0L, 0L)
        }
    }

    sealed class Outcome(val bytesReadFromSocket: Int, val received: Received) {
        class Ok(val response: Response, bytesReadFromSocket: Int, received: Received = Received.NONE) :
            Outcome(bytesReadFromSocket, received) {
            /** [System.nanoTime] when the response's first byte (of a 1xx before it, if any) was read off the socket. */
            val firstByteAtNanos: Long get() = received.firstByteAtNanos

            /** [System.nanoTime] when the response's last byte was read off the socket. */
            val lastByteAtNanos: Long get() = received.lastByteAtNanos
        }
        class Eof(val partial: String, bytesReadFromSocket: Int, received: Received = Received.NONE) :
            Outcome(bytesReadFromSocket, received)
        class TimedOut(val partial: String, val kind: String, bytesReadFromSocket: Int, received: Received = Received.NONE) :
            Outcome(bytesReadFromSocket, received)
        class Reset(val partial: String, val message: String, bytesReadFromSocket: Int, received: Received = Received.NONE) :
            Outcome(bytesReadFromSocket, received)
        class Malformed(val reason: String, val partial: String, bytesReadFromSocket: Int, received: Received = Received.NONE) :
            Outcome(bytesReadFromSocket, received)
    }

    /** The code writing requests on the socket a [Reader] reads, while it reads. */
    interface Activity {
        /** Called on the reading thread right after a read returned data. */
        fun dataArrived()

        /**
         * [System.currentTimeMillis] from which the idle timeout may count (it counts from the
         * latest data when that is later), or null while it must not run at all because requests
         * are still being written.
         */
        fun quietSinceMs(): Long?
    }

    private sealed class ReadResult {
        object Data : ReadResult()
        object Eof : ReadResult()
        object TimedOut : ReadResult()
        class Errored(val message: String) : ReadResult()
    }

    /** A body read to its end, or the [Outcome] that ended the response before that. */
    private sealed class Body {
        class Read(val text: String, val trailers: List<Pair<String, String>> = emptyList()) : Body()
        class Failed(val outcome: Outcome) : Body()
    }

    private class ChunkParseException(message: String) : Exception(message)

    private val STATUS_LINE = Regex("""^HTTP/\d\.\d\s+(\d+)""")

    /**
     * Reads exactly one HTTP/1.1 response from [socket]. [carry] holds bytes already pulled off
     * the wire past this response's boundary (pipelined ahead by the server) so they are handed to
     * the *next* [readOne] call rather than lost or re-read. [carry] is only appended to on the
     * [Outcome.Ok] path — any other outcome means the caller stops reading from this socket, so
     * there is no "next call" to hand leftover bytes to.
     *
     * @param carryReadAtNanos when the bytes in [carry] were read: the [Outcome.Ok.lastByteAtNanos]
     *   of the call that left them there. Null dates them at the start of this call.
     */
    fun readOne(
        socket: Socket,
        carry: StringBuilder,
        idleTimeoutMs: Long,
        totalDeadlineAtMs: Long,
        maxResponseBytes: Int = DEFAULT_MAX_RESPONSE_BYTES,
        expectNoBody: Boolean = false,
        carryReadAtNanos: Long? = null,
    ): Outcome {
        val reader = Reader(
            socket, idleTimeoutMs, totalDeadlineAtMs, maxResponseBytes,
            carry = carry, carryReadAtNanos = carryReadAtNanos ?: System.nanoTime(),
        )
        carry.setLength(0)
        val outcome = reader.next(expectNoBody)
        if (outcome is Outcome.Ok) carry.append(reader.leftover())
        return outcome
    }

    /** `name: value` field lines from [lines] (from index [from] on); a line without a colon is skipped. */
    private fun parseFields(lines: List<String>, from: Int): List<Pair<String, String>> =
        lines.drop(from).mapNotNull { line ->
            val idx = line.indexOf(':')
            if (idx <= 0) null else line.substring(0, idx).trim() to line.substring(idx + 1).trim()
        }

    /** Size announced by a `chunk-size [; ext]` line, bounded by [maxBytes]. */
    private fun chunkSize(line: String, maxBytes: Int): Int {
        val token = line.substringBefore(';').trim()
        if (token.isEmpty() || !token.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
            throw ChunkParseException("invalid chunk size '$token'")
        }
        val size = token.toLongOrNull(16) ?: throw ChunkParseException("chunk size '$token' overflows")
        if (size > maxBytes) throw ChunkParseException("chunk size $size out of bounds (max $maxBytes)")
        return size.toInt()
    }

    /**
     * Reads the responses on [socket], one per [next] call. Not thread-safe: one thread reads.
     *
     * [buf] holds the bytes read so far as ISO-8859-1 chars and [pos] is the first one not consumed
     * yet. Consumed data is dropped in bulk ([compact]) instead of being shifted out after every
     * chunk, and every search resumes where the previous one stopped, so a large or finely chunked
     * response costs linear time. A response's bytes are copied to its capture as they are dropped,
     * so the capture survives compaction, and each byte is copied at most once.
     *
     * Bytes are only read while the current response is incomplete, so the read that completes a
     * response delivered its last byte and everything after it: [lastDataAtNanos] dates both the
     * end of one response and the bytes of the next that came with it.
     *
     * @param totalDeadlineAtMs [System.currentTimeMillis] at which reading stops for good.
     * @param captureBytes how many bytes of each response to keep in [Received.bytes] (0: none).
     * @param activity the code writing to [socket] meanwhile, if any: it holds off the idle timeout
     *   while it writes and hears about every read that returned data.
     * @param carry bytes already read off [socket], at [carryReadAtNanos], that start the first response.
     */
    class Reader(
        private val socket: Socket,
        private val idleTimeoutMs: Long,
        private val totalDeadlineAtMs: Long,
        private val maxBytes: Int = DEFAULT_MAX_RESPONSE_BYTES,
        private val captureBytes: Int = 0,
        private val activity: Activity? = null,
        carry: CharSequence = "",
        carryReadAtNanos: Long = System.nanoTime(),
    ) {
        private val input = socket.getInputStream()
        private val readBuf = ByteArray(65536)
        private val buf = StringBuilder(carry)
        private var pos = 0
        private var lastDataAtMs = System.currentTimeMillis()

        /** [System.nanoTime] after the latest read that returned data (of the carry before any). */
        var lastDataAtNanos: Long = carryReadAtNanos
            private set

        /** Bytes this reader has read off the socket. */
        var totalBytesRead: Long = 0
            private set

        // The response being read: bytes read for it, when its first byte arrived, and its capture
        // (bytes before buf index [capFrom] are in [capture] or past the cap, [capLength] in all).
        private var bytesRead = 0
        private var hasFirstByte = false
        private var firstByteAtNanos = 0L
        private val capture = StringBuilder()
        private var capFrom = 0
        private var capLength = 0

        private val available: Int get() = buf.length - pos

        /** The next response; after any outcome but [Outcome.Ok], reading this socket is over. */
        fun next(expectNoBody: Boolean = false): Outcome {
            bytesRead = 0
            hasFirstByte = available > 0
            firstByteAtNanos = lastDataAtNanos
            capture.setLength(0)
            capFrom = pos
            capLength = 0
            compact()
            return readResponse(expectNoBody)
        }

        /** Bytes read past the end of the last response [next] returned. */
        fun leftover(): String = rest()

        private fun rest(): String = buf.substring(pos)

        private fun totalExceeded() = System.currentTimeMillis() >= totalDeadlineAtMs

        /**
         * Waits for more bytes and appends them to [buf]. Idle time counts from the latest data,
         * and not at all while [activity] is still writing: a request being written or held in a
         * pause is not an idle connection. A timeout in between re-checks both deadlines.
         */
        private fun read(): ReadResult {
            while (true) {
                val now = System.currentTimeMillis()
                if (now >= totalDeadlineAtMs) return ReadResult.TimedOut
                val quietSince = if (activity == null) lastDataAtMs else activity.quietSinceMs()?.let { maxOf(it, lastDataAtMs) } ?: now
                val idleDeadline = quietSince + idleTimeoutMs
                if (now >= idleDeadline) return ReadResult.TimedOut
                try {
                    socket.soTimeout = (minOf(idleDeadline, totalDeadlineAtMs) - now).coerceIn(1, Int.MAX_VALUE.toLong()).toInt()
                    val len = input.read(readBuf)
                    if (len == -1) return ReadResult.Eof
                    lastDataAtNanos = System.nanoTime()
                    lastDataAtMs = System.currentTimeMillis()
                    if (!hasFirstByte) {
                        hasFirstByte = true
                        firstByteAtNanos = lastDataAtNanos
                    }
                    buf.append(String(readBuf, 0, len, Charsets.ISO_8859_1))
                    bytesRead += len
                    totalBytesRead += len
                    activity?.dataArrived()
                    return ReadResult.Data
                } catch (_: SocketTimeoutException) {
                    // Both deadlines are re-checked above.
                } catch (e: SocketException) {
                    return ReadResult.Errored(e.message ?: "connection reset")
                } catch (e: IOException) {
                    return ReadResult.Errored(e.message ?: "io error")
                }
            }
        }

        /** Moves the current response's bytes up to buf index [end] into its capture. */
        private fun captureTo(end: Int) {
            if (end <= capFrom) return
            val room = captureBytes - capture.length
            if (room > 0) capture.append(buf, capFrom, capFrom + minOf(room, end - capFrom))
            capLength += end - capFrom
            capFrom = end
        }

        /** What arrived for the current response, through buf index [end]. */
        private fun receivedThrough(end: Int): Received {
            captureTo(end)
            return if (capLength == 0) Received.NONE else Received(capture.toString(), capLength, firstByteAtNanos, lastDataAtNanos)
        }

        /** The [Outcome] for a read that ended the response: timeout, reset, or (otherwise) EOF. */
        private fun fail(r: ReadResult, partial: String): Outcome = when (r) {
            ReadResult.TimedOut -> Outcome.TimedOut(partial, if (totalExceeded()) "total" else "idle", bytesRead, receivedThrough(buf.length))
            is ReadResult.Errored -> Outcome.Reset(partial, r.message, bytesRead, receivedThrough(buf.length))
            else -> Outcome.Eof(partial, bytesRead, receivedThrough(buf.length))
        }

        private fun malformed(reason: String, partial: String) =
            Outcome.Malformed(reason, partial, bytesRead, receivedThrough(buf.length))

        private fun compact() {
            if (pos >= COMPACT_AFTER && pos > buf.length / 2) {
                captureTo(pos)
                buf.delete(0, pos)
                pos = 0
                capFrom = 0
            }
        }

        private fun readResponse(expectNoBody: Boolean): Outcome {
            while (true) {
                var scanFrom = pos
                var headerEnd = buf.indexOf("\r\n\r\n", scanFrom)
                while (headerEnd == -1) {
                    scanFrom = maxOf(pos, buf.length - 3)
                    when (val r = read()) {
                        ReadResult.Data -> if (available > maxBytes) {
                            return malformed("response headers exceeded $maxBytes byte cap", rest())
                        }
                        ReadResult.Eof -> return if (available == 0) {
                            Outcome.Eof("", bytesRead, receivedThrough(buf.length))
                        } else {
                            malformed("connection closed before headers completed", rest())
                        }
                        else -> return fail(r, rest())
                    }
                    headerEnd = buf.indexOf("\r\n\r\n", scanFrom)
                }

                val headerSection = buf.substring(pos, headerEnd)
                if (!headerSection.startsWith("HTTP/")) {
                    return malformed("response did not start with HTTP/: '${headerSection.take(80)}'", rest())
                }
                val lines = headerSection.split("\r\n")
                val statusCode = STATUS_LINE.find(lines[0])?.groupValues?.get(1)?.toIntOrNull() ?: 0
                pos = headerEnd + 4
                // 1xx informational (e.g. 100-continue) is absorbed and does not count as the
                // response; 101 is final, the connection stops speaking HTTP/1.1 after it.
                if (statusCode in 100..199 && statusCode != 101) continue
                return readBody(lines[0], statusCode, parseFields(lines, 1), expectNoBody)
            }
        }

        private fun readBody(
            statusLine: String,
            statusCode: Int,
            headers: List<Pair<String, String>>,
            expectNoBody: Boolean,
        ): Outcome {
            val warnings = mutableListOf<String>()
            val connectionClose = headers.any {
                it.first.equals("Connection", ignoreCase = true) && it.second.contains("close", ignoreCase = true)
            }
            fun ok(body: Body.Read, framing: String, closes: Boolean = connectionClose) = Outcome.Ok(
                Response(statusLine, statusCode, headers, body.text, framing, closes, warnings, body.trailers),
                bytesRead,
                receivedThrough(pos),
            )

            if (statusCode == 101) return ok(Body.Read(""), "switching-protocols")
            if (expectNoBody || statusCode == 204 || statusCode == 304) return ok(Body.Read(""), "no-body")

            val codings = headers.filter { it.first.equals("Transfer-Encoding", ignoreCase = true) }
                .flatMap { it.second.split(',') }.map { it.trim() }.filter { it.isNotEmpty() }
            val lengths = headers.filter { it.first.equals("Content-Length", ignoreCase = true) }
                .flatMap { it.second.split(',') }.map { it.trim() }
            if (codings.isNotEmpty() && lengths.isNotEmpty()) {
                // RFC 9112 §6.3: Transfer-Encoding wins, but an ambiguous response from the target is
                // itself a smuggling-research finding, so it is surfaced rather than silently resolved.
                warnings += "both_content_length_and_transfer_encoding"
            }

            if (codings.isNotEmpty()) {
                if (codings.last().equals("chunked", ignoreCase = true)) {
                    return when (val body = readChunked()) {
                        is Body.Failed -> body.outcome
                        is Body.Read -> ok(body, "chunked")
                    }
                }
                // chunked is not the final coding, so the body runs until the server closes (RFC 9112 §6.3).
                warnings += "transfer_encoding_not_chunked"
            } else if (lengths.isNotEmpty()) {
                val distinct = lengths.distinct()
                if (distinct.size > 1) {
                    return malformed("conflicting Content-Length values: ${lengths.joinToString(", ")}", "")
                }
                val declared = distinct.single()
                val length = declared.takeIf { v -> v.isNotEmpty() && v.all { it in '0'..'9' } }?.toLongOrNull()
                    ?: return malformed("invalid Content-Length '$declared'", "")
                if (length > maxBytes) {
                    return malformed("declared Content-Length $length exceeds $maxBytes byte cap", "")
                }
                if (lengths.size > 1) warnings += "repeated_content_length"
                return when (val body = readFixed(length.toInt())) {
                    is Body.Failed -> body.outcome
                    is Body.Read -> ok(body, "content-length")
                }
            }

            // Close-delimited: this is exactly the "no response came back the normal way" signal a
            // 0.CL-style probe cares about, so EOF here is the expected terminator, not an error.
            return when (val body = readToClose()) {
                is Body.Failed -> body.outcome
                is Body.Read -> ok(body, "close-delimited", closes = true)
            }
        }

        private fun readFixed(length: Int): Body {
            while (available < length) {
                val r = read()
                if (r != ReadResult.Data) return Body.Failed(fail(r, rest()))
            }
            val text = buf.substring(pos, pos + length)
            pos += length
            return Body.Read(text)
        }

        private fun readToClose(): Body {
            while (true) {
                when (val r = read()) {
                    ReadResult.Data -> if (available > maxBytes) {
                        return Body.Failed(malformed("response exceeded $maxBytes byte cap", rest()))
                    }
                    ReadResult.Eof -> {
                        val text = rest()
                        pos = buf.length
                        return Body.Read(text)
                    }
                    else -> return Body.Failed(fail(r, rest()))
                }
            }
        }

        private fun readChunked(): Body {
            val body = StringBuilder()
            while (true) {
                var scanFrom = pos
                var lineEnd = buf.indexOf("\r\n", scanFrom)
                while (lineEnd == -1) {
                    scanFrom = maxOf(pos, buf.length - 1)
                    when (val r = read()) {
                        ReadResult.Data -> if (body.length.toLong() + available > maxBytes) {
                            return Body.Failed(malformed("response exceeded $maxBytes byte cap", body.toString()))
                        }
                        else -> return Body.Failed(fail(r, body.toString()))
                    }
                    lineEnd = buf.indexOf("\r\n", scanFrom)
                }
                val size = try {
                    chunkSize(buf.substring(pos, lineEnd), maxBytes)
                } catch (e: ChunkParseException) {
                    return Body.Failed(malformed(e.message ?: "invalid chunked encoding", body.toString()))
                }
                pos = lineEnd + 2
                if (size == 0) return readTrailers(body)
                if (body.length.toLong() + size > maxBytes) {
                    return Body.Failed(malformed("response exceeded $maxBytes byte cap", body.toString()))
                }
                while (available.toLong() < size.toLong() + 2) {
                    val r = read()
                    if (r != ReadResult.Data) return Body.Failed(fail(r, body.toString()))
                }
                body.append(buf, pos, pos + size)
                if (buf[pos + size] != '\r' || buf[pos + size + 1] != '\n') {
                    return Body.Failed(malformed("chunk data not followed by CRLF", body.toString()))
                }
                pos += size + 2
                compact()
            }
        }

        /** Consumes the trailer section after the last chunk: field lines up to an empty line (RFC 9112 §7.1.2). */
        private fun readTrailers(body: StringBuilder): Body {
            var scanFrom = pos
            while (true) {
                if (available >= 2) {
                    if (buf[pos] == '\r' && buf[pos + 1] == '\n') {
                        pos += 2
                        return Body.Read(body.toString())
                    }
                    val end = buf.indexOf("\r\n\r\n", scanFrom)
                    if (end != -1) {
                        val trailers = parseFields(buf.substring(pos, end).split("\r\n"), 0)
                        pos = end + 4
                        return Body.Read(body.toString(), trailers)
                    }
                    scanFrom = maxOf(pos, buf.length - 3)
                }
                when (val r = read()) {
                    ReadResult.Data -> if (body.length.toLong() + available > maxBytes) {
                        return Body.Failed(malformed("chunk trailers exceeded $maxBytes byte cap", body.toString()))
                    }
                    else -> return Body.Failed(fail(r, body.toString()))
                }
            }
        }
    }
}
