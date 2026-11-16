package io.bitbytelab.raijin.bridge

import java.io.IOException
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException

/**
 * Dependency-free HTTP/1.1 response framing reader for [HttpPipelineBridge]. Reads exactly one
 * response per [readOne] call off a shared socket, so [HttpPipelineBridge] can pipeline several
 * raw requests over one connection and read the responses back in order.
 *
 * Uses the same byte<->ISO-8859-1-String bijection Turbo's
 * [io.bitbytelab.raijin.turbo.ThreadedRequestEngine] uses for its own HTTP/1.1 parsing, so no byte
 * is ever lost or corrupted.
 *
 * Framing is strict, because a framing disagreement with the target is the finding this tool exists
 * to surface: anything it cannot frame unambiguously (bad or conflicting Content-Length, bad chunk
 * size, chunk data without its CRLF) ends in [Outcome.Malformed] instead of a guess or an exception.
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

    sealed class Outcome(val bytesReadFromSocket: Int) {
        class Ok(val response: Response, bytesReadFromSocket: Int) : Outcome(bytesReadFromSocket)
        class Eof(val partial: String, bytesReadFromSocket: Int) : Outcome(bytesReadFromSocket)
        class TimedOut(val partial: String, val kind: String, bytesReadFromSocket: Int) : Outcome(bytesReadFromSocket)
        class Reset(val partial: String, val message: String, bytesReadFromSocket: Int) : Outcome(bytesReadFromSocket)
        class Malformed(val reason: String, val partial: String, bytesReadFromSocket: Int) : Outcome(bytesReadFromSocket)
    }

    private sealed class ReadResult {
        class Data(val len: Int) : ReadResult()
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
     */
    fun readOne(
        socket: Socket,
        carry: StringBuilder,
        idleTimeoutMs: Long,
        totalDeadlineAtMs: Long,
        maxResponseBytes: Int = DEFAULT_MAX_RESPONSE_BYTES,
        expectNoBody: Boolean = false,
    ): Outcome {
        val wire = Wire(socket, StringBuilder(carry), idleTimeoutMs, totalDeadlineAtMs, maxResponseBytes)
        carry.setLength(0)
        val outcome = wire.readResponse(expectNoBody)
        if (outcome is Outcome.Ok) carry.append(wire.buf, wire.pos, wire.buf.length)
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
     * One response's read off [socket]. [buf] holds the bytes read so far as ISO-8859-1 chars and
     * [pos] is the first one not consumed yet. Consumed data is dropped in bulk ([compact]) instead
     * of being shifted out after every chunk, and every search resumes where the previous one
     * stopped, so a large or finely chunked response costs linear time.
     */
    private class Wire(
        private val socket: Socket,
        val buf: StringBuilder,
        private val idleTimeoutMs: Long,
        private val totalDeadlineAtMs: Long,
        private val maxBytes: Int,
    ) {
        private val input = socket.getInputStream()
        private val readBuf = ByteArray(65536)
        var pos = 0
        private var bytesRead = 0

        private val available: Int get() = buf.length - pos

        private fun rest(): String = buf.substring(pos)

        private fun totalExceeded() = System.currentTimeMillis() >= totalDeadlineAtMs

        private fun read(): ReadResult {
            if (totalExceeded()) return ReadResult.TimedOut
            return try {
                socket.soTimeout = minOf(idleTimeoutMs, totalDeadlineAtMs - System.currentTimeMillis())
                    .coerceIn(1, Int.MAX_VALUE.toLong()).toInt()
                val len = input.read(readBuf)
                if (len == -1) {
                    ReadResult.Eof
                } else {
                    bytesRead += len
                    ReadResult.Data(len)
                }
            } catch (_: SocketTimeoutException) {
                ReadResult.TimedOut
            } catch (e: SocketException) {
                ReadResult.Errored(e.message ?: "connection reset")
            } catch (e: IOException) {
                ReadResult.Errored(e.message ?: "io error")
            }
        }

        private fun append(len: Int) {
            buf.append(String(readBuf, 0, len, Charsets.ISO_8859_1))
        }

        /** The [Outcome] for a read that ended the response: timeout, reset, or (otherwise) EOF. */
        private fun fail(r: ReadResult, partial: String): Outcome = when (r) {
            ReadResult.TimedOut -> Outcome.TimedOut(partial, if (totalExceeded()) "total" else "idle", bytesRead)
            is ReadResult.Errored -> Outcome.Reset(partial, r.message, bytesRead)
            else -> Outcome.Eof(partial, bytesRead)
        }

        private fun malformed(reason: String, partial: String) = Outcome.Malformed(reason, partial, bytesRead)

        private fun compact() {
            if (pos >= COMPACT_AFTER && pos > buf.length / 2) {
                buf.delete(0, pos)
                pos = 0
            }
        }

        fun readResponse(expectNoBody: Boolean): Outcome {
            while (true) {
                var scanFrom = pos
                var headerEnd = buf.indexOf("\r\n\r\n", scanFrom)
                while (headerEnd == -1) {
                    scanFrom = maxOf(pos, buf.length - 3)
                    when (val r = read()) {
                        is ReadResult.Data -> {
                            if (available.toLong() + r.len > maxBytes) {
                                return malformed("response headers exceeded $maxBytes byte cap", rest())
                            }
                            append(r.len)
                        }
                        ReadResult.Eof -> return if (available == 0) {
                            Outcome.Eof("", bytesRead)
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
                when (val r = read()) {
                    is ReadResult.Data -> append(r.len)
                    else -> return Body.Failed(fail(r, rest()))
                }
            }
            val text = buf.substring(pos, pos + length)
            pos += length
            return Body.Read(text)
        }

        private fun readToClose(): Body {
            while (true) {
                when (val r = read()) {
                    is ReadResult.Data -> {
                        if (available.toLong() + r.len > maxBytes) {
                            return Body.Failed(malformed("response exceeded $maxBytes byte cap", rest()))
                        }
                        append(r.len)
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
                        is ReadResult.Data -> {
                            if (body.length.toLong() + available + r.len > maxBytes) {
                                return Body.Failed(malformed("response exceeded $maxBytes byte cap", body.toString()))
                            }
                            append(r.len)
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
                    when (val r = read()) {
                        is ReadResult.Data -> append(r.len)
                        else -> return Body.Failed(fail(r, body.toString()))
                    }
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
                    is ReadResult.Data -> {
                        if (body.length.toLong() + available + r.len > maxBytes) {
                            return Body.Failed(malformed("chunk trailers exceeded $maxBytes byte cap", body.toString()))
                        }
                        append(r.len)
                    }
                    else -> return Body.Failed(fail(r, body.toString()))
                }
            }
        }
    }
}
