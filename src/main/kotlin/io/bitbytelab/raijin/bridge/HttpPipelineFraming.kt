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
 */
internal object HttpPipelineFraming {

    const val DEFAULT_MAX_RESPONSE_BYTES = 10_000_000

    data class Response(
        val statusLine: String,
        val statusCode: Int,
        val headers: List<Pair<String, String>>,
        val body: String,
        val framing: String, // "content-length" | "chunked" | "close-delimited" | "no-body"
        val connectionCloseHeader: Boolean,
        val warnings: List<String>,
    )

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
    ): Outcome {
        val input = socket.getInputStream()
        val readBuf = ByteArray(65536)
        var buffer = carry.toString()
        carry.setLength(0)
        var bytesRead = 0

        fun totalExceeded() = System.currentTimeMillis() >= totalDeadlineAtMs

        fun remainingIdleMs(): Int {
            val remainingTotal = totalDeadlineAtMs - System.currentTimeMillis()
            return minOf(idleTimeoutMs, remainingTotal).coerceIn(1, Int.MAX_VALUE.toLong()).toInt()
        }

        fun readMore(): ReadResult {
            if (totalExceeded()) return ReadResult.TimedOut
            return try {
                socket.soTimeout = remainingIdleMs()
                val len = input.read(readBuf)
                if (len == -1) {
                    ReadResult.Eof
                } else {
                    bytesRead += len
                    ReadResult.Data(len)
                }
            } catch (e: SocketTimeoutException) {
                ReadResult.TimedOut
            } catch (e: SocketException) {
                ReadResult.Errored(e.message ?: "connection reset")
            } catch (e: IOException) {
                ReadResult.Errored(e.message ?: "io error")
            }
        }

        while (true) {
            var headerEnd = buffer.indexOf("\r\n\r\n")
            while (headerEnd == -1) {
                when (val r = readMore()) {
                    is ReadResult.Data -> buffer += String(readBuf, 0, r.len, Charsets.ISO_8859_1)
                    ReadResult.Eof -> return if (buffer.isEmpty()) {
                        Outcome.Eof(buffer, bytesRead)
                    } else {
                        Outcome.Malformed("connection closed before headers completed", buffer, bytesRead)
                    }
                    ReadResult.TimedOut -> return Outcome.TimedOut(buffer, if (totalExceeded()) "total" else "idle", bytesRead)
                    is ReadResult.Errored -> return Outcome.Reset(buffer, r.message, bytesRead)
                }
                headerEnd = buffer.indexOf("\r\n\r\n")
            }

            val headerSection = buffer.substring(0, headerEnd)
            if (!headerSection.startsWith("HTTP/")) {
                return Outcome.Malformed("response did not start with HTTP/: '${headerSection.take(80)}'", buffer, bytesRead)
            }
            val lines = headerSection.split("\r\n")
            val statusLine = lines[0]
            val statusCode = STATUS_LINE.find(statusLine)?.groupValues?.get(1)?.toIntOrNull() ?: 0

            if (statusCode in 100..199) {
                // 1xx informational (e.g. 100-continue) is absorbed transparently and does not
                // count as a response — keep reading for the real one.
                buffer = buffer.substring(headerEnd + 4)
                continue
            }

            val headers = lines.drop(1).mapNotNull { line ->
                val idx = line.indexOf(':')
                if (idx <= 0) null else line.substring(0, idx).trim() to line.substring(idx + 1).trim()
            }
            val warnings = mutableListOf<String>()
            val hasContentLength = headers.any { it.first.equals("Content-Length", ignoreCase = true) }
            val hasChunked = headers.any {
                it.first.equals("Transfer-Encoding", ignoreCase = true) && it.second.contains("chunked", ignoreCase = true)
            }
            if (hasContentLength && hasChunked) {
                // RFC 7230 §3.3.3: ambiguous when both are present. We resolve it (Transfer-Encoding
                // wins, below) but an ambiguous response from the target is itself a smuggling-research
                // finding, not noise, so it's surfaced rather than silently resolved.
                warnings += "both_content_length_and_transfer_encoding"
            }
            val connectionCloseHeader = headers.any {
                it.first.equals("Connection", ignoreCase = true) && it.second.contains("close", ignoreCase = true)
            }

            buffer = buffer.substring(headerEnd + 4)

            if (statusCode == 204 || statusCode == 304) {
                carry.append(buffer)
                return Outcome.Ok(Response(statusLine, statusCode, headers, "", "no-body", connectionCloseHeader, warnings), bytesRead)
            }

            if (hasChunked) {
                val body = StringBuilder()
                try {
                    while (true) {
                        var chunk = nextChunk(buffer)
                        while (chunk == null || buffer.length < chunk.second + 2) {
                            when (val r = readMore()) {
                                is ReadResult.Data -> buffer += String(readBuf, 0, r.len, Charsets.ISO_8859_1)
                                ReadResult.Eof -> return Outcome.Eof(body.toString(), bytesRead)
                                ReadResult.TimedOut -> return Outcome.TimedOut(body.toString(), if (totalExceeded()) "total" else "idle", bytesRead)
                                is ReadResult.Errored -> return Outcome.Reset(body.toString(), r.message, bytesRead)
                            }
                            chunk = nextChunk(buffer)
                        }
                        val (skip, end) = chunk
                        body.append(buffer.substring(skip, end))
                        buffer = buffer.substring(end + 2)
                        if (end == skip) break // zero-length terminal chunk
                        if (body.length > maxResponseBytes) {
                            return Outcome.Malformed("response exceeded $maxResponseBytes byte cap", body.toString(), bytesRead)
                        }
                    }
                } catch (e: ChunkParseException) {
                    return Outcome.Malformed(e.message ?: "invalid chunked encoding", body.toString(), bytesRead)
                }
                carry.append(buffer)
                return Outcome.Ok(Response(statusLine, statusCode, headers, body.toString(), "chunked", connectionCloseHeader, warnings), bytesRead)
            }

            val contentLength = headers.firstOrNull { it.first.equals("Content-Length", ignoreCase = true) }
                ?.second?.trim()?.toIntOrNull()
            if (contentLength != null) {
                if (contentLength > maxResponseBytes) {
                    return Outcome.Malformed("declared Content-Length $contentLength exceeds $maxResponseBytes byte cap", "", bytesRead)
                }
                while (buffer.length < contentLength) {
                    when (val r = readMore()) {
                        is ReadResult.Data -> buffer += String(readBuf, 0, r.len, Charsets.ISO_8859_1)
                        ReadResult.Eof -> return Outcome.Eof(buffer, bytesRead)
                        ReadResult.TimedOut -> return Outcome.TimedOut(buffer, if (totalExceeded()) "total" else "idle", bytesRead)
                        is ReadResult.Errored -> return Outcome.Reset(buffer, r.message, bytesRead)
                    }
                }
                val body = buffer.substring(0, contentLength)
                carry.append(buffer.substring(contentLength))
                return Outcome.Ok(Response(statusLine, statusCode, headers, body, "content-length", connectionCloseHeader, warnings), bytesRead)
            }

            // Close-delimited: no Content-Length, no Transfer-Encoding. This is exactly the "no
            // response came back the normal way" signal a 0.CL-style probe cares about — EOF here
            // is the expected terminator, not an error.
            val body = StringBuilder(buffer)
            while (true) {
                when (val r = readMore()) {
                    is ReadResult.Data -> {
                        body.append(String(readBuf, 0, r.len, Charsets.ISO_8859_1))
                        if (body.length > maxResponseBytes) {
                            return Outcome.Malformed("response exceeded $maxResponseBytes byte cap", body.toString(), bytesRead)
                        }
                    }
                    ReadResult.Eof -> return Outcome.Ok(
                        Response(statusLine, statusCode, headers, body.toString(), "close-delimited", true, warnings),
                        bytesRead,
                    )
                    ReadResult.TimedOut -> return Outcome.TimedOut(body.toString(), if (totalExceeded()) "total" else "idle", bytesRead)
                    is ReadResult.Errored -> return Outcome.Reset(body.toString(), r.message, bytesRead)
                }
            }
        }
    }

    /** (skipBytes, endOfChunkDataOffset) for the next chunk in [buf], or null if not enough data buffered yet. */
    private fun nextChunk(buf: String): Pair<Int, Int>? {
        val sizeLineEnd = buf.indexOf("\r\n")
        if (sizeLineEnd == -1) return null
        val sizeToken = buf.substring(0, sizeLineEnd).split(";").first().trim()
        val size = sizeToken.toIntOrNull(16) ?: throw ChunkParseException("invalid chunk size '$sizeToken'")
        val skip = sizeLineEnd + 2
        return skip to (skip + size)
    }
}
