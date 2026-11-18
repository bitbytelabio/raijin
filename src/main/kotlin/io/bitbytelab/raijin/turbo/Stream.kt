package io.bitbytelab.raijin.turbo

import java.io.IOException

class Stream(val connection: H2Connection, val streamID: Int, val req: Request, fromClient: Boolean) {

    companion object {
        const val CLEAN = 0
        const val WANTBODY = 1
        const val DONE = 2

        /** Appended once to a body cut at [Http1ResponseReader.MAX_RESPONSE_BYTES]. */
        const val TRUNCATED_NOTE = "\n[truncated at 10MB]"
    }

    var state = Stream.CLEAN
    var headers: String = ""
    private val body = StringBuilder()
    private var truncated = false

    /** System.nanoTime() when the request's last frame went out; the response timings count from here. */
    @Volatile
    var sentAt: Long = 0L
    private var firstFrameAt: Long = 0L

    init {
        if (!fromClient) {
            throw Exception("Can't handle client-initiated streams yet")
        }
    }

    /**
     * Handles one frame for this stream on the connection's reader thread. Nothing here holds a lock,
     * so an exception cannot wedge the connection: the reader closes it, and the engine retries
     * whatever was still in flight once the reader has exited.
     */
    fun processFrame(frameBytes: ByteArray) {
        val frame = parseFrame(frameBytes, streamID)

        H2Connection.debug("Stream $streamID type ${frame.type} flags ${frame.flags}")
        if (frame is GoAwayFrame || frame is RstStreamFrame) {
            val kind = if (frame is GoAwayFrame) "GOAWAY" else "RST_STREAM"
            Utils.out("Server sent a $kind, dumping the whole connection")
            connection.fail(IOException("server sent $kind on stream $streamID"))
            return
        }

        if (state == CLEAN) {
            if (frame is HeaderFrame) {
                if (firstFrameAt == 0L) firstFrameAt = System.nanoTime()
                headers = frame.headerString
                state = when {
                    frame.die -> DONE
                    // Interim 1xx (100 Continue, 103 Early Hints): keep waiting for the final HEADERS.
                    isInterimStatus(frame.headerString) -> CLEAN
                    else -> WANTBODY
                }
            } else if (frame is DataFrame) {
                throw IOException("Expected headers, got data")
            }
        }

        if (state == WANTBODY && frame is DataFrame && !truncated) {
            // Bounded as the HTTP/1 engine is: the rest of an oversized body is read and dropped.
            val room = Http1ResponseReader.MAX_RESPONSE_BYTES - body.length
            if (frame.body.length <= room) {
                body.append(frame.body)
            } else {
                body.append(frame.body, 0, room.coerceAtLeast(0)).append(TRUNCATED_NOTE)
                truncated = true
            }
        }

        if (frame.die) {
            complete()
        }
    }

    private fun isInterimStatus(headerString: String): Boolean {
        val statusLine = headerString.lineSequence()
            .map { it.trim() }
            .firstOrNull { it.startsWith(":status:", ignoreCase = true) }
            ?: return false
        val status = statusLine.substring(8).trim()
        return status.length == 3 && status[0] == '1' && status.all { it.isDigit() }
    }

    private fun complete() {
        val now = System.nanoTime()
        // Microseconds, as on every other engine.
        req.ttfb = (firstFrameAt - sentAt) / 1000
        req.ttlb = (now - sentAt) / 1000
        req.time = req.ttlb
        connection.engine.successfulRequests.getAndIncrement()

        val response = headers + "\r\n" + body.toString()
        req.response = response
        val interesting = connection.engine.processResponse(req, response.toByteArray(Charsets.ISO_8859_1))
        connection.engine.invokeCallback(req, interesting)

        // Only after the callback: until then the request still counts as in flight, so a request the
        // callback queues is never mistaken for the end of the run.
        H2Connection.debug("Deleting stream $streamID")
        connection.streamCompleted(streamID)
    }

    fun parseFrame(raw: ByteArray, streamID: Int): Frame {
        val type = raw[3]
        val flags = raw[4]
        val payload = raw.sliceArray(9..raw.size-1)

        if (streamID != (HTTP2Utils.fourByteInt(raw.sliceArray(5..8)) and 0x7fffffff)) {
            throw Exception("bad stream ID")
        }
        return when(type.toInt()) {
            0 -> DataFrame(type, flags, streamID, payload)
            1 -> HeaderFrame(type, flags, streamID, payload, connection.decoder)
            3 -> RstStreamFrame(type, flags, streamID, payload)
            4 -> SettingsFrame(type, flags, streamID, payload)
            6 -> PingFrame(type, flags, streamID, payload)
            7 -> GoAwayFrame(type, flags, streamID, payload)
            8 -> WindowFrame(type, flags, streamID, payload)
            else -> Frame(type, flags, streamID, payload)
        }
    }
}
