package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.bridge.HttpPipelineFraming.Outcome
import java.net.ServerSocket
import java.net.Socket
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Exercises [HttpPipelineFraming] over a real loopback TCP connection (no fakes/mocks for the
 * socket itself — this is wire-framing logic, so the test fixture is a tiny local server that
 * writes canned bytes, matching how [io.bitbytelab.raijin.turbo.ThreadedRequestEngine] is
 * exercised in this codebase).
 */
class HttpPipelineFramingTest {

    /** Starts a one-shot local server that writes [serverWrites] (in order, with the given
     * delays) to whatever connects, then returns the client-side [Socket]. */
    private fun connectedClient(serverWrites: List<Pair<ByteArray, Long>>, closeAfter: Boolean = false): Pair<Socket, ServerSocket> {
        val server = ServerSocket(0)
        val thread = Thread {
            val conn = server.accept()
            conn.getOutputStream().use { out ->
                serverWrites.forEach { (bytes, delayMs) ->
                    if (delayMs > 0) Thread.sleep(delayMs)
                    out.write(bytes)
                    out.flush()
                }
                if (!closeAfter) Thread.sleep(5000) // hold the connection open past the test's timeouts
            }
        }
        thread.isDaemon = true
        thread.start()
        val client = Socket("localhost", server.localPort)
        return client to server
    }

    private fun bytes(s: String) = s.toByteArray(Charsets.ISO_8859_1)

    @Test
    fun `reads a simple content-length response`() {
        val (client, server) = connectedClient(listOf(bytes("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello") to 0))
        try {
            val carry = StringBuilder()
            val outcome = HttpPipelineFraming.readOne(client, carry, idleTimeoutMs = 2000, totalDeadlineAtMs = System.currentTimeMillis() + 5000)
            val ok = outcome as HttpPipelineFraming.Outcome.Ok
            assertEquals(200, ok.response.statusCode)
            assertEquals("content-length", ok.response.framing)
            assertEquals("hello", ok.response.body)
            assertTrue(ok.response.warnings.isEmpty())
        } finally {
            client.close(); server.close()
        }
    }

    @Test
    fun `reads a chunked response across two chunks`() {
        val body = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        val (client, server) = connectedClient(listOf(bytes("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n$body") to 0))
        try {
            val carry = StringBuilder()
            val outcome = HttpPipelineFraming.readOne(client, carry, idleTimeoutMs = 2000, totalDeadlineAtMs = System.currentTimeMillis() + 5000)
            val ok = outcome as HttpPipelineFraming.Outcome.Ok
            assertEquals("chunked", ok.response.framing)
            assertEquals("hello world", ok.response.body)
        } finally {
            client.close(); server.close()
        }
    }

    @Test
    fun `splits two pipelined responses via carry`() {
        val combined = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
        val (client, server) = connectedClient(listOf(bytes(combined) to 0))
        try {
            val carry = StringBuilder()
            val first = HttpPipelineFraming.readOne(client, carry, idleTimeoutMs = 2000, totalDeadlineAtMs = System.currentTimeMillis() + 5000) as HttpPipelineFraming.Outcome.Ok
            assertEquals(200, first.response.statusCode)
            assertEquals("ok", first.response.body)

            val second = HttpPipelineFraming.readOne(client, carry, idleTimeoutMs = 2000, totalDeadlineAtMs = System.currentTimeMillis() + 5000) as HttpPipelineFraming.Outcome.Ok
            assertEquals(404, second.response.statusCode)
        } finally {
            client.close(); server.close()
        }
    }

    @Test
    fun `close-delimited response completes on EOF, not as an error`() {
        val (client, server) = connectedClient(
            listOf(bytes("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nno-length-body") to 0),
            closeAfter = true,
        )
        try {
            val carry = StringBuilder()
            val outcome = HttpPipelineFraming.readOne(client, carry, idleTimeoutMs = 2000, totalDeadlineAtMs = System.currentTimeMillis() + 5000)
            val ok = outcome as HttpPipelineFraming.Outcome.Ok
            assertEquals("close-delimited", ok.response.framing)
            assertEquals("no-length-body", ok.response.body)
            assertTrue(ok.response.connectionCloseHeader)
        } finally {
            client.close(); server.close()
        }
    }

    @Test
    fun `100-continue is absorbed and does not count as the response`() {
        val (client, server) = connectedClient(
            listOf(bytes("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok") to 0),
        )
        try {
            val carry = StringBuilder()
            val outcome = HttpPipelineFraming.readOne(client, carry, idleTimeoutMs = 2000, totalDeadlineAtMs = System.currentTimeMillis() + 5000)
            val ok = outcome as HttpPipelineFraming.Outcome.Ok
            assertEquals(200, ok.response.statusCode)
            assertEquals("ok", ok.response.body)
        } finally {
            client.close(); server.close()
        }
    }

    @Test
    fun `ambiguous content-length and transfer-encoding is flagged, not silently resolved`() {
        val (client, server) = connectedClient(
            listOf(bytes("HTTP/1.1 200 OK\r\nContent-Length: 999\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n") to 0),
        )
        try {
            val carry = StringBuilder()
            val outcome = HttpPipelineFraming.readOne(client, carry, idleTimeoutMs = 2000, totalDeadlineAtMs = System.currentTimeMillis() + 5000)
            val ok = outcome as HttpPipelineFraming.Outcome.Ok
            // RFC 7230 3.3.3: Transfer-Encoding wins when both are present.
            assertEquals("chunked", ok.response.framing)
            assertEquals("abc", ok.response.body)
            assertTrue("both_content_length_and_transfer_encoding" in ok.response.warnings)
        } finally {
            client.close(); server.close()
        }
    }

    @Test
    fun `idle timeout is reported distinctly from eof`() {
        // Server writes nothing at all and holds the connection open past our idle budget.
        val (client, server) = connectedClient(listOf(bytes("") to 0))
        try {
            val carry = StringBuilder()
            val outcome = HttpPipelineFraming.readOne(client, carry, idleTimeoutMs = 300, totalDeadlineAtMs = System.currentTimeMillis() + 5000)
            val timedOut = outcome as HttpPipelineFraming.Outcome.TimedOut
            assertEquals("idle", timedOut.kind)
        } finally {
            client.close(); server.close()
        }
    }

    @Test
    fun `chunked trailers are consumed cleanly before next pipelined response`() {
        val combined = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Checksum: abc\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        val (client, server) = connectedClient(listOf(bytes(combined) to 0))
        try {
            val carry = StringBuilder()
            val first = HttpPipelineFraming.readOne(client, carry, idleTimeoutMs = 2000, totalDeadlineAtMs = System.currentTimeMillis() + 5000) as HttpPipelineFraming.Outcome.Ok
            assertEquals("hello", first.response.body)
            val second = HttpPipelineFraming.readOne(client, carry, idleTimeoutMs = 2000, totalDeadlineAtMs = System.currentTimeMillis() + 5000) as HttpPipelineFraming.Outcome.Ok
            assertEquals("ok", second.response.body)
        } finally {
            client.close(); server.close()
        }
    }

    @Test
    fun `negative Content-Length and negative hex chunk size fail cleanly as Malformed`() {
        val (c1, s1) = connectedClient(listOf(bytes("HTTP/1.1 200 OK\r\nContent-Length: -5\r\n\r\nhello") to 0))
        try {
            val o1 = HttpPipelineFraming.readOne(c1, StringBuilder(), 1000, System.currentTimeMillis() + 3000)
            assertTrue(o1 is HttpPipelineFraming.Outcome.Malformed, o1.toString())
        } finally {
            c1.close(); s1.close()
        }

        val (c2, s2) = connectedClient(listOf(bytes("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n-1\r\nhello") to 0))
        try {
            val o2 = HttpPipelineFraming.readOne(c2, StringBuilder(), 1000, System.currentTimeMillis() + 3000)
            assertTrue(o2 is HttpPipelineFraming.Outcome.Malformed, o2.toString())
        } finally {
            c2.close(); s2.close()
        }
    }

    @Test
    fun `HEAD response with declared Content-Length treats body as empty and preserves carry`() {
        val combined = "HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n"
        val (client, server) = connectedClient(listOf(bytes(combined) to 0))
        try {
            val carry = StringBuilder()
            val first = HttpPipelineFraming.readOne(client, carry, 1000, System.currentTimeMillis() + 3000, expectNoBody = true) as HttpPipelineFraming.Outcome.Ok
            assertEquals("no-body", first.response.framing)
            assertEquals("", first.response.body)
            val second = HttpPipelineFraming.readOne(client, carry, 1000, System.currentTimeMillis() + 3000) as HttpPipelineFraming.Outcome.Ok
            assertEquals(204, second.response.statusCode)
        } finally {
            client.close(); server.close()
        }
    }

    /** Serves [wire] in one write to a fresh connection and reads one response off it. */
    private fun frame(
        wire: String,
        closeAfter: Boolean = false,
        maxResponseBytes: Int = HttpPipelineFraming.DEFAULT_MAX_RESPONSE_BYTES,
        carry: StringBuilder = StringBuilder(),
    ): Outcome {
        val (client, server) = connectedClient(listOf(bytes(wire) to 0), closeAfter)
        try {
            return HttpPipelineFraming.readOne(client, carry, 2000, System.currentTimeMillis() + 5000, maxResponseBytes)
        } finally {
            client.close(); server.close()
        }
    }

    private fun describe(o: Outcome): String = when (o) {
        is Outcome.Ok -> "Ok(${o.response})"
        is Outcome.Malformed -> "Malformed(${o.reason})"
        is Outcome.Eof -> "Eof(${o.partial})"
        is Outcome.TimedOut -> "TimedOut(${o.kind})"
        is Outcome.Reset -> "Reset(${o.message})"
    }

    @Test
    fun `chunk size that overflows or exceeds the byte cap is Malformed`() {
        val overflow = frame("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFFFFFF\r\nx")
        assertTrue(overflow is Outcome.Malformed && "overflows" in overflow.reason, describe(overflow))

        val tooBig = frame("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFF\r\nx", maxResponseBytes = 1024)
        assertTrue(tooBig is Outcome.Malformed && "out of bounds" in tooBig.reason, describe(tooBig))
    }

    @Test
    fun `chunk data without its CRLF is Malformed`() {
        val o = frame("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcXY0\r\n\r\n")
        assertTrue(o is Outcome.Malformed && "CRLF" in o.reason, describe(o))
    }

    @Test
    fun `chunk trailers are returned with the response`() {
        val ok = frame("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Checksum: abc\r\nX-Other: 1\r\n\r\n") as Outcome.Ok
        assertEquals("hello", ok.response.body)
        assertEquals(listOf("X-Checksum" to "abc", "X-Other" to "1"), ok.response.trailers)
    }

    @Test
    fun `conflicting or non-numeric Content-Length is Malformed and a repeated equal one is a warning`() {
        for (cl in listOf("Content-Length: 5\r\nContent-Length: 6", "Content-Length: 5, 6", "Content-Length: +5", "Content-Length: 0x5")) {
            val o = frame("HTTP/1.1 200 OK\r\n$cl\r\n\r\nhello")
            assertTrue(o is Outcome.Malformed, "$cl -> ${describe(o)}")
        }
        val ok = frame("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok") as Outcome.Ok
        assertEquals("ok", ok.response.body)
        assertTrue("repeated_content_length" in ok.response.warnings)
    }

    @Test
    fun `transfer-encoding whose final coding is not chunked reads to close`() {
        for (te in listOf("chunked, gzip", "xchunked")) {
            val o = frame("HTTP/1.1 200 OK\r\nTransfer-Encoding: $te\r\n\r\n3\r\nabc\r\n0\r\n\r\n", closeAfter = true)
            val ok = o as? Outcome.Ok ?: error("$te -> ${describe(o)}")
            assertEquals("close-delimited", ok.response.framing, te)
            assertEquals("3\r\nabc\r\n0\r\n\r\n", ok.response.body, te)
            assertTrue("transfer_encoding_not_chunked" in ok.response.warnings, te)
        }
    }

    @Test
    fun `101 ends HTTP framing and leaves the upgraded bytes in carry`() {
        val carry = StringBuilder()
        val ok = frame("HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\nPRI-bytes", carry = carry) as Outcome.Ok
        assertEquals(101, ok.response.statusCode)
        assertEquals("switching-protocols", ok.response.framing)
        assertFalse(ok.response.persistent)
        assertEquals("PRI-bytes", carry.toString())
    }

    @Test
    fun `persistence follows Connection and the HTTP version`() {
        fun persistent(head: String) = (frame("$head\r\nContent-Length: 0\r\n\r\n") as Outcome.Ok).response.persistent
        assertTrue(persistent("HTTP/1.1 200 OK"))
        assertFalse(persistent("HTTP/1.1 200 OK\r\nConnection: close"))
        assertFalse(persistent("HTTP/1.0 200 OK"))
        assertTrue(persistent("HTTP/1.0 200 OK\r\nConnection: keep-alive"))
        val closeDelimited = frame("HTTP/1.1 200 OK\r\n\r\nbody", closeAfter = true) as Outcome.Ok
        assertFalse(closeDelimited.response.persistent)
    }

    @Test
    fun `responses over the byte cap are Malformed`() {
        val headers = frame("HTTP/1.1 200 OK\r\nX-Big: ${"a".repeat(500)}\r\n\r\n", maxResponseBytes = 100)
        assertTrue(headers is Outcome.Malformed && "exceeded" in headers.reason, describe(headers))
        val declared = frame("HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\nabc", maxResponseBytes = 1000)
        assertTrue(declared is Outcome.Malformed && "exceeds" in declared.reason, describe(declared))
    }

    @Test
    fun `a finely chunked large body and the response after it frame correctly`() {
        val wire = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + "1\r\nx\r\n".repeat(30_000) +
            "0\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n"
        val (client, server) = connectedClient(listOf(bytes(wire) to 0))
        try {
            val carry = StringBuilder()
            val first = HttpPipelineFraming.readOne(client, carry, 2000, System.currentTimeMillis() + 10_000) as Outcome.Ok
            assertEquals("x".repeat(30_000), first.response.body)
            val second = HttpPipelineFraming.readOne(client, carry, 2000, System.currentTimeMillis() + 10_000) as Outcome.Ok
            assertEquals(204, second.response.statusCode)
        } finally {
            client.close(); server.close()
        }
    }

    @Test
    fun `framing boundaries split across reads are still found`() {
        val (client, server) = connectedClient(
            listOf(
                bytes("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r") to 0,
                bytes("\n\r\n5") to 100,
                bytes("\r\nhel") to 100,
                bytes("lo\r\n0\r") to 100,
                bytes("\nX-T: 1\r\n\r") to 100,
                bytes("\n") to 100,
            )
        )
        try {
            val ok = HttpPipelineFraming.readOne(client, StringBuilder(), 2000, System.currentTimeMillis() + 5000) as Outcome.Ok
            assertEquals("hello", ok.response.body)
            assertEquals(listOf("X-T" to "1"), ok.response.trailers)
        } finally {
            client.close(); server.close()
        }
    }
}
