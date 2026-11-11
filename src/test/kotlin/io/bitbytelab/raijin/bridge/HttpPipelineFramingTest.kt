package io.bitbytelab.raijin.bridge

import java.net.ServerSocket
import java.net.Socket
import kotlin.test.Test
import kotlin.test.assertEquals
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
}
