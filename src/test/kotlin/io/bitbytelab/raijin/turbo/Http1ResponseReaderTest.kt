package io.bitbytelab.raijin.turbo

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.io.ByteArrayOutputStream
import java.net.SocketTimeoutException
import java.util.zip.GZIPOutputStream

/** ThreadedRequestEngine's response framing, driven by scripted reads with their arrival times. */
class Http1ResponseReaderTest {

    /** Hands out [steps] one read at a time; a string arrives at its time, null is a read timeout. */
    private class ScriptedSource(vararg steps: Pair<String?, Long>) : Http1Source {
        private val pending = ArrayDeque(steps.toList())
        var now = 0L
        val timeoutsSet = mutableListOf<Int>()
        override var readTimeoutMillis: Int = 10_000
            set(value) {
                field = value
                timeoutsSet += value
            }

        override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
            val (text, at) = pending.removeFirstOrNull() ?: return -1
            now = at
            if (text == null) throw SocketTimeoutException("read timed out")
            val bytes = text.toByteArray(Charsets.ISO_8859_1)
            if (bytes.size > length) {
                pending.addFirst(String(bytes, length, bytes.size - length, Charsets.ISO_8859_1) to at)
            }
            val count = minOf(length, bytes.size)
            System.arraycopy(bytes, 0, buffer, offset, count)
            return count
        }
    }

    private fun reader(source: ScriptedSource, abandon: () -> Boolean = { false }) =
        Http1ResponseReader(source, readSize = 1024, shouldAbandon = abandon, clock = { source.now })

    private fun Http1Response.bodyText() = String(body, Charsets.ISO_8859_1)

    @Test
    fun `content-length is matched in any case and frames the response exactly`() {
        val source = ScriptedSource(
            "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhelloHTTP/1.1 404 Not Found\r\nCONTENT-LENGTH:2\r\n\r\nno" to 10L,
        )
        val reader = reader(source)

        val first = reader.readResponse(ignoreLength = false)!!
        val second = reader.readResponse(ignoreLength = false)!!

        assertEquals("HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\n", first.head)
        assertEquals("hello", first.bodyText())
        assertTrue(second.head.startsWith("HTTP/1.1 404"))
        assertEquals("no", second.bodyText())
        assertFalse(first.closeConnection)
    }

    @Test
    fun `a Content-Length in the body is not taken for the header`() {
        val body = "Content-Length: 3\r\n"
        val source = ScriptedSource(
            "HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n\r\n$body" to 1L,
        )

        val response = reader(source).readResponse(ignoreLength = false)!!

        assertEquals(body, response.bodyText())
    }

    @Test
    fun `100 Continue arriving in the same read as the final response is consumed`() {
        val source = ScriptedSource(
            "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" to 5L,
        )

        val response = reader(source).readResponse(ignoreLength = false)!!

        assertEquals("HTTP/1.1 100 Continue\r\n\r\n", response.interim)
        assertTrue(response.head.startsWith("HTTP/1.1 200 OK"))
        assertEquals("ok", response.bodyText())
    }

    @Test
    fun `100 Continue alone in the first read is still skipped`() {
        val source = ScriptedSource(
            "HTTP/1.1 100 Continue\r\n\r\n" to 5L,
            "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n" to 9L,
        )

        val response = reader(source).readResponse(ignoreLength = false)!!

        assertEquals("HTTP/1.1 100 Continue\r\n\r\n", response.interim)
        assertTrue(response.head.startsWith("HTTP/1.1 201"))
        assertEquals(9L, response.headCompletedAt)
    }

    @Test
    fun `an interim response with nothing after it is reported as the response`() {
        val source = ScriptedSource(
            "HTTP/1.1 100 Continue\r\n\r\n" to 5L,
            null to 105L,
        )

        val response = reader(source).readResponse(ignoreLength = false)!!

        assertEquals("HTTP/1.1 100 Continue\r\n\r\n", response.head)
        assertTrue(response.closeConnection)
    }

    @Test
    fun `101 Switching Protocols is a final response`() {
        val source = ScriptedSource("HTTP/1.1 101 Switching Protocols\r\nContent-Length: 0\r\n\r\n" to 1L)

        val response = reader(source).readResponse(ignoreLength = false)!!

        assertEquals("", response.interim)
        assertTrue(response.head.startsWith("HTTP/1.1 101"))
    }

    @Test
    fun `pipelined responses are timed by when their own bytes arrived`() {
        val source = ScriptedSource(
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na" to 100L,
            "HTTP/1.1 200 OK\r\nContent-Le" to 300L,
            "ngth: 1\r\n\r\nb" to 450L,
        )
        val reader = reader(source)

        val first = reader.readResponse(ignoreLength = false)!!
        val second = reader.readResponse(ignoreLength = false)!!

        assertEquals(100L, first.headCompletedAt)
        assertEquals(100L, first.lastByteAt)
        assertEquals(450L, second.headCompletedAt)
        assertEquals(450L, second.lastByteAt)
    }

    @Test
    fun `responses that arrived together share their arrival time however late they are parsed`() {
        val source = ScriptedSource(
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\naHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nb" to 70L,
        )
        val reader = reader(source)

        reader.readResponse(ignoreLength = false)
        source.now = 999L
        val second = reader.readResponse(ignoreLength = false)!!

        assertEquals(70L, second.headCompletedAt)
    }

    @Test
    fun `chunked bodies are de-chunked past extensions and trailers, leaving the next response intact`() {
        val source = ScriptedSource(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
                "5;name=value\r\nhello\r\n0\r\nX-Checksum: 1\r\n\r\n" +
                "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n" to 1L,
        )
        val reader = reader(source)

        val chunked = reader.readResponse(ignoreLength = false)!!
        val next = reader.readResponse(ignoreLength = false)!!

        assertEquals("hello", chunked.bodyText())
        assertTrue(next.head.startsWith("HTTP/1.1 204"))
    }

    @Test
    fun `a negative chunk size is rejected`() {
        val source = ScriptedSource("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n-1\r\n" to 1L)

        assertThrows<RuntimeException> { reader(source).readResponse(ignoreLength = false) }
    }

    @Test
    fun `a negative content length is rejected`() {
        val source = ScriptedSource("HTTP/1.1 200 OK\r\nContent-Length: -5\r\n\r\n" to 1L)

        assertThrows<RuntimeException> { reader(source).readResponse(ignoreLength = false) }
    }

    @Test
    fun `body bytes are kept exactly as received`() {
        val raw = String(ByteArray(128) { (0x80 + it).toByte() }, Charsets.ISO_8859_1)
        val source = ScriptedSource("HTTP/1.1 200 OK\r\nContent-Length: 128\r\n\r\n$raw" to 1L)

        val response = reader(source).readResponse(ignoreLength = false)!!

        assertArrayEquals(ByteArray(128) { (0x80 + it).toByte() }, response.body)
    }

    @Test
    fun `ignoreLength reads a chunked response raw until the connection goes quiet`() {
        val chunks = "3\r\nabc\r\n0\r\n\r\n"
        val source = ScriptedSource(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n$chunks" to 1L,
            null to 5001L,
        )

        val response = reader(source).readResponse(ignoreLength = true)!!

        assertEquals(chunks, response.bodyText())
        assertFalse(response.closeConnection)
        assertEquals(listOf(5000, 10_000), source.timeoutsSet, "the read timeout is restored after the timed read")
    }

    @Test
    fun `a response without a length is read until quiet, then the connection is retired`() {
        val source = ScriptedSource(
            "HTTP/1.1 200 OK\r\n\r\npart one, " to 1L,
            "part two" to 2L,
            null to 1002L,
        )

        val response = reader(source).readResponse(ignoreLength = false)!!

        assertEquals("part one, part two", response.bodyText())
        assertTrue(response.closeConnection)
        assertEquals(2L, response.lastByteAt)
        assertEquals(listOf(1000, 10_000), source.timeoutsSet)
    }

    @Test
    fun `a connection that closes mid-body keeps what arrived and is retired`() {
        val source = ScriptedSource("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhalf" to 1L)

        val response = reader(source).readResponse(ignoreLength = false)!!

        assertEquals("half", response.bodyText())
        assertTrue(response.closeConnection)
    }

    @Test
    fun `an abandoned run stops reading`() {
        val source = ScriptedSource("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhalf" to 1L)

        assertNull(reader(source) { true }.readResponse(ignoreLength = false))
    }

    @Test
    fun `no bytes at all is no response`() {
        assertThrows<java.net.ConnectException> { reader(ScriptedSource()).readResponse(ignoreLength = false) }
    }

    @Test
    fun `bytes received while a request is held part-sent start the next response`() {
        val head = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
        val source = ScriptedSource(head to 40L)
        val reader = reader(source)

        assertEquals(head.length, reader.readWithin(250))
        val response = reader.readResponse(ignoreLength = false)!!

        assertTrue(response.head.startsWith("HTTP/1.1 400"))
        assertEquals(40L, response.headCompletedAt)
        assertEquals(listOf(250, 10_000), source.timeoutsSet)
    }

    @Test
    fun `a pause that hears nothing leaves the buffer as it was`() {
        val source = ScriptedSource(
            null to 250L,
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" to 300L,
        )
        val reader = reader(source)

        assertEquals(0, reader.readWithin(250))
        assertTrue(reader.readResponse(ignoreLength = false)!!.head.startsWith("HTTP/1.1 200"))
    }

    @Test
    fun `header helpers read only the head, in any case, with or without a space`() {
        val head = "HTTP/1.1 200 OK\r\nX-Note: transfer-encoding: chunked\r\ncontent-length:7\r\nTransfer-Encoding: gzip, Chunked\r\n\r\n"

        assertEquals("7", Http1ResponseReader.headerValue(head, "Content-Length"))
        assertEquals(7, Http1ResponseReader.contentLength(head))
        assertTrue(Http1ResponseReader.isChunked(head))
        assertEquals(-1, Http1ResponseReader.contentLength("HTTP/1.1 204 No Content\r\n\r\n"))
        assertFalse(Http1ResponseReader.isChunked("HTTP/1.1 200 OK\r\nX-Note: transfer-encoding: chunked\r\n\r\n"))
    }

    @Test
    fun `decompression gets the body bytes exactly as received`() {
        val original = ByteArray(256) { it.toByte() }
        val compressed = ByteArrayOutputStream().also { out ->
            GZIPOutputStream(out).use { it.write(original) }
        }.toByteArray()

        val text = ThreadedRequestEngine.uncompressIfNecessary(
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n",
            compressed,
        )

        assertArrayEquals(original, text.toByteArray(Charsets.ISO_8859_1))
        assertEquals(
            String(original, Charsets.ISO_8859_1),
            ThreadedRequestEngine.uncompressIfNecessary("HTTP/1.1 200 OK\r\n\r\n", original),
        )
    }
}
