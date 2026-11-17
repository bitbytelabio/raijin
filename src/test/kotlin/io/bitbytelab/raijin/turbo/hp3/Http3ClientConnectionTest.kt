package io.bitbytelab.raijin.turbo.hp3

import io.bitbytelab.raijin.turbo.hp3.h3.Http3ClientConnection
import io.bitbytelab.raijin.turbo.hp3.h3.Http3Exception
import io.bitbytelab.raijin.turbo.hp3.h3.Http3FrameReader
import io.bitbytelab.raijin.turbo.hp3.h3.Http3FrameType
import io.bitbytelab.raijin.turbo.hp3.h3.Http3FrameWriter
import io.bitbytelab.raijin.turbo.hp3.h3.Http3Request
import io.bitbytelab.raijin.turbo.hp3.h3.Http3Settings
import io.bitbytelab.raijin.turbo.hp3.h3.qpack.FieldLine
import io.bitbytelab.raijin.turbo.hp3.h3.qpack.QpackDecoder
import io.bitbytelab.raijin.turbo.hp3.h3.qpack.QpackEncoder
import io.bitbytelab.raijin.turbo.hp3.h3.qpack.QpackEncoderStream
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class Http3ClientConnectionTest {

    private fun headers(vararg fields: Pair<String, String>): ByteArray =
        Http3FrameWriter.toBytes(
            Http3FrameType.HEADERS,
            QpackEncoder.encodeFieldSection(fields.map { (name, value) -> FieldLine(name, value) }),
        )

    private fun data(body: String): ByteArray =
        Http3FrameWriter.toBytes(Http3FrameType.DATA, body.toByteArray(Charsets.ISO_8859_1))

    private fun <T> withConnection(block: (Http3ClientConnection, MemoryTransport) -> T): T {
        val transport = MemoryTransport()
        return Http3ClientConnection.open(transport).use { connection -> block(connection, transport) }
    }

    /** The peer's control stream: its stream type and SETTINGS, held open afterwards. */
    private fun peerControlStream(settings: Http3Settings): HeldOpenInput = HeldOpenInput(
        byteArrayOf(0x00) + Http3FrameWriter.toBytes(Http3FrameType.SETTINGS, settings.encodePayload()),
    )

    private fun eventually(what: String, condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (!condition()) {
            check(System.nanoTime() - deadline < 0) { "timed out waiting for $what" }
            Thread.sleep(5)
        }
    }

    @Test
    fun earlyHintsAheadOfTheFinalResponseAreReadPast() = withConnection { connection, _ ->
        val stream = headers(":status" to "103", "link" to "</style.css>; rel=preload") +
            headers(":status" to "200", "content-type" to "text/plain") +
            data("hello")

        val response = connection.readResponse(ByteArrayInputStream(stream))

        assertEquals(200, response.status())
        assertEquals(
            listOf(FieldLine(":status", "200"), FieldLine("content-type", "text/plain")),
            response.fields(),
        )
        assertEquals("hello", String(response.body(), Charsets.ISO_8859_1))
        assertEquals(emptyList(), response.trailers())
    }

    @Test
    fun severalInterimResponsesStillLeaveTheTrailersWhereTheyBelong() = withConnection { connection, _ ->
        val stream = headers(":status" to "100") +
            headers(":status" to "103", "link" to "</app.js>; rel=preload") +
            headers(":status" to "200") +
            data("he") +
            data("llo") +
            headers("x-checksum" to "abc")

        val response = connection.readResponse(ByteArrayInputStream(stream))

        assertEquals(200, response.status())
        assertEquals("hello", String(response.body(), Charsets.ISO_8859_1))
        assertEquals(listOf(FieldLine("x-checksum", "abc")), response.trailers())
    }

    @Test
    fun aStreamThatEndsAfterOnlyInterimResponsesIsAnError() = withConnection { connection, _ ->
        val failure = assertFailsWith<Http3Exception> {
            connection.readResponse(ByteArrayInputStream(headers(":status" to "103")))
        }

        assertEquals(Http3Exception.H3_FRAME_UNEXPECTED, failure.errorCode())
        assertContains(failure.message.orEmpty(), "interim")
    }

    @Test
    fun contentAfterAnInterimResponseIsAnError() = withConnection { connection, _ ->
        val failure = assertFailsWith<Http3Exception> {
            connection.readResponse(ByteArrayInputStream(headers(":status" to "100") + data("early")))
        }

        assertEquals(Http3Exception.H3_FRAME_UNEXPECTED, failure.errorCode())
    }

    @Test
    fun aMalformedStatusIsReportedRatherThanReadPast() = withConnection { connection, _ ->
        val response = connection.readResponse(
            ByteArrayInputStream(headers(":status" to "1xx") + data("body")),
        )

        assertEquals(listOf(FieldLine(":status", "1xx")), response.fields())
        assertEquals("body", String(response.body(), Charsets.ISO_8859_1))
    }

    @Test
    fun peerStreamsAreReadOnThreadsThatBlockingInKwikDoesNotPin() = withConnection { _, transport ->
        val readBy = CompletableFuture<Thread>()
        val input = object : InputStream() {
            override fun read(): Int {
                readBy.complete(Thread.currentThread())
                return -1
            }
        }

        transport.openPeerStream(MemoryStream(3, true, input))

        val reader = readBy.get(5, TimeUnit.SECONDS)
        assertTrue(reader.isVirtual)
    }

    @Test
    fun aFailedConnectionReleasesSettingsWaitersAtOnce() = withConnection { connection, transport ->
        // RFC 9114 section 6.1: a server may not open a bidirectional stream.
        transport.openPeerStream(MemoryStream(1, false))
        assertEquals(
            Http3Exception.H3_STREAM_CREATION_ERROR,
            transport.closedWithError.get(5, TimeUnit.SECONDS),
        )

        val started = System.nanoTime()
        val settings = connection.awaitPeerSettings(30, TimeUnit.SECONDS)
        val waitedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)

        assertTrue(waitedMillis < 5_000, "waited ${waitedMillis}ms for SETTINGS on a failed connection")
        assertEquals(0, settings.size())
    }

    @Test
    fun closingReleasesSettingsWaiters() {
        val connection = Http3ClientConnection.open(MemoryTransport())
        val waiter = CompletableFuture.supplyAsync { connection.awaitPeerSettings(30, TimeUnit.SECONDS) }

        connection.close()

        assertEquals(0, waiter.get(5, TimeUnit.SECONDS).size())
    }

    @Test
    fun anInsertionBeforeTheCapacityIsSetFailsTheConnection() = withConnection { _, transport ->
        val encoderStream = byteArrayOf(0x02) +
            QpackEncoderStream.encodeInsertWithNameReference(0, "example.com")

        transport.openPeerStream(MemoryStream(7, true, ByteArrayInputStream(encoderStream)))

        assertEquals(
            Http3Exception.QPACK_ENCODER_STREAM_ERROR,
            transport.closedWithError.get(5, TimeUnit.SECONDS),
        )
    }

    @Test
    fun aCapacityAboveTheOneWeAdvertisedFailsTheConnection() = withConnection { _, transport ->
        val encoderStream = byteArrayOf(0x02) +
            QpackEncoderStream.encodeSetCapacity(Http3Settings.DEFAULT_QPACK_MAX_TABLE_CAPACITY + 1)

        transport.openPeerStream(MemoryStream(7, true, ByteArrayInputStream(encoderStream)))

        assertEquals(
            Http3Exception.QPACK_ENCODER_STREAM_ERROR,
            transport.closedWithError.get(5, TimeUnit.SECONDS),
        )
    }

    @Test
    fun anInsertionAfterTheCapacityIsSetIsAcknowledged() = withConnection { connection, transport ->
        val encoderStream = HeldOpenInput(
            byteArrayOf(0x02) +
                QpackEncoderStream.encodeSetCapacity(Http3Settings.DEFAULT_QPACK_MAX_TABLE_CAPACITY) +
                QpackEncoderStream.encodeInsertWithNameReference(0, "example.com"),
        )
        try {
            transport.openPeerStream(MemoryStream(7, true, encoderStream))

            eventually("the insertion to be acknowledged") {
                // Our decoder stream: its type, then Insert Count Increment of one (RFC 9204 4.4.3).
                transport.unidirectionalStreamOfType(0x03).writtenBytes().contentEquals(byteArrayOf(0x03, 0x01))
            }
            assertEquals(1L, connection.peerDynamicTableInsertCount())
            assertTrue(!transport.closedWithError.isDone)
        } finally {
            encoderStream.end()
        }
    }

    @Test
    fun anAuthorityTooLargeForThePeersTableIsSpelledOutRatherThanInserted() {
        val transport = MemoryTransport()
        val connection = Http3ClientConnection.open(transport)
        val control = peerControlStream(Http3Settings().with(Http3Settings.QPACK_MAX_TABLE_CAPACITY, 64))
        try {
            transport.openPeerStream(MemoryStream(3, true, control))
            assertEquals(64L, connection.awaitPeerSettings(5, TimeUnit.SECONDS)
                .get(Http3Settings.QPACK_MAX_TABLE_CAPACITY, 0))
            // 32 + 10 + 31 = 73 octets, RFC 9204 section 3.2.1, against a table of 64.
            val request = Http3Request.of(listOf(
                FieldLine(":method", "GET"),
                FieldLine(":scheme", "https"),
                FieldLine(":authority", "a-host-name-long-enough.example"),
                FieldLine(":path", "/"),
            ))
            val stream = connection.openRequestStream() as MemoryStream

            connection.writeRequest(stream, request)

            // Nothing past the stream type went out on our encoder stream...
            assertContentEquals(byteArrayOf(0x02), transport.unidirectionalStreamOfType(0x02).writtenBytes())
            // ...and the request decodes without any dynamic table at all.
            val frame = Http3FrameReader(ByteArrayInputStream(stream.writtenBytes())).readFrame()!!
            assertEquals(request.fields(), QpackDecoder.decodeFieldSection(frame.payload()))
            assertTrue(!transport.closedWithError.isDone)
        } finally {
            connection.close()
            control.end()
        }
    }

    @Test
    fun anAuthorityThatFitsThePeersTableIsInserted() {
        val transport = MemoryTransport()
        val connection = Http3ClientConnection.open(transport)
        val control = peerControlStream(Http3Settings().with(Http3Settings.QPACK_MAX_TABLE_CAPACITY, 4096))
        try {
            transport.openPeerStream(MemoryStream(3, true, control))
            connection.awaitPeerSettings(5, TimeUnit.SECONDS)
            val request = Http3Request.of(listOf(
                FieldLine(":method", "GET"),
                FieldLine(":scheme", "https"),
                FieldLine(":authority", "a-host-name-long-enough.example"),
                FieldLine(":path", "/"),
            ))

            connection.writeRequest(connection.openRequestStream(), request)

            val expected = byteArrayOf(0x02) +
                QpackEncoderStream.encodeSetCapacity(4096) +
                QpackEncoderStream.encodeInsertWithNameReference(0, "a-host-name-long-enough.example")
            assertContentEquals(expected, transport.unidirectionalStreamOfType(0x02).writtenBytes())
        } finally {
            connection.close()
            control.end()
        }
    }
}
