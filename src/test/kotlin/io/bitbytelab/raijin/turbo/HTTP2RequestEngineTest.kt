package io.bitbytelab.raijin.turbo

import java.io.DataInputStream
import java.io.EOFException
import java.io.IOException
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class HTTP2RequestEngineTest {

    private companion object {
        const val TEMPLATE = "GET /%s HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
    }

    private val servers = mutableListOf<FakeH2Server>()
    private val engines = mutableListOf<HTTP2RequestEngine>()

    @BeforeTest
    fun liveTurbo() {
        Utils.unloaded = false
    }

    @AfterTest
    fun tearDown() {
        engines.filter { it.runState.get() < 3 }.forEach { it.cancel() }
        servers.forEach { it.close() }
    }

    private fun server(
        sendSettings: Boolean = true,
        respond: Boolean = true,
        responseDelayMillis: Long = 0,
        respondWithDataFirst: Boolean = false,
        connectionFrames: Boolean = false,
        closeAfterResponses: Int = Int.MAX_VALUE,
    ) = FakeH2Server(sendSettings, respond, responseDelayMillis, respondWithDataFirst, connectionFrames, closeAfterResponses)
        .also { servers += it }

    private fun engine(
        server: FakeH2Server,
        threads: Int = 1,
        requestsPerConnection: Int = 100,
        maxRetries: Int = 0,
        idleTimeoutMillis: Long = 0,
        socketTimeoutMillis: Int = 10_000,
        maxQueueSize: Int = 0,
        onResponse: (Request) -> Unit = {},
    ) = HTTP2RequestEngine(
        "http://127.0.0.1:${server.port}", threads, maxQueueSize, requestsPerConnection, maxRetries, idleTimeoutMillis,
        { req, _ -> onResponse(req); false }, null, socketTimeoutMillis,
    ).also { engines += it }

    private fun answeredWords(answered: ConcurrentLinkedQueue<Request>) = answered.map { requireNotNull(it.words.single()) }

    @Test
    fun `a run that recycles connections completes only once every request is answered`() {
        val answered = ConcurrentLinkedQueue<Request>()
        val engine = engine(server(), threads = 2, requestsPerConnection = 2) { answered += it }
        engine.start(5)
        repeat(7) { engine.queue(TEMPLATE, "$it") }

        engine.showStats(30)

        assertEquals(4, engine.runState.get())
        assertEquals((0 until 7).map { "$it" }.sorted(), answeredWords(answered).sorted())
        assertEquals(7, engine.successfulRequests.get())
        assertEquals(0, engine.permaFails.get())
        assertTrue(engine.connections.get() >= 4, "two requests per connection needs at least four connections")
    }

    @Test
    fun `a server that never sends SETTINGS fails the queued requests instead of hanging`() {
        val engine = engine(server(sendSettings = false), threads = 2, maxRetries = 1, socketTimeoutMillis = 300)
        engine.start(5)
        repeat(3) { engine.queue(TEMPLATE, "$it") }
        val started = System.nanoTime()

        engine.showStats(30)

        assertEquals(4, engine.runState.get())
        assertTrue(elapsedMillis(started) < 15_000, "the run should give up after its connection attempts")
        assertEquals(3, engine.permaFails.get())
        assertEquals(0, engine.successfulRequests.get())
        assertTrue(assertNotNull(engine.lastError).contains("SETTINGS"), engine.lastError)
        assertNotNull(engine.failureSummary())
    }

    @Test
    fun `a server that stops answering fails the in-flight request instead of hanging`() {
        val engine = engine(server(respond = false), maxRetries = 0, socketTimeoutMillis = 300)
        engine.start(5)
        engine.queue(TEMPLATE, "0")

        engine.showStats(30)

        assertEquals(4, engine.runState.get())
        assertEquals(1, engine.permaFails.get())
        assertTrue(assertNotNull(engine.lastError).contains("in-flight"), engine.lastError)
    }

    @Test
    fun `idleTimeout is in milliseconds and cancels a run whose responses stop`() {
        val engine = engine(server(respond = false), idleTimeoutMillis = 300)
        engine.start(5)
        engine.queue(TEMPLATE, "0")
        val started = System.nanoTime()

        engine.showStats(30)

        assertEquals(3, engine.runState.get())
        assertTrue(elapsedMillis(started) < 5_000, "a 300ms idle timeout took ${elapsedMillis(started)}ms")
    }

    @Test
    fun `cancelling closes every connection's socket and ends its threads`() {
        val server = server()
        val engine = engine(server, threads = 2)
        assertTrue(waitUntil { server.clientAcks.get() == 2 }, "both connections should finish the handshake")

        engine.cancel()

        assertTrue(waitUntil { server.eofs.get() == 2 }, "the server should see both sockets closed")
        val label = "127.0.0.1:${server.port}"
        assertTrue(waitUntil { liveThreads("turbo-h2-reader-$label") == 0 && liveThreads("turbo-h2-writer-$label") == 0 })
    }

    @Test
    fun `requests queued past a full queue before start are still sent`() {
        val answered = ConcurrentLinkedQueue<Request>()
        val engine = engine(server(), maxQueueSize = 100) { answered += it }
        // Before start() nothing is sent, so the 101st and 102nd requests overflow the queue
        // and wait in the engine's pre-start backlog.
        repeat(102) { engine.queue(TEMPLATE, "$it") }

        engine.start(5)
        engine.showStats(30)

        assertEquals(4, engine.runState.get())
        assertTrue("101" in answeredWords(answered), "the request queued into the replacement queue was never sent")
        assertTrue("99" in answeredWords(answered))
    }

    @Test
    fun `a response that breaks its stream closes the connection and the run still completes`() {
        val engine = engine(server(respondWithDataFirst = true), maxRetries = 0)
        engine.start(5)
        engine.queue(TEMPLATE, "0")

        engine.showStats(30)

        assertEquals(4, engine.runState.get())
        assertEquals(0, engine.successfulRequests.get())
        assertEquals(1, engine.permaFails.get())
        assertTrue(assertNotNull(engine.lastError).contains("Expected headers"), engine.lastError)
    }

    @Test
    fun `connection-level frames never turn into requests when connections die`() {
        val answered = ConcurrentLinkedQueue<Request>()
        val engine = engine(server(connectionFrames = true, closeAfterResponses = 1), maxRetries = 5) { answered += it }
        engine.start(5)
        repeat(3) { engine.queue(TEMPLATE, "$it") }

        engine.showStats(30)

        assertEquals(4, engine.runState.get())
        assertEquals(listOf("0", "1", "2"), answeredWords(answered).sorted())
        assertEquals(0, engine.permaFails.get())
    }

    @Test
    fun `response timings are in microseconds`() {
        val answered = ConcurrentLinkedQueue<Request>()
        val engine = engine(server(responseDelayMillis = 150)) { answered += it }
        engine.start(5)
        engine.queue(TEMPLATE, "0")

        engine.showStats(30)

        val req = answered.single()
        assertTrue(req.time in 140_000L..10_000_000L, "req.time ${req.time} should be microseconds")
        assertEquals(req.ttlb, req.time)
        assertTrue(req.ttfb in 140_000L..req.ttlb, "ttfb ${req.ttfb} should be microseconds")
    }

    private fun elapsedMillis(startedNanos: Long) = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedNanos)

    private fun liveThreads(prefix: String) = Thread.getAllStackTraces().keys.count { it.isAlive && it.name.startsWith(prefix) }

    private fun waitUntil(timeoutMillis: Long = 5_000, condition: () -> Boolean): Boolean {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        while (System.nanoTime() < deadline) {
            if (condition()) return true
            Thread.sleep(10)
        }
        return condition()
    }
}

/**
 * A cleartext HTTP/2 server with just enough protocol to drive the engine: it answers each request
 * with a bare `:status: 200`, or misbehaves in the one way a test asks for.
 */
private class FakeH2Server(
    private val sendSettings: Boolean,
    private val respond: Boolean,
    private val responseDelayMillis: Long,
    private val respondWithDataFirst: Boolean,
    private val connectionFrames: Boolean,
    private val closeAfterResponses: Int,
) : AutoCloseable {
    private val server = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
    private val sockets = CopyOnWriteArrayList<Socket>()
    val port: Int = server.localPort

    /** Connections whose client acknowledged our SETTINGS, i.e. finished the handshake. */
    val clientAcks = AtomicInteger()

    /** Connections the client closed. */
    val eofs = AtomicInteger()

    init {
        thread(isDaemon = true, name = "fake-h2-accept-$port") {
            while (true) {
                val socket = try {
                    server.accept()
                } catch (e: IOException) {
                    return@thread
                }
                sockets += socket
                thread(isDaemon = true, name = "fake-h2-serve-$port") { serve(socket) }
            }
        }
    }

    private fun serve(socket: Socket) {
        socket.use {
            try {
                val input = DataInputStream(socket.getInputStream())
                val out = socket.getOutputStream()
                input.readFully(ByteArray(24)) // the client preface
                if (!sendSettings) {
                    drain(input)
                    return
                }
                // Empty, which is legal and is not an ACK.
                frame(out, 0x04, 0x00, 0, ByteArray(0))
                if (connectionFrames) {
                    frame(out, 0x08, 0x00, 0, byteArrayOf(0, 0, 0x10, 0)) // WINDOW_UPDATE
                    frame(out, 0x06, 0x00, 0, ByteArray(8)) // PING
                }

                var answered = 0
                while (true) {
                    val header = ByteArray(9)
                    input.readFully(header)
                    val length = ((header[0].toInt() and 0xff) shl 16) or ((header[1].toInt() and 0xff) shl 8) or (header[2].toInt() and 0xff)
                    val type = header[3].toInt()
                    val flags = header[4].toInt()
                    val stream = ByteBuffer.wrap(header, 5, 4).int and 0x7fffffff
                    input.readFully(ByteArray(length))

                    if (type == 0x04 && (flags and 0x01) != 0) {
                        clientAcks.incrementAndGet()
                    }
                    val endsStream = (type == 0x00 || type == 0x01) && (flags and 0x01) != 0
                    if (!endsStream || !respond) {
                        continue
                    }
                    if (responseDelayMillis > 0) {
                        Thread.sleep(responseDelayMillis)
                    }
                    if (respondWithDataFirst) {
                        frame(out, 0x00, 0x01, stream, "oops".toByteArray())
                    } else {
                        frame(out, 0x01, 0x05, stream, byteArrayOf(0x88.toByte())) // :status: 200, END_STREAM | END_HEADERS
                    }
                    answered++
                    if (answered >= closeAfterResponses) {
                        // FIN rather than RST, so the client still reads the response it was sent.
                        socket.shutdownOutput()
                        drain(input)
                        return
                    }
                }
            } catch (e: EOFException) {
                eofs.incrementAndGet()
            } catch (e: IOException) {
                // reset, or closed by the test
            }
        }
    }

    private fun drain(input: DataInputStream) {
        while (input.read() != -1) {
            // discard until the client closes
        }
        eofs.incrementAndGet()
    }

    private fun frame(out: OutputStream, type: Int, flags: Int, stream: Int, payload: ByteArray) {
        val header = ByteBuffer.allocate(9)
            .put((payload.size shr 16).toByte())
            .put((payload.size shr 8).toByte())
            .put(payload.size.toByte())
            .put(type.toByte())
            .put(flags.toByte())
            .putInt(stream)
        out.write(header.array())
        out.write(payload)
        out.flush()
    }

    override fun close() {
        server.close()
        sockets.forEach { runCatching { it.close() } }
    }
}
