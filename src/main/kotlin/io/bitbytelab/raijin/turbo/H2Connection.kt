package io.bitbytelab.raijin.turbo
import com.twitter.hpack.Decoder
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.lang.Exception
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.URL
import java.util.concurrent.ConcurrentHashMap
import kotlin.concurrent.thread
import java.security.cert.X509Certificate
import java.util.*
import javax.net.ssl.*

/**
 * One HTTP/2 connection. Its reader thread connects, then reads frames and completes streams; once
 * the server's SETTINGS arrive a writer thread takes requests from the engine. The engine's manager
 * thread owns the lifecycle and collects what a closed connection left in flight only after both
 * threads have exited, so frame processing needs no lock and the in-flight set it sees is final.
 */
class H2Connection(val target: URL, val requestsPerConnection: Int, val engine: HTTP2RequestEngine) {

    companion object {
        const val CONNECTING = 1
        const val ALIVE = 2
        const val HALFCLOSED = 3
        const val CLOSED = 4

        private const val DEBUG = false

        /** How long the writer waits on an empty queue before it looks at the connection and run state again. */
        private const val QUEUE_POLL_MILLIS = 100L
        private const val SETTINGS_FRAME = 0x04
        private val PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(Charsets.ISO_8859_1)
        private val INITIAL_SETTINGS = byteArrayOf(0, 4, 0x7f, -1, -1, -1, // MAXINT window size (Burp match)
                                                   0, 2, 0, 0, 0, 0,   // no PUSH (Burp match)
                                                   0, 1, 0, 0, 0x10, 0, //  4096 header table size (Burp match)
                                                   0, 3, 0, 0, 0x01, 0 // 256 max *concurrent* streams (Burp match)
        )

        fun debug(message: String) {
            if (DEBUG) {
                Utils.out("Debug ${Thread.currentThread().id}: $message")
            }
        }

        private fun transformHeader(value: String, name: Boolean = false): String {
            var out = value.replace("^", "\r")
            out = out.replace("~", "\n")
            if (name) {
                out = out.replace("`", ":")
            }
            return out
        }

        fun buildReq(parsedRequest: HTTP2Request): LinkedList<Pair<String, String>> {
            return buildReq(parsedRequest, true)
        }

        fun buildReq(parsedRequest: HTTP2Request, transform: Boolean): LinkedList<Pair<String, String>> {
            val pseudoHeaders = LinkedHashMap<String, String>()
            val headers = LinkedList<Pair<String, String>>()
            val final = LinkedList<Pair<String, String>>()
            var host = ""

            for (header: String in parsedRequest.headers) {
                var name: String
                var value = ""
                if (header.contains(": ")) {
                    val split = header.split(": ", limit = 2)
                    name = split[0]
                    value = split[1]
               } else {
                   name = header
                }

                if (name == "Connection") {
                    continue
                }

                if (name == ":connection") {
                    name = "Connection"
                }

                // Any case: an HTTP/2-style template, or one DesyncTechniques lower-cased, says "host".
                if (name.equals("Host", ignoreCase = true) && host == "") {
                    host = value
                }

                if (name == "Cookie") {
                    val cookiesplit = value.split(";")
                    for (cookie: String in cookiesplit) {
                        if (cookie != "") {
                            var fixed = cookie
                            if (transform) {
                                fixed = transformHeader(cookie)
                            }
                            headers.add(Pair("cookie", fixed))
                        }
                    }
                    continue
                }

                if (transform) {
                    name = transformHeader(name, true)
                    value = transformHeader(value, false)
                }
                name = name.lowercase()

                if (name.startsWith(":")) {
                    if (pseudoHeaders.containsKey(name)) {
                        headers.add(Pair(name, value))
                    } else {
                        pseudoHeaders.put(name, value)
                    }
                } else {
                    headers.add(Pair(name, value))
                }
            }

            var stripHost = false

            if (!pseudoHeaders.containsKey(":scheme")) {
                final.add(Pair(":scheme", "https"))
            }
            if (!pseudoHeaders.containsKey(":method")) {
                final.add(Pair(":method", parsedRequest.method))
            }
            if (!pseudoHeaders.containsKey(":path")) {
                final.add(Pair(":path", parsedRequest.path))
            }
            if (!pseudoHeaders.containsKey(":authority")) {
                final.add(Pair(":authority", host))
                stripHost = true // if there's no :authority and there is a Host header, strip the first instance of the host header
            }

            for ((key, value) in pseudoHeaders) {
                final.add(Pair(key, value))
            }

            for ((key, value) in headers) {
                if (stripHost && key.equals("host")) {
                    stripHost = false
                    continue
                }
                final.add(Pair(key, value))
            }

            return final
        }
    }

    /** Streams this connection opened that still await their response; read by the reader, writer and manager threads. */
    val streams: MutableMap<Int, Stream> = ConcurrentHashMap()
    @Volatile
    var totalQueuedRequests = 0
        private set
    val decoder = Decoder(4096, 4096)
    private val encoder = HeaderEncoder()
    @Volatile
    var maxConcurrentStreams = 100

    @Volatile
    var state: Int = CONNECTING
        private set
    @Volatile
    var lastCreatedStreamID = -1
        private set

    /** Whether the server's SETTINGS arrived; a connection that closes without them never got past the handshake. */
    @Volatile
    var established = false
        private set

    /** What closed the connection, when an error did rather than the run or the connection's own work ending. */
    @Volatile
    var failure: Throwable? = null
        private set

    /** Guards the state transitions, the socket hand-over and stream registration. */
    private val lifecycle = Any()
    /** Serialises whole frames onto the socket: the reader writes ACKs while the writer writes requests. */
    private val writeLock = Any()
    @Volatile
    private var socket: Socket? = null
    @Volatile
    private var output: OutputStream? = null
    @Volatile
    private var writer: Thread? = null
    private val label = "${target.host}:${if (target.port == -1) target.defaultPort else target.port}"
    private val reader: Thread

    init {
        // Last, so the thread starts on a fully built connection. Connecting happens on it too: a
        // slow or silent server then costs this connection its timeout, not the manager thread.
        reader = thread(name = "turbo-h2-reader-$label", isDaemon = true) { readForever() }
    }

    /** Closes the connection. Closing the socket is also what unblocks the reader. */
    fun close() = shutDown(null)

    /** Closes the connection because of [cause], which the engine reports as the reason requests failed. */
    internal fun fail(cause: Throwable) = shutDown(cause)

    private fun shutDown(cause: Throwable?) {
        val open: Socket?
        synchronized(lifecycle) {
            if (state == CLOSED) {
                return
            }
            debug("Closing connection...")
            state = CLOSED
            failure = cause
            open = socket
        }
        try {
            open?.close()
        } catch (e: IOException) {
            debug("Error closing socket: $e")
        }
    }

    /** True once the connection is closed and neither of its threads can touch it again. */
    internal fun isFinished(): Boolean = state == CLOSED && !reader.isAlive && writer?.isAlive != true

    /** Waits, until [deadlineNanos] at the latest, for both threads to exit. */
    internal fun awaitExit(deadlineNanos: Long) {
        for (thread in listOfNotNull(reader, writer)) {
            val remainingMillis = (deadlineNanos - System.nanoTime()) / 1_000_000
            if (remainingMillis <= 0) {
                return
            }
            thread.join(remainingMillis)
        }
    }

    private fun connect(): InputStream {
        val port = if (target.port == -1) target.defaultPort else target.port
        val timeout = engine.socketTimeoutMillis
        val plain = Socket()
        adopt(plain)
        plain.connect(InetSocketAddress(target.host, port), timeout)
        // Before the handshake, so a server that accepts and then says nothing cannot stall it.
        plain.soTimeout = timeout
        var connected: Socket = plain
        if (target.protocol == "https") {
            val sslHost = target.host.removePrefix("[").removeSuffix("]")
            val ssl = createSSLSocketFactory().createSocket(plain, sslHost, port, true) as SSLSocket
            val sslp = ssl.sslParameters
            sslp.applicationProtocols = arrayOf("h2") // don't offer "http/1.1"
            ssl.sslParameters = sslp
            adopt(ssl)
            ssl.startHandshake()
            connected = ssl
        }

        val out = connected.outputStream
        output = out
        synchronized(writeLock) {
            out.write(PREFACE)
            out.write(Frame(0x04, 0x00, 0, INITIAL_SETTINGS).asBytes())
            out.write(Frame(0x08, 0x00, 0, HTTP2Utils.intToFourBytes(2147418112)).asBytes()) // Burp match
            out.flush()
        }
        return connected.inputStream
    }

    /** Makes [candidate] the socket [close] closes, unless the connection already closed while connecting. */
    private fun adopt(candidate: Socket) {
        synchronized(lifecycle) {
            if (state != CLOSED) {
                socket = candidate
                return
            }
        }
        candidate.close()
        throw SocketException("Connection closed while connecting")
    }

    private fun startSendingRequests() {
        synchronized(lifecycle) {
            if (state != CONNECTING) {
                return
            }
            state = ALIVE
            established = true
            writer = thread(name = "turbo-h2-writer-$label", isDaemon = true) { writeForever() }
        }
    }

    private fun halfClose() {
        synchronized(lifecycle) {
            if (state != ALIVE) {
                return
            }
            state = HALFCLOSED
        }
        if (streams.isEmpty()) {
            close()
        }
    }

    /** Called by a stream once its callback has run. */
    internal fun streamCompleted(streamID: Int) {
        streams.remove(streamID)
        if (state == HALFCLOSED && streams.isEmpty()) {
            debug("Transitioning halfclosed connection to closed")
            close()
        }
    }

    private fun readForever() {
        try {
            val input = connect()
            val header = ByteArray(9)
            while (state != CLOSED) {
                if (engine.runState.get() >= 3) {
                    close()
                    return
                }
                if (state == HALFCLOSED && streams.isEmpty()) {
                    debug("Transitioning halfclosed connection to closed")
                    close()
                    return
                }

                debug("Reading...")
                if (!readFrameHeader(input, header)) {
                    continue
                }
                if (state == CONNECTING && header[3].toInt() != SETTINGS_FRAME) {
                    throw IOException("The server's first frame was not SETTINGS - is $label speaking HTTP/2?")
                }
                val payload = ByteArray(HTTP2Utils.threeByteInt(header))
                readFully(input, payload)
                handleFrame(header + payload)
            }
        } catch (e: Exception) {
            if (state != CLOSED) {
                Utils.out("Stopping read thread: $e")
            }
            fail(e)
        }
        debug("Closing read thread...")
    }

    /**
     * Reads the next frame header. Returns false when the read timed out with nothing read and
     * nothing to wait for, so an idle connection stays open; a timeout during the handshake, with
     * requests in flight, or part-way through a header is the connection's end, and so is EOF.
     */
    private fun readFrameHeader(input: InputStream, header: ByteArray): Boolean {
        var haveRead = 0
        while (haveRead < header.size) {
            val justRead = try {
                input.read(header, haveRead, header.size - haveRead)
            } catch (e: SocketTimeoutException) {
                if (haveRead == 0 && state != CONNECTING && streams.isEmpty()) {
                    return false
                }
                throw readTimeout(e)
            }
            if (justRead == -1) {
                throw EOFException("The server closed the connection")
            }
            haveRead += justRead
        }
        return true
    }

    private fun readFully(input: InputStream, buffer: ByteArray) {
        var haveRead = 0
        while (haveRead < buffer.size) {
            val justRead = try {
                input.read(buffer, haveRead, buffer.size - haveRead)
            } catch (e: SocketTimeoutException) {
                throw readTimeout(e)
            }
            if (justRead == -1) {
                throw EOFException("The server closed the connection mid-frame")
            }
            haveRead += justRead
        }
    }

    private fun readTimeout(cause: SocketTimeoutException): IOException {
        val waitedFor = if (state == CONNECTING) "the server's SETTINGS" else "responses to ~${streams.size} in-flight requests"
        return IOException("Socket read timeout after ${engine.socketTimeoutMillis}ms waiting for $waitedFor", cause)
    }

    private fun handleFrame(frameBytes: ByteArray) {
        val streamID = HTTP2Utils.fourByteInt(frameBytes.sliceArray(5..8)) and 0x7fffffff
        if (streamID == 0) {
            handleConnectionFrame(frameBytes)
            return
        }

        val stream = streams[streamID]
        if (stream == null) {
            // RFC 9113 section 5.1: WINDOW_UPDATE and RST_STREAM can still arrive for a stream that
            // has finished. Now that idle connections keep reading, they must not kill the connection.
            val type = frameBytes[3].toInt()
            if (streamID <= lastCreatedStreamID && (type == 0x08 || type == 0x03)) {
                debug("Ignoring frame of type $type on finished stream $streamID")
                return
            }
            throw IOException("Received message on unrecognised or closed stream: $streamID | $lastCreatedStreamID")
        }
        stream.processFrame(frameBytes)
    }

    /** Frames on stream 0 belong to the connection, never to a request. */
    private fun handleConnectionFrame(frameBytes: ByteArray) {
        val type = frameBytes[3]
        val flags = frameBytes[4]
        val payload = frameBytes.sliceArray(9 until frameBytes.size)
        when (type.toInt()) {
            SETTINGS_FRAME -> {
                val settings = SettingsFrame(type, flags, 0, payload)
                if (settings.isAck) {
                    return
                }
                settings.maxConcurrentStreams?.takeIf { it > 0L }?.let { limit ->
                    val capped = limit.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
                    debug("Change max concurrent streams from $maxConcurrentStreams to $capped")
                    maxConcurrentStreams = capped
                }
                settings.headerTableSize?.let { encoder.peerTableSize(it) }
                sendFrame(Frame(0x04, 0x01, 0, byteArrayOf()))
                startSendingRequests()
            }
            0x07 -> {
                GoAwayFrame(type, flags, 0, payload)
                Utils.out("Server sent a GOAWAY, dumping the whole connection")
                fail(IOException("The server sent GOAWAY"))
            }
            else -> debug("Ignoring connection frame of type $type")
        }
    }

    private fun writeForever() {
        debug("Starting write thread")
        try {
            while (state == ALIVE) {
                val runState = engine.runState.get()
                if (runState >= 3) {
                    close()
                    return
                }
                // 0 is "connecting": nothing goes out before start(), as on the other engines.
                if (runState == 0) {
                    Thread.sleep(10)
                    continue
                }

                // todo use a lock instead, should be faster
                if (streams.size >= maxConcurrentStreams) {
                    Thread.sleep(100)
                    continue
                }

                if (totalQueuedRequests >= requestsPerConnection) {
                    halfClose()
                    return
                }

                val req = engine.nextRequest(QUEUE_POLL_MILLIS)
                if (req == null) {
                    // In flight first, then the queues: a callback queues its follow-ups before its
                    // stream is removed, so this order cannot miss one.
                    if (engine.runState.get() == 2 && streams.isEmpty() && engine.hasNoQueuedWork()) {
                        close()
                        return
                    }
                    continue
                }

                send(req)
            }
        } catch (e: Exception) {
            if (state != CLOSED) {
                Utils.out("Stopping write thread: $e")
            }
            fail(e)
        }
        debug("Exiting write thread")
    }

    private fun send(req: Request) {
        val parsedRequest: HTTP2Request
        val built: List<Pair<String, String>>
        try {
            parsedRequest = HTTP2Request(req.getRequest())
            built = buildReq(parsedRequest)
        } catch (e: Exception) {
            // The request itself cannot be expressed; no retry or other connection would change that.
            Utils.out("Skipping a request that could not be built as HTTP/2: $e")
            engine.permaFails.incrementAndGet()
            return
        }

        val stream = addStream(req)
        if (stream == null) {
            engine.requeue(req) // never sent, so no retry is charged; the loop sees the closed state
            return
        }

        val headerBlock = encoder.encode(built)
        val body = parsedRequest.body
        if (body.isNullOrEmpty()) {
            // 5 = 4 + 1 (end headers & end stream)
            stream.sentAt = System.nanoTime()
            sendFrame(Frame(0x01, 0x05, stream.streamID, headerBlock))
        }
        else {
            //debug("Sending a data frame: '"+parsedRequest.body+"'")
            sendFrame(Frame(0x01, 0x04, stream.streamID, headerBlock))
            stream.sentAt = System.nanoTime()
            sendFrame(Frame(0x00, 0x01, stream.streamID, body.toByteArray(Charsets.ISO_8859_1)))
        }
    }

    fun hasInflightRequests(): Boolean = streams.isNotEmpty()

    fun getInflightRequests(): List<Request> {
        if (state != CLOSED) {
            throw Exception("Access to in-flight requests is hazardous on live connections")
        }
        return streams.values.map{it.req}
    }

    fun sendFrame(frame: Frame) {
        val out = output ?: throw SocketException("Not connected")
        synchronized(writeLock) {
            out.write(frame.asBytes())
            out.flush()
        }
    }

    /**
     * Registers a stream for [req], or returns null once the connection has stopped taking work.
     * Atomic with [shutDown], so no stream joins a connection after it has closed.
     */
    private fun addStream(req: Request): Stream? {
        synchronized(lifecycle) {
            if (state != ALIVE || totalQueuedRequests >= requestsPerConnection) {
                return null
            }
            totalQueuedRequests += 1
            lastCreatedStreamID += 2
            val stream = Stream(this, lastCreatedStreamID, req, true)
            streams[lastCreatedStreamID] = stream
            debug("Sending on stream ${stream.streamID}")
            return stream
        }
    }

    private fun createSSLSocketFactory(): SSLSocketFactory {
        val trustingSslContext = SSLContext.getInstance("TLS")
        trustingSslContext.init(null, arrayOf<TrustManager>(TrustingTrustManager()), null)
        return trustingSslContext.socketFactory
    }

    private class TrustingTrustManager : X509TrustManager {
        override fun getAcceptedIssuers(): Array<X509Certificate>? {
            return null
        }

        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
    }
}


class HTTP2Request(raw: String) {
    val method: String
    val path: String
    val headers: List<String>
    var body: String? = null

    init {
        val start = raw.split(" ", limit=3)
        method = start[0]
        path = start[1]
        val prepped: String
        if (!raw.contains("\r\n")) {
            prepped = raw.replace("\n", "\r\n")
        } else {
            prepped = raw
        }
        val split = prepped.split("\r\n\r\n", ignoreCase = false, limit = 2)
        headers = split[0].split("\r\n").drop(1).dropLastWhile { it == ""}
        if (split.size > 1) {
            body = split[1]
        }
    }
}
