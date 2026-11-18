package io.bitbytelab.raijin.turbo

import burp.api.montoya.utilities.CompressionType
import java.io.*
import java.net.*
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.zip.GZIPInputStream
import javax.net.ssl.*
import kotlin.IllegalStateException

open class ThreadedRequestEngine @JvmOverloads constructor(url: String, val threads: Int, maxQueueSize: Int, val readFreq: Int, requestsPerConnection: Int, override val maxRetriesPerRequest: Int, override var idleTimeout: Long = 0, override val callback: (Request, Boolean) -> Boolean, var timeout: Int, override var readCallback: ((String) -> Boolean)?, val readSize: Int, val resumeSSL: Boolean, var explodeOnEarlyRead: Boolean = false, private val adaptive: Boolean = false): RequestEngine(), AdaptiveTransport {

    private val connectedLatch = CountDownLatch(threads)
    // A fixed worker pipelines up to readFreq requests before it reads; an adaptive one reads each
    // response before it sends again.
    private val workers = AdaptiveWorkerLifecycle(this, adaptive, threads) { handle ->
        sendRequests(handle, if (handle == null) readFreq else 1)
    }
    private val requestLimit = AtomicInteger(requestsPerConnection)
    private val retryQueue = LinkedBlockingQueue<Request>()
    private lateinit var connector: Http1Connector

    val requestsPerConnection: Int
        get() = requestLimit.get()

    // Filled from certificates during handshakes on every worker thread.
    val domains: MutableSet<String> = ConcurrentHashMap.newKeySet()

    init {
        try {
            require(!adaptive || requestsPerConnection in 1..1_000_000) {
                "Adaptive request lifetime must be between 1 and 1,000,000"
            }
            val desyncMode = TurboSettings.desyncAgent
            Utils.out("desync-agent-mode = $desyncMode, requestsPerConnection = $requestsPerConnection")
            if (desyncMode == true && requestsPerConnection > 1) {
                throw IllegalArgumentException("desync-agent-mode is enabled: requestsPerConnection must be 1 to prevent false-positives (currently set to $requestsPerConnection)")
            }

            internalSettings.put("ignoreLength", false)

            // idleTimeout is in milliseconds, as on every other engine and in the docs.
            lastLife = System.currentTimeMillis()

            require(!adaptive || threads > 0) { "Adaptive worker count must be positive" }
            target = URL(url)

            requestQueue = if (maxQueueSize > 0) {
                LinkedBlockingQueue(maxQueueSize)
            }
            else {
                LinkedBlockingQueue()
            }

            completedLatch = CountDownLatch(threads)
            connector = Http1Connector(target, domains)

            Utils.err("Establishing $threads connection to $url ...");
            // Gate admission counts only workers that have actually entered their run loop.
            workers.startInitial(awaitRunning = true)
        } catch(failure: Throwable) {
            workers.abortStart()
            Utils.unregisterEngine(this)
            throw failure
        }

    }

    companion object {

        @JvmSynthetic
        internal fun withAdaptiveWorkerStarter(
            url: String,
            threads: Int,
            maxQueueSize: Int,
            readFreq: Int,
            requestsPerConnection: Int,
            maxRetriesPerRequest: Int,
            idleTimeout: Long,
            callback: (Request, Boolean) -> Boolean,
            timeout: Int,
            readCallback: ((String) -> Boolean)?,
            readSize: Int,
            resumeSSL: Boolean,
            explodeOnEarlyRead: Boolean,
            starter: AdaptiveWorkerStarter,
        ) = AdaptiveWorkerStarterConstructionContext.withStarter(starter) {
            ThreadedRequestEngine(
                url, threads, maxQueueSize, readFreq, requestsPerConnection, maxRetriesPerRequest,
                idleTimeout, callback, timeout, readCallback, readSize, resumeSSL, explodeOnEarlyRead,
                adaptive = true,
            )
        }

        internal fun connectionBackoffMillis(consecutiveFailures: Int, adaptive: Boolean): Long {
            val exponent = if (adaptive) consecutiveFailures.coerceIn(1, 7) else consecutiveFailures
            // 2^n grows past any sensible wait (and past Long) for a target that stays down.
            return (Math.pow(2.0, exponent.toDouble()) * 200.0).coerceAtMost(MAX_CONNECT_BACKOFF_MS.toDouble()).toLong()
        }

        /** Longest pause between connection attempts to a target that keeps refusing. */
        internal const val MAX_CONNECT_BACKOFF_MS = 30_000L

        /**
         * The response body as a string of bytes (ISO-8859-1), decompressed when [headers] name a
         * content coding. The bytes go to the decompressor exactly as received: passing them through
         * a String first corrupted every byte from 0x80 to 0xFF.
         */
        fun uncompressIfNecessary(headers: String, body: ByteArray): String {
            val lowered = headers.lowercase()
            if (lowered.indexOf("content-encoding: ") == -1) {
                return Utils.bytesToString(body)
            }
            val compressionType = when {
                lowered.indexOf("content-encoding: gzip") != -1 -> CompressionType.GZIP
                lowered.indexOf("content-encoding: deflate") != -1 -> CompressionType.DEFLATE
                lowered.indexOf("content-encoding: br") != -1 -> CompressionType.BROTLI
                else -> return Utils.bytesToString(body)
            }

            val api = Utils.montoyaApi
            if (api == null) {
                if (compressionType == CompressionType.GZIP) {
                    return ungzip(body)
                }
                Utils.out("Can't decompress response")
                return Utils.bytesToString(body)
            }

            return try {
                val decompressed = api.utilities().compressionUtils()
                    .decompress(burp.api.montoya.core.ByteArray.byteArray(*body), compressionType)
                Utils.bytesToString(decompressed.bytes)
            } catch (e: RuntimeException) {
                Utils.err("Decompression failed - possible partial response. Using undecompressed bytes instead.")
                Utils.bytesToString(body)
            }
        }

        fun ungzip(compressed: ByteArray): String {
            if (compressed.isEmpty()) {
                return ""
            }

            val out = ByteArrayOutputStream()
            try {
                val bytesIn = ByteArrayInputStream(compressed)
                val unzipped = GZIPInputStream(bytesIn)
                while (true) {
                    val bytes = ByteArray(1024)
                    val read = unzipped.read(bytes, 0, 1024)
                    if (read <= 0) {
                        break
                    }
                    out.write(bytes, 0, read)
                }
            } catch (e: IOException) {
                Utils.err("GZIP decompression failed - possible partial response. Using undecompressed bytes instead.")
                return Utils.bytesToString(compressed)
            }

            return Utils.bytesToString(out.toByteArray())
        }


    }

    /** A TLS socket factory that trusts every certificate, collecting the names they carry in [domains]. */
    fun createSSLSocketFactory(): SSLSocketFactory = Http1Connector.trustingTlsFactory(domains)

    // val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("localhost", 6574))

    override fun start(timeout: Int) {
        connectedLatch.await(timeout.toLong(), TimeUnit.SECONDS)
        goLive()
    }

    // A run that ends while start() still waits for its connections has none left to wait for.
    override fun onTerminalStateEntering(state: Int) {
        while (connectedLatch.count > 0) connectedLatch.countDown()
    }

    override val autoProtocol = AutoProtocol.HTTP1

    override fun defaultAdaptiveLimits() = AdaptiveLimits(50, 100)

    override fun currentAdaptiveLimits() = AdaptiveLimits(
        workers.targetSize(),
        requestLimit.get(),
    )

    override fun adaptiveMetrics(): AdaptiveMetrics {
        val limits = currentAdaptiveLimits()
        val saturated = requestQueue.isNotEmpty() || retryQueue.isNotEmpty() || activeRequests.get() >= limits.concurrency
        return baseAdaptiveMetrics(limits, saturated).copy(
            safeToMeasure = workers.converged(),
        )
    }

    override fun resizeConcurrency(newLimit: Int) {
        require(adaptive) { "Live resize is available only to adaptive threaded engines" }
        workers.resize(newLimit)
    }

    override fun resizeRequestsPerConnection(newLimit: Int): Boolean {
        require(adaptive) { "Live request lifetime is available only to adaptive threaded engines" }
        requestLimit.set(newLimit.coerceIn(1, 1_000_000))
        return true
    }

    internal fun currentWorkerCapacity(): Int = workers.liveSize()

    internal fun awaitAdaptiveWorkerCount(target: Int, timeout: Long, unit: TimeUnit): Int =
        workers.awaitWorkerCount(target, timeout, unit)

    override fun completionInitialized(): Boolean = adaptive || super.completionInitialized()

    override fun awaitCompletion(timeout: Long, unit: TimeUnit): Boolean = workers.awaitCompletion(timeout, unit)

    override fun sealCompletion() = workers.sealCompletion()

    override fun buildRequest(template: String, payloads: List<String?>, learnBoring: Int?, label: String): Request {
        var prepared = template

        if (Utils.isHTTP2(prepared.toByteArray())) {
            prepared = prepared.replaceFirst("HTTP/2\r\n", "HTTP/1.1\r\n")
        }

        if(Utils.getHeaders(prepared).contains("Connection: close")) {
            prepared = prepared.replaceFirst("Connection: close", "Connection: keep-alive")
        }

        return Request(prepared, payloads, learnBoring?: 0, label)
    }

    private fun sendRequests(handle: DynamicWorkerRegistry.Handle?, baseReadFreq: Int) {
        val readFreq = baseReadFreq
        val inflight = ArrayDeque<Request>()
        var connected = false
        var reqWithResponse: Request? = null
        var answeredRequests = 0
        var consecutiveFailedConnections = 0
        var reuseSSL = resumeSSL
        var requestReservedForSetup: Request? = null

        try {
            while (!shouldAbandonRun()) {
                if (workers.shouldRetire(handle)) return
                if (adaptive && runState.get() >= 1 && requestReservedForSetup == null) {
                    while (!shouldAbandonRun() && !workers.shouldRetire(handle)) {
                        requestReservedForSetup = retryQueue.poll() ?: requestQueue.poll(100, TimeUnit.MILLISECONDS)
                        if (requestReservedForSetup != null || runState.get() >= 2) break
                    }
                    if (requestReservedForSetup == null) {
                        if (runState.get() >= 2 || shouldAbandonRun() || workers.shouldRetire(handle)) return
                        continue
                    }
                    activeRequests.incrementAndGet()
                }
                try {

                val socket = try {
                    connector.open(reuseSSL, timeout * 1000)
                }
                catch (ex: Exception) {
                    recordTransportFailure(ex)
                    Utils.out("Thread failed to connect")
                    val stackTrace = StringWriter()
                    ex.printStackTrace(PrintWriter(stackTrace))
                    Utils.err(stackTrace.toString())
                    consecutiveFailedConnections += 1
                    if (adaptive) {
                        requestReservedForSetup?.let { request ->
                            if (!shouldRetry(request)) {
                                finishFailedSetupRequest(request, ex)
                                activeRequests.decrementAndGet()
                                requestReservedForSetup = null
                            }
                        }
                        if (!waitForAdaptiveConnectionBackoff(consecutiveFailedConnections, handle)) return
                    } else {
                        retries.getAndIncrement()
                        Thread.sleep(connectionBackoffMillis(consecutiveFailedConnections, adaptive = false))
                    }
                    continue
                }
                val connectionIdAuto = connections.incrementAndGet().toString()
                try {
                val connection = Http1Connection(socket, timeout * 1000, readSize, ::triggerReadCallback, ::shouldAbandonRun)

                if(!connected) {
                    connected = true
                    connectedLatch.countDown()
                    while(!Utils.unloaded && runState.get() == 0 && !shouldAbandonRun()) {
                        Thread.sleep(10)
                    }
                }

                consecutiveFailedConnections = 0

                var requestsSent = 0
                answeredRequests = 0
                while (requestsSent < requestLimit.get() && !shouldAbandonRun()) {
                    if (workers.shouldRetire(handle)) return
                    val ignoreLength = internalSettings["ignoreLength"] == true
                    var ditchConnection = false
                    var readCount = 0
                    // Every batch starts on a clean buffer: bytes left over from the last are dropped.
                    connection.discard()

                    for (j in 1..readFreq) {
                        if (requestsSent >= requestLimit.get() || workers.shouldRetire(handle)) {
                            break
                        }

                        val wasReservedForSetup = requestReservedForSetup != null
                        var req = requestReservedForSetup.also { requestReservedForSetup = null }
                            ?: retryQueue.poll()
                        while (req == null && !shouldAbandonRun() && !workers.shouldRetire(handle) && requestsSent < requestLimit.get()) {
                            req = requestQueue.poll(100, TimeUnit.MILLISECONDS)

                            if (req == null) {
                                if (readCount > 0) {
                                    break
                                }
                                if(runState.get() >= 2) {
                                    return
                                }
                            }
                        }

                        if (req == null) break
                        if (requestsSent >= requestLimit.get() || workers.shouldRetire(handle)) {
                            // The bounded request queue may refill after poll returns. The retry
                            // queue is unbounded and checked first by every worker, so this stays
                            // non-blocking without dropping the request during shrink or shutdown.
                            retryQueue.add(req)
                            if (wasReservedForSetup) activeRequests.decrementAndGet()
                            break
                        }

                        inflight.addLast(req)
                        if (!wasReservedForSetup) activeRequests.incrementAndGet()
                        connection.write(req, explodeOnEarlyRead)

                        readCount++
                        requestsSent++

                    }

                    for (k in 1..readCount) {
                        val head = inflight.firstOrNull()?.template?.trimStart()?.startsWith("HEAD ", ignoreCase = true) == true
                        val response = connection.readResponse(ignoreLength, bodyless = head) ?: break
                        if (response.closeConnection) {
                            ditchConnection = true
                        }

                        if (!response.head.startsWith("HTTP")) {
                            throw Exception("no http")
                        }

                        val msg = response.interim + response.head + uncompressIfNecessary(response.head, response.body)

                        reqWithResponse = inflight.removeFirst()
                        try {
                            successfulRequests.getAndIncrement()
                            reqWithResponse.response = msg
                            if (reqWithResponse.connectionId == null) {
                                reqWithResponse.connectionId = connectionIdAuto
                            }
                            val sentAt = reqWithResponse.sent
                            reqWithResponse.ttfb = (response.headCompletedAt - sentAt) / 1000 // convert ns to microseconds
                            reqWithResponse.ttlb = (response.lastByteAt - sentAt) / 1000
                            reqWithResponse.time = reqWithResponse.ttfb
                            reqWithResponse.arrival = (response.headCompletedAt - start) / 1000

                            answeredRequests += 1
                            val interesting = try {
                                processResponse(
                                    reqWithResponse,
                                    (reqWithResponse.response as String).toByteArray(Charsets.ISO_8859_1),
                                )
                            } catch (exception: Throwable) {
                                recordResponseProcessingFailure(exception)
                                null
                            }
                            if (interesting != null) invokeCallback(reqWithResponse, interesting)
                        } finally {
                            activeRequests.decrementAndGet()
                            finishGatedRequest(reqWithResponse)
                        }

                    }

                    if (ditchConnection) {
                        break
                    }
                }
                } finally {
                    runCatching { socket.close() }
                    retiredConnections.incrementAndGet()
                }
            } catch (ex: Exception) {

                val failedAttemptCount = inflight.size
                if (ex !is InterruptedException) {
                    repeat(maxOf(1, failedAttemptCount)) { recordTransportFailure(ex) }
                }

                if (reuseSSL && (ex is SSLHandshakeException || ex is SSLException)) {
                    reuseSSL = false
                }
                else {
                    // todo distinguish couldn't send vs couldn't read
                    val activeRequest = inflight.peek()
                    if (activeRequest != null) {
                        val activeWord = activeRequest.words.joinToString(separator="/")
                        if (shouldRetry(activeRequest)) {
                            if (reqWithResponse != null) {
                                Utils.out("Autorecovering error after $answeredRequests answered requests. After '${reqWithResponse.words.joinToString(separator = "/")}' during '$activeWord'")
                            } else {
                                Utils.out("Autorecovering first-request error during '$activeWord'")
                            }
                        } else {
                            ex.printStackTrace()
                            Utils.err("Ignoring error: "+ex.toString())
                            val badReq = inflight.pop()
                            if (ex is IllegalStateException) {
                                badReq.response = "early-response"
                            } else {
                                badReq.response = "null"
                            }
                            if (badReq.sent != 0L) {
                                val elapsed = (System.nanoTime() - badReq.sent) / 1000
                                badReq.ttfb = elapsed
                                badReq.ttlb = elapsed
                                badReq.time = elapsed
                            }
                            invokeCallback(badReq, true)
                            finishGatedRequest(badReq)
                        }
                    } else {
                        if (ex !is InterruptedException) {
                            Utils.out("Autorecovering error with empty queue: ${ex.message}")
                            ex.printStackTrace()
                        }
                    }
                }

                // do callback here (allow user code change
                //readFreq = max(1, readFreq / 2)
                //requestsPerConnection = max(1, requestsPerConnection/2)
                //println("Lost ${inflight.size} requests. Changing requestsPerConnection to $requestsPerConnection and readFreq to $readFreq")
                activeRequests.addAndGet(-failedAttemptCount)
                retryQueue.addAll(inflight)
                inflight.clear()
                }
            }
        } finally {
            requestReservedForSetup?.let { request ->
                if (runState.get() < 3) retryQueue.add(request)
                activeRequests.decrementAndGet()
            }
            activeRequests.addAndGet(-inflight.size)
            inflight.clear()
        }
    }

    private fun finishFailedSetupRequest(request: Request, failure: Throwable) {
        request.gate?.let { gate ->
            gate.reportReadyWithoutWaiting()
            while (!gate.isOpen.get() && runState.get() < 3 && !Thread.currentThread().isInterrupted) {
                Thread.sleep(10)
            }
        }
        if (runState.get() >= 3) return
        request.response = "null"
        Utils.err("Ignoring error: $failure")
        invokeCallback(request, true)
        finishGatedRequest(request)
    }

    private fun waitForAdaptiveConnectionBackoff(
        consecutiveFailures: Int,
        handle: DynamicWorkerRegistry.Handle?,
    ): Boolean {
        var remainingMillis = connectionBackoffMillis(consecutiveFailures, adaptive = true)
        while (remainingMillis > 0) {
            if (shouldAbandonRun() || workers.shouldRetire(handle)) return false
            val pause = minOf(remainingMillis, 50L)
            try {
                Thread.sleep(pause)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return false
            }
            remainingMillis -= pause
        }
        return !shouldAbandonRun() && !workers.shouldRetire(handle)
    }

    override fun cleanup() {
        // Clean up thread-specific resources first
        domains.clear()

        // Interrupt the workers still running, giving each a moment to stop
        workers.stopAll()

        // Call parent cleanup for shared resources
        super.cleanup()
    }
}
