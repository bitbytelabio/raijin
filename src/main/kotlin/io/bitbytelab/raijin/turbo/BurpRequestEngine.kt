package io.bitbytelab.raijin.turbo
import java.lang.RuntimeException
import java.net.URL
import java.util.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.thread
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse
import kotlin.collections.ArrayList

internal fun interface BurpRequestSender {
    fun send(service: TurboService, request: Request)
}

internal fun interface BurpBatchRequestSender {
    fun send(service: TurboService, requests: List<Request>, protocolVersion: HttpMode): List<HttpRequestResponse>
}

open class BurpRequestEngine private constructor(url: String, threads: Int, maxQueueSize: Int, override val maxRetriesPerRequest: Int, override var idleTimeout: Long, override val callback: (Request, Boolean) -> Boolean, override var readCallback: ((String) -> Boolean)?, val useHTTP1: Boolean, private val adaptive: Boolean, requestSender: BurpRequestSender?, batchRequestSender: BurpBatchRequestSender?, @Suppress("UNUSED_PARAMETER") internalMarker: Unit): RequestEngine(), AdaptiveTransport {

    @JvmOverloads
    constructor(url: String, threads: Int, maxQueueSize: Int, maxRetriesPerRequest: Int, idleTimeout: Long = 0, callback: (Request, Boolean) -> Boolean, readCallback: ((String) -> Boolean)?, useHTTP1: Boolean, adaptive: Boolean = false) : this(url, threads, maxQueueSize, maxRetriesPerRequest, idleTimeout, callback, readCallback, useHTTP1, adaptive, null, null, Unit)

    companion object {
        @JvmSynthetic
        internal fun withRequestSender(url: String, threads: Int, maxQueueSize: Int, maxRetriesPerRequest: Int, idleTimeout: Long = 0, callback: (Request, Boolean) -> Boolean, readCallback: ((String) -> Boolean)?, useHTTP1: Boolean, adaptive: Boolean = false, requestSender: BurpRequestSender, batchRequestSender: BurpBatchRequestSender? = null, adaptiveWorkerStarter: AdaptiveWorkerStarter? = null) =
            AdaptiveWorkerStarterConstructionContext.withStarter(adaptiveWorkerStarter) {
                BurpRequestEngine(url, threads, maxQueueSize, maxRetriesPerRequest, idleTimeout, callback, readCallback, useHTTP1, adaptive, requestSender, batchRequestSender, Unit)
            }

        /** How long a gate nothing can open any more is left before its requests are failed. */
        private const val UNOPENABLE_GATE_GRACE_NANOS = 1_000_000_000L
    }

    private val threadPool = Collections.synchronizedList(ArrayList<Thread>())
    private val workerRegistry = DynamicWorkerRegistry()
    private val adaptiveWorkerStarter = AdaptiveWorkerStarterConstructionContext.current()
    private val adaptiveWorkersReady = CountDownLatch(if (adaptive) 1 else 0)
    // ConcurrentHashMap with synchronised lists: every worker thread parks gated requests here
    // while the sending side iterates and removes, and a plain HashMap + LinkedList loses or
    // duplicates parked requests under that race.
    private val gatedRequests = ConcurrentHashMap<String, MutableList<Request>>()
    /** One per connectionId in use, removed when its last user lets go, so dynamic ids (0cl) do not pile up. */
    private val connectionLocks = ConcurrentHashMap<String, ConnectionLock>()
    /** Workers holding a request or a gated batch; a response callback in one of them could still open a gate. */
    private val busyWorkers = AtomicInteger(0)
    private val unopenableGateLock = Any()
    private var unopenableSince: Long? = null // guarded by unopenableGateLock
    private val hasInjectedRequestSender = requestSender != null
    private val montoyaRequestBuilder = BurpMontoyaRequestBuilder()
    private val requestSender = requestSender ?: BurpRequestSender(::sendMontoyaRequest)
    private val batchRequestSender = batchRequestSender ?: BurpBatchRequestSender(::sendMontoyaBatch)
    private lateinit var service: TurboService

    init {
        try {
            require(!adaptive || !useHTTP1) { "Adaptive Burp workers require HTTP/2" }
            require(!adaptive || threads > 0) { "Adaptive worker count must be positive" }

            requestQueue = if (maxQueueSize > 0) {
                LinkedBlockingQueue(maxQueueSize)
            }
            else {
                LinkedBlockingQueue()
            }


            completedLatch = CountDownLatch(threads)

            target = URL(url)
            val port = if (target.port == -1) target.defaultPort else target.port
            service = buildService(target, port)

            if (adaptive) {
                workerRegistry.resizeTo(threads, ::startWorker)
                adaptiveWorkersReady.countDown()
            } else {
                repeat(threads) { startFixedWorker() }
            }
        } catch (failure: Throwable) {
            if (adaptive) {
                runState.set(3)
                workerRegistry.abort()
                adaptiveWorkersReady.countDown()
                val partialWorkers = synchronized(threadPool) {
                    threadPool.toList().also { threadPool.clear() }
                }
                partialWorkers.forEach(Thread::interrupt)
            }
            Utils.unregisterEngine(this)
            throw failure
        }
    }

    override fun start(timeout: Int) {
        // Stamped before the run goes live, so no worker can time an arrival from the old value.
        start = System.nanoTime()
        runState.set(1)
    }

    override val autoProtocol = AutoProtocol.HTTP2
    override val supportsKettledRequests: Boolean
        get() = !useHTTP1

    override fun defaultAdaptiveLimits() = AdaptiveLimits(50, null)

    override fun currentAdaptiveLimits() = AdaptiveLimits(workerRegistry.desiredSize(), null)

    override fun adaptiveMetrics(): AdaptiveMetrics {
        val limits = currentAdaptiveLimits()
        val saturated = requestQueue.isNotEmpty() || activeRequests.get() >= limits.concurrency
        return baseAdaptiveMetrics(limits, saturated).copy(
            safeToMeasure = !adaptive || workerRegistry.isConverged(),
        )
    }

    override fun resizeConcurrency(newLimit: Int) {
        require(adaptive) { "Live resize is available only to adaptive Burp engines" }
        require(newLimit > 0) { "Adaptive worker count must be positive" }
        workerRegistry.resizeTo(
            target = newLimit,
            start = ::startWorker,
            onStartFailure = ::handleAdaptiveWorkerStartFailure,
        )
    }

    private fun handleAdaptiveWorkerStartFailure(failure: Throwable) {
        if (isRecoverableAdaptiveCapacityFailure(failure)) recordTransportFailure(failure)
        else throw failure
    }

    override fun resizeRequestsPerConnection(newLimit: Int) = false

    internal fun awaitAdaptiveWorkerCount(target: Int, timeout: Long, unit: TimeUnit): Int {
        require(adaptive)
        workerRegistry.awaitCount(target, timeout, unit)
        return workerRegistry.size()
    }

    override fun completionInitialized(): Boolean = if (adaptive) true else super.completionInitialized()

    override fun awaitCompletion(timeout: Long, unit: TimeUnit): Boolean =
        if (adaptive) workerRegistry.awaitEmptyAndSeal(timeout, unit) else super.awaitCompletion(timeout, unit)

    override fun sealCompletion() {
        if (adaptive) workerRegistry.seal() else super.sealCompletion()
    }


    override fun buildRequest(template: String, payloads: List<String?>, learnBoring: Int?, label: String): Request {
        var prepared = template
        if (useHTTP1) {
            prepared = prepared.replaceFirst("HTTP/2\r\n", "HTTP/1.1\r\n")
        } else {
            if (!Utils.isHTTP2(prepared.toByteArray())) {
                prepared = prepared.replaceFirst("HTTP/1.1\r\n", "HTTP/2\r\n")
            }
        }
        return Request(prepared, payloads, learnBoring ?: 0, label)
    }

    private fun sendMontoyaRequest(service: TurboService, req: Request) {
        if (req.endpointOverride != null) {
            val montoyaService = service.toMontoya()
            val protocolVersion = if (useHTTP1) HttpMode.HTTP_1 else HttpMode.HTTP_2
            val raw = if (req.kettled) {
                req.getRequest()
            } else {
                req.getRequest().replace("HTTP/2\r\n", "HTTP/1.1\r\n")
            }
            val montoyaResp = Utils.montoyaApi!!.http().sendRequest(
                montoyaRequestBuilder.build(montoyaService, raw, req.kettled, useHTTP1),
                protocolVersion,
            )
            req.response = montoyaResp.response()?.toString()
            req.montoyaReq = montoyaResp
            recordTiming(req, montoyaResp)
            return
        }

        // Lock on connectionId to ensure sequential requests for connection reuse
        val connectionId = req.connectionId
        val lock = connectionId?.let(::lockConnection)
        try {
            val montoyaService = service.toMontoya()
            val protocolVersion = if (useHTTP1) HttpMode.HTTP_1 else HttpMode.HTTP_2

            val montoyaResp = if (connectionId != null) {
                Utils.montoyaApi!!.http().sendRequest(
                    montoyaRequestBuilder.build(montoyaService, req.getRequest(), req.kettled, useHTTP1),
                    protocolVersion,
                    connectionId
                )
            } else {
                Utils.montoyaApi!!.http().sendRequest(
                    montoyaRequestBuilder.build(montoyaService, req.getRequest(), req.kettled, useHTTP1),
                    protocolVersion
                )
            }

            recordTiming(req, montoyaResp)
            if (montoyaResp.response() != null) {
                req.response = montoyaResp.response().toString()
            }
            if (req.connectionId == null) {
                req.connectionId = connections.incrementAndGet().toString()
            }
        } finally {
            if (connectionId != null && lock != null) unlockConnection(connectionId, lock)
        }
    }

    private class ConnectionLock {
        val lock = ReentrantLock()
        var users = 0 // changed only inside connectionLocks' compute for this id
    }

    private fun lockConnection(connectionId: String): ConnectionLock {
        val entry = connectionLocks.compute(connectionId) { _, existing ->
            (existing ?: ConnectionLock()).also { it.users++ }
        }!!
        entry.lock.lock()
        return entry
    }

    private fun unlockConnection(connectionId: String, entry: ConnectionLock) {
        entry.lock.unlock()
        connectionLocks.computeIfPresent(connectionId) { _, existing ->
            if (--existing.users == 0) null else existing
        }
    }

    /**
     * ttfb/ttlb/time in microseconds from Montoya's timing data, which is absent when no response
     * came back; reading it unconditionally threw for every unanswered request in a gated batch.
     */
    private fun recordTiming(req: Request, exchange: HttpRequestResponse) {
        val timing = exchange.timingData().orElse(null) ?: return
        req.ttfb = timing.timeBetweenRequestSentAndStartOfResponse().toNanos() / 1000
        req.ttlb = timing.timeBetweenRequestSentAndEndOfResponse().toNanos() / 1000
        req.time = req.ttfb
    }

    private fun buildService(target: URL, port: Int): TurboService =
        TurboService(target.host, port, target.protocol == "https")

    private fun sendMontoyaBatch(service: TurboService, requests: List<Request>, protocolVersion: HttpMode): List<HttpRequestResponse> {
        val montoyaService = service.toMontoya()
        val batch = requests.map { request ->
            montoyaRequestBuilder.build(montoyaService, request.getRequest(), request.kettled, useHTTP1)
        }
        return Utils.montoyaApi!!.http().sendRequests(batch, protocolVersion)
    }

    private fun startFixedWorker() = launchWorker(null)

    private fun startWorker(handle: DynamicWorkerRegistry.Handle) {
        adaptiveWorkerStarter?.start(handle) ?: launchWorker(handle)
    }

    private fun launchWorker(handle: DynamicWorkerRegistry.Handle?) {
        val worker = thread(start = false) {
            handle?.markStarted()
            try {
                if (handle != null) adaptiveWorkersReady.await()
                sendRequests(service, handle)
            } finally {
                threadPool.remove(Thread.currentThread())
            }
        }
        startTrackedWorker(worker, threadPool)
    }

    private fun shouldRetire(handle: DynamicWorkerRegistry.Handle?): Boolean =
        handle != null && workerRegistry.claimRetirement(handle)


    // this will return null unless there's an open gate with pending requests
    private fun getGatedRequests(): List<Request>? {
        for (gate in gatedRequests.keys) {
            if (floodgates.get(gate)?.isOpen?.get() == true) {
                // remove() is the claim: exactly one worker walks away with the batch.
                gatedRequests.remove(gate)?.let { return it }
            }
        }
        return null
    }

    private fun sendRequests(service: TurboService, handle: DynamicWorkerRegistry.Handle?) {
        try {
            while (runState.get() < 1 && !shouldAbandonRun()) {
                Thread.sleep(10)
            }

            // shouldAbandonRun() also applies idleTimeout, which this engine used to ignore.
            while (!shouldAbandonRun()) {

                if (shouldRetire(handle)) return

                try {
                val requestGroup = getGatedRequests()
                if (requestGroup != null) {
                    busyWorkers.incrementAndGet()
                    try {
                        sendGatedBatch(service, requestGroup)
                    } finally {
                        busyWorkers.decrementAndGet()
                    }
                    continue
                }

                val req = requestQueue.poll(100, TimeUnit.MILLISECONDS)

                if (req == null) {
                    if (gatedRequests.isNotEmpty()) {
                        failUnopenableGates()
                        continue
                    }

                    if (runState.get() == 2) {
                        return
                    } else {
                        continue
                    }
                }

                busyWorkers.incrementAndGet()
                try {
                    sendQueuedRequest(service, req)
                } finally {
                    busyWorkers.decrementAndGet()
                }

            } catch (ex: Exception) {
                ex.printStackTrace()
                Utils.err("Ignoring error: "+ex.toString())
                lastError = ex.toString()
                permaFails.getAndIncrement()
                // todo add null response to table
                continue
                }
            }
        } finally {
            if (handle == null) completedLatch.countDown() else handle.close()
        }
    }

    private fun sendGatedBatch(service: TurboService, requestGroup: List<Request>) {
        if (adaptive) activeRequests.addAndGet(requestGroup.size)
        try {
            val protocolVersion: HttpMode
            var sharedConnectionId: String? = null
            if (useHTTP1) {
                connections.addAndGet(requestGroup.size)
                protocolVersion = HttpMode.HTTP_1
            } else {
                protocolVersion = HttpMode.HTTP_2
                sharedConnectionId = connections.incrementAndGet().toString()
            }

            val timer = System.nanoTime()
            val responses = try {
                batchRequestSender.send(service, requestGroup, protocolVersion)
            } catch (failure: Exception) {
                if (adaptive) repeat(requestGroup.size) { recordTransportFailure(failure) }
                throw failure
            }

            var n = 0

            val reqs: ArrayList<Request> = ArrayList()
            for (resp in responses) {
                val req = requestGroup.get(n++)
                val response = resp.response()

                // we don't need to support retries for batches requests
                if (response == null) {
                    if (adaptive) recordTransportFailure(IllegalStateException("Montoya returned no response"))
                    req.response = "The server closed the connection without issuing a response."
                    permaFails.incrementAndGet()
                } else {
                    successfulRequests.getAndIncrement()
                    req.response = response.toString()
                }

                recordTiming(req, resp)
                req.arrival = (timer - start) / 1000 + req.ttfb

                if (req.connectionId == null) {
                    req.connectionId = if (useHTTP1) {
                        connections.incrementAndGet().toString()
                    } else {
                        sharedConnectionId
                    }
                }
                req.interesting = if (response == null) {
                    true
                } else {
                    processResponse(req, response.toByteArray().bytes)
                }
                reqs.add(req)
            }

            reqs.sortBy { it.ttfb }

            var i = 0
            for (req in reqs) {
                req.order = i++
                invokeCallback(req, req.interesting)
            }
        } finally {
            if (adaptive) activeRequests.addAndGet(-requestGroup.size)
            requestGroup.firstOrNull()?.gate?.let { finishGateLifecycle(it.name) }
        }
    }

    private fun sendQueuedRequest(service: TurboService, req: Request) {
        if (req.gate != null) {
            gatedRequests.computeIfAbsent(req.gate!!.name) {
                Collections.synchronizedList(LinkedList<Request>())
            }.add(req)
            // Parked until the gate opens; this also wakes an openGate() waiting for it.
            req.gate!!.reportReadyWithoutWaiting()
            return
        }


        if (req.endpointOverride != null) {
            val overrideTarget = URL(req.endpointOverride)
            val tempService = buildService(overrideTarget, getEffectivePort(overrideTarget))

            connections.incrementAndGet()
            if (adaptive) activeRequests.incrementAndGet()
            try {
                try {
                    requestSender.send(tempService, req)
                } catch (failure: Exception) {
                    if (adaptive) recordTransportFailure(failure)
                    throw failure
                }
                if (req.response == null) {
                    val failure = IllegalStateException("Montoya returned no response")
                    if (adaptive) recordTransportFailure(failure)
                    throw failure
                }
                req.interesting = processResponse(req, req.getResponseAsBytes()!!)
                successfulRequests.getAndIncrement()
                invokeCallback(req, req.interesting)
            } finally {
                if (adaptive) activeRequests.decrementAndGet()
            }
            return
        }

        if (adaptive) {
            activeRequests.incrementAndGet()
            try {
                sendAdaptiveRequest(service, req)
                finishRequest(req)
            } finally {
                activeRequests.decrementAndGet()
            }
            return
        }

        requestSender.send(service, req)
        connections.incrementAndGet()
        while (req.response == null && shouldRetry(req)) {
            Utils.out("Retrying ${req.words}")
            requestSender.send(service, req)
            connections.incrementAndGet()
            Utils.out("Retried ${req.words}")
        }

        finishRequest(req)
    }

    /**
     * Fails parked gated requests whose gate can no longer open. Once the script has finished
     * queueing (runState 2) only a response callback could still call openGate(), so when the
     * queue stays empty with nothing in flight for a whole grace period, nothing will, and the
     * workers used to wait on such a gate forever.
     */
    private fun failUnopenableGates() {
        synchronized(unopenableGateLock) {
            val stalled = runState.get() == 2 &&
                requestQueue.isEmpty() &&
                busyWorkers.get() == 0 &&
                gatedRequests.keys.none { floodgates[it]?.hasStartedOpening() == true }
            if (!stalled) {
                unopenableSince = null
                return
            }
            val now = System.nanoTime()
            val since = unopenableSince ?: now.also { unopenableSince = it }
            if (now - since < UNOPENABLE_GATE_GRACE_NANOS) return
            unopenableSince = null

            for (gateName in gatedRequests.keys.toList()) {
                val parked = gatedRequests.remove(gateName) ?: continue
                val message = "Gate '$gateName' was never opened, so its ${parked.size} requests were not sent. " +
                    "Call engine.openGate('$gateName') before engine.complete()"
                Utils.err(message)
                lastError = message
                permaFails.addAndGet(parked.size)
                finishGateLifecycle(gateName)
            }
        }
    }

    private fun sendAdaptiveRequest(service: TurboService, req: Request) {
        var retrying = false
        while (true) {
            req.response = null
            if (retrying) Utils.out("Retrying ${req.words}")
            val failure = try {
                requestSender.send(service, req)
                if (req.response == null) {
                    IllegalStateException("Montoya returned no response")
                } else {
                    null
                }
            } catch (failure: Exception) {
                req.response = null
                failure
            }
            connections.incrementAndGet()

            if (failure == null) {
                if (retrying) Utils.out("Retried ${req.words}")
                return
            }
            recordTransportFailure(failure)
            if (!shouldRetry(req)) return
            retrying = true
        }
    }

    private fun finishRequest(req: Request) {
        if (req.response == null) {
            req.response = "The server closed the connection without issuing a response."
            invokeCallback(req, true)
        } else {
            successfulRequests.getAndIncrement()
            val interesting = processResponse(req, req.getResponseAsBytes()!!)
            invokeCallback(req, interesting)
        }
    }

}
