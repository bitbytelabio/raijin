package io.bitbytelab.raijin.turbo

import burp.api.montoya.core.ByteArray as MontoyaBytes
import burp.api.montoya.http.handler.TimingData
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.responses.HttpResponse
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertTimeoutPreemptively
import java.lang.reflect.Proxy
import java.time.Duration
import java.util.Optional
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * BurpRequestEngine's queueing and gated batches, through injected senders instead of Burp: a
 * single request is answered at once, and a gated batch as each test says.
 */
class BurpRequestEngineTest {

    private companion object {
        const val TEMPLATE = "GET / HTTP/2\r\nHost: test.local\r\n\r\n"
        const val OK = "HTTP/2 200 OK\r\ncontent-length: 0\r\n\r\n"
        const val GATE = "race"
    }

    private val engines = mutableListOf<BurpRequestEngine>()

    @BeforeEach
    fun liveTurbo() {
        Utils.unloaded = false
    }

    @AfterEach
    fun tearDown() {
        engines.forEach { it.cancel() }
    }

    /**
     * A one-worker HTTP/2 engine. [firstByteMicros] answers each request of a gated batch with its
     * time to first byte, or null for no response at all.
     */
    private fun burpEngine(
        maxQueueSize: Int,
        firstByteMicros: (Request) -> Long? = { 1_000 },
        onResponse: (Request) -> Unit,
    ): BurpRequestEngine = BurpRequestEngine.withRequestSender(
        "https://test.local", 1, maxQueueSize, 0, 0,
        callback = { req, _ -> onResponse(req); false },
        readCallback = null,
        useHTTP1 = false,
        requestSender = BurpRequestSender { _, req -> req.response = OK },
        batchRequestSender = BurpBatchRequestSender { _, requests, _ -> requests.map { exchange(firstByteMicros(it)) } },
    ).also { engines += it }

    private fun BurpRequestEngine.queueLabelled(label: String, gate: String? = null) {
        queue(TEMPLATE, emptyList<Any>(), 0, null, gate, label)
    }

    @Test
    fun `a gate whose requests overflowed the queue before start still opens`() {
        val answered = ConcurrentLinkedQueue<String>()
        val engine = burpEngine(maxQueueSize = 2) { answered += it.label }
        // Before start() the queue takes two of them; the other three wait in the pre-start backlog.
        repeat(5) { engine.queueLabelled("r$it", GATE) }
        engine.start(5)

        // Only queue() and complete() moved that backlog on, so openGate() waited for good for
        // three requests that never reached the worker to be staged.
        assertTimeoutPreemptively(Duration.ofSeconds(10)) { engine.openGate(GATE) }
        engine.showStats(10)

        assertEquals(4, engine.runState.get())
        assertEquals((0 until 5).map { "r$it" }, answered.sorted())
    }

    @Test
    fun `callbacks queue follow-ups behind an overflowed pre-start backlog without blocking`() {
        val answered = ConcurrentLinkedQueue<String>()
        lateinit var engine: BurpRequestEngine
        engine = burpEngine(maxQueueSize = 2) { req ->
            answered += req.label
            if (req.label.startsWith("seed")) engine.queueLabelled(req.label.replace("seed", "follow"))
        }
        repeat(4) { engine.queueLabelled("seed$it") } // two wait in the queue, two in the backlog
        engine.start(5)

        // The one worker is all that takes from the queue. Its callback used to wait there for the
        // backlog to fit, while complete() waited on the worker: the run stopped for good.
        assertTimeoutPreemptively(Duration.ofSeconds(20)) { engine.showStats(15) }

        assertEquals(4, engine.runState.get())
        assertEquals((0 until 4).map { "seed$it" } + (0 until 4).map { "follow$it" }, answered.toList())
    }

    @Test
    fun `a gated request that got no response is not ranked as the race winner`() {
        val answered = ConcurrentLinkedQueue<Request>()
        val firstByte = mapOf("slow" to 9_000L, "fast" to 4_000L, "dropped" to null)
        val engine = burpEngine(maxQueueSize = 10, firstByteMicros = { firstByte[it.label] }) { answered += it }
        engine.start(5)
        listOf("slow", "dropped", "fast").forEach { engine.queueLabelled(it, GATE) }

        engine.openGate(GATE)
        engine.showStats(10)

        // With no response it has no time to first byte, which used to rank it ahead of both
        // answers: req.order 0, the request the server answered first.
        assertEquals(listOf("fast", "slow", "dropped"), answered.map { it.label }, "called back in rank order")
        assertEquals(listOf(0, 1, -1), answered.map { it.order })
        assertEquals(1, engine.permaFails.get())
    }

    @Test
    fun `a gate nobody answered has no winner`() {
        val answered = ConcurrentLinkedQueue<Request>()
        val engine = burpEngine(maxQueueSize = 10, firstByteMicros = { null }) { answered += it }
        engine.start(5)
        repeat(3) { engine.queueLabelled("r$it", GATE) }

        engine.openGate(GATE)
        engine.showStats(10)

        assertEquals(3, answered.size)
        assertTrue(answered.none { it.order == 0 }, "an unanswered request was ranked first")
    }

    @Test
    fun `starting a stopped run leaves it stopped`() {
        val engine = burpEngine(maxQueueSize = 10) {}
        engine.cancel()

        // start() used to set the run live outright, undoing the stop.
        engine.start(5)

        assertEquals(3, engine.runState.get())
    }

    /** What Montoya hands back for one request of a batch: a response [firstByteMicros] in, or none. */
    private fun exchange(firstByteMicros: Long?): HttpRequestResponse {
        val response = firstByteMicros?.let {
            fake<HttpResponse> { method ->
                when (method) {
                    "toString" -> OK
                    "toByteArray" -> fake<MontoyaBytes> { if (it == "getBytes") OK.toByteArray(Charsets.ISO_8859_1) else null }
                    else -> null
                }
            }
        }
        val timing = firstByteMicros?.let { micros ->
            fake<TimingData> { method ->
                when (method) {
                    "timeBetweenRequestSentAndStartOfResponse" -> Duration.ofNanos(micros * 1_000)
                    "timeBetweenRequestSentAndEndOfResponse" -> Duration.ofNanos(micros * 1_000 + 500_000)
                    else -> null
                }
            }
        }
        return fake { method ->
            when (method) {
                "response" -> response
                "timingData" -> Optional.ofNullable(timing)
                else -> null
            }
        }
    }

    /** A Montoya interface answering each method by name. */
    private inline fun <reified T> fake(crossinline answer: (String) -> Any?): T =
        Proxy.newProxyInstance(T::class.java.classLoader, arrayOf(T::class.java)) { proxy, method, args ->
            when (method.name) {
                "equals" -> proxy === args?.get(0)
                "hashCode" -> System.identityHashCode(proxy)
                else -> answer(method.name)
            }
        } as T
}
