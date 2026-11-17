package io.bitbytelab.raijin.turbo

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.BurpSuite
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.core.Version
import burp.api.montoya.logging.Logging
import io.bitbytelab.raijin.turbo.hp3.quic.StreamFragment
import io.bitbytelab.raijin.turbo.http3.SdaOptions
import io.bitbytelab.raijin.turbo.http3.TurboHttp3Request
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.io.IOException
import java.lang.reflect.Proxy
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * HTTP3RequestEngine over fake QUIC sessions. Engine.HTTP3 will not construct outside Burp Suite
 * Professional, so each test runs inside a fake one whose log lines it can act on.
 */
class HTTP3RequestEngineTest {

    private companion object {
        const val TEMPLATE = "GET / HTTP/1.1\r\nHost: test.local\r\n\r\n"
    }

    private val engines = mutableListOf<HTTP3RequestEngine>()

    /** Sees every line the engine logs, so a test can act at that point of a run. */
    @Volatile
    private var onLog: (String) -> Unit = {}

    @BeforeEach
    fun professionalBurp() {
        val version: Version = fake { method, _ ->
            if (method == "edition") BurpSuiteEdition.PROFESSIONAL else error("unexpected Version.$method")
        }
        val burpSuite: BurpSuite = fake { method, _ ->
            if (method == "version") version else error("unexpected BurpSuite.$method")
        }
        val logging: Logging = fake { method, args ->
            when (method) {
                "logToOutput", "logToError" -> onLog(args.firstOrNull().toString())
                else -> error("unexpected Logging.$method")
            }
            null
        }
        Utils.init(fake<MontoyaApi> { method, _ ->
            when (method) {
                "burpSuite" -> burpSuite
                "logging" -> logging
                else -> error("unexpected MontoyaApi.$method")
            }
        })
    }

    @AfterEach
    fun leaveBurp() {
        engines.forEach { it.cancel() }
        Utils.shutdown()
        Utils.unloaded = false
    }

    /** One connection from [factory], carrying up to [streams] requests at once. */
    private fun engine(
        factory: H3ConnectionFactory,
        streams: Int = 1,
        onResponse: (Request) -> Unit = {},
    ): HTTP3RequestEngine = HTTP3RequestEngine(
        url = "https://test.local",
        threads = 1,
        maxQueueSize = 0,
        requestsPerConnection = 100,
        maxRetriesPerRequest = 0,
        callback = { request, _ -> onResponse(request); false },
        readCallback = null,
        connectionFactory = factory,
        maxConcurrentStreams = streams,
    ).also { engine ->
        // Ranking asks Burp to analyse the responses, which this fake cannot.
        engine.internalSettings["calculateAnomalyRank"] = false
        engines += engine
    }

    private fun answering(opened: MutableCollection<AnsweringSession>) =
        H3ConnectionFactory { _, _ -> AnsweringSession().also { opened += it } }

    @Test
    fun `starting a stopped run leaves it stopped and opens nothing`() {
        val opened = ConcurrentLinkedQueue<AnsweringSession>()
        val engine = engine(answering(opened))
        engine.cancel()

        engine.start(1)

        assertEquals(3, engine.runState.get())
        assertTrue(opened.isEmpty(), "a stopped run opened a connection")
    }

    @Test
    fun `a stop that lands as start puts the run live stands`() {
        val opened = ConcurrentLinkedQueue<AnsweringSession>()
        // More streams than any JVM lets one engine carry, so start() logs the cap: the last thing
        // it does before the run goes live, and so a point a stop can be made to land on.
        val engine = engine(answering(opened), streams = HTTP3RequestEngine.MAX_REQUESTS_IN_FLIGHT + 1)
        onLog = { line -> if ("Capping at" in line) engine.finish(3) }

        engine.start(1)

        // start() used to set the run live outright once its checks had passed, undoing the stop.
        assertEquals(3, engine.runState.get())
        assertTrue(engine.completedLatch.await(5, TimeUnit.SECONDS), "the stopped run never wound down")
        assertTrue(opened.single().closed.get(), "the pooled connection outlived the stopped run")
    }

    @Test
    fun `a run's requests share its pooled connection, which closes when the run completes`() {
        val opened = ConcurrentLinkedQueue<AnsweringSession>()
        val answered = ConcurrentLinkedQueue<Request>()
        val engine = engine(answering(opened)) { answered += it }
        engine.start(1)
        repeat(3) { engine.queue(TEMPLATE) }

        engine.showStats(30)

        assertEquals(4, engine.runState.get())
        assertEquals(3, engine.successfulRequests.get())
        assertEquals(0, engine.permaFails.get())
        assertEquals(1, engine.connections.get())
        assertEquals(listOf("1", "1", "1"), answered.map { it.connectionId })
        // A completed run is still in state 2 when the pool closes, so runState alone would miss it.
        assertTrue(opened.single().closed.get(), "the pooled connection outlived the run")
    }

    @Test
    fun `a run where no QUIC handshake succeeds stops at start and says why`() {
        val refusing = H3ConnectionFactory { _, _ -> throw IOException("handshake refused") }
        val engine = engine(refusing)

        val failure = assertThrows<Exception> { engine.start(1) }

        assertEquals(3, engine.runState.get())
        assertTrue("every QUIC handshake failed" in failure.message.orEmpty(), failure.message)
        assertTrue("handshake refused" in failure.message.orEmpty(), failure.message)
    }
}

/** A QUIC session that answers every request at once, and is never asked to gate one. */
private class AnsweringSession : H3Session {
    val closed = AtomicBoolean()

    override fun send(request: TurboHttp3Request): H3Exchange {
        val now = System.nanoTime()
        return H3Exchange("HTTP/3 200 OK\r\n\r\n".toByteArray(Charsets.ISO_8859_1), now, now)
    }

    override fun stage(request: TurboHttp3Request, finalBytes: Int): StagedExchange = error("not a gated run")

    override fun release(fragments: List<StreamFragment>, options: SdaOptions) {
        error("not a gated run")
    }

    override fun isConnected(): Boolean = !closed.get()

    override fun close() {
        closed.set(true)
    }
}

/** A [T] whose calls go to [handler] with the method name and its arguments. */
private inline fun <reified T : Any> fake(noinline handler: (String, Array<out Any?>) -> Any?): T {
    val text = "fake ${T::class.simpleName}"
    return Proxy.newProxyInstance(T::class.java.classLoader, arrayOf(T::class.java)) { proxy, method, args ->
        when (method.name) {
            "toString" -> text
            "hashCode" -> System.identityHashCode(proxy)
            "equals" -> proxy === args?.firstOrNull()
            else -> handler(method.name, args ?: emptyArray<Any?>())
        }
    } as T
}
