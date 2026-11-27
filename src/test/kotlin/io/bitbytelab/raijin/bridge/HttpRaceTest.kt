package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpMode
import io.bitbytelab.raijin.safety.ScopeGate
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.lang.reflect.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * The last-byte barrier of `http_race`: no connection gets its final byte before every connection
 * holds the rest of its request, and the responses are read back per connection.
 */
class HttpRaceTest {

    /**
     * A socket that records every write into [log] (as "index:length") and answers with [response].
     */
    private class RecordingSocket(
        private val index: Int,
        private val log: MutableList<String>,
        response: String,
    ) : Socket() {
        private val input: InputStream =
            ByteArrayInputStream(response.toByteArray(Charsets.ISO_8859_1))
        private val output =
            object : OutputStream() {
                override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)

                override fun write(b: ByteArray, off: Int, len: Int) {
                    log += "$index:$len"
                }
            }

        override fun getInputStream(): InputStream = input

        override fun getOutputStream(): OutputStream = output

        override fun setSoTimeout(timeout: Int) = Unit

        override fun close() = Unit
    }

    private fun request(i: Int) =
        "GET /$i HTTP/1.1\r\nHost: h\r\n\r\n".toByteArray(Charsets.ISO_8859_1)

    @Test
    fun `every prefix is written before any final byte is released`() {
        val log = Collections.synchronizedList(ArrayList<String>())
        val requests = (0 until 6).map(::request)
        val result = LastByteSync { i ->
            RecordingSocket(i, log, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n$i")
        }
            .run(requests, totalTimeoutMs = 5_000)

        assertEquals(6, result.primed)
        val writes = log.toList()
        val prefixes = writes.withIndex().filter { (_, w) -> w.substringAfter(':').toInt() > 1 }
        val finals = writes.withIndex().filter { (_, w) -> w.substringAfter(':') == "1" }
        assertEquals(6, prefixes.size, writes.toString())
        assertEquals(6, finals.size, writes.toString())
        assertTrue(
            prefixes.maxOf { it.index } < finals.minOf { it.index },
            "a final byte left before every prefix: $writes",
        )
        requests.forEachIndexed { i, bytes ->
            assertTrue("$i:${bytes.size - 1}" in writes)
        }

        result.outcomes.forEach { outcome ->
            val ok = outcome.response as HttpPipelineFraming.Outcome.Ok
            assertEquals(200, ok.response.statusCode)
            assertEquals(outcome.index.toString(), ok.response.body)
            assertNotNull(outcome.releasedAtNanos)
            assertNull(outcome.error)
        }
        assertTrue(result.releaseEndNanos >= result.releaseStartNanos)
    }

    @Test
    fun `a connection that fails is reported and the others are still released`() {
        val log = Collections.synchronizedList(ArrayList<String>())
        val result = LastByteSync { i ->
            if (i == 1) throw java.net.ConnectException("refused")
            RecordingSocket(i, log, "HTTP/1.1 204 No Content\r\n\r\n")
        }
            .run((0 until 3).map(::request), totalTimeoutMs = 5_000)

        assertEquals(2, result.primed)
        val failed = result.outcomes[1]
        assertNull(failed.response)
        assertNull(failed.releasedAtNanos)
        assertTrue(failed.error!!.contains("refused"), failed.error)
        assertEquals(
            listOf(0, 2),
            result.outcomes.filter { it.releasedAtNanos != null }.map { it.index },
        )
        assertFalse(log.any { it.startsWith("1:") })
    }

    private fun stubApi(): MontoyaApi =
        Proxy.newProxyInstance(
            MontoyaApi::class.java.classLoader,
            arrayOf(MontoyaApi::class.java),
        ) { proxy, method, args ->
            when (method.name) {
                "hashCode" -> System.identityHashCode(proxy)
                "equals" -> proxy === args?.firstOrNull()
                else -> null
            }
        } as MontoyaApi

    @Test
    fun `a race with no answer is a no_response error without a race verdict`() {
        val port = ServerSocket(0).use { it.localPort }
        val api = stubApi()
        val texts = (0 until 2).map { "GET /$it HTTP/1.1\r\nHost: localhost\r\n\r\n" }
        val out =
            HttpRace(api, ScopeGate(api), HttpTimeouts())
                .run(
                    texts,
                    null,
                    "localhost",
                    port,
                    false,
                    HttpRace.Sync.LAST_BYTE,
                    HttpMode.HTTP_1,
                    null,
                    null,
                    5_000,
                    90.0,
                )

        // The stand-in has no scope, so the scope gate adds its warning first.
        assertEquals(
            listOf("error", "code"),
            out.keys.filter { it != "scope_warning" }.take(2),
            out.toString(),
        )
        assertEquals("no_response", out.getValue("code").jsonPrimitive.content)
        assertTrue(
            "none of the 2 requests got a response" in out.getValue("error").jsonPrimitive.content,
            out.toString(),
        )
        assertEquals(2, out.getValue("results").jsonArray.size)
        assertFalse("race_condition_likely" in out.getValue("analysis").jsonObject, out.toString())
        assertFalse("uniform" in out.getValue("analysis").jsonObject, out.toString())
        assertFalse(
            out["notes"]?.jsonArray.orEmpty().any { "HTTP/2" in it.jsonPrimitive.content },
            out.toString(),
        )
    }

    @Test
    fun `last_byte race against a real server reports clusters and per-request timing`() {
        val received = ConcurrentHashMap<Int, ByteArray>()
        ServerSocket(0).use { server ->
            thread(isDaemon = true) {
                repeat(3) { n ->
                    val connection = server.accept()
                    thread(isDaemon = true) {
                        connection.use { conn ->
                            val input = conn.getInputStream()
                            val bytes = ByteArrayOutputStream()
                            while (!bytes.toString(Charsets.ISO_8859_1).endsWith("\r\n\r\n")) {
                                val b = input.read()
                                if (b < 0) break
                                bytes.write(b)
                            }
                            received[n] = bytes.toByteArray()
                            // The first request to finish wins; the others find the coupon used.
                            val body =
                                if (bytes.toString(Charsets.ISO_8859_1).contains("/0 ")) "applied"
                                else "used!!!"
                            val status = if (body == "applied") "200 OK" else "409 Conflict"
                            conn
                                .getOutputStream()
                                .write(
                                    "HTTP/1.1 $status\r\nContent-Length: ${body.length}\r\n\r\n$body"
                                        .toByteArray(),
                                )
                            conn.getOutputStream().flush()
                            Thread.sleep(500)
                        }
                    }
                }
            }
            val api =
                Proxy.newProxyInstance(
                    MontoyaApi::class.java.classLoader,
                    arrayOf(MontoyaApi::class.java),
                ) { proxy, method, args ->
                    when (method.name) {
                        "hashCode" -> System.identityHashCode(proxy)
                        "equals" -> proxy === args?.firstOrNull()
                        else -> null
                    }
                } as MontoyaApi
            val texts = (0 until 3).map { "GET /$it HTTP/1.1\r\nHost: localhost\r\n\r\n" }
            val out: JsonObject =
                HttpRace(api, ScopeGate(api), HttpTimeouts())
                    .run(
                        texts,
                        null,
                        "localhost",
                        server.localPort,
                        false,
                        HttpRace.Sync.LAST_BYTE,
                        HttpMode.HTTP_1,
                        null,
                        null,
                        5_000,
                        90.0,
                    )

            assertEquals("last_byte", out.getValue("sync").jsonPrimitive.content, out.toString())
            assertEquals(3, out.getValue("primed_connections").jsonPrimitive.int)
            val results = out.getValue("results").jsonArray.map { it.jsonObject }
            assertEquals(
                listOf(200, 409, 409),
                results.map { it.getValue("status_code").jsonPrimitive.int },
            )
            results.forEach {
                assertTrue(
                    it.getValue("ttfb_ms").jsonPrimitive.content.toDouble() >= 0.0,
                    it.toString(),
                )
            }
            val analysis = out.getValue("analysis").jsonObject
            assertTrue(
                analysis.getValue("race_condition_likely").jsonPrimitive.boolean,
                analysis.toString(),
            )
            assertEquals(2, analysis.getValue("cluster_count").jsonPrimitive.int)
            assertEquals(
                texts.map { it }.toSet(),
                received.values.map { String(it, Charsets.ISO_8859_1) }.toSet(),
            )
        }
    }
}
