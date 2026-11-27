package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import java.io.ByteArrayOutputStream
import java.lang.reflect.Proxy
import java.math.BigInteger
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.util.Collections
import java.util.Date
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import java.util.zip.DeflaterOutputStream
import java.util.zip.GZIPOutputStream
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SNIMatcher
import javax.net.ssl.SNIServerName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.StandardConstants
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.double
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

/**
 * [HttpPipelineBridge] against a real loopback server: which sockets are kept for reuse, where
 * reading stops, what the result says about the bytes on the wire and their timing, and how pauses
 * split a request.
 */
class HttpPipelineBridgeTest {

    /**
     * Montoya is only asked for the scope mode (and brotli), and both fail soft when it cannot
     * answer.
     */
    private val bridge =
        HttpPipelineBridge(
            Proxy.newProxyInstance(
                MontoyaApi::class.java.classLoader,
                arrayOf(MontoyaApi::class.java),
            ) { proxy, method, args ->
                when (method.name) {
                    "hashCode" -> System.identityHashCode(proxy)
                    "equals" -> proxy === args?.firstOrNull()
                    "toString" -> "MontoyaApi"
                    else -> null
                }
            } as MontoyaApi,
        )

    // Bind and connect on the same loopback address: a wildcard bind plus "localhost" can reach
    // another process listening on that port in the other address family.
    private val loopback: InetAddress = InetAddress.getLoopbackAddress()
    private val host: String = loopback.hostAddress

    private fun bytes(s: String) = s.toByteArray(Charsets.ISO_8859_1)

    private fun hex(s: String) = HttpContentDecoding.hex(bytes(s))

    private fun spec(raw: String, pauseOffsets: List<Int> = emptyList(), pauseMs: Long = 1000) =
        PipelineRequestSpec(bytes(raw), pauseOffsets, pauseMs)

    private val get = spec("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    private val ok = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"

    /** Serves one connection with [script] on a daemon thread. */
    private fun peer(script: (Socket) -> Unit): ServerSocket {
        val server = ServerSocket(0, 50, loopback)
        thread(isDaemon = true) { runCatching { server.accept().use(script) } }
        return server
    }

    /** Skips one request head (up to its blank line). */
    private fun java.io.BufferedReader.skipHead() {
        while (readLine()?.isNotEmpty() == true) Unit
    }

    /**
     * Accepts one connection and answers each request (headers up to the blank line) with
     * [responses] in turn.
     */
    private fun serve(vararg responses: String) = peer { conn ->
        val input = conn.getInputStream().bufferedReader(Charsets.ISO_8859_1)
        for (response in responses) {
            input.skipHead()
            conn.getOutputStream().write(bytes(response))
            conn.getOutputStream().flush()
        }
        Thread.sleep(3000)
    }

    private fun send(
        port: Int,
        requests: List<PipelineRequestSpec>,
        keepOpen: Boolean = false,
        connectionId: String? = null,
        maxResponses: Int? = null,
        writeMode: String = "concat",
        totalTimeoutMs: Long = 5000,
        decodeContent: Boolean = false,
        rawHexMaxBytes: Int = HttpPipelineBridge.DEFAULT_RAW_HEX_MAX_BYTES,
    ): JsonObject =
        bridge.send(
            host,
            port,
            false,
            null,
            requests,
            writeMode = writeMode,
            maxResponses = maxResponses,
            idleTimeoutMs = 1000,
            totalTimeoutMs = totalTimeoutMs,
            keepOpen = keepOpen,
            connectionId = connectionId,
            decodeContent = decodeContent,
            rawHexMaxBytes = rawHexMaxBytes,
        )

    private fun JsonObject.str(key: String) = getValue(key).jsonPrimitive.content

    private fun JsonObject.flag(key: String) = getValue(key).jsonPrimitive.boolean

    private fun JsonObject.int(key: String) = getValue(key).jsonPrimitive.int

    private fun JsonObject.num(key: String) = getValue(key).jsonPrimitive.double

    private fun JsonObject.list(key: String) = getValue(key).jsonArray.map { it.jsonObject }

    private fun JsonObject.response(i: Int) = list("responses")[i]

    private fun JsonObject.request(i: Int) = list("requests")[i]

    @Test
    fun `a closed port is reported as a connect failure naming the call and the target`() {
        val port = ServerSocket(0, 50, loopback).use { it.localPort }
        val result = send(port, listOf(get))
        val error = result.str("error")
        assertTrue(
            error.startsWith("http_send_pipeline: could not connect to $host:$port: "),
            error,
        )
        assertFalse("(connect failed)" in error, error)
        assertEquals("no_response", result.str("code"))
        assertEquals("connect", result.str("phase"))
    }

    @Test
    fun `a socket is not kept for reuse after Connection close`() {
        serve("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok").use { server ->
            val result = send(server.localPort, listOf(get), keepOpen = true)
            assertEquals("max_responses", result.str("close_reason"))
            assertEquals(false, result.flag("connection_open"))
            assertEquals(JsonNull, result["connection_id"])
        }
    }

    @Test
    fun `a keep-alive socket is kept, reused by connection_id, then retired`() {
        serve(ok, ok).use { server ->
            val first = send(server.localPort, listOf(get), keepOpen = true)
            assertEquals(true, first.flag("connection_open"), first.toString())
            val id = first.str("connection_id")

            val second = send(server.localPort, listOf(get), connectionId = id)
            assertEquals(true, second.flag("connection_reused"), second.toString())
            assertEquals(200, second.response(0).int("status_code"))
            assertNull(
                HttpPipelineConnectionRegistry.get(id),
                "keep_open=false retires the reused connection",
            )
        }
    }

    @Test
    fun `bytes past the last returned response are handed to the next call on the connection`() {
        val extra = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
        serve(ok + extra, ok).use { server ->
            val first = send(server.localPort, listOf(get), keepOpen = true)
            val unparsed = first.getValue("unparsed").jsonObject
            assertEquals(extra.length, unparsed.int("bytes"), first.toString())
            assertEquals(hex(extra), unparsed.str("raw_hex"))
            assertEquals(true, unparsed.flag("kept_for_next_call"))

            val second =
                send(server.localPort, listOf(get), connectionId = first.str("connection_id"))
            val response = second.response(0)
            assertEquals(404, response.int("status_code"), second.toString())
            assertTrue(
                response.num("first_byte_ms") < 0,
                "it arrived before this call wrote anything: $response",
            )
        }
    }

    @Test
    fun `reading stops after 101 Switching Protocols and the upgraded bytes are shown`() {
        serve("HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\n\u0000\u0000\u0012\u0004")
            .use { server ->
                val result = send(server.localPort, listOf(get), keepOpen = true, maxResponses = 2)
                assertEquals("switching_protocols", result.str("close_reason"))
                assertEquals(1, result.int("responses_received"))
                assertEquals(false, result.flag("connection_open"))
                assertEquals(
                    "00001204",
                    result.getValue("unparsed").jsonObject.str("raw_hex"),
                    result.toString(),
                )
            }
    }

    @Test
    fun `chunk trailers are reported per response`() {
        serve(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX-Checksum: 9\r\n\r\n",
            )
            .use { server ->
                val response = send(server.localPort, listOf(get)).response(0)
                assertEquals("ok", response.str("body"))
                val trailer = response.list("trailers").single()
                assertEquals("X-Checksum", trailer.str("name"))
                assertEquals("9", trailer.str("value"))
            }
    }

    @Test
    fun `raw_response_hex holds each response's bytes exactly as received`() {
        val interim = "HTTP/1.1 100 Continue\r\n\r\n"
        val chunked =
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX-Checksum: 9\r\n\r\n"
        val plain = "HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nnah"
        // Both requests are read before answering, so the responses come back to back in one write.
        peer { conn ->
            val input = conn.getInputStream().bufferedReader(Charsets.ISO_8859_1)
            repeat(2) { input.skipHead() }
            conn.getOutputStream().write(bytes(interim + chunked + plain))
            Thread.sleep(2000)
        }
            .use { server ->
                val result = send(server.localPort, listOf(get, get))
                assertEquals("max_responses", result.str("close_reason"), result.toString())
                assertEquals(hex(interim + chunked), result.response(0).str("raw_response_hex"))
                assertEquals(
                    (interim + chunked).length,
                    result.response(0).int("raw_response_bytes"),
                )
                assertFalse("raw_response_truncated" in result.response(0))
                assertEquals(hex(plain), result.response(1).str("raw_response_hex"))
                assertEquals(2 * get.bytes.size, result.int("bytes_sent"))
                assertEquals((interim + chunked + plain).length, result.int("bytes_received"))
            }
    }

    @Test
    fun `raw_hex_max_bytes caps the dump and 0 leaves it out`() {
        serve(ok).use { server ->
            val response = send(server.localPort, listOf(get), rawHexMaxBytes = 4).response(0)
            assertEquals(hex(ok.take(4)), response.str("raw_response_hex"))
            assertEquals(true, response.flag("raw_response_truncated"))
            assertEquals(ok.length, response.int("raw_response_bytes"))
        }
        serve(ok).use { server ->
            val response = send(server.localPort, listOf(get), rawHexMaxBytes = 0).response(0)
            assertFalse("raw_response_hex" in response)
            assertEquals(ok.length, response.int("raw_response_bytes"))
        }
    }

    @Test
    fun `a cut connection reports the partial response in hex`() {
        val partial = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc"
        peer { conn ->
            conn.getInputStream().bufferedReader(Charsets.ISO_8859_1).skipHead()
            conn.getOutputStream().write(bytes(partial))
            conn.shutdownOutput()
            Thread.sleep(2000)
        }
            .use { server ->
                val result = send(server.localPort, listOf(get))
                assertEquals("fin", result.str("close_reason"), result.toString())
                assertEquals(0, result.int("responses_received"))
                val cut = result.getValue("partial_response").jsonObject
                assertEquals(0, cut.int("index"))
                assertEquals(hex(partial), cut.str("raw_response_hex"))
                assertEquals(partial.length, cut.int("raw_response_bytes"))
                assertTrue(cut.num("first_byte_ms") <= cut.num("last_byte_ms"))
            }
    }

    @Test
    fun `decode_content undoes gzip and deflate and reports a br body it cannot decode`() {
        fun compressed(encoding: String, body: ByteArray) =
            "HTTP/1.1 200 OK\r\nContent-Encoding: $encoding\r\nContent-Length: ${body.size}\r\n\r\n" +
                String(body, Charsets.ISO_8859_1)
        val gzip =
            ByteArrayOutputStream()
                .also { out -> GZIPOutputStream(out).use { it.write("hello gzip".toByteArray()) } }
                .toByteArray()
        val zlib =
            ByteArrayOutputStream()
                .also { out ->
                    DeflaterOutputStream(out).use { it.write("hello deflate".toByteArray()) }
                }
                .toByteArray()
        val gzipResponse = compressed("gzip", gzip)
        serve(gzipResponse, compressed("deflate", zlib), compressed("br", bytes("not brotli")))
            .use { server ->
                val result = send(server.localPort, listOf(get, get, get), decodeContent = true)
                val (unzipped, inflated, brotli) = result.list("responses")
                assertEquals("hello gzip", unzipped.str("body"), result.toString())
                assertEquals(
                    listOf("gzip"),
                    unzipped.getValue("decoded_codings").jsonArray.map { it.jsonPrimitive.content },
                )
                assertEquals(
                    hex(gzipResponse),
                    unzipped.str("raw_response_hex"),
                    "raw hex stays the wire bytes",
                )
                assertEquals("hello deflate", inflated.str("body"))
                assertEquals("not brotli", brotli.str("body"))
                assertFalse("decoded_codings" in brotli)
                assertTrue("not available" in brotli.str("decode_error"), brotli.toString())
            }
    }

    @Test
    fun `each response is timed from its first to its last byte and against its request`() {
        peer { conn ->
            conn.getInputStream().bufferedReader(Charsets.ISO_8859_1).skipHead()
            Thread.sleep(150) // the request was completely written well before the response starts
            conn.getOutputStream().write(bytes("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nab"))
            Thread.sleep(300)
            conn.getOutputStream().write(bytes("cd"))
            Thread.sleep(2000)
        }
            .use { server ->
                val result = send(server.localPort, listOf(get))
                val response = result.response(0)
                assertTrue(
                    response.num("last_byte_ms") - response.num("first_byte_ms") >= 250,
                    response.toString(),
                )
                assertTrue(response.num("ttfb_ms") > 100, response.toString())
                assertTrue(
                    response.num("ttlb_ms") >= response.num("ttfb_ms") + 250,
                    response.toString(),
                )
                val request = result.request(0)
                assertEquals(get.bytes.size, request.int("bytes_written"))
                assertTrue(
                    request.num("write_start_ms") <= request.num("write_end_ms"),
                    request.toString(),
                )
            }
    }

    @Test
    fun `a response that starts while its request is paused ends the pause and has a negative ttfb`() {
        val raw = "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nbody"
        val split = raw.indexOf("\r\n\r\n") + 4
        val rest = AtomicReference<String>()
        val restRead = CountDownLatch(1)
        peer { conn ->
            val input = conn.getInputStream()
            input.readNBytes(split)
            conn.getOutputStream().write(bytes(ok)) // answer before the body has arrived
            rest.set(String(input.readNBytes(raw.length - split), Charsets.ISO_8859_1))
            restRead.countDown()
            Thread.sleep(2000)
        }
            .use { server ->
                val result =
                    send(
                        server.localPort,
                        listOf(spec(raw, listOf(split), pauseMs = 10_000)),
                        totalTimeoutMs = 8000,
                    )
                val pause = result.request(0).list("pauses").single()
                assertEquals("data", pause.str("ended_by"), result.toString())
                assertEquals(split, pause.int("offset"))
                assertTrue(pause.num("duration_ms") < 5000, pause.toString())
                assertTrue(result.response(0).num("ttfb_ms") < 0, result.toString())
                assertTrue(restRead.await(3, TimeUnit.SECONDS))
                assertEquals("body", rest.get(), "the rest of the request still went out")
            }
    }

    @Test
    fun `pause_before holds the end of the request back for pause_ms`() {
        val raw = "GET /pause HTTP/1.1\r\nHost: x\r\n\r\n"
        val offsets = PipelineRequestSpec.pauseOffsets(bytes(raw), -4, emptyList())
        assertEquals(listOf(raw.length - 4), offsets)
        val gapNanos = AtomicLong()
        peer { conn ->
            val input = conn.getInputStream()
            input.readNBytes(raw.length - 4)
            val firstPart = System.nanoTime()
            input.readNBytes(4)
            gapNanos.set(System.nanoTime() - firstPart)
            conn.getOutputStream().write(bytes(ok))
            Thread.sleep(2000)
        }
            .use { server ->
                val result = send(server.localPort, listOf(spec(raw, offsets, pauseMs = 300)))
                val pause = result.request(0).list("pauses").single()
                assertEquals("pause_ms", pause.str("ended_by"), result.toString())
                assertTrue(pause.num("duration_ms") >= 299, pause.toString())
                assertTrue(
                    gapNanos.get() >= TimeUnit.MILLISECONDS.toNanos(250),
                    "server saw a ${gapNanos.get()} ns gap",
                )
                assertEquals(200, result.response(0).int("status_code"))
            }
    }

    @Test
    fun `pause offsets follow Turbo's pause_before and every marker occurrence`() {
        val request = bytes("POST / HTTP/1.1\r\nA: 1\r\n\r\nxx")
        fun offsets(pauseBefore: Int, vararg markers: String) =
            PipelineRequestSpec.pauseOffsets(request, pauseBefore, markers.map { bytes(it) })
        assertEquals(listOf(4), offsets(5), "n > 0 sends the first n-1 bytes")
        assertEquals(listOf(request.size - 2), offsets(-2), "n < 0 holds back the last |n|")
        assertEquals(listOf(0), offsets(1))
        assertEquals(listOf(request.size), offsets(request.size + 1))
        assertEquals(emptyList<Int>(), offsets(0))
        // After every occurrence, left to right; of two markers starting together the shorter wins.
        assertEquals(listOf(17, 23, 25), offsets(0, "\r\n", "\r\n\r\n"))
        assertEquals(listOf(17, 25), offsets(18, "\r\n\r\n"), "pause_before and markers combine")
        assertEquals(
            listOf(2, 4),
            PipelineRequestSpec.pauseOffsets(bytes("aaaa"), 3, listOf(bytes("aa"))),
            "no overlap, offsets merge",
        )
    }

    @Test
    fun `pause_markers split the bytes the server sees in both write modes`() {
        val post = "POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi"
        val second = "GET /b HTTP/1.1\r\nHost: x\r\n\r\n"
        val marker = listOf(bytes("\r\n\r\n"))
        val requests =
            listOf(post, second).map {
                spec(it, PipelineRequestSpec.pauseOffsets(bytes(it), 0, marker), pauseMs = 300)
            }
        val headEnd = post.indexOf("\r\n\r\n") + 4
        for (mode in listOf("concat", "single_write")) {
            val gapNanos = AtomicLong()
            val restSeen = AtomicReference<String>()
            peer { conn ->
                val input = conn.getInputStream()
                input.readNBytes(headEnd)
                val head = System.nanoTime()
                restSeen.set(
                    String(
                        input.readNBytes(post.length - headEnd + second.length),
                        Charsets.ISO_8859_1,
                    ),
                )
                gapNanos.set(System.nanoTime() - head)
                conn.getOutputStream().write(bytes(ok + ok))
                Thread.sleep(2000)
            }
                .use { server ->
                    val result = send(server.localPort, requests, writeMode = mode)
                    assertEquals(2, result.int("responses_received"), "$mode: $result")
                    assertEquals("hi$second", restSeen.get(), mode)
                    assertTrue(
                        gapNanos.get() >= TimeUnit.MILLISECONDS.toNanos(250),
                        "$mode: server saw a ${gapNanos.get()} ns gap",
                    )
                    val pauses = result.list("requests").map { it.list("pauses").single() }
                    assertEquals(
                        listOf(headEnd, second.length),
                        pauses.map { it.int("offset") },
                        mode,
                    )
                    assertEquals("pause_ms", pauses[0].str("ended_by"), mode)
                    assertEquals(
                        "data",
                        pauses[1].str("ended_by"),
                        "$mode: the answer ends the last pause",
                    )
                }
        }
    }

    @Test
    fun `a write that fails after a response was read keeps that response`() {
        // Far more than the socket buffers on both ends hold, so the write is still blocked when
        // the server goes away.
        val big =
            PipelineRequestSpec(
                ByteArray(32 shl 20).apply { fill('a'.code.toByte()) },
                listOf(0),
                pauseMs = 5000,
            )
        peer { conn ->
            conn.getInputStream().bufferedReader(Charsets.ISO_8859_1).skipHead()
            conn
                .getOutputStream()
                .write(bytes("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok"))
            conn.getOutputStream().flush()
            Thread.sleep(300)
            // Closing with the big request unread resets the connection under the writer.
        }
            .use { server ->
                val result =
                    send(
                        server.localPort,
                        listOf(get, big),
                        writeMode = "single_write",
                        totalTimeoutMs = 10_000,
                    )
                assertEquals(1, result.int("responses_received"), result.toString())
                assertEquals(200, result.response(0).int("status_code"))
                assertNotNull(result["write_error"], result.toString())
                assertTrue(result.str("close_reason") in setOf("fin", "rst"), result.toString())
                assertFalse("write_end_ms" in result.request(1), result.toString())
                assertTrue(result.request(1).int("bytes_written") < big.bytes.size)
            }
    }

    @Test
    fun `kept connections are listed and closed, a busy one only with force`() {
        serve(ok, ok).use { server ->
            val id = "pipeline-list-" + System.nanoTime()
            assertEquals(
                true,
                send(server.localPort, listOf(get), keepOpen = true, connectionId = id)
                    .flag("connection_open"),
            )

            val listed = bridge.connections(emptyList(), closeAll = false, force = false)
            assertFalse("closed" in listed)
            val entry = listed.list("connections").single { it.str("connection_id") == id }
            assertEquals(host, entry.str("host"))
            assertEquals(server.localPort, entry.int("port"))
            assertEquals(false, entry.flag("use_tls"))
            assertEquals(false, entry.flag("busy"))
            assertTrue(
                entry.int("evicts_in_ms") in
                    1..HttpPipelineConnectionRegistry.IDLE_EVICTION_MS.toInt(),
                entry.toString(),
            )

            // A call holds the entry's lock while it uses the socket.
            val kept = HttpPipelineConnectionRegistry.get(id)!!
            val locked = CountDownLatch(1)
            val release = CountDownLatch(1)
            val holder =
                thread(isDaemon = true) {
                    kept.lock.lock()
                    try {
                        locked.countDown()
                        release.await(5, TimeUnit.SECONDS)
                    } finally {
                        kept.lock.unlock()
                    }
                }
            assertTrue(locked.await(5, TimeUnit.SECONDS))
            try {
                val busy =
                    bridge.connections(
                        listOf(id, "no-such-connection"),
                        closeAll = false,
                        force = false,
                    )
                assertEquals(
                    listOf(id),
                    busy.getValue("busy").jsonArray.map { it.jsonPrimitive.content },
                )
                assertEquals(
                    listOf("no-such-connection"),
                    busy.getValue("unknown").jsonArray.map { it.jsonPrimitive.content },
                )
                assertEquals(
                    true,
                    busy.list("connections").single { it.str("connection_id") == id }.flag("busy"),
                )
                assertFalse(kept.socket.isClosed)

                val forced = bridge.connections(listOf(id), closeAll = false, force = true)
                assertEquals(
                    listOf(id),
                    forced.getValue("closed").jsonArray.map { it.jsonPrimitive.content },
                )
                assertTrue(kept.socket.isClosed)
                assertNull(HttpPipelineConnectionRegistry.get(id))
            } finally {
                release.countDown()
                holder.join(5000)
            }
        }
    }

    @Test
    fun `an idle kept connection closes without force`() {
        serve(ok).use { server ->
            val id = "pipeline-close-" + System.nanoTime()
            send(server.localPort, listOf(get), keepOpen = true, connectionId = id)
            val socket = HttpPipelineConnectionRegistry.get(id)!!.socket
            val closed = bridge.connections(listOf(id), closeAll = false, force = false)
            assertEquals(
                listOf(id),
                closed.getValue("closed").jsonArray.map { it.jsonPrimitive.content },
            )
            assertTrue(closed.list("connections").none { it.str("connection_id") == id })
            assertTrue(socket.isClosed)
        }
    }

    @Test
    fun `sni is sent as given and a kept connection is reused only for the same sni`() {
        val tls = TlsPeer()
        tls.use {
            fun call(sni: String?, connectionId: String?) =
                bridge.send(
                    host,
                    tls.port,
                    true,
                    null,
                    listOf(get),
                    idleTimeoutMs = 1000,
                    totalTimeoutMs = 5000,
                    keepOpen = true,
                    connectionId = connectionId,
                    sni = sni,
                )
            val first = call("a.example", connectionId = null)
            assertEquals(true, first.flag("connection_open"), first.toString())
            val id = first.str("connection_id")
            assertEquals(
                "a.example",
                bridge
                    .connections(emptyList(), false, false)
                    .list("connections")
                    .single { it.str("connection_id") == id }
                    .str("sni"),
            )

            val same = call("a.example", id)
            assertEquals(true, same.flag("connection_reused"), same.toString())

            val other = call("b.example", id)
            assertEquals(false, other.flag("connection_reused"), other.toString())
            assertEquals(true, other.flag("connection_id_target_mismatch"))

            val none = call("", connectionId = null)
            assertEquals(200, none.response(0).int("status_code"), none.toString())
            HttpPipelineConnectionRegistry.close(other.str("connection_id"))
            HttpPipelineConnectionRegistry.close(none.str("connection_id"))

            assertEquals(
                listOf(listOf("a.example"), listOf("b.example"), emptyList()),
                tls.serverNames.toList(),
            )
        }
    }

    /**
     * A TLS server on loopback with a fresh self-signed certificate. Every connection gets its own
     * thread, records the SNI its ClientHello carried (connections are made one after another), and
     * answers each request with a keep-alive `200`.
     */
    private inner class TlsPeer : AutoCloseable {
        val serverNames: MutableList<List<String>> = Collections.synchronizedList(ArrayList())
        private val offered: MutableList<String> = Collections.synchronizedList(ArrayList())
        private val server =
            context().serverSocketFactory.createServerSocket(0, 50, loopback) as SSLServerSocket
        val port: Int = server.localPort

        init {
            // A matcher sees the SNI of every ClientHello, resumed session or not.
            server.sslParameters =
                server.sslParameters.apply {
                    sniMatchers =
                        listOf(
                            object : SNIMatcher(StandardConstants.SNI_HOST_NAME) {
                                override fun matches(serverName: SNIServerName): Boolean {
                                    offered += String(serverName.encoded, Charsets.US_ASCII)
                                    return true
                                }
                            },
                        )
                }
            thread(isDaemon = true) {
                while (!server.isClosed) {
                    val conn = runCatching { server.accept() as SSLSocket }.getOrNull() ?: break
                    thread(isDaemon = true) {
                        runCatching {
                            conn.use {
                                conn.startHandshake()
                                synchronized(offered) {
                                    serverNames.add(offered.toList())
                                    offered.clear()
                                }
                                val input = conn.inputStream.bufferedReader(Charsets.ISO_8859_1)
                                while (true) {
                                    val line = input.readLine() ?: break
                                    if (line.isNotEmpty()) continue
                                    conn.outputStream.write(bytes(ok))
                                    conn.outputStream.flush()
                                }
                            }
                        }
                    }
                }
            }
        }

        private fun context(): SSLContext {
            val keys =
                KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
            val name = X500Name("CN=raijin-test")
            val now = System.currentTimeMillis()
            val holder =
                JcaX509v3CertificateBuilder(
                        name,
                        BigInteger.valueOf(now),
                        Date(now - 60_000),
                        Date(now + 3_600_000),
                        name,
                        keys.public,
                    )
                    .build(JcaContentSignerBuilder("SHA256withECDSA").build(keys.private))
            val certificate = JcaX509CertificateConverter().getCertificate(holder)
            val password = "changeit".toCharArray()
            val store =
                KeyStore.getInstance("PKCS12").apply {
                    load(null, null)
                    setKeyEntry("key", keys.private, password, arrayOf(certificate))
                }
            val managers =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply {
                    init(store, password)
                }
            return SSLContext.getInstance("TLS").apply { init(managers.keyManagers, null, null) }
        }

        override fun close() = server.close()
    }
}
