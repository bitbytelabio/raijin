package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.state.WebSocketConnection
import io.bitbytelab.raijin.state.WebSocketMessage
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.util.Base64
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * [WebSocketFuzzPlan] (payload expansion) and [WebSocketFuzz.run] against an in-memory server: which
 * frames each payload is credited with, on one connection and on a fresh one per payload, when a
 * run stops and how it resumes, and how the responses are clustered.
 */
class WebSocketFuzzTest {

    /**
     * A server behind [WebSocketFuzzHost]. Frames are recorded as the bridge records them: the
     * client frame first, then whatever the server answers, so an answer always gets a higher index.
     */
    private class FakeHost : WebSocketFuzzHost {
        override var stopping = false
        val connections = LinkedHashMap<String, WebSocketConnection>()
        val sent = ArrayList<String>()
        val closedIds = ArrayList<String>()
        var openError: String? = null

        /** Runs when a connection opens, e.g. to push a greeting. */
        var onOpen: (WebSocketConnection) -> Unit = {}

        /** Runs before a payload is recorded: for frames that arrive just before it goes out. */
        var beforeSend: (WebSocketConnection, String) -> Unit = { _, _ -> }

        /** The server's reaction to a text frame. */
        var server: (WebSocketConnection, String) -> Unit = { _, _ -> }

        /** The server's reaction to a binary frame. */
        var binaryServer: (WebSocketConnection, ByteArray) -> Unit = { _, _ -> }

        private var ids = 0

        fun connect(): WebSocketConnection =
            WebSocketConnection("ws-${++ids}", "wss://fuzz.test/ws", "2026-11-17T00:00:00Z").also { connections[it.connectionId] = it }

        override fun find(connectionId: String) = connections[connectionId]

        override fun unsendableReason(connection: WebSocketConnection): String? =
            if (connection.status == "connected") null else "Connection is not active: status=${connection.status}"

        override fun open(url: String, headers: Map<String, String>?, subprotocol: String?): WebSocketFuzzHost.Opened {
            openError?.let { return WebSocketFuzzHost.Opened(null, it) }
            val connection = connect()
            onOpen(connection)
            return WebSocketFuzzHost.Opened(connection, null)
        }

        override fun sendText(connection: WebSocketConnection, message: String): WebSocketMessage {
            unsendableReason(connection)?.let { throw IllegalStateException(it) }
            beforeSend(connection, message)
            val record = connection.append("client_to_server", "TEXT", message, message.length)
            sent += message
            server(connection, message)
            return record
        }

        override fun sendBinary(connection: WebSocketConnection, bytes: ByteArray): WebSocketMessage {
            unsendableReason(connection)?.let { throw IllegalStateException(it) }
            val record = connection.append("client_to_server", "BINARY", WebSocketFrames.encodeBase64(bytes), bytes.size)
            binaryServer(connection, bytes)
            return record
        }

        override fun close(connection: WebSocketConnection) {
            closedIds += connection.connectionId
            connection.markClosed()
        }
    }

    private fun WebSocketConnection.reply(text: String) = append("server_to_client", "TEXT", text, text.length)

    private val host = FakeHost()

    /** Short windows: a reply recorded during the send ends its window after [idleMs]. */
    private fun fuzz(request: WebSocketFuzzRequest): JsonObject = WebSocketFuzz.run(request, host)

    private fun JsonObject.results() = getValue("results").jsonArray.map { it.jsonObject }

    private fun JsonObject.clusters() = getValue("clusters").jsonArray.map { it.jsonObject }

    private fun JsonObject.frames() = getValue("frames").jsonArray.map { it.jsonObject["payload"]!!.jsonPrimitive.content }

    private fun JsonObject.text(key: String) = getValue(key).jsonPrimitive.content

    // --- payload expansion ---

    @Test
    fun `a payload goes into the template at every marker, JSON-escaped on request`() {
        val plan = WebSocketFuzzPlan.expand(listOf("a\"b", "x"), """{"q":"FUZZ","r":"FUZZ"}""", null, "json", binary = false)

        val frames = (plan as WebSocketFuzzPlan.Result.Ok).frames
        assertEquals(listOf("""{"q":"a\"b","r":"a\"b"}""", """{"q":"x","r":"x"}"""), frames.map { it.message })
        assertEquals(listOf("a\"b", "x"), frames.map { it.payload })
        assertTrue(frames.all { it.bytes == null })
    }

    @Test
    fun `without a template the payload is the message, and a custom marker can be set`() {
        val raw = WebSocketFuzzPlan.expand(listOf("<script>"), null, null, "none", binary = false) as WebSocketFuzzPlan.Result.Ok
        assertEquals("<script>", raw.frames.single().message)

        val marked = WebSocketFuzzPlan.expand(listOf("1"), "id=§§", "§§", "none", binary = false) as WebSocketFuzzPlan.Result.Ok
        assertEquals("id=1", marked.frames.single().message)
    }

    @Test
    fun `a template without its marker and a binary message that is not base64 are errors`() {
        val noMarker = WebSocketFuzzPlan.expand(listOf("a"), "no marker here", null, "none", binary = false)
        assertTrue((noMarker as WebSocketFuzzPlan.Result.Error).message.contains("FUZZ"))

        val notBase64 = WebSocketFuzzPlan.expand(listOf("AAE=", "not base64!", "AAI="), null, null, "none", binary = true)
        assertTrue((notBase64 as WebSocketFuzzPlan.Result.Error).message.contains("index 1"))
    }

    @Test
    fun `a binary payload is sent as its decoded bytes`() {
        val plan = WebSocketFuzzPlan.expand(listOf("AAH/", "AAH_"), null, null, "none", binary = true) as WebSocketFuzzPlan.Result.Ok
        for (frame in plan.frames) assertContentEquals(byteArrayOf(0x00, 0x01, 0xFF.toByte()), frame.bytes)
    }

    // --- one open connection ---

    @Test
    fun `each payload gets the frames that answered it, and the clusters single out the odd response`() {
        val connection = host.connect()
        var tick = 0
        host.server = { c, m ->
            tick++
            if (m.contains("'")) c.reply("""{"error":"SQL syntax near '$m'"}""")
            else c.reply("""{"ok":true,"echo":"$m","at":"2026-11-17T10:00:0${tick}Z"}""")
        }

        val result = fuzz(WebSocketFuzzRequest(listOf("alice", "bob", "o'brien", "carol"), connectionId = connection.connectionId, idleMs = 50))

        assertEquals("connection", result.text("mode"))
        assertEquals(4, result["sent"]!!.jsonPrimitive.int)
        assertEquals(4, result["responded"]!!.jsonPrimitive.int)
        assertFalse(result["stopped_early"]!!.jsonPrimitive.boolean)
        val results = result.results()
        assertEquals(listOf(0, 1, 2, 3), results.map { it["index"]!!.jsonPrimitive.int })
        assertEquals(listOf("""{"error":"SQL syntax near 'o'brien'"}"""), results[2].frames())
        assertEquals("""{"ok":true,"echo":"bob","at":"2026-11-17T10:00:02Z"}""", results[1].frames().single())
        // Each payload's own frame sits right before its reply.
        assertEquals(listOf(0L, 2L, 4L, 6L), results.map { it["sent_index"]!!.jsonPrimitive.long })

        assertEquals("content", result.text("clustered_by"))
        val clusters = result.clusters()
        assertEquals(listOf(3, 1), clusters.map { it["count"]!!.jsonPrimitive.int })
        assertEquals(listOf(2), clusters[1]["indices"]!!.jsonArray.map { it.jsonPrimitive.int })
        assertEquals(1, results[2]["cluster"]!!.jsonPrimitive.int)
        assertEquals(0, results[0]["cluster"]!!.jsonPrimitive.int)
    }

    @Test
    fun `a template message is sent and echoed in the result next to the payload`() {
        val connection = host.connect()
        host.server = { c, _ -> c.reply("ack") }

        val result = fuzz(
            WebSocketFuzzRequest(
                listOf("x\"y"), connectionId = connection.connectionId, template = """{"q":"FUZZ"}""",
                payloadEncoding = "JSON", idleMs = 50,
            )
        )

        assertEquals(listOf("""{"q":"x\"y"}"""), host.sent)
        val entry = result.results().single()
        assertEquals("x\"y", entry.text("payload"))
        assertEquals("""{"q":"x\"y"}""", entry.text("message"))
    }

    @Test
    fun `a frame that arrives after the window but before the next payload counts for the earlier payload`() {
        val connection = host.connect()
        host.server = { c, m -> if (m == "fast") c.reply("fast answer") }
        // Just before "fast" goes out, the answer to "slow" turns up.
        host.beforeSend = { c, m -> if (m == "fast") c.reply("slow answer") }

        val result = fuzz(WebSocketFuzzRequest(listOf("slow", "fast"), connectionId = connection.connectionId, windowMs = 100, idleMs = 50))

        val (slow, fast) = result.results()
        assertEquals(listOf("slow answer"), slow.frames())
        assertNull(slow["response_ms"], "nothing answered within the window")
        assertEquals(listOf("fast answer"), fast.frames())
        assertNotNull(fast["response_ms"])
    }

    @Test
    fun `frames that arrive during the delay are credited to the payload before it`() {
        val connection = host.connect()
        host.server = { c, m ->
            if (m == "slow") thread { Thread.sleep(200); c.reply("late answer") } else c.reply("fast answer")
        }

        val result = fuzz(
            WebSocketFuzzRequest(listOf("slow", "fast"), connectionId = connection.connectionId, windowMs = 50, idleMs = 20, delayMs = 1_500)
        )

        val (slow, fast) = result.results()
        assertEquals(listOf("late answer"), slow.frames())
        assertEquals(listOf("fast answer"), fast.frames())
    }

    @Test
    fun `frames recorded before the run are not responses`() {
        val connection = host.connect()
        connection.reply("old news")
        host.server = { c, _ -> c.reply("new") }

        val result = fuzz(WebSocketFuzzRequest(listOf("a"), connectionId = connection.connectionId, idleMs = 50))

        assertEquals(listOf("new"), result.results().single().frames())
    }

    @Test
    fun `setup messages are sent once and their replies are not counted`() {
        val connection = host.connect()
        host.server = { c, m -> c.reply(if (m == "LOGIN") "welcome back" else "echo $m") }

        val result = fuzz(
            WebSocketFuzzRequest(listOf("a", "b"), connectionId = connection.connectionId, setupMessages = listOf("LOGIN"), idleMs = 50)
        )

        assertEquals(listOf("LOGIN", "a", "b"), host.sent)
        assertEquals(listOf(listOf("echo a"), listOf("echo b")), result.results().map { it.frames() })
    }

    @Test
    fun `a pattern keeps heartbeats out of the responses`() {
        val connection = host.connect()
        host.server = { c, m ->
            c.reply("heartbeat")
            c.reply("result for $m")
        }

        val result = fuzz(WebSocketFuzzRequest(listOf("a"), connectionId = connection.connectionId, pattern = "^result", idleMs = 50))

        assertEquals(listOf("result for a"), result.results().single().frames())
    }

    @Test
    fun `a connection the server closes stops the run with the index to resume from`() {
        val connection = host.connect()
        host.server = { c, m ->
            c.reply("got $m")
            if (m == "bye") c.markClosed()
        }

        val result = fuzz(WebSocketFuzzRequest(listOf("a", "bye", "c"), connectionId = connection.connectionId, idleMs = 50))

        assertTrue(result["stopped_early"]!!.jsonPrimitive.boolean)
        assertEquals(2, result["next_index"]!!.jsonPrimitive.int)
        assertTrue(result.text("stop_reason").contains("connection closed after payload 1"), result.text("stop_reason"))
        val results = result.results()
        assertEquals(2, results.size)
        assertTrue(results[1]["connection_closed"]!!.jsonPrimitive.boolean)
        assertEquals(listOf("got bye"), results[1].frames())
        assertEquals(listOf("a", "bye"), host.sent)
    }

    @Test
    fun `a resumed run starts at start_index`() {
        val connection = host.connect()
        host.server = { c, m -> c.reply("echo $m") }

        val result = fuzz(WebSocketFuzzRequest(listOf("a", "b", "c"), connectionId = connection.connectionId, startIndex = 2, idleMs = 50))

        assertEquals(listOf("c"), host.sent)
        assertEquals(2, result.results().single()["index"]!!.jsonPrimitive.int)
        assertEquals(2, result["start_index"]!!.jsonPrimitive.int)
    }

    @Test
    fun `the time budget stops the run before the next payload`() {
        val connection = host.connect()
        // A silent server: every payload waits out its whole window.

        val result = fuzz(
            WebSocketFuzzRequest(listOf("a", "b", "c"), connectionId = connection.connectionId, windowMs = 600, timeoutMs = 300)
        )

        assertEquals(listOf("a"), host.sent)
        assertEquals("timeout_ms reached", result.text("stop_reason"))
        assertEquals(1, result["next_index"]!!.jsonPrimitive.int)
        val only = result.results().single()
        assertEquals(0, only["frame_count"]!!.jsonPrimitive.int)
        assertTrue(result.clusters().single()["no_response"]!!.jsonPrimitive.boolean)
    }

    @Test
    fun `an unloading extension stops the run`() {
        val connection = host.connect()
        host.server = { c, m ->
            c.reply("echo $m")
            host.stopping = true
        }

        val result = fuzz(WebSocketFuzzRequest(listOf("a", "b"), connectionId = connection.connectionId, idleMs = 50))

        assertEquals("extension is unloading", result.text("stop_reason"))
        assertEquals(1, result["next_index"]!!.jsonPrimitive.int)
    }

    @Test
    fun `binary payloads go out as bytes and binary answers come back as base64`() {
        val connection = host.connect()
        val received = ArrayList<ByteArray>()
        host.binaryServer = { c, bytes ->
            received += bytes
            val answer = bytes.reversedArray()
            c.append("server_to_client", "BINARY", WebSocketFrames.encodeBase64(answer), answer.size)
        }
        val payload = byteArrayOf(0x00, 0x7F, 0x80.toByte(), 0xFF.toByte())

        val result = fuzz(
            WebSocketFuzzRequest(
                listOf(Base64.getUrlEncoder().withoutPadding().encodeToString(payload)), connectionId = connection.connectionId,
                messageType = "binary", idleMs = 50,
            )
        )

        assertEquals("BINARY", result.text("message_type"))
        assertContentEquals(payload, received.single())
        val frame = result.results().single().getValue("frames").jsonArray.single().jsonObject
        assertEquals("BINARY", frame.text("type"))
        assertEquals(Base64.getEncoder().encodeToString(payload.reversedArray()), frame.text("payload"))
        assertEquals(4, frame["length"]!!.jsonPrimitive.int)
    }

    // --- a fresh connection per payload ---

    @Test
    fun `with a url every payload gets its own connection, after its greeting and setup`() {
        host.onOpen = { c -> c.reply("welcome") }
        host.server = { c, m -> c.reply(if (m == "LOGIN") "logged in" else "echo $m") }

        val result = fuzz(
            WebSocketFuzzRequest(listOf("p1", "p2"), url = "wss://fuzz.test/ws", setupMessages = listOf("LOGIN"), idleMs = 50)
        )

        assertEquals("fresh_connection", result.text("mode"))
        assertEquals(listOf("LOGIN", "p1", "LOGIN", "p2"), host.sent)
        val results = result.results()
        assertEquals(listOf(listOf("echo p1"), listOf("echo p2")), results.map { it.frames() })
        assertEquals(listOf("ws-1", "ws-2"), results.map { it.text("connection_id") })
        assertEquals(listOf("ws-1", "ws-2"), host.closedIds)
        assertTrue(host.connections.values.all { it.status == "closed" })
    }

    @Test
    fun `a server that closes on bad input is fuzzed past it with fresh connections`() {
        host.server = { c, m ->
            if (m.contains("'")) {
                c.reply("""{"error":"bad input"}""")
                c.markClosed()
            } else {
                c.reply("""{"ok":true}""")
            }
        }

        val result = fuzz(WebSocketFuzzRequest(listOf("a", "b'", "c"), url = "wss://fuzz.test/ws", idleMs = 50))

        assertFalse(result["stopped_early"]!!.jsonPrimitive.boolean)
        assertEquals(3, result["sent"]!!.jsonPrimitive.int)
        val results = result.results()
        assertTrue(results[1]["connection_closed"]!!.jsonPrimitive.boolean)
        assertNull(results[0]["connection_closed"])
        assertEquals(listOf(2, 1), result.clusters().map { it["count"]!!.jsonPrimitive.int })
    }

    @Test
    fun `three failed opens in a row stop the run at the first of them`() {
        host.openError = "Connection failed (could not reach the host)"

        val result = fuzz(WebSocketFuzzRequest(listOf("a", "b", "c", "d", "e"), url = "wss://down.test/ws"))

        assertEquals(3, result.results().size)
        assertEquals(0, result["next_index"]!!.jsonPrimitive.int)
        assertEquals(0, result["sent"]!!.jsonPrimitive.int)
        assertTrue(result.text("stop_reason").contains("3 times in a row"), result.text("stop_reason"))
        assertTrue(result.results().all { it.text("error").contains("could not reach") })
    }

    @Test
    fun `an interrupted run stops at once and closes the connection it opened`() {
        val failure = AtomicReference<Throwable>()
        val runner = thread {
            try {
                // A silent server and a long window: only the interrupt can end this soon.
                fuzz(WebSocketFuzzRequest(listOf("a", "b"), url = "wss://fuzz.test/ws", windowMs = 60_000, idleMs = 0))
            } catch (t: Throwable) {
                failure.set(t)
            }
        }
        Thread.sleep(300)
        runner.interrupt()
        runner.join(20_000)

        assertFalse(runner.isAlive)
        assertTrue(failure.get() is InterruptedException, "got ${failure.get()}")
        assertEquals(listOf("ws-1"), host.closedIds)
    }

    // --- arguments ---

    @Test
    fun `out-of-range numbers are clamped and listed`() {
        val connection = host.connect()

        val result = fuzz(
            WebSocketFuzzRequest(
                listOf("a", "b"), connectionId = connection.connectionId, windowMs = 999_999, delayMs = -5,
                startIndex = 9, timeoutMs = 0, maxFrameLength = -1,
            )
        )

        val clamped = result.getValue("clamped").jsonObject
        assertEquals(60_000L, clamped["window_ms"]!!.jsonPrimitive.long)
        assertEquals(0L, clamped["delay_ms"]!!.jsonPrimitive.long)
        assertEquals(2L, clamped["start_index"]!!.jsonPrimitive.long)
        assertEquals(0L, clamped["max_frame_length"]!!.jsonPrimitive.long)
        assertNull(clamped["timeout_ms"], "0 means the longest budget, not a clamp")
        assertEquals(0, result["sent"]!!.jsonPrimitive.int)
        assertTrue(host.sent.isEmpty())
    }

    @Test
    fun `bad arguments are reported before anything is sent`() {
        val connection = host.connect()
        val closed = host.connect().also { it.markClosed() }
        val id = connection.connectionId

        fun error(request: WebSocketFuzzRequest) = assertNotNull(fuzz(request)["error"], "$request").jsonPrimitive.content

        assertTrue(error(WebSocketFuzzRequest(listOf("a"))).contains("connection_id"))
        assertTrue(error(WebSocketFuzzRequest(listOf("a"), connectionId = id, url = "wss://x.test/ws")).contains("not both"))
        assertTrue(error(WebSocketFuzzRequest(listOf("a"), connectionId = "ws-missing")).contains("not found"))
        assertTrue(error(WebSocketFuzzRequest(listOf("a"), connectionId = closed.connectionId)).contains("not active"))
        assertTrue(error(WebSocketFuzzRequest(emptyList(), connectionId = id)).contains("No payloads"))
        assertTrue(error(WebSocketFuzzRequest(listOf("a"), connectionId = id, pattern = "(")).contains("pattern"))
        assertTrue(error(WebSocketFuzzRequest(listOf("a"), connectionId = id, payloadEncoding = "xml")).contains("payload_encoding"))
        assertTrue(error(WebSocketFuzzRequest(listOf("a"), connectionId = id, messageType = "json")).contains("message_type"))
        assertTrue(error(WebSocketFuzzRequest(listOf("a"), connectionId = id, template = "{}")).contains("marker"))
        assertTrue(host.sent.isEmpty())
    }

    @Test
    fun `long frames and payloads are cut in the result, and say so`() {
        val connection = host.connect()
        host.server = { c, _ -> c.reply("r".repeat(100)) }

        val result = fuzz(WebSocketFuzzRequest(listOf("p".repeat(30)), connectionId = connection.connectionId, maxFrameLength = 10, idleMs = 50))

        val entry = result.results().single()
        assertEquals(10, entry.text("payload").length)
        assertTrue(entry["payload_truncated"]!!.jsonPrimitive.boolean)
        val frame = entry.getValue("frames").jsonArray.single().jsonObject
        assertEquals(10, frame.text("payload").length)
        assertTrue(frame["truncated"]!!.jsonPrimitive.boolean)
        assertEquals(100, frame["length"]!!.jsonPrimitive.int)
    }
}
