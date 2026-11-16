package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.state.WebSocketMessage
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

/**
 * [WebSocketFuzzClusters]: responses that only differ in what the server echoed back or in volatile
 * tokens share a cluster, different outcomes never do, and coarser levels are used only when the
 * finest one leaves most responses alone.
 */
class WebSocketFuzzClustersTest {

    private fun frame(payload: String, type: String = "TEXT") =
        WebSocketMessage(0, "server_to_client", type, payload, payload.length, "2026-11-17T00:00:00Z")

    private fun response(
        payload: String,
        vararg frames: String,
        message: String = payload,
        closed: Boolean = false,
        error: String? = null,
    ) = WebSocketFuzzClusters.Response(payload, message, frames.map { frame(it) }, frames.size, closed, error)

    /** Payload positions per cluster, largest cluster first. */
    private fun groups(responses: List<WebSocketFuzzClusters.Response>) = WebSocketFuzzClusters.cluster(responses).clusters

    @Test
    fun `echoed payloads, timestamps, UUIDs and long ids do not split a cluster`() {
        val responses = listOf(
            response("alice", """{"ok":true,"echo":"alice","at":"2026-11-17T10:00:01Z","id":"0f8fad5b-d9cb-469f-a165-70867728950e"}"""),
            response("bob", """{"ok":true,"echo":"bob","at":"2026-11-17T10:00:02.250+02:00","id":"7c9e6679-7425-40de-944b-e07fc1f90ae7"}"""),
            response("<b>", """{"ok":true,"echo":"&lt;b&gt;","at":"2026-11-17 10:00:03","id":"00000000-0000-0000-0000-000000000000"}"""),
            response("o'neil", """{"error":"syntax error near 'o'neil' at 1234567"}"""),
        )

        val clustering = WebSocketFuzzClusters.cluster(responses)

        assertEquals("content", clustering.basis)
        assertEquals(listOf(listOf(0, 1, 2), listOf(3)), clustering.clusters)
        assertEquals(listOf(0, 0, 0, 1), clustering.clusterOf.toList())
    }

    @Test
    fun `an unescaped reflection never clusters with an escaped one`() {
        val responses = listOf(
            response("<i>a</i>", """{"ok":true,"echo":"&lt;i&gt;a&lt;/i&gt;"}"""),
            response("<u>c</u>", """{"ok":true,"echo":"&lt;u&gt;c&lt;/u&gt;"}"""),
            response("<b>b</b>", """{"ok":true,"echo":"<b>b</b>"}"""),
        )

        val clustering = WebSocketFuzzClusters.cluster(responses)

        assertEquals(listOf(listOf(0, 1), listOf(2)), clustering.clusters)
    }

    @Test
    fun `different outcomes never share a cluster`() {
        val responses = listOf(
            response("a", "same"),
            response("b"),
            response("c", "same", closed = true),
            response("d", error = "Connection is not active: status=closed"),
            response("e", "same", "same"),
            response("f", "same"),
        )

        assertEquals(listOf(listOf(0, 5), listOf(1), listOf(2), listOf(3), listOf(4)), groups(responses))
    }

    @Test
    fun `error messages that only differ in numbers share a cluster`() {
        val responses = listOf(
            response("a", error = "payload 3 could not be sent on ws-012"),
            response("b", error = "payload 4 could not be sent on ws-013"),
        )
        assertEquals(listOf(listOf(0, 1)), groups(responses))
    }

    @Test
    fun `digits are masked when exact content leaves most responses alone`() {
        val responses = (0 until 10).map { response("p$it", "queue position ${it * 7 + 3}") }

        val clustering = WebSocketFuzzClusters.cluster(responses)

        assertEquals("content_digits_masked", clustering.basis)
        assertEquals(1, clustering.clusters.size)
    }

    @Test
    fun `the JSON shape is the last resort`() {
        val names = listOf("ant", "bee", "cat", "dog", "eel", "fox", "gnu", "hen", "ibis", "jay")
        val responses = names.mapIndexed { i, name -> response("p$i", """{"user":"$name","admin":false}""") } +
            response("odd", """{"error":"boom"}""")

        val clustering = WebSocketFuzzClusters.cluster(responses)

        assertEquals("shape", clustering.basis)
        assertEquals(listOf((0 until 10).toList(), listOf(10)), clustering.clusters)
    }

    @Test
    fun `a handful of clusters is kept at the finest level, however small the run`() {
        val responses = listOf(response("a", "one"), response("b", "two"), response("c", "three"))

        val clustering = WebSocketFuzzClusters.cluster(responses)

        assertEquals("content", clustering.basis)
        assertEquals(3, clustering.clusters.size)
    }

    @Test
    fun `the frame count is part of the signature even beyond the frames kept`() {
        val kept = listOf(frame("tick"))
        val one = WebSocketFuzzClusters.Response("a", "a", kept, 1, closed = false, error = null)
        val many = WebSocketFuzzClusters.Response("b", "b", kept, 500, closed = false, error = null)

        for (level in WebSocketFuzzClusters.Level.entries) {
            assertNotEquals(WebSocketFuzzClusters.signature(one, level), WebSocketFuzzClusters.signature(many, level))
        }
    }

    @Test
    fun `binary frames are compared by their bytes, and only by kind at the shape level`() {
        val a = WebSocketFuzzClusters.Response("a", "a", listOf(frame("AAE=", "BINARY")), 1, closed = false, error = null)
        val b = WebSocketFuzzClusters.Response("b", "b", listOf(frame("AAI=", "BINARY")), 1, closed = false, error = null)

        assertNotEquals(
            WebSocketFuzzClusters.signature(a, WebSocketFuzzClusters.Level.CONTENT),
            WebSocketFuzzClusters.signature(b, WebSocketFuzzClusters.Level.CONTENT),
        )
        assertEquals(
            WebSocketFuzzClusters.signature(a, WebSocketFuzzClusters.Level.SHAPE),
            WebSocketFuzzClusters.signature(b, WebSocketFuzzClusters.Level.SHAPE),
        )
    }
}
