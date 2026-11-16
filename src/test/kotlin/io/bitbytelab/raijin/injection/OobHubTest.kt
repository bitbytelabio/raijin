package io.bitbytelab.raijin.injection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class OobHubTest {

    /** Stand-in for a Collaborator client: numbered payloads, and a queue each poll drains unless it [replays]. */
    private class Client {
        var issued = 0
        var broken = false
        var replays = false
        val queue = ArrayList<OobChannel.Interaction>()

        fun generate(): OobChannel.Payload {
            if (broken) throw IllegalStateException("Collaborator is disabled")
            return OobChannel.Payload("p${issued}", "p${issued++}.oob.test")
        }

        fun fetch(): List<OobChannel.Interaction> = queue.toList().also { if (!replays) queue.clear() }

        fun receive(id: String, type: String = "dns") {
            queue += OobChannel.Interaction(id, type)
        }
    }

    private fun hub(client: Client) = OobHub(client::generate, client::fetch)

    @Test
    fun `a run collects the interactions for its own payloads, each once`() {
        val client = Client()
        val channel = hub(client).channel()
        val first = channel.issue("ssrf one")!!
        val second = channel.issue("ssrf two")!!
        assertEquals(listOf("p0", "p1"), listOf(first.id, second.id))
        assertEquals("p0.oob.test", first.host)

        client.receive("p1", "http")
        assertEquals(listOf(OobChannel.Interaction("p1", "http")), channel.collect())
        assertTrue(channel.collect().isEmpty(), "an interaction is handed out once")

        client.receive("p0")
        assertEquals(listOf("p0"), channel.collect().map { it.payloadId })
    }

    @Test
    fun `a poll made by one run keeps what belongs to another`() {
        val client = Client()
        val hub = hub(client)
        val a = hub.channel()
        val b = hub.channel()
        val fromA = a.issue("a")!!
        val fromB = b.issue("b")!!

        client.receive(fromA.id)
        client.receive(fromB.id)
        assertEquals(listOf(fromB.id), b.collect().map { it.payloadId })
        assertEquals(listOf(fromA.id), a.collect().map { it.payloadId }, "b's poll must not swallow a's interaction")
    }

    @Test
    fun `what arrives after a run has ended is reported as late, once, with what was sent`() {
        val client = Client()
        val hub = hub(client)
        val finished = hub.channel()
        val payload = finished.issue("ssrf out-of-band: http://{host}/")!!
        hub.release(finished)
        assertTrue(hub.late().isEmpty())

        client.receive(payload.id, "http")
        val running = hub.channel()
        running.issue("xxe")
        assertTrue(running.collect().isEmpty(), "not this run's payload")

        val late = hub.late().single()
        assertEquals("ssrf out-of-band: http://{host}/", late.purpose)
        assertEquals(payload.host, late.host)
        assertEquals("http", late.interaction.type)
        assertTrue(hub.late().isEmpty())
    }

    @Test
    fun `interactions of a run still in progress are not late`() {
        val client = Client()
        val hub = hub(client)
        val running = hub.channel()
        val payload = running.issue("cmdi")!!
        client.receive(payload.id)
        assertTrue(hub.late().isEmpty())
        assertEquals(listOf(payload.id), running.collect().map { it.payloadId })
    }

    @Test
    fun `unknown payloads are ignored and a client that cannot issue yields no payload`() {
        val client = Client()
        val hub = hub(client)
        val channel = hub.channel()
        client.receive("someone-else")
        assertTrue(channel.collect().isEmpty())
        assertTrue(hub.late().isEmpty())

        client.broken = true
        assertNull(channel.issue("ssrf"))
    }

    @Test
    fun `a client that returns an interaction again does not repeat it`() {
        val client = Client().apply { replays = true }
        val hub = hub(client)
        val channel = hub.channel()
        val payload = channel.issue("ssrf")!!
        client.receive(payload.id, "http")
        assertEquals(1, channel.collect().size)
        assertTrue(channel.collect().isEmpty())

        hub.release(channel)
        assertTrue(hub.late().isEmpty(), "already collected by its run")
    }
}
