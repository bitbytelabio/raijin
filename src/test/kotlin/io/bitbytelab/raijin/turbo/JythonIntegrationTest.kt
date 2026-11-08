package io.bitbytelab.raijin.turbo

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag

@Tag("integration")
class JythonIntegrationTest {

    private lateinit var handler: RunHandler
    private lateinit var store: ResultStore

    @BeforeEach
    fun setUp() {
        handler = RunHandler()
        store = ResultStore()
    }

    @Test
    fun `ThreadedRequestEngine sends requests and captures responses`() {
        val script = """
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=2,
                           requestsPerConnection=1,
                           pipeline=False,
                           engine=Engine.THREADED)

    engine.queue(target.req, "request1")
    engine.queue(target.req, "request2")
    engine.queue(target.req, "request3")

def handleResponse(req, interesting):
    table.add(req)
""".trimIndent()

        val baseRequest = """GET /static/test?x=%s HTTP/1.1
Host: hackxor.net
Connection: close

""".replace("\n", "\r\n")

        evalJython(
            code = script,
            baseRequest = baseRequest,
            rawRequest = baseRequest.toByteArray(Charsets.ISO_8859_1),
            endpoint = "https://hackxor.net:443",
            host = "hackxor.net",
            baseInput = "",
            store = store,
            handler = handler,
            reqs = null,
            requestTable = null
        )

        val results = store.getAllRquests()

        assertEquals(3, results.size, "Should have received 3 responses")

        results.forEach { req ->
            assertTrue(req.code in 200..599, "Response code should be valid HTTP status: ${req.code}")
            assertTrue(req.response != null, "Response should not be null")
            assertTrue(req.length > 0, "Response should have content")
        }
    }
}
