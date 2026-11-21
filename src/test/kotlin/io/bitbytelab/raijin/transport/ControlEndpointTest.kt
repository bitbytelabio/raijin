package io.bitbytelab.raijin.transport

import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ControlEndpointTest {
    private val shutdownCalled = CountDownLatch(1)

    @AfterTest fun clearToken() {
        System.clearProperty(ControlEndpoint.PROP_TOKEN)
    }

    private fun ApplicationTestBuilder.mount() {
        routing { route("/api") { with(ControlEndpoint) { shutdownRoute { shutdownCalled.countDown() } } } }
    }

    @Test fun `shutdown is 404 without a control token property`() = testApplication {
        mount()
        val r = client.post("/api/shutdown") { header(ControlEndpoint.TOKEN_HEADER, "anything") }
        assertEquals(HttpStatusCode.NotFound, r.status)
        assertTrue("control endpoint disabled" in r.bodyAsText())
        assertFalse(shutdownCalled.await(400, TimeUnit.MILLISECONDS))
    }

    @Test fun `shutdown is 403 with a wrong or missing token`() = testApplication {
        System.setProperty(ControlEndpoint.PROP_TOKEN, "secret")
        mount()
        assertEquals(HttpStatusCode.Forbidden, client.post("/api/shutdown") { header(ControlEndpoint.TOKEN_HEADER, "secreT") }.status)
        assertEquals(HttpStatusCode.Forbidden, client.post("/api/shutdown").status)
        assertFalse(shutdownCalled.await(400, TimeUnit.MILLISECONDS))
    }

    @Test fun `shutdown with the right token replies 202 then shuts down`() = testApplication {
        System.setProperty(ControlEndpoint.PROP_TOKEN, "secret")
        mount()
        val r = client.post("/api/shutdown") { header(ControlEndpoint.TOKEN_HEADER, "secret") }
        assertEquals(HttpStatusCode.Accepted, r.status)
        assertTrue("shutdown_initiated" in r.bodyAsText())
        assertTrue(shutdownCalled.await(5, TimeUnit.SECONDS))
    }
}
