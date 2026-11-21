package io.bitbytelab.raijin.transport

import io.ktor.http.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.security.MessageDigest

/**
 * Lifecycle control for a Burp launched by the `raijin` CLI. The CLI passes a random
 * `-Draijin.controlToken` at launch and sends it back in [TOKEN_HEADER]; without the property the
 * endpoint does not exist (404). The dashboard's `installLocalhostSecurity` still applies, and no
 * MCP tool gains anything from it.
 */
internal object ControlEndpoint {
    const val PROP_TOKEN = "raijin.controlToken"
    const val TOKEN_HEADER = "X-Raijin-Control-Token"
    private const val SHUTDOWN_DELAY_MS = 200L

    /** `POST shutdown` under the current route; [shutdown] runs on a daemon thread after the reply is sent. */
    fun Route.shutdownRoute(shutdown: () -> Unit) {
        post("/shutdown") {
            val token = System.getProperty(PROP_TOKEN)
            if (token.isNullOrBlank()) {
                call.respondText(error("control endpoint disabled"), ContentType.Application.Json, HttpStatusCode.NotFound)
                return@post
            }
            val presented = call.request.headers[TOKEN_HEADER].orEmpty()
            if (!MessageDigest.isEqual(presented.toByteArray(Charsets.UTF_8), token.toByteArray(Charsets.UTF_8))) {
                call.respondText(error("bad control token"), ContentType.Application.Json, HttpStatusCode.Forbidden)
                return@post
            }
            call.respondText(
                buildJsonObject { put("status", "shutdown_initiated") }.toString(),
                ContentType.Application.Json,
                HttpStatusCode.Accepted
            )
            Thread {
                Thread.sleep(SHUTDOWN_DELAY_MS)
                shutdown()
            }.apply { isDaemon = true; name = "raijin-control-shutdown" }.start()
        }
    }

    private fun error(message: String) = buildJsonObject { put("error", message) }.toString()
}
