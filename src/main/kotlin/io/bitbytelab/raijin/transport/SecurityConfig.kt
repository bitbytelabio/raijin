package io.bitbytelab.raijin.transport

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.response.*

/**
 * Localhost security hardening for the embedded Ktor servers.
 *
 * Binding to `127.0.0.1` is NOT a trust boundary against a web page: any page the operator
 * visits can issue requests to localhost, and DNS rebinding can make those responses
 * cross-origin-readable. Two independent controls close that hole:
 *
 *  1. **Host-header allowlist** — defeats DNS rebinding. A rebound request carries
 *     `Host: attacker.com`, which is not on the allowlist and is rejected before any handler runs.
 *  2. **Origin lockdown** — rejects any cross-origin browser request outright (and CORS only
 *     ever advertises the configured origins).
 *
 * There is deliberately no bearer token: MCP clients connect with just the URL. Non-browser
 * local processes can therefore call the server, which is why the server only binds to
 * loopback unless the operator explicitly opts into remote binding ([BindHostPolicy]).
 */
object SecurityConfig {
    /**
     * Builds the (Host-header allowlist, CORS-origin allowlist) for every ([hosts] x [ports])
     * pair. Pure — the anti-DNS-rebinding invariant is that only these explicit hosts are ever
     * permitted, never `anyHost()`.
     */
    fun buildAllowlists(hosts: List<String>, ports: List<Int>): Pair<Set<String>, Set<String>> {
        val h = hosts.distinct()
        val allowedHosts = ports.flatMap { port -> h.map { host -> "$host:$port" } }.toSet()
        val allowedOrigins = ports.flatMap { port -> h.map { host -> "http://$host:$port" } }.toSet()
        return allowedHosts to allowedOrigins
    }
}

/**
 * Installs Host validation + locked CORS on this [Application].
 *
 * @param ports ports that, combined with [hosts], define the valid Host / Origin allowlist.
 * @param hosts the allowed bind hosts. Defaults to loopback; a non-loopback value is only ever
 *   passed after [BindHostPolicy] has confirmed the operator opted into network exposure.
 */
fun Application.installLocalhostSecurity(
    ports: List<Int>,
    hosts: List<String> = listOf("127.0.0.1", "localhost")
) {
    val (allowedHosts, allowedOrigins) = SecurityConfig.buildAllowlists(hosts, ports)

    install(CORS) {
        allowMethod(HttpMethod.Options)
        allowMethod(HttpMethod.Get)
        allowMethod(HttpMethod.Post)
        allowMethod(HttpMethod.Delete)
        allowHeader(HttpHeaders.ContentType)
        // Streamable HTTP session and protocol headers.
        allowHeader("Mcp-Session-Id")
        allowHeader("Mcp-Protocol-Version")
        allowHeader(HttpHeaders.LastEventID)
        exposeHeader("Mcp-Session-Id")
        allowNonSimpleContentTypes = true
        // Only the explicitly configured host:port origins are ever permitted — never anyHost().
        allowedHosts.forEach { hostPort -> allowHost(hostPort, schemes = listOf("http")) }
    }

    intercept(ApplicationCallPipeline.ApplicationPhase.Plugins) {
        // 1. Host-header allowlist — primary anti-DNS-rebinding control.
        val host = call.request.headers[HttpHeaders.Host]
        if (host == null || host !in allowedHosts) {
            call.respondText(
                """{"error":"forbidden: invalid Host header"}""",
                ContentType.Application.Json,
                HttpStatusCode.Forbidden
            )
            return@intercept finish()
        }

        // 2. Origin lockdown — reject cross-origin browser requests outright.
        val origin = call.request.headers[HttpHeaders.Origin]
        if (origin != null && origin !in allowedOrigins) {
            call.respondText(
                """{"error":"forbidden: cross-origin request rejected"}""",
                ContentType.Application.Json,
                HttpStatusCode.Forbidden
            )
            return@intercept finish()
        }
    }
}
