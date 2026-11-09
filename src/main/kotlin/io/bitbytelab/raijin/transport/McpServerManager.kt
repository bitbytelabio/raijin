// The legacy HTTP+SSE transport is deprecated in the SDK; it stays for clients still configured with "type": "sse".
@file:Suppress("DEPRECATION")

package io.bitbytelab.raijin.transport

import burp.api.montoya.logging.Logging
import io.bitbytelab.raijin.bridge.BridgeFactory
import io.bitbytelab.raijin.core.BuildInfo
import io.bitbytelab.raijin.core.ConnectionInfo
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.skills.SkillCatalog
import io.bitbytelab.raijin.state.StateManager
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.cio.*
import io.ktor.server.engine.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.sse.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.SseServerTransport
import io.modelcontextprotocol.kotlin.sdk.server.mcpStreamableHttp
import io.modelcontextprotocol.kotlin.sdk.shared.Transport
import io.modelcontextprotocol.kotlin.sdk.shared.TransportSendOptions
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.JSONRPCMessage
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import kotlinx.coroutines.*
import java.util.concurrent.ConcurrentHashMap

/**
 * Manages the lifecycle of MCP server instances and their underlying
 * Ktor HTTP servers.
 *
 * Two listeners are exposed on separate ports so that multiple MCP clients can connect
 * independently: **primary** on [ssePort] (default 9876) and **secondary** on [httpPort]
 * (default 9877). Each serves the same two transports:
 * - **Streamable HTTP** at [STREAMABLE_HTTP_PATH] (`/mcp`): what clients should use
 *   (`"type": "http"` in Claude Code and omp).
 * - **Legacy HTTP+SSE** (deprecated by the MCP spec, kept for old client configs): the SSE
 *   stream is the ROOT path "/" (GET) and the back-channel is "/?sessionId=..." (POST), NOT "/sse".
 *
 * @param bridges All bridge instances for tool/resource registration.
 * @param eventBus Shared event bus for event-related tools/resources.
 * @param stateManager Shared state for stateful tools.
 * @param bindHost Interface address to bind the transport servers to. Defaults to loopback; a
 *   non-loopback value only ever reaches here after [BindHostPolicy] confirmed the operator
 *   opted into network exposure (GitHub issue #4).
 * @param ssePort TCP port for the primary SSE transport (default 9876).
 * @param httpPort TCP port for the secondary SSE transport (default 9877).
 * @param logging Burp Suite logging API for startup/error messages.
 */
class McpServerManager(
    private val bridges: BridgeFactory.Bridges,
    private val eventBus: EventBus,
    private val stateManager: StateManager,
    private var bindHost: String = "127.0.0.1",
    private val ssePort: Int = 9876,
    private val httpPort: Int = 9877,
    private val logging: Logging
) {
    private var sseServer: EmbeddedServer<CIOApplicationEngine, CIOApplicationEngine.Configuration>? = null
    private var httpServer: EmbeddedServer<CIOApplicationEngine, CIOApplicationEngine.Configuration>? = null
    private var scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    /**
     * Hard cap on a single SSE write. The failure mode is a client that stops draining the
     * stream (e.g. a long-running PostToolUse hook), wedging the per-session write forever
     * (docs/BUG-sse-backpressure-hang.md) — NOT slowness — so this is generous: it must clear a
     * normal large-result flush but still bound the hang. On expiry the session is torn down
     * (its coroutine cancelled) and a standard SSE client reconnects.
     */
    private val sendTimeoutMs: Long = 45_000L

    companion object {
        /** Path of the Streamable HTTP endpoint on both listeners. */
        const val STREAMABLE_HTTP_PATH = ConnectionInfo.MCP_PATH

        /**
         * Sent to every client on initialize. Keep it short (omp keeps only the first 4000
         * characters) and point at the skills; the skills themselves carry the detail.
         */
        internal val SERVER_INSTRUCTIONS: String =
            "Raijin drives Burp Suite (proxy, scanner, Repeater, Turbo scripting, recon). " +
                "Most tools take an `action` parameter; the tool description lists the actions. " +
                "New here? Read the resource ${SkillCatalog.uri(SkillCatalog.ENTRY_SKILL)} first; " +
                "the other skills are at ${SkillCatalog.uri("<name>")}. " +
                "Skills: ${SkillCatalog.NAMES.joinToString(", ")}. " +
                "Each is also an MCP prompt (clients list prompts as slash commands; type /skill): " +
                "${SkillCatalog.NAMES.joinToString(", ") { SkillCatalog.promptName(it) }}. " +
                "Check scope first (scope: get_config / check); the recon and probe tools " +
                "only run against in-scope targets."

        /**
         * What the server advertises on initialize. Clients only ask for tools, resources or
         * prompts that are declared here: without `prompts`, Claude Code and omp never call
         * `prompts/list`, so no skill shows up (and the SDK refuses to register one).
         */
        internal fun serverCapabilities() = ServerCapabilities(
            tools = ServerCapabilities.Tools(listChanged = true),
            resources = ServerCapabilities.Resources(
                subscribe = true,
                listChanged = true
            ),
            // Skills are static, so the list never changes while a session is open.
            prompts = ServerCapabilities.Prompts(listChanged = false)
        )
    }

    /**
     * Creates a fresh MCP [Server] instance with all tools, resources and prompts registered.
     * Each listener builds one and serves every client session from it ([Server.createSession]
     * keeps per-client state).
     */
    fun createMcpServer(): Server {
        val server = Server(
            serverInfo = Implementation(
                name = "burpsuite",
                version = BuildInfo.VERSION
            ),
            options = ServerOptions(capabilities = serverCapabilities()),
            instructions = SERVER_INSTRUCTIONS
        )

        // Register all tools, resources and prompts on this server instance
        ToolRegistry.registerAll(server, bridges, eventBus, stateManager)
        ResourceRegistry.registerAll(server, bridges, eventBus, stateManager)
        PromptRegistry.registerAll(server)

        // Wrap all tools to emit tool.called events for dashboard + native UI visibility
        ToolCallTracker.wrapAll(server, eventBus, stateManager)

        return server
    }

    /**
     * Returns the REAL number of (tools, resources, prompts) actually registered, by
     * building a throwaway server and counting. Used for honest startup
     * reporting instead of a hardcoded count that drifts as tools change.
     */
    fun registeredCounts(): Triple<Int, Int, Int> {
        val s = createMcpServer()
        return Triple(s.tools.size, s.resources.size, s.prompts.size)
    }

    /**
     * Starts both transport servers asynchronously. Failures on one
     * transport do not prevent the other from starting.
     *
     * Each server is hardened via [installLocalhostSecurity] (Host-header allowlist + locked
     * CORS), then mounts the MCP SSE transport with our OWN wiring —
     * equivalent to the SDK's `mcp()` helper, but giving us a handle to each per-session
     * [SseServerTransport] and the SSE GET coroutine's [Job], so [TimeoutSseTransport] can
     * bound `send()` and recover a back-pressured client instead of wedging forever. The SSE
     * stream is the ROOT path '/' (GET); the POST back-channel is keyed by a `sessionId` query
     * param — NOT '/sse'.
     */
    fun start() {
        startTransport("Primary SSE", ssePort) { sseServer = it }
        startTransport("Secondary SSE", httpPort) { httpServer = it }
    }

    /**
     * Launches one CIO transport on [port] and VERIFIES it actually bound.
     *
     * `start(wait = false)` returns before Ktor's CIO engine has bound the
     * socket, and a bind failure surfaces on the engine's own coroutines — not
     * the launching one — so a plain try/catch logs a false "started" while the
     * port never opens. That is the GitHub issue #2/#3 symptom: the UI shows
     * "running", 9876/9877 never listen, and there is no error. We therefore
     * actively probe the port and log a loud, actionable error if it didn't come
     * up (the usual cause is a JAR built with Java 22+).
     */
    private fun startTransport(
        label: String,
        port: Int,
        assign: (EmbeddedServer<CIOApplicationEngine, CIOApplicationEngine.Configuration>) -> Unit
    ) {
        scope.launch {
            try {
                // Pre-flight: if the port is already taken, say so plainly. The old failure text
                // blamed the build JDK, which is the wrong lead when the real cause is a clash with
                // PortSwigger's own MCP Server extension (same default port). See PortPolicy.
                if (portInUse(port)) {
                    logging.logToError(
                        PortPolicy.conflictMessage(
                            label, bindHost, port,
                            if (port == ssePort) PortPolicy.PREF_SSE_PORT else PortPolicy.PREF_HTTP_PORT
                        )
                    )
                    return@launch
                }
                val mcpServer = createMcpServer()
                val server = embeddedServer(CIO, port = port, host = bindHost) {
                    installLocalhostSecurity(listOf(port), allowedSecurityHosts())
                    val sessions = ConcurrentHashMap<String, SseServerTransport>()
                    // Hand-rolled equivalent of the SDK's `mcp(serverFactory())` so we OWN each
                    // per-session SseServerTransport AND the SSE GET coroutine's Job — the SDK's
                    // mcp() builds the transport internally and hands us no handle. Route shape is
                    // byte-identical: SSE GET at "/", POST back-channel at "/?sessionId=...".
                    // The wrapped transport bounds send() (TimeoutSseTransport); the raw transport
                    // is registered for the POST path. See docs/BUG-sse-backpressure-hang.md.
                    install(SSE)
                    // Accept the URL with or without a trailing slash.
                    install(IgnoreTrailingSlash)
                    installStreamableHttp(mcpServer)
                    routing {
                        // NOTE: every SSE mount is wrapped in an explicit GET selector. Ktor's
                        // no-path `sse { }` overload registers a bare handler with NO HttpMethod
                        // selector, so it answers ANY verb — which combined with the old
                        // OPTIONS-skips-everything rule let an unauthenticated request open a
                        // stream and harvest a session id. Never drop the `method(Get)` wrapper.

                        method(HttpMethod.Get) { sse { serveMcpSse(mcpServer, sessions) } }
                        post { handleMcpPost(sessions) }
                    }
                }
                server.start(wait = false)
                assign(server)

                if (verifyListening(port)) {
                    logging.logToOutput(
                        "Raijin: $label listening: Streamable HTTP at http://$bindHost:$port$STREAMABLE_HTTP_PATH, " +
                            "legacy SSE at http://$bindHost:$port/ (not '/sse')"
                    )
                } else {
                    logging.logToError(
                        if (portInUse(port))
                            PortPolicy.conflictMessage(
                                label, bindHost, port,
                                if (port == ssePort) PortPolicy.PREF_SSE_PORT else PortPolicy.PREF_HTTP_PORT
                            )
                        else
                        "Raijin: $label transport reported start() but $bindHost:$port is NOT listening. " +
                            "This is the GitHub issue #2/#3 symptom — almost always a JAR built with Java 22+ " +
                            "(Kotlin/Ktor/MCP-SDK incompatibility). Rebuild with a JDK 17-21 (NOT Burp's bundled Java 25)."
                    )
                }
            } catch (e: Exception) {
                logging.logToError("Raijin: Failed to start $label transport on $bindHost:$port: ${e.message}")
                logging.logToError("Raijin: Stack trace: ${e.stackTraceToString()}")
            }
        }
    }

    /**
     * True when something is already listening on [port], i.e. our bind is going to fail. A
     * wildcard bind is not connectable at its own address, so the probe is redirected to loopback
     * exactly as [verifyListening] does.
     */
    private fun portInUse(port: Int): Boolean = try {
        java.net.Socket().use {
            it.connect(java.net.InetSocketAddress(BindHostPolicy.probeHost(bindHost), port), 300)
        }
        true
    } catch (_: Exception) {
        false
    }

    /**
     * Serves one MCP SSE session. The advertised POST endpoint is deliberately the relative
     * reference `?sessionId=...`: the client resolves it against the URL it connected to.
     */
    private suspend fun ServerSSESession.serveMcpSse(
        mcpServer: Server,
        sessions: ConcurrentHashMap<String, SseServerTransport>
    ) {
        val raw = SseServerTransport("", this)
        val tx = TimeoutSseTransport(raw, coroutineContext.job, sendTimeoutMs, logging)
        sessions[raw.sessionId] = raw
        try {
            val session = mcpServer.createSession(tx)   // responses flow through the bounded send
            session.onClose { sessions.remove(raw.sessionId) }
            awaitCancellation()                         // keep the SSE stream open until torn down
        } finally {
            sessions.remove(raw.sessionId)
        }
    }

    /** Routes one back-channel POST into its SSE session (`onMessage` -> server -> bounded `tx.send`). */
    private suspend fun RoutingContext.handleMcpPost(sessions: ConcurrentHashMap<String, SseServerTransport>) {
        val sid = call.request.queryParameters["sessionId"]
            ?: return call.respond(HttpStatusCode.BadRequest, "sessionId query parameter is not provided")
        val raw = sessions[sid]
            ?: return call.respond(HttpStatusCode.NotFound, "Session not found")
        raw.handlePostMessage(call)
    }

    /**
     * Probes the bound socket for up to ~3s to confirm the engine actually bound. A wildcard
     * bind (`0.0.0.0`/`::`) isn't connectable at that address, so [BindHostPolicy.probeHost]
     * redirects the probe to loopback — otherwise this false-negatives and logs a misleading error.
     */
    private suspend fun verifyListening(port: Int): Boolean {
        val probe = BindHostPolicy.probeHost(bindHost)
        repeat(15) {
            try {
                java.net.Socket().use { it.connect(java.net.InetSocketAddress(probe, port), 200) }
                return true
            } catch (_: Exception) {
                kotlinx.coroutines.delay(200)
            }
        }
        return false
    }

    /**
     * Hosts accepted by the Host-header + CORS allowlist. Always loopback; when bound to a
     * network interface (operator opted in) this machine's own addresses are added so real LAN
     * clients — whose `Host` header is the concrete IP, not the wildcard — pass the check.
     */
    private fun allowedSecurityHosts(): List<String> {
        val extra = if (BindHostPolicy.classify(bindHost) != BindHostPolicy.Kind.LOOPBACK) NetworkHosts.local() else emptyList()
        return (listOf(bindHost, "127.0.0.1", "localhost") + extra).distinct()
    }

    /**
     * Gracefully stops both transport servers and cancels the coroutine scope.
     * Called from the extension unload handler.
     */
    fun stop() {
        sseServer?.stop(gracePeriodMillis = 1000, timeoutMillis = 2000)
        httpServer?.stop(gracePeriodMillis = 1000, timeoutMillis = 2000)
        scope.cancel()
        logging.logToOutput("Raijin: MCP servers stopped")
    }

    /**
     * Hot-rebinds both SSE transports to [newHost] WITHOUT an extension reload: a bound socket
     * cannot change address, so the listeners are stopped and reopened on the new interface. Runs
     * on the caller's thread (blocks up to a few seconds while sockets stop + rebind) — the UI
     * calls this OFF the EDT. [newHost] is the already-gated effective host (see [BindHostPolicy]).
     * Returns whether the primary port came back up. Any live MCP client is disconnected by this,
     * exactly as a reload would.
     */
    fun rebind(newHost: String): Boolean {
        sseServer?.stop(gracePeriodMillis = 500, timeoutMillis = 1500); sseServer = null
        httpServer?.stop(gracePeriodMillis = 500, timeoutMillis = 1500); httpServer = null
        scope.cancel()
        scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        bindHost = newHost
        start()
        return blockingWaitListening(ssePort)
    }

    /** Blocking sibling of [verifyListening] for the rebind path (already off the EDT). */
    private fun blockingWaitListening(port: Int): Boolean {
        val probe = BindHostPolicy.probeHost(bindHost)
        repeat(15) {
            try {
                java.net.Socket().use { it.connect(java.net.InetSocketAddress(probe, port), 200) }
                return true
            } catch (_: Exception) {
                Thread.sleep(200)
            }
        }
        return false
    }
}

/**
 * Mounts the Streamable HTTP endpoint at [McpServerManager.STREAMABLE_HTTP_PATH], serving every session
 * from [mcpServer]. Install [installLocalhostSecurity] first: the SDK's own Host/Origin check is off
 * because it only knows loopback names and would refuse the opt-in LAN bind.
 */
internal fun Application.installStreamableHttp(mcpServer: Server) {
    mcpStreamableHttp(path = McpServerManager.STREAMABLE_HTTP_PATH, enableDnsRebindingProtection = false) { mcpServer }
}

/**
 * Wraps an [SseServerTransport] and bounds its [send] with a hard timeout so a client that
 * stops draining the SSE stream cannot wedge the per-session write forever (the 57-min hang —
 * see docs/BUG-sse-backpressure-hang.md). On timeout we cancel the SSE GET coroutine's
 * [sessionJob]: this is the ONLY recovery that works, because the session's `close()` and the
 * SSE heartbeat both re-acquire the same per-session Mutex the wedged `send()` holds and would
 * deadlock behind it. Cancelling the Job cancels the shared response byte-channel, which resumes
 * the parked `flush()` with a cause, releasing the Mutex and unwinding the POST coroutine into a
 * recoverable error. All members except [send] delegate unchanged to [delegate].
 */
private class TimeoutSseTransport(
    private val delegate: SseServerTransport,
    private val sessionJob: Job,
    private val sendTimeoutMs: Long,
    private val logging: Logging
) : Transport by delegate {
    override suspend fun send(message: JSONRPCMessage, options: TransportSendOptions?) {
        runWithSendTimeout(sendTimeoutMs, sessionJob, onTimeout = {
            logging.logToError(
                "Raijin: an SSE write stalled >${sendTimeoutMs}ms (client stopped reading the " +
                    "stream); tearing that session down to recover instead of wedging it — the client reconnects."
            )
        }) { delegate.send(message, options) }
    }
}

/**
 * Runs [block] under a [timeoutMs] deadline; on timeout invokes [onTimeout], cancels [sessionJob]
 * (the SSE GET coroutine), and re-throws. Cancelling that job cancels the shared response
 * byte-channel, which resumes the back-pressured flush() with a cause and releases the per-session
 * Mutex — the only sound recovery (close()/heartbeat would deadlock on that same Mutex). Extracted
 * from [TimeoutSseTransport.send] so the recovery TRIGGER is deterministically unit-testable
 * without needing to induce a real TCP-level write wedge.
 */
internal suspend fun <T> runWithSendTimeout(
    timeoutMs: Long,
    sessionJob: Job,
    onTimeout: () -> Unit,
    block: suspend () -> T
): T = try {
    withTimeout(timeoutMs) { block() }
} catch (t: TimeoutCancellationException) {
    onTimeout()
    sessionJob.cancel(CancellationException("SSE send back-pressure timeout after ${timeoutMs}ms"))
    throw t
}
