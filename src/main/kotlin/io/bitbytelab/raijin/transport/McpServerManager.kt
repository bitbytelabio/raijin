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
import io.github.oshai.kotlinlogging.DirectLoggerFactory
import io.github.oshai.kotlinlogging.KotlinLoggingConfiguration
import io.github.oshai.kotlinlogging.Level
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.cio.*
import io.ktor.server.engine.*
import io.ktor.server.http.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.sse.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.sse.ServerSentEvent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.ServerSession
import io.modelcontextprotocol.kotlin.sdk.server.SseServerTransport
import io.modelcontextprotocol.kotlin.sdk.server.mcpStreamableHttp
import io.modelcontextprotocol.kotlin.sdk.shared.Transport
import io.modelcontextprotocol.kotlin.sdk.shared.TransportSendOptions
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.JSONRPCMessage
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import kotlinx.coroutines.*
import kotlin.time.Duration.Companion.hours
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Manages the lifecycle of MCP server instances and their underlying
 * Ktor HTTP servers.
 *
 * Two listeners are exposed on separate ports so that multiple MCP clients can connect
 * independently: **primary** on [ssePort] (default 9876) and **secondary** on [httpPort]
 * (default 9877). Both serve one shared MCP [Server] (each client gets its own session) over the
 * same two transports:
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
    @Volatile
    private var sseServer: EmbeddedServer<CIOApplicationEngine, CIOApplicationEngine.Configuration>? = null
    @Volatile
    private var httpServer: EmbeddedServer<CIOApplicationEngine, CIOApplicationEngine.Configuration>? = null
    @Volatile
    private var scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    /** Guards the listener fields and [generation] between a start finishing and a stop or rebind. */
    private val lifecycle = Any()

    /** Bumped by [stop] and [rebind]: a start that finishes under an older one stops its own listener. */
    @Volatile
    private var generation = 0

    /**
     * Hard cap on a single SSE write. The failure mode is a client that stops draining the
     * stream (e.g. a long-running PostToolUse hook), wedging the per-session write forever
     * (docs/BUG-sse-backpressure-hang.md) — NOT slowness — so this is generous: it must clear a
     * normal large-result flush but still bound the hang. On expiry the session is torn down
     * (its coroutine cancelled) and a standard SSE client reconnects.
     */
    private val sendTimeoutMs: Long = 45_000L

    /** The [Server] both listeners serve; built on first use and replaced after [stop] / [rebind]. */
    @Volatile
    private var servedServer: Server? = null

    companion object {
        init {
            silenceSdkLogging()
        }

        /**
         * Suppresses the MCP SDK's kotlin-logging startup banner and INFO/DEBUG/WARN connection
         * churn (`New SSE connection...`, `FeatureRegistry Adding Tool...`) without dropping errors.
         */
        internal fun silenceSdkLogging() {
            System.setProperty("kotlin-logging.logStartupMessage", "false")
            KotlinLoggingConfiguration.logStartupMessage = false
            KotlinLoggingConfiguration.loggerFactory = DirectLoggerFactory
            KotlinLoggingConfiguration.direct.logLevel = Level.ERROR
        }

        /** Path of the Streamable HTTP endpoint on both listeners. */
        const val STREAMABLE_HTTP_PATH = ConnectionInfo.MCP_PATH

        /** Cap on concurrent legacy SSE connections per listener to bound memory/file descriptors. */
        private const val MAX_SSE_SESSIONS = 64
        private const val SSE_HEARTBEAT_INTERVAL_MS = 15_000L

        /** Bound on closing a session or the server; a wedged send can hold a session's lock. */
        private const val SESSION_CLOSE_TIMEOUT_MS = 3_000L

        /** How long [rebind] waits for both listeners to report they came up. */
        private const val REBIND_WAIT_MS = 10_000L

        /**
         * Largest MCP request a legacy SSE session accepts. The SDK 0.16 Streamable HTTP route has
         * no such option and keeps its own 4 MiB limit.
         */
        internal const val MAX_REQUEST_BODY_BYTES = 64L * 1024 * 1024

        /** Streamable HTTP: a session idle this long is closed (an agent may pause for hours mid-engagement). */
        internal val STREAMABLE_SESSION_IDLE = 24.hours

        /** Streamable HTTP: most sessions open at once per listener. */
        internal const val MAX_STREAMABLE_SESSIONS = 256

        /**
         * Sent to every client on initialize. Keep it short (omp keeps only the first 4000
         * characters) and point at the skills; the skills themselves carry the detail.
         */
        internal val SERVER_INSTRUCTIONS: String =
            "Raijin drives Burp Suite (proxy, scanner, Repeater, Turbo scripting, recon). " +
                "Grouped tools take an \"action\" argument plus that action's parameters, e.g. " +
                "scope {\"action\": \"check\", \"url\": \"https://example.com\"}; the tool description lists each action " +
                "and marks required parameters with *. Use only parameter names from the inputSchema: unknown names are rejected. " +
                "An error result says what to fix and usually carries 'usage' and 'example': correct the arguments from them " +
                "instead of resending the same call. " +
                "New here? Load the `${SkillCatalog.ENTRY_SKILL}` skill first " +
                "(resource `${SkillCatalog.uri(SkillCatalog.ENTRY_SKILL)}`, `load_skill`, or prompt `${SkillCatalog.ENTRY_SKILL}`). " +
                "Skills: ${SkillCatalog.NAMES.joinToString(", ")}. " +
                "Check scope first (scope with action=get_config / check). Outbound requests are checked " +
                "against Burp's scope per the operator's mcp_scope_mode: warn (default) sends and adds scope_warning; " +
                "enforce refuses (out_of_scope=true). Turbo, Scanner and WebSocket are advisory only."

        /**
         * What the server advertises on initialize. Clients only ask for tools, resources or
         * prompts that are declared here: without `prompts`, Claude Code and omp never call
         * `prompts/list`, so no skill shows up (and the SDK refuses to register one).
         */
        internal fun serverCapabilities() = ServerCapabilities(
            tools = ServerCapabilities.Tools(listChanged = true),
            resources = ServerCapabilities.Resources(
                subscribe = false,
                listChanged = false
            ),
            // Skills are static, so the list never changes while a session is open.
            prompts = ServerCapabilities.Prompts(listChanged = false)
        )
    }

    /**
     * Creates a fresh MCP [Server] instance with all tools, resources and prompts registered.
     * Both listeners serve every client session from one ([Server.createSession] keeps
     * per-client state).
     */
    fun createMcpServer(): Server {
        val options = ServerOptions(capabilities = serverCapabilities()).apply {
            handlerCoroutineContext = Dispatchers.IO
        }
        val server = Server(
            serverInfo = Implementation(
                name = "burpsuite",
                version = BuildInfo.VERSION
            ),
            options = options,
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

    /** The server both listeners serve, built on first use. */
    private fun sharedServer(): Server = servedServer ?: synchronized(this) {
        servedServer ?: createMcpServer().also { servedServer = it }
    }

    /**
     * Returns the REAL number of (tools, resources, prompts) registered on the server the listeners
     * serve. Asked before [start], it builds that server once and [start] then reuses it.
     */
    fun registeredCounts(): Triple<Int, Int, Int> {
        val server = sharedServer()
        return Triple(server.tools.size, server.resources.size, server.prompts.size)
    }

    /**
     * Starts both transport servers asynchronously. Failures on one
     * transport do not prevent the other from starting.
     *
     * Each server is hardened via [installLocalhostSecurity] (Host-header allowlist, locked
     * CORS, and the remote-access checks), then mounts the MCP SSE transport with our OWN wiring —
     * equivalent to the SDK's `mcp()` helper, but giving us a handle to each per-session
     * [SseServerTransport] and the SSE GET coroutine's [Job], so [TimeoutSseTransport] can
     * bound `send()` and recover a back-pressured client instead of wedging forever. The SSE
     * stream is the ROOT path '/' (GET); the POST back-channel is keyed by a `sessionId` query
     * param — NOT '/sse'.
     */
    fun start() {
        startAll()
    }

    /** Starts both listeners; each result completes with whether that listener came up. */
    private fun startAll(): List<CompletableDeferred<Boolean>> {
        val server = sharedServer()
        return listOf(
            startTransport("Primary SSE", ssePort, server) { sseServer = it },
            startTransport("Secondary SSE", httpPort, server) { httpServer = it },
        )
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
     * up.
     */
    private fun startTransport(
        label: String,
        port: Int,
        mcpServer: Server,
        assign: (EmbeddedServer<CIOApplicationEngine, CIOApplicationEngine.Configuration>) -> Unit
    ): CompletableDeferred<Boolean> {
        val listening = CompletableDeferred<Boolean>()
        val gen = generation
        scope.launch {
            var server: EmbeddedServer<CIOApplicationEngine, CIOApplicationEngine.Configuration>? = null
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
                    listening.complete(false)
                    return@launch
                }
                server = embeddedServer(CIO, port = port, host = bindHost) {
                    installLocalhostSecurity(listOf(port), allowedSecurityHosts())
                    install(HttpRequestLifecycle) { cancelCallOnClose = true }
                    val sessions = ConcurrentHashMap<String, SseServerTransport>()
                    val openSseSessions = AtomicInteger(0)
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

                        method(HttpMethod.Get) { sse { serveMcpSse(mcpServer, sessions, openSseSessions) } }
                        post { handleMcpPost(sessions) }
                    }
                }
                server.start(wait = false)
                val stale = synchronized(lifecycle) {
                    (gen != generation).also { if (!it) assign(server) }
                }
                if (stale) {
                    // A stop or rebind ran while this was starting: this listener belongs to no one.
                    server.stop(0, 500)
                    listening.complete(false)
                    return@launch
                }

                val displayHost = SecurityConfig.formatHostForAuthority(bindHost)
                val up = verifyListening(port)
                listening.complete(up)
                if (!up) {
                    logging.logToError(
                        if (portInUse(port))
                            PortPolicy.conflictMessage(
                                label, bindHost, port,
                                if (port == ssePort) PortPolicy.PREF_SSE_PORT else PortPolicy.PREF_HTTP_PORT
                            )
                        else
                        "Raijin: $label transport reported start() but $displayHost:$port is NOT listening, " +
                            "and no other process holds the port. Look for a Ktor/CIO error earlier in this " +
                            "extension's error output."
                    )
                }
            } catch (e: CancellationException) {
                listening.complete(false)
                throw e
            } catch (e: Exception) {
                runCatching { server?.stop(0, 0) }
                listening.complete(false)
                logging.logToError("Raijin: Failed to start $label transport on $bindHost:$port: ${e.message}")
                logging.logToError("Raijin: Stack trace: ${e.stackTraceToString()}")
            }
        }
        return listening
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
     * Serves one MCP SSE session, refusing it once [MAX_SSE_SESSIONS] streams are open on this
     * listener. The slot is reserved atomically, so a burst of connections cannot overshoot the cap.
     */
    private suspend fun ServerSSESession.serveMcpSse(
        mcpServer: Server,
        sessions: ConcurrentHashMap<String, SseServerTransport>,
        openSessions: AtomicInteger
    ) {
        if (openSessions.incrementAndGet() > MAX_SSE_SESSIONS) {
            openSessions.decrementAndGet()
            try {
                send(ServerSentEvent(event = "error", data = "Maximum concurrent SSE sessions ($MAX_SSE_SESSIONS) reached"))
                close()
            } catch (_: Exception) {
            }
            return
        }
        try {
            serveOpenMcpSse(mcpServer, sessions)
        } finally {
            openSessions.decrementAndGet()
        }
    }

    /**
     * Runs one MCP SSE session until the client goes away (the call is cancelled on close) or the
     * session closes. The advertised POST endpoint is deliberately the relative reference
     * `?sessionId=...`: the client resolves it against the URL it connected to.
     */
    private suspend fun ServerSSESession.serveOpenMcpSse(
        mcpServer: Server,
        sessions: ConcurrentHashMap<String, SseServerTransport>
    ) {
        val sessionJob = coroutineContext.job
        // Large enough for a whole OpenAPI document or a big raw request (the SDK default is 4 MiB).
        val raw = SseServerTransport("", this, MAX_REQUEST_BODY_BYTES)
        val tx = TimeoutSseTransport(raw, sessionJob, sendTimeoutMs, logging)
        sessions[raw.sessionId] = raw
        var mcpSession: ServerSession? = null
        val heartbeatJob = launch {
            while (isActive) {
                delay(SSE_HEARTBEAT_INTERVAL_MS)
                runWithSendTimeout(sendTimeoutMs, sessionJob, onTimeout = {}) {
                    send(ServerSentEvent(comments = "keepalive"))
                }
            }
        }
        try {
            val session = mcpServer.createSession(tx)   // responses flow through the bounded send
            mcpSession = session
            session.onClose {
                sessions.remove(raw.sessionId)
                heartbeatJob.cancel()
            }
            awaitCancellation()                         // keep the SSE stream open until torn down
        } finally {
            heartbeatJob.cancel()
            sessions.remove(raw.sessionId)
            // The call is usually cancelled by now, and a cancelled close() could stop before the
            // transport's close callbacks run, leaving the session registered on the Server. Close
            // without cancellation, bounded in case a wedged send still holds the session lock.
            withContext(NonCancellable) {
                withTimeoutOrNull(SESSION_CLOSE_TIMEOUT_MS) {
                    try {
                        val session = mcpSession
                        if (session != null) session.close() else tx.close()
                    } catch (_: Exception) {
                    }
                }
            }
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
     * Hosts accepted by the Host-header + CORS allowlist besides the loopback names
     * [installLocalhostSecurity] always accepts. When bound to a network interface (operator opted
     * in) this machine's own addresses are added so real LAN clients — whose `Host` header is the
     * concrete IP, not the wildcard — pass the check.
     */
    private fun allowedSecurityHosts(): List<String> {
        val extra = if (BindHostPolicy.classify(bindHost) != BindHostPolicy.Kind.LOOPBACK) NetworkHosts.local() else emptyList()
        return (listOf(bindHost) + extra).distinct()
    }

    /**
     * Gracefully stops both transport servers, closes the MCP server's remaining sessions and
     * cancels the coroutine scope. Called from the extension unload handler.
     */
    fun stop() {
        retireListeners().forEach { it.stop(gracePeriodMillis = 1000, timeoutMillis = 2000) }
        closeMcpServer()
        scope.cancel()
        logging.logToOutput("Raijin: MCP servers stopped")
    }

    /** Takes both listeners out of service, so a start still in flight will not install itself. */
    private fun retireListeners(): List<EmbeddedServer<CIOApplicationEngine, CIOApplicationEngine.Configuration>> =
        synchronized(lifecycle) {
            generation++
            listOfNotNull(sseServer, httpServer).also {
                sseServer = null
                httpServer = null
            }
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
        retireListeners().forEach { it.stop(gracePeriodMillis = 500, timeoutMillis = 1500) }
        closeMcpServer()
        scope.cancel()
        scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        bindHost = newHost
        val (primary, secondary) = startAll()
        // The starts report whether each listener came up; no second probe of the ports.
        return runBlocking {
            withTimeoutOrNull(REBIND_WAIT_MS) {
                primary.await() && (httpPort == ssePort || secondary.await())
            } ?: false
        }
    }

    /**
     * Closes the shared server once its listeners are down: its sessions (whose clients are gone)
     * and notification jobs would otherwise outlive it. The next [start] builds a fresh one.
     */
    private fun closeMcpServer() {
        val server = synchronized(this) { servedServer.also { servedServer = null } } ?: return
        try {
            runBlocking { withTimeoutOrNull(SESSION_CLOSE_TIMEOUT_MS) { server.close() } }
        } catch (e: Exception) {
            logging.logToError("Raijin: closing the MCP server failed: ${e.message}")
        }
    }
}

/**
 * Mounts the Streamable HTTP endpoint at [McpServerManager.STREAMABLE_HTTP_PATH], serving every session
 * from [mcpServer]. Install [installLocalhostSecurity] first: the SDK's own Host/Origin check is off
 * because it only knows loopback names and would refuse the opt-in LAN bind.
 */
internal fun Application.installStreamableHttp(mcpServer: Server) {
    mcpStreamableHttp(
        path = McpServerManager.STREAMABLE_HTTP_PATH,
        enableDnsRebindingProtection = false,
        sessionIdleTimeout = McpServerManager.STREAMABLE_SESSION_IDLE,
        maxSessions = McpServerManager.MAX_STREAMABLE_SESSIONS,
    ) { mcpServer }
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
            logging.logToError("Raijin: SSE write timed out (${sendTimeoutMs}ms); closed session")
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
