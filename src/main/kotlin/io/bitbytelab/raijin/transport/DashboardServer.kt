package io.bitbytelab.raijin.transport

import burp.api.montoya.logging.Logging
import io.bitbytelab.raijin.bridge.BridgeFactory
import io.bitbytelab.raijin.core.BuildInfo
import io.bitbytelab.raijin.core.ConnectionInfo
import io.bitbytelab.raijin.events.BurpEvent
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.ui.RaijinTheme
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.cio.*
import io.ktor.server.engine.*
import io.ktor.server.http.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sse.*
import io.ktor.sse.ServerSentEvent
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.serialization.json.*
import java.security.MessageDigest
import java.time.Duration
import java.time.Instant
import java.time.ZonedDateTime
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * The web dashboard. The page itself is static (`resources/dashboard/`); every dynamic value
 * (version, ports, connection strings, theme, history) comes from the `/api` endpoints, and all
 * URLs in the page are relative so a session cookie set on `/?token=...` rides along.
 *
 * [primaryMcpPort] / [secondaryMcpPort] are the ports the MCP listeners actually bound to; they
 * are only displayed.
 */
class DashboardServer(
    private val bridges: BridgeFactory.Bridges,
    private val eventBus: EventBus,
    private val stateManager: StateManager,
    private var bindHost: String = "127.0.0.1",
    private val port: Int = PortPolicy.DEFAULT_DASHBOARD,
    private val logging: Logging,
    private val primaryMcpPort: Int = PortPolicy.DEFAULT_SSE,
    private val secondaryMcpPort: Int = PortPolicy.DEFAULT_HTTP,
) {
    private var server: EmbeddedServer<CIOApplicationEngine, CIOApplicationEngine.Configuration>? = null
    private var scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val startTime = Instant.now()
    private val openSseSubscribers = AtomicInteger(0)

    fun start() {
        scope.launch {
            try {
                server = embeddedServer(CIO, port = port, host = bindHost) {
                    // Host-header allowlist + locked CORS.
                    installLocalhostSecurity(listOf(port), allowedSecurityHosts())
                    install(HttpRequestLifecycle) { cancelCallOnClose = true }
                    install(SSE)

                    routing {
                        DashboardAssets.paths.forEach { path ->
                            get(path) { call.respondAsset(DashboardAssets.lookup(path)!!) }
                        }

                        // One bounded queue per subscriber (drops the oldest event for a slow
                        // client), a heartbeat so a closed tab is noticed even when Burp is idle,
                        // and the EventBus subscriber is always released when the stream ends.
                        sse("/events") {
                            if (openSseSubscribers.incrementAndGet() > MAX_SSE_SUBSCRIBERS) {
                                openSseSubscribers.decrementAndGet()
                                try {
                                    send(ServerSentEvent(event = "error", data = "Maximum concurrent dashboard SSE streams ($MAX_SSE_SUBSCRIBERS) reached"))
                                    close()
                                } catch (_: Exception) {
                                }
                                return@sse
                            }
                            val queue = Channel<BurpEvent>(capacity = SSE_QUEUE_CAPACITY, onBufferOverflow = BufferOverflow.DROP_OLDEST)
                            val subId = eventBus.subscribeInternal(emptyList()) { event ->
                                queue.trySend(event)
                            }
                            try {
                                while (isActive) {
                                    val event = withTimeoutOrNull(SSE_HEARTBEAT_MS) { queue.receive() }
                                    if (event == null) {
                                        send(ServerSentEvent(comments = "keepalive"))
                                    } else {
                                        send(ServerSentEvent(data = DashboardApi.eventJson(event).toString(), event = event.type))
                                    }
                                }
                            } catch (e: CancellationException) {
                                throw e
                            } catch (_: Exception) {
                                // Client disconnected or the write failed: the finally block cleans up.
                            } finally {
                                eventBus.unsubscribe(subId)
                                queue.close()
                                openSseSubscribers.decrementAndGet()
                            }
                        }

                        route("/api") {
                            get("/info") {
                                call.respondJson(
                                    DashboardApi.info(BuildInfo.VERSION, bindHost, port, primaryMcpPort, secondaryMcpPort)
                                )
                            }

                            get("/stats") {
                                call.respondJson(buildJsonObject {
                                    put("uptime_seconds", Duration.between(startTime, Instant.now()).seconds)
                                    put("event_buffer_size", eventBus.size())
                                    put("proxy_rules", stateManager.proxyRules.size)
                                    put("traffic_rules", stateManager.trafficRules.size)
                                    put("session_rules", stateManager.sessionRules.size)
                                    put("scan_tasks", stateManager.scanTasks.size)
                                    put("websocket_connections", stateManager.websocketConnections.size)
                                    put("collaborator_clients", stateManager.collaboratorClients.size)
                                })
                            }

                            // Burp's current look, so the page matches the Burp window (dark or light)
                            get("/theme") {
                                fun hex(c: java.awt.Color) = String.format("#%02x%02x%02x", c.red, c.green, c.blue)
                                call.respondJson(buildJsonObject {
                                    put("dark", RaijinTheme.isDark())
                                    put("background", hex(RaijinTheme.background()))
                                    put("foreground", hex(RaijinTheme.foreground()))
                                    put("muted", hex(RaijinTheme.muted()))
                                    put("border", hex(RaijinTheme.border()))
                                    put("accent", hex(RaijinTheme.accent()))
                                    put("success", hex(RaijinTheme.success()))
                                    put("warning", hex(RaijinTheme.warning()))
                                    put("error", hex(RaijinTheme.error()))
                                    put("info", hex(RaijinTheme.info()))
                                    put("purple", hex(RaijinTheme.purple()))
                                })
                            }

                            get("/events/recent") {
                                val limit = DashboardApi.clampInt(
                                    call.request.queryParameters["limit"],
                                    DashboardApi.DEFAULT_LIMIT, 0, DashboardApi.MAX_EVENTS_LIMIT
                                )
                                call.respondJson(buildJsonArray {
                                    eventBus.getRecentEvents(limit).forEach { add(DashboardApi.eventJson(it)) }
                                })
                            }

                            // Metadata only by default (what the table shows); request/response
                            // material is opt-in per side.
                            get("/proxy/recent") {
                                val q = call.request.queryParameters
                                val limit = DashboardApi.clampInt(q["limit"], DashboardApi.DEFAULT_LIMIT, 0, DashboardApi.MAX_PROXY_LIMIT)
                                val includeRequest = DashboardApi.flag(q["include_request"])
                                val includeResponse = DashboardApi.flag(q["include_response"])
                                val maxBodyLength = DashboardApi.clampInt(
                                    q["max_body_length"], DashboardApi.DEFAULT_BODY_LENGTH, 1, DashboardApi.MAX_BODY_LENGTH
                                )
                                val body = try {
                                    val total = bridges.proxy.getHistory(
                                        startIndex = 0, count = 0, host = null, method = null, statusCode = null,
                                        mimeType = null, inScopeOnly = false
                                    )["total_filtered"]?.jsonPrimitive?.intOrNull ?: 0
                                    val history = bridges.proxy.getHistory(
                                        startIndex = DashboardApi.recentStart(total, limit),
                                        count = limit,
                                        host = null,
                                        method = null,
                                        statusCode = null,
                                        mimeType = null,
                                        inScopeOnly = false,
                                        includeRequest = includeRequest,
                                        includeResponse = includeResponse,
                                        statusCodeRange = null,
                                        maxResponseLength = maxBodyLength
                                    )
                                    DashboardApi.proxyRecent(history, includeRequest, includeResponse)
                                } catch (e: Exception) {
                                    call.respondJson(
                                        buildJsonObject { put("error", e.message ?: "Unknown error") },
                                        HttpStatusCode.InternalServerError
                                    )
                                    return@get
                                }
                                call.respondJson(body)
                            }

                            get("/rules") {
                                call.respondJson(buildJsonObject {
                                    put("proxy_rules", buildJsonArray {
                                        stateManager.proxyRules.forEach { r ->
                                            add(buildJsonObject {
                                                put("id", r.ruleId)
                                                put("type", r.type)
                                                put("action", r.action)
                                                put("enabled", r.enabled)
                                            })
                                        }
                                    })
                                    put("traffic_rules", buildJsonArray {
                                        stateManager.trafficRules.forEach { r ->
                                            add(buildJsonObject {
                                                put("id", r.ruleId)
                                                put("direction", r.direction)
                                                put("enabled", r.enabled)
                                            })
                                        }
                                    })
                                    put("session_rules", buildJsonArray {
                                        stateManager.sessionRules.forEach { r ->
                                            add(buildJsonObject {
                                                put("name", r.ruleName)
                                                put("enabled", r.enabled)
                                            })
                                        }
                                    })
                                })
                            }
                        }
                    }
                }.also { it.start(wait = false) }
            } catch (e: Exception) {
                logging.logToError("Raijin: Dashboard server failed: ${e.message}")
            }
        }
    }

    fun stop() {
        server?.stop(1000, 2000)
        scope.cancel()
    }

    /**
     * Hot-rebinds the dashboard to [newHost] WITHOUT an extension reload (see
     * [McpServerManager.rebind]). Stops the listener, swaps the host, restarts on a fresh scope.
     * Runs on the caller's thread (blocks briefly) — the UI calls this OFF the EDT.
     */
    fun rebind(newHost: String) {
        server?.stop(500, 1500)
        server = null
        scope.cancel()
        scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        bindHost = newHost
        start()
    }

    /**
     * Hosts accepted by the Host-header + CORS allowlist. Always loopback; when bound to a network
     * interface (operator opted in) this machine's own addresses are added so real remote clients
     * pass the anti-rebinding Host check.
     */
    private fun allowedSecurityHosts(): List<String> {
        val extra = if (BindHostPolicy.classify(bindHost) != BindHostPolicy.Kind.LOOPBACK) NetworkHosts.local() else emptyList()
        return (listOf(bindHost, "127.0.0.1", "localhost") + extra).distinct()
    }

    private suspend fun ApplicationCall.respondJson(json: JsonElement, status: HttpStatusCode = HttpStatusCode.OK) {
        respondText(json.toString(), ContentType.Application.Json, status)
    }

    private suspend fun ApplicationCall.respondAsset(asset: DashboardAssets.Asset) {
        val loaded = DashboardAssets.load(asset)
        if (loaded == null) {
            respond(HttpStatusCode.NotFound)
            return
        }
        response.header(HttpHeaders.CacheControl, asset.cacheControl)
        response.header(HttpHeaders.ETag, loaded.etag)
        response.header("X-Content-Type-Options", "nosniff")
        if (DashboardAssets.notModified(request.headers[HttpHeaders.IfNoneMatch], loaded.etag)) {
            respond(HttpStatusCode.NotModified)
            return
        }
        respondBytes(loaded.bytes, ContentType.parse(asset.contentType))
    }

    private companion object {
        const val MAX_SSE_SUBSCRIBERS = 64
        const val SSE_QUEUE_CAPACITY = 256
        const val SSE_HEARTBEAT_MS = 15_000L
    }
}

/**
 * The dashboard's static files, served from the classpath. Only the paths listed here are
 * served (no path is ever joined onto a resource directory).
 */
internal object DashboardAssets {
    data class Asset(val resource: String, val contentType: String, val cacheControl: String)

    class Loaded(val bytes: ByteArray, val etag: String)

    /** Revalidate on every load (cheap 304 via ETag) so a reloaded extension never serves stale JS. */
    private const val REVALIDATE = "no-cache"

    private val page = Asset("/dashboard/index.html", "text/html; charset=utf-8", REVALIDATE)

    private val assets: Map<String, Asset> = mapOf(
        "/" to page,
        "/index.html" to page,
        "/dashboard.css" to Asset("/dashboard/dashboard.css", "text/css; charset=utf-8", REVALIDATE),
        "/dashboard.js" to Asset("/dashboard/dashboard.js", "text/javascript; charset=utf-8", REVALIDATE),
        "/logo.png" to Asset("/raijin/logo-64.png", "image/png", "public, max-age=86400"),
    )

    private val cache = ConcurrentHashMap<String, Loaded>()

    val paths: Set<String> get() = assets.keys

    fun lookup(path: String): Asset? = assets[path]

    /** The asset's bytes and ETag, or null when the resource is missing from the jar. */
    fun load(asset: Asset): Loaded? {
        cache[asset.resource]?.let { return it }
        val bytes = DashboardAssets::class.java.getResourceAsStream(asset.resource)?.use { it.readBytes() } ?: return null
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        val etag = "\"" + digest.take(16).joinToString("") { "%02x".format(it) } + "\""
        return cache.putIfAbsent(asset.resource, Loaded(bytes, etag)) ?: cache.getValue(asset.resource)
    }

    /** True when an `If-None-Match` header names [etag] (or `*`). */
    fun notModified(ifNoneMatch: String?, etag: String): Boolean =
        ifNoneMatch?.split(',')?.any { val tag = it.trim().removePrefix("W/"); tag == etag || tag == "*" } == true
}

/** Pure request/response shaping for the dashboard's `/api` endpoints. */
internal object DashboardApi {
    const val DEFAULT_LIMIT = 50
    const val MAX_EVENTS_LIMIT = 500
    const val MAX_PROXY_LIMIT = 500
    const val DEFAULT_BODY_LENGTH = 4000
    const val MAX_BODY_LENGTH = 1_000_000

    /** What the table needs: URL, method, status and the other cheap per-item facts. */
    val METADATA_FIELDS: Set<String> = setOf(
        "index", "host", "port", "secure", "method", "url", "path", "edited", "mime_type",
        "has_response", "time", "timing", "status_code", "response_length", "response_mime_type",
        "comment", "highlight",
    )
    val REQUEST_FIELDS: Set<String> = setOf("request_headers", "request", "request_binary", "request_truncated")
    val RESPONSE_FIELDS: Set<String> = setOf("response", "response_binary", "response_truncated")

    /**
     * Parses a numeric query parameter and clamps it to [min]..[max]. Missing or non-numeric
     * values give [default]; out-of-range values (negative, or larger than a Long) are clamped,
     * never an error.
     */
    fun clampInt(raw: String?, default: Int, min: Int, max: Int): Int {
        val value = raw?.trim()?.toBigIntegerOrNull() ?: return default.coerceIn(min, max)
        return when {
            value < min.toBigInteger() -> min
            value > max.toBigInteger() -> max
            else -> value.toInt()
        }
    }

    fun flag(raw: String?): Boolean = when (raw?.trim()?.lowercase()) {
        "true", "1", "yes" -> true
        else -> false
    }

    /** Start index of the newest [limit] items out of [total]. */
    fun recentStart(total: Int, limit: Int): Int = (total - limit).coerceAtLeast(0)

    fun eventJson(event: BurpEvent): JsonObject = buildJsonObject {
        put("id", event.id)
        put("type", event.type)
        put("timestamp", event.timestamp)
        put("data", event.data)
    }

    /**
     * Reshapes a `getHistory` result for the dashboard: items keep [METADATA_FIELDS] plus the
     * request/response fields only when asked for, and `time` becomes an ISO instant a browser
     * can parse.
     */
    fun proxyRecent(history: JsonObject, includeRequest: Boolean, includeResponse: Boolean): JsonObject = buildJsonObject {
        history.forEach { (key, value) -> if (key != "items") put(key, value) }
        put("metadata_only", !includeRequest && !includeResponse)
        put("items", buildJsonArray {
            (history["items"] as? JsonArray)?.forEach { item ->
                if (item is JsonObject) add(proxyItem(item, includeRequest, includeResponse))
            }
        })
    }

    fun proxyItem(item: JsonObject, includeRequest: Boolean, includeResponse: Boolean): JsonObject = buildJsonObject {
        item.forEach { (key, value) ->
            val keep = key in METADATA_FIELDS ||
                (includeRequest && key in REQUEST_FIELDS) ||
                (includeResponse && key in RESPONSE_FIELDS)
            if (!keep) return@forEach
            if (key == "time" && value is JsonPrimitive && value.isString) put(key, isoInstant(value.content))
            else put(key, value)
        }
    }

    /** `ZonedDateTime.toString()` (`...+07:00[Asia/Saigon]`) is not parseable by `Date.parse`. */
    fun isoInstant(text: String): String =
        runCatching { ZonedDateTime.parse(text).toInstant().toString() }.getOrDefault(text)

    /** The dashboard's base URL on [host], an IPv6 literal bracketed. */
    fun dashboardUrl(host: String, port: Int): String = "http://${SecurityConfig.formatHostForAuthority(host)}:$port"

    fun info(version: String, host: String, dashboardPort: Int, primaryMcpPort: Int, secondaryMcpPort: Int): JsonObject {
        val primaryUrl = ConnectionInfo.mcpUrl(primaryMcpPort, host)
        val dashboard = dashboardUrl(host, dashboardPort)
        return buildJsonObject {
            put("version", version)
            put("bind_host", host)
            putJsonObject("ports") {
                put("primary_mcp", primaryMcpPort)
                put("secondary_mcp", secondaryMcpPort)
                put("dashboard", dashboardPort)
            }
            put("primary_mcp_url", primaryUrl)
            put("secondary_mcp_url", ConnectionInfo.mcpUrl(secondaryMcpPort, host))
            put("dashboard_url", dashboard)
            put("proxy_history_url", "$dashboard/api/proxy/recent?limit=$DEFAULT_LIMIT")
            putJsonObject("mcp_client_config") {
                putJsonObject("mcpServers") {
                    putJsonObject(ConnectionInfo.SERVER_NAME) {
                        put("type", "http")
                        put("url", primaryUrl)
                    }
                }
            }
            put("claude_code_command", ConnectionInfo.claudeCodeCommand(primaryMcpPort, host))
        }
    }
}
