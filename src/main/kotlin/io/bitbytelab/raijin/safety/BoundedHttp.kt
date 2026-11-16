package io.bitbytelab.raijin.safety

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import java.util.concurrent.Callable
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Hard-timeout wrapper for outbound Burp HTTP sends made OUTSIDE [io.bitbytelab.raijin.bridge.HttpBridge]
 * — the recon / web-probe / graphql / injection / access-control / scan / import bridges all call
 * `api.http().sendRequest(...)` directly with no timeout. A host that accepts the TCP connection but
 * never responds (common with WAFs / black-holing targets) would then block the single MCP dispatch
 * coroutine indefinitely (see docs/BUG-sse-backpressure-hang.md, secondary finding). This bounds every
 * such send: on timeout or error it returns null and the caller simply skips that probe.
 *
 * Documented limitation: `Future.cancel(true)` interrupts the worker, but Burp's native send is not
 * reliably interruptible, so a timed-out worker may linger until the OS socket timeout. The daemon
 * cached pool keeps that lingering off the dispatch path; bounding the CALLER is what prevents the hang.
 */
object BoundedHttp {
    const val DEFAULT_TIMEOUT_MS = 30_000L
    const val INTERNAL_BYPASS_HEADER = "X-Raijin-Bypass-Rules"

    @Volatile
    private var poolRef: ExecutorService? = null

    private fun getPool(): ExecutorService {
        val current = poolRef
        if (current != null && !current.isShutdown) return current
        return synchronized(this) {
            val again = poolRef
            if (again != null && !again.isShutdown) again
            else Executors.newCachedThreadPool { r ->
                Thread(r, "raijin-bhttp-${System.nanoTime()}").apply { isDaemon = true }
            }.also { poolRef = it }
        }
    }

    /** Stops worker threads on extension unload; lazily recreated if the extension reloads. */
    fun shutdown() {
        synchronized(this) {
            poolRef?.shutdownNow()
            poolRef = null
        }
    }

    /** Marks a request so Raijin's global TrafficRule/SessionRule HttpHandler skips modifying it. */
    fun markInternal(request: HttpRequest): HttpRequest = request.withHeader(INTERNAL_BYPASS_HEADER, "1")

    /** Bounded single send; null on timeout/error so callers can skip the probe instead of hanging. */
    fun send(api: MontoyaApi, request: HttpRequest, timeoutMs: Long = DEFAULT_TIMEOUT_MS): HttpRequestResponse? =
        runBounded(timeoutMs) { api.http().sendRequest(request) }

    /**
     * Bounded send for internal replays (auth_diff / autorize / idor_hunt) that must not be
     * contaminated by global TrafficRule/SessionRule auth injection.
     */
    fun sendInternal(api: MontoyaApi, request: HttpRequest, timeoutMs: Long = DEFAULT_TIMEOUT_MS): HttpRequestResponse? =
        send(api, markInternal(request), timeoutMs)

    /** Runs [block] on a daemon thread with a hard [timeoutMs]; returns null on timeout or error. */
    fun <T> runBounded(timeoutMs: Long, block: () -> T): T? {
        if (timeoutMs <= 0) return try { block() } catch (_: Exception) { null }
        val future = getPool().submit(Callable { block() })
        return try {
            future.get(timeoutMs, TimeUnit.MILLISECONDS)
        } catch (_: Exception) {
            future.cancel(true)
            null
        }
    }
}
