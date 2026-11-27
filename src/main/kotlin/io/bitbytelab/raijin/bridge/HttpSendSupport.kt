package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.RedirectionMode
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.HttpRequestResponse
import io.bitbytelab.raijin.transport.ExchangeArchive
import java.util.concurrent.Callable
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * Burp's request options for `http_send_request` (Montoya [RequestOptions]).
 *
 * @param redirects how Burp follows redirects; null keeps Burp's default (it does not follow them).
 * @param sni TLS server name sent instead of the target host.
 * @param responseTimeoutMs Burp's own timeout for reading the response; 0 = none; null = Burp's
 *   default.
 * @param verifyTls enforce verification of the target's TLS certificate (Burp does not by default).
 */
data class HttpSendOptions(
    val redirects: RedirectionMode? = null,
    val sni: String? = null,
    val responseTimeoutMs: Long? = null,
    val verifyTls: Boolean = false,
) {
    /** No option set: the request is sent the classic way, without [RequestOptions]. */
    val isDefault: Boolean
        get() = redirects == null && sni == null && responseTimeoutMs == null && !verifyTls

    fun toRequestOptions(mode: HttpMode, connectionId: String?): RequestOptions {
        var options = RequestOptions.requestOptions().withHttpMode(mode)
        if (connectionId != null) options = options.withConnectionId(connectionId)
        if (redirects != null) options = options.withRedirectionMode(redirects)
        if (sni != null) options = options.withServerNameIndicator(sni)
        if (responseTimeoutMs != null) options = options.withResponseTimeout(responseTimeoutMs)
        if (verifyTls) options = options.withUpstreamTLSVerification()
        return options
    }

    companion object {
        /** `follow_redirects` values and their [RedirectionMode]. */
        val REDIRECTS: Map<String, RedirectionMode> =
            linkedMapOf(
                "never" to RedirectionMode.NEVER,
                "always" to RedirectionMode.ALWAYS,
                "same_host" to RedirectionMode.SAME_HOST,
                "in_scope" to RedirectionMode.IN_SCOPE,
            )
    }
}

/** Thrown when a send outlives its hard timeout, so callers detect a timeout structurally. */
internal class HttpRequestTimeoutException(message: String, val timeoutMs: Long) :
    RuntimeException(message)

/**
 * Hard timeouts for Burp sends. Montoya's `sendRequest` blocks until Burp gives up on its own; this
 * runs the send on a daemon thread and stops waiting for it after the timeout (the request may
 * still complete in Burp, but the caller is released). Shut down with the extension.
 */
internal class HttpTimeouts {

    private val executor: ExecutorService = Executors.newCachedThreadPool { r ->
        Thread(r, "raijin-http-${System.nanoTime()}").apply { isDaemon = true }
    }

    /**
     * Runs [action] bounded by [timeoutMs]; null or 0 (or less) runs it on the calling thread with
     * no hard timeout.
     *
     * @throws HttpRequestTimeoutException when the timeout passes first.
     */
    fun <T> run(timeoutMs: Long?, action: () -> T): T {
        if (timeoutMs == null || timeoutMs <= 0) return action()
        val future = executor.submit(Callable { action() })
        return try {
            future.get(timeoutMs, TimeUnit.MILLISECONDS)
        } catch (_: TimeoutException) {
            future.cancel(true)
            throw HttpRequestTimeoutException("no response in $timeoutMs ms (timed out)", timeoutMs)
        } catch (e: java.util.concurrent.ExecutionException) {
            throw (e.cause as? Exception) ?: e
        }
    }

    fun shutdown() {
        executor.shutdownNow()
    }
}

/** The `http_mode` values the Montoya-backed tools take, and their [HttpMode]. */
internal object HttpModes {

    val NAMES: List<String> = listOf("AUTO", "HTTP_1", "HTTP_2", "HTTP_2_IGNORE_ALPN")

    /** [mode] (any case) as an [HttpMode]; null, blank or unknown is [HttpMode.AUTO]. */
    fun resolve(mode: String?): HttpMode =
        when (mode?.trim()?.uppercase()) {
            "HTTP_1" -> HttpMode.HTTP_1
            "HTTP_2" -> HttpMode.HTTP_2
            "HTTP_2_IGNORE_ALPN" -> HttpMode.HTTP_2_IGNORE_ALPN
            else -> HttpMode.AUTO
        }
}

/**
 * Adds an exchange sent by a tool to Burp's site map, annotated with [note], so it can be found in
 * the Burp UI. Best effort: a site map or annotation failure never fails the send.
 */
internal fun MontoyaApi.recordInSiteMap(result: HttpRequestResponse, note: String) {
    // Annotate first: the site map stores a copy at add(), so a note set afterwards never reaches
    // it.
    try {
        result.annotations().setNotes(note)
    } catch (_: Exception) {}
    try {
        siteMap().add(result)
    } catch (_: Exception) {}
}

/**
 * [recordInSiteMap], plus the exchange archive the `raijin` CLI reads offline (a no-op unless
 * `-Draijin.archiveDir` is set).
 */
internal fun MontoyaApi.recordToolExchange(
    result: HttpRequestResponse,
    note: String,
    tool: String,
) {
    recordInSiteMap(result, note)
    ExchangeArchive.appendExchange(tool, result)
}
