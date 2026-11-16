package io.bitbytelab.raijin.graphql.subscriptions

import io.bitbytelab.raijin.safety.RequestHygiene
import java.net.URI

/**
 * A GraphQL WebSocket target. Built from the endpoint's `ws(s)://` URL or from the `http(s)://`
 * URL the other GraphQL modes take, since subscriptions are usually served at that same address.
 */
class SubscriptionEndpoint private constructor(
    /** Host without the brackets of an IPv6 literal. */
    val host: String,
    val port: Int,
    val secure: Boolean,
    private val authority: String,
    private val target: String,
) {
    /** `ws(s)://` form, the one results name. */
    val wsUrl: String get() = "${if (secure) "wss" else "ws"}://$authority$target"

    /** `http(s)://` form, the one Burp's scope and Proxy history know the endpoint by. */
    val httpUrl: String get() = "${if (secure) "https" else "http"}://$authority$target"

    /**
     * The HTTP/1.1 upgrade request asking for [subprotocol]. [headers] are the caller's: a `Host`
     * among them replaces the default, and the headers the handshake itself defines are dropped so
     * that the probe decides the subprotocol. Control characters are stripped, as a stray newline
     * would break the request apart.
     */
    fun upgradeRequest(subprotocol: String, headers: Map<String, String>, key: String): String = buildString {
        val custom = headers.filterKeys { it.trim().lowercase() !in HANDSHAKE_HEADERS }
        val hostOverride = custom.entries.firstOrNull { it.key.trim().equals("Host", ignoreCase = true) }?.value
        append("GET ").append(target).append(" HTTP/1.1\r\n")
        append("Host: ").append(hostOverride?.let { RequestHygiene.stripControl(it) } ?: authority).append("\r\n")
        append("Upgrade: websocket\r\n")
        append("Connection: Upgrade\r\n")
        append("Sec-WebSocket-Version: 13\r\n")
        append("Sec-WebSocket-Key: ").append(key).append("\r\n")
        append("Sec-WebSocket-Protocol: ").append(subprotocol).append("\r\n")
        for ((name, value) in custom) {
            if (name.trim().equals("Host", ignoreCase = true)) continue
            append(RequestHygiene.stripControl(name)).append(": ").append(RequestHygiene.stripControl(value)).append("\r\n")
        }
        append("\r\n")
    }

    companion object {
        private val HANDSHAKE_HEADERS = setOf(
            "upgrade", "connection", "sec-websocket-version", "sec-websocket-key", "sec-websocket-protocol",
        )

        /** Parses [url]; the failure carries a message fit to show the caller. */
        fun parse(url: String): Result<SubscriptionEndpoint> {
            val uri = try {
                URI(url.trim())
            } catch (e: Exception) {
                return failure("Invalid URL '$url': ${e.message}")
            }
            val secure = when (uri.scheme?.lowercase()) {
                "wss", "https" -> true
                "ws", "http" -> false
                else -> return failure("Unsupported scheme in '$url': expected ws, wss, http or https")
            }
            val rawHost = uri.host?.takeIf { it.isNotBlank() } ?: return failure("Invalid URL '$url': missing host")
            val defaultPort = if (secure) 443 else 80
            val port = if (uri.port > 0) uri.port else defaultPort
            val path = uri.rawPath?.takeIf { it.isNotEmpty() } ?: "/"
            val query = uri.rawQuery?.let { "?$it" } ?: ""
            return Result.success(
                SubscriptionEndpoint(
                    host = rawHost.removeSurrounding("[", "]"),
                    port = port,
                    secure = secure,
                    authority = if (port == defaultPort) rawHost else "$rawHost:$port",
                    target = RequestHygiene.stripControl(path + query),
                )
            )
        }

        private fun failure(message: String): Result<SubscriptionEndpoint> = Result.failure(IllegalArgumentException(message))
    }
}
