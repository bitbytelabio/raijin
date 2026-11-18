package io.bitbytelab.raijin.graphql.subscriptions

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
     * that the probe decides the subprotocol. Names and values are written exactly as given.
     */
    fun upgradeRequest(subprotocol: String, headers: Map<String, String>, key: String): String = buildString {
        val custom = headers.filterKeys { it.trim().lowercase() !in HANDSHAKE_HEADERS }
        val hostOverride = custom.entries.firstOrNull { it.key.trim().equals("Host", ignoreCase = true) }?.value
        append("GET ").append(target).append(" HTTP/1.1\r\n")
        append("Host: ").append(hostOverride ?: authority).append("\r\n")
        append("Upgrade: websocket\r\n")
        append("Connection: Upgrade\r\n")
        append("Sec-WebSocket-Version: 13\r\n")
        append("Sec-WebSocket-Key: ").append(key).append("\r\n")
        append("Sec-WebSocket-Protocol: ").append(subprotocol).append("\r\n")
        for ((name, value) in custom) {
            if (name.trim().equals("Host", ignoreCase = true)) continue
            append(name).append(": ").append(value).append("\r\n")
        }
        append("\r\n")
    }

    companion object {
        private val HANDSHAKE_HEADERS = setOf(
            "upgrade", "connection", "sec-websocket-version", "sec-websocket-key", "sec-websocket-protocol",
        )

        /**
         * The caller headers an anonymous session keeps: they route the request and describe the
         * client, and identify nobody. Any other header may be a credential, whatever its name
         * (`x-hasura-admin-secret`, `apikey`, a session cookie), so it is left out.
         */
        private val ANONYMOUS_HEADERS = setOf("host", "origin", "user-agent")

        /** A host name as it may stand in a URL, underscores included (`graphql_api`, a Docker service). */
        private val HOST_NAME = Regex("[A-Za-z0-9_-]+(?:\\.[A-Za-z0-9_-]+)*\\.?")

        /** [headers] as an anonymous session sends them: only [ANONYMOUS_HEADERS]. */
        fun anonymousHeaders(headers: Map<String, String>): Map<String, String> =
            headers.filterKeys { it.trim().lowercase() in ANONYMOUS_HEADERS }

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
            val (rawHost, givenPort) = hostAndPort(uri, url).getOrElse { return Result.failure(it) }
            val defaultPort = if (secure) 443 else 80
            val port = when {
                givenPort.isEmpty() -> defaultPort
                else -> givenPort.toIntOrNull()?.takeIf { it in 1..65535 }
                    ?: return failure("Invalid URL '$url': port $givenPort is out of range")
            }
            val path = uri.rawPath?.takeIf { it.isNotEmpty() } ?: "/"
            val query = uri.rawQuery?.let { "?$it" } ?: ""
            return Result.success(
                SubscriptionEndpoint(
                    host = rawHost.removeSurrounding("[", "]"),
                    port = port,
                    secure = secure,
                    authority = if (port == defaultPort) rawHost else "$rawHost:$port",
                    target = path + query,
                )
            )
        }

        /**
         * The host as written (an IPv6 literal keeps its brackets) and the port's digits, empty when
         * the URL gives none. User info is never part of either.
         */
        private fun hostAndPort(uri: URI, url: String): Result<Pair<String, String>> {
            uri.host?.takeIf { it.isNotBlank() }?.let { host ->
                return Result.success(host to if (uri.port == -1) "" else uri.port.toString())
            }
            // java.net.URI only fills in the host for a name it accepts as a host name. One with an
            // underscore, such as the Docker service `graphql_api`, leaves just the raw authority.
            val authority = uri.rawAuthority?.substringAfterLast('@').orEmpty()
            val colon = authority.indexOf(':')
            val host = if (colon < 0) authority else authority.substring(0, colon)
            val port = if (colon < 0) "" else authority.substring(colon + 1)
            return when {
                host.isEmpty() -> failure("Invalid URL '$url': missing host")
                !HOST_NAME.matches(host) -> failure("Invalid URL '$url': invalid host '$host'")
                port.any { it !in '0'..'9' } -> failure("Invalid URL '$url': invalid port '$port'")
                else -> Result.success(host to port)
            }
        }

        private fun <T> failure(message: String): Result<T> = Result.failure(IllegalArgumentException(message))
    }
}
