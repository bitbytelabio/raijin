package io.bitbytelab.raijin.transport

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.atomic.AtomicReference

/**
 * Transport security for the embedded Ktor servers: both MCP listeners and the dashboard.
 *
 * Binding to `127.0.0.1` is NOT a trust boundary against a web page: any page the operator
 * visits can issue requests to localhost, and DNS rebinding can make those responses
 * cross-origin-readable. Two controls always apply:
 *
 *  1. **Host-header allowlist** — defeats DNS rebinding. A rebound request carries
 *     `Host: attacker.com`, which is not on the allowlist and is rejected before any handler runs.
 *  2. **Origin lockdown** — rejects any cross-origin browser request outright (and CORS only
 *     ever advertises the allowed origins).
 *
 * On loopback that is all: MCP clients connect with just the URL. Remote access adds, from
 * [RemoteAccess.current] (read per request, so changes apply without a restart):
 *
 *  3. **Source-address allowlist** — IPs / CIDR ranges ([SourceAddressPolicy]); loopback always
 *     passes, any other peer outside the list gets `403`. Only the socket peer counts, never
 *     `X-Forwarded-For`.
 *  4. **Bearer token** — required once a listener is exposed or the operator opts in:
 *     `Authorization: Bearer <token>`, or for a browser a one-time `?token=` that sets an HttpOnly
 *     `SameSite=Strict` cookie. Anything else gets `401`. CORS preflights pass (browsers never attach
 *     credentials to them); the CORS plugin answers them, so they never reach a route.
 *
 * Extra allowed hosts (MagicDNS names, reverse-proxy names) join the Host and Origin allowlists.
 */
object SecurityConfig {
    /** Cookie set after a `?token=` visit; it holds a digest of the token, never the token itself. */
    const val AUTH_COOKIE = "raijin_auth"

    /** Query parameter a browser can use once instead of the `Authorization` header. */
    const val TOKEN_QUERY_PARAM = "token"

    /** Loopback names the Host / Origin allowlists accept on every listener. */
    internal val LOOPBACK_HOSTS = listOf("127.0.0.1", "localhost", "::1")

    private val HOST_NAME = Regex("""[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?""")

    /**
     * Normalizes a hostname / literal IP so IPv6 addresses are bracketed as `[addr]` in their
     * RFC 5952 form (what clients send) and hostnames are lowercased per RFC 3986.
     */
    internal fun formatHostForAuthority(host: String): String {
        val clean = host.trim().removePrefix("[").removeSuffix("]").lowercase()
        if (':' !in clean) return clean
        val v6 = SourceAddressPolicy.parseAddress(clean)?.address?.takeIf { it.size == 16 }
        return "[${v6?.let(SourceAddressPolicy::formatIpv6) ?: clean}]"
    }

    /** Normalizes a `host[:port]` value (a `Host` header) the way the allowlists are built. */
    internal fun normalizeAuthority(authority: String): String {
        val a = authority.trim().lowercase()
        if (!a.startsWith("[")) return a
        val close = a.indexOf(']')
        if (close < 0) return a
        return formatHostForAuthority(a.substring(1, close)) + a.substring(close + 1)
    }

    /** Normalizes an `Origin` value (`scheme://host[:port]`) the way the origin allowlists are built. */
    internal fun normalizeOrigin(origin: String): String {
        val o = origin.trim().lowercase()
        val sep = o.indexOf("://")
        if (sep < 0) return o
        return o.substring(0, sep + 3) + normalizeAuthority(o.substring(sep + 3).removeSuffix("/"))
    }

    /**
     * Builds the (Host-header allowlist, CORS-origin allowlist) for every ([hosts] x [ports])
     * pair. Pure — the anti-DNS-rebinding invariant is that only these explicit hosts are ever
     * permitted, never `anyHost()`.
     */
    fun buildAllowlists(hosts: List<String>, ports: List<Int>): Pair<Set<String>, Set<String>> {
        val h = hosts.map(::formatHostForAuthority).filter { it.isNotEmpty() }.distinct()
        val allowedHosts = ports.flatMap { port -> h.map { host -> "$host:$port" } }.toSet()
        val allowedOrigins = ports.flatMap { port -> h.map { host -> "http://$host:$port" } }.toSet()
        return allowedHosts to allowedOrigins
    }

    /**
     * Splits a configured extra host (`name`, `name:port`, an IP, `[v6]:port`; a pasted `https://`
     * prefix or path is ignored) into its authority host and optional port. Null when malformed.
     */
    internal fun parseHostEntry(raw: String): Pair<String, Int?>? {
        val s = raw.trim().lowercase().removePrefix("http://").removePrefix("https://").substringBefore('/')
        if (s.isEmpty()) return null
        fun port(text: String): Int? = text.toIntOrNull()?.takeIf { it in 1..65535 }
        return when {
            s.startsWith("[") -> {
                val close = s.indexOf(']')
                if (close < 0) return null
                val host = s.substring(1, close)
                val rest = s.substring(close + 1)
                val p = when {
                    rest.isEmpty() -> null
                    rest.startsWith(":") -> port(rest.substring(1)) ?: return null
                    else -> return null
                }
                if (SourceAddressPolicy.parseAddress(host) == null) return null
                formatHostForAuthority(host) to p
            }
            s.count { it == ':' } >= 2 ->
                if (SourceAddressPolicy.parseAddress(s) == null) null else formatHostForAuthority(s) to null
            ':' in s -> {
                val host = s.substringBefore(':')
                val p = port(s.substringAfter(':')) ?: return null
                if (!HOST_NAME.matches(host)) null else host to p
            }
            else -> if (!HOST_NAME.matches(s)) null else s to null
        }
    }

    /** The configured extra hosts that [parseHostEntry] cannot use. */
    internal fun invalidHostEntries(entries: List<String>): List<String> = entries.filter { parseHostEntry(it) == null }

    /**
     * (Host allowlist, Origin allowlist) for operator-configured extra hosts. A bare name is accepted
     * without a port (a reverse proxy forwarding `Host: name` on 80/443) and on each listener port;
     * an entry with an explicit port only on that port. Origins cover `http` and `https`, since TLS
     * is usually terminated by a proxy in front.
     */
    internal fun extraHostAllowlists(entries: List<String>, ports: List<Int>): Pair<Set<String>, Set<String>> {
        val hosts = linkedSetOf<String>()
        val origins = linkedSetOf<String>()
        for ((host, port) in entries.mapNotNull(::parseHostEntry)) {
            val authorities = if (port != null) listOf("$host:$port") else listOf(host) + ports.map { "$host:$it" }
            hosts += authorities
            authorities.forEach { origins += "http://$it"; origins += "https://$it" }
        }
        return hosts to origins
    }

    /** The token of an `Authorization: Bearer <token>` value; null when absent or another scheme. */
    internal fun bearerToken(authorization: String?): String? {
        val value = authorization?.trim() ?: return null
        val space = value.indexOf(' ')
        if (space <= 0 || !value.substring(0, space).equals("Bearer", ignoreCase = true)) return null
        return value.substring(space + 1).trim().ifEmpty { null }
    }

    /** Constant-time comparison over SHA-256 digests, so neither the content nor the length leaks. */
    internal fun tokenMatches(presented: String?, expected: String?): Boolean {
        if (presented.isNullOrEmpty() || expected.isNullOrEmpty()) return false
        return MessageDigest.isEqual(sha256(presented), sha256(expected))
    }

    /** The [AUTH_COOKIE] value for [token]: a digest, so the cookie never carries the token. */
    internal fun authCookieValue(token: String): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(sha256("raijin-auth-cookie\u0000$token"))

    /** [path] plus [query] without the token parameter: where a browser lands after a `?token=` visit. */
    internal fun withoutTokenParam(path: String, query: Parameters): String {
        // Collapse leading slashes so the Location can never become a protocol-relative `//host`.
        val safePath = "/" + path.trimStart('/')
        val rest = query.entries().flatMap { (name, values) ->
            if (name == TOKEN_QUERY_PARAM) emptyList() else values.map { name to it }
        }
        return if (rest.isEmpty()) safePath else "$safePath?${rest.formUrlEncode()}"
    }

    private fun sha256(s: String): ByteArray = MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8))
}

/** A [RemoteAccess.Config] prepared once per change for the per-request checks of [installLocalhostSecurity]. */
internal class RemoteAccessPolicy(val config: RemoteAccess.Config, ports: List<Int>) {
    /** Null when no source allowlist is configured; invalid entries are dropped, the list stays active. */
    private val ipRanges = config.allowedIps.takeIf { it.isNotEmpty() }?.mapNotNull(SourceAddressPolicy::parseRange)
    private val token = config.token?.takeIf { it.isNotEmpty() }
    val cookieValue: String? = token?.let(SecurityConfig::authCookieValue)
    val extraHosts: Set<String>
    val extraOrigins: Set<String>

    init {
        val (hosts, origins) = SecurityConfig.extraHostAllowlists(config.allowedHosts, ports)
        extraHosts = hosts
        extraOrigins = origins
    }

    fun sourceAllowed(remoteAddress: String): Boolean = SourceAddressPolicy.isAllowed(remoteAddress, ipRanges)

    fun headerValid(authorization: String?): Boolean =
        SecurityConfig.tokenMatches(SecurityConfig.bearerToken(authorization), token)

    fun queryValid(value: String?): Boolean = SecurityConfig.tokenMatches(value, token)

    fun cookieValid(value: String?): Boolean =
        value != null && cookieValue != null && MessageDigest.isEqual(value.toByteArray(), cookieValue.toByteArray())
}

/**
 * Installs Host validation, locked CORS and the remote-access checks (source allowlist, bearer
 * token) on this [Application]; see [SecurityConfig].
 *
 * @param ports ports that, combined with [hosts], define the valid Host / Origin allowlist.
 * @param hosts the allowed bind hosts; loopback names are always allowed as well. A non-loopback
 *   value is only ever passed after [BindHostPolicy] has confirmed the operator opted into
 *   network exposure.
 * @param remoteAccess the remote-access settings, read on every request.
 * @param sourceAddress the peer address of a call (the socket peer, never a forwarding header).
 */
fun Application.installLocalhostSecurity(
    ports: List<Int>,
    hosts: List<String> = listOf("127.0.0.1", "localhost"),
    remoteAccess: () -> RemoteAccess.Config = { RemoteAccess.current },
    sourceAddress: (ApplicationCall) -> String = { it.request.local.remoteAddress },
) {
    val (allowedHosts, allowedOrigins) = SecurityConfig.buildAllowlists(hosts + SecurityConfig.LOOPBACK_HOSTS, ports)
    val compiled = AtomicReference<RemoteAccessPolicy?>(null)

    fun policy(): RemoteAccessPolicy {
        val config = remoteAccess()
        compiled.get()?.let { if (it.config == config) return it }
        return RemoteAccessPolicy(config, ports).also { compiled.set(it) }
    }

    fun originAllowed(origin: String): Boolean {
        val normalized = SecurityConfig.normalizeOrigin(origin)
        return normalized in allowedOrigins || normalized in policy().extraOrigins
    }

    install(CORS) {
        allowMethod(HttpMethod.Options)
        allowMethod(HttpMethod.Get)
        allowMethod(HttpMethod.Post)
        allowMethod(HttpMethod.Delete)
        allowHeader(HttpHeaders.ContentType)
        allowHeader(HttpHeaders.Authorization)
        // Streamable HTTP session and protocol headers.
        allowHeader("Mcp-Session-Id")
        allowHeader("Mcp-Protocol-Version")
        allowHeader(HttpHeaders.LastEventID)
        exposeHeader("Mcp-Session-Id")
        allowNonSimpleContentTypes = true
        // The same allowlist as the Origin check below, never anyHost(); read per request so
        // configured extra hosts apply live.
        allowOrigins { originAllowed(it) }
    }

    intercept(ApplicationCallPipeline.Plugins) {
        val policy = policy()

        // 1. Source-address allowlist (remote access): the socket peer, never X-Forwarded-For.
        if (!policy.sourceAllowed(sourceAddress(call))) {
            call.rejectJson(HttpStatusCode.Forbidden, "forbidden: source address not allowed")
            return@intercept finish()
        }

        // 2. Host-header allowlist — primary anti-DNS-rebinding control (case-insensitive, IPv6 normalized).
        val host = call.request.headers[HttpHeaders.Host]?.let(SecurityConfig::normalizeAuthority)
        if (host == null || (host !in allowedHosts && host !in policy.extraHosts)) {
            call.rejectJson(HttpStatusCode.Forbidden, "forbidden: invalid Host header")
            return@intercept finish()
        }

        // 3. Origin lockdown — reject cross-origin browser requests outright.
        val origin = call.request.headers[HttpHeaders.Origin]
        if (origin != null && !originAllowed(origin)) {
            call.rejectJson(HttpStatusCode.Forbidden, "forbidden: cross-origin request rejected")
            return@intercept finish()
        }

        // 4. Bearer token once remote access requires it. A CORS preflight carries no credentials;
        //    its Origin passed step 3, so the CORS plugin answers it before any route runs.
        if (policy.config.authRequired && !call.isCorsPreflight()) {
            val authorization = call.request.headers[HttpHeaders.Authorization]
            val cookie = call.request.cookies[SecurityConfig.AUTH_COOKIE, CookieEncoding.RAW]
            val queryToken = call.request.queryParameters[SecurityConfig.TOKEN_QUERY_PARAM]
            val viaHeader = policy.headerValid(authorization)
            val viaCookie = !viaHeader && policy.cookieValid(cookie)
            val viaQuery = !viaHeader && !viaCookie && policy.queryValid(queryToken)
            if (!viaHeader && !viaCookie && !viaQuery) {
                val presented = authorization != null || cookie != null || queryToken != null
                call.response.header(
                    HttpHeaders.WWWAuthenticate,
                    if (presented) "Bearer realm=\"raijin\", error=\"invalid_token\"" else "Bearer realm=\"raijin\""
                )
                call.rejectJson(
                    HttpStatusCode.Unauthorized,
                    if (presented) "unauthorized: invalid token" else "unauthorized: bearer token required",
                    hint = "Send 'Authorization: Bearer <token>'. The token is on the Raijin Server tab " +
                        "(preference ${RemoteAccess.PREF_AUTH_TOKEN}). A browser can open the URL once with " +
                        "?${SecurityConfig.TOKEN_QUERY_PARAM}=<token>."
                )
                return@intercept finish()
            }
            if (viaQuery) {
                policy.cookieValue?.let { value ->
                    // Rendered by hand: Cookie() via response.cookies would add Ktor's private `$x-enc` attribute.
                    call.response.headers.append(
                        HttpHeaders.SetCookie,
                        renderSetCookieHeader(
                            name = SecurityConfig.AUTH_COOKIE,
                            value = value,
                            encoding = CookieEncoding.RAW,
                            path = "/",
                            httpOnly = true,
                            extensions = mapOf("SameSite" to "Strict"),
                            includeEncoding = false
                        )
                    )
                }
                // A page load drops the token from the address bar; API and MCP calls carry on.
                if (call.request.httpMethod == HttpMethod.Get &&
                    call.request.accept()?.contains("text/html", ignoreCase = true) == true
                ) {
                    call.respondRedirect(SecurityConfig.withoutTokenParam(call.request.path(), call.request.queryParameters))
                    return@intercept finish()
                }
            }
        }
    }
}

private fun ApplicationCall.isCorsPreflight(): Boolean =
    request.httpMethod == HttpMethod.Options &&
        request.headers[HttpHeaders.Origin] != null &&
        request.headers[HttpHeaders.AccessControlRequestMethod] != null

private suspend fun ApplicationCall.rejectJson(status: HttpStatusCode, error: String, hint: String? = null) {
    respondText(
        buildJsonObject {
            put("error", error)
            if (hint != null) put("hint", hint)
        }.toString(),
        ContentType.Application.Json,
        status
    )
}
