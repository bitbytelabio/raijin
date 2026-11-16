package io.bitbytelab.raijin.transport

import java.security.SecureRandom
import java.util.Base64

/**
 * Remote-access settings shared by the MCP listeners, the dashboard and the Server tab.
 *
 * On loopback nothing here applies: clients connect with the URL alone. Once a listener is
 * exposed (non-loopback bind, see [BindHostPolicy]) or the operator ticks "Require Auth Token",
 * a bearer token is required, and the optional source-IP and Host allowlists are enforced.
 *
 * Each setting resolves on the usual ladder: JVM system property, then Burp preference.
 */
object RemoteAccess {
    const val PREF_REQUIRE_AUTH = "mcp_require_auth"
    const val PREF_AUTH_TOKEN = "mcp_auth_token"
    const val PREF_ALLOWED_IPS = "mcp_allowed_ips"
    const val PREF_ALLOWED_HOSTS = "mcp_allowed_hosts"

    const val PROP_REQUIRE_AUTH = "raijin.requireAuth"
    const val PROP_AUTH_TOKEN = "raijin.authToken"
    const val PROP_ALLOWED_IPS = "raijin.allowedIps"
    const val PROP_ALLOWED_HOSTS = "raijin.allowedHosts"

    private const val TOKEN_BYTES = 32

    /**
     * @param authRequired requests must carry `Authorization: Bearer <token>`.
     * @param token the expected bearer token; non-null whenever [authRequired].
     * @param allowedIps source IPs / CIDR ranges allowed besides loopback; empty = any source.
     * @param allowedHosts extra hostnames accepted in `Host` / `Origin` (MagicDNS, reverse proxy).
     */
    data class Config(
        val authRequired: Boolean = false,
        val token: String? = null,
        val allowedIps: List<String> = emptyList(),
        val allowedHosts: List<String> = emptyList(),
    )

    /** @param generatedToken [config]'s token was created by this call; the caller persists it. */
    data class Resolved(val config: Config, val generatedToken: Boolean)

    /** The settings the running listeners enforce. Read per request, so [install] applies live. */
    @Volatile
    var current: Config = Config()
        private set

    fun install(config: Config) {
        current = config
    }

    /** A fresh URL-safe token with 256 bits of entropy. */
    fun generateToken(): String {
        val bytes = ByteArray(TOKEN_BYTES)
        SecureRandom().nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    /** Splits a comma / whitespace separated setting into distinct non-blank entries. */
    fun parseList(raw: String?): List<String> =
        raw.orEmpty().split(',', ' ', '\t', '\n', '\r', ';').map { it.trim() }.filter { it.isNotEmpty() }.distinct()

    /**
     * Resolves the effective settings.
     *
     * @param exposed the listeners bind a non-loopback address ([BindHostPolicy.Decision.exposed]);
     *   forces auth on.
     * @param sysProp system property lookup, injectable for tests.
     */
    fun resolve(
        exposed: Boolean,
        requireAuthPref: Boolean?,
        tokenPref: String?,
        allowedIpsPref: String?,
        allowedHostsPref: String?,
        sysProp: (String) -> String? = System::getProperty,
    ): Resolved {
        val requireAuth = sysProp(PROP_REQUIRE_AUTH)?.trim()?.toBooleanStrictOrNull() ?: requireAuthPref ?: false
        val authRequired = exposed || requireAuth
        val configured = (sysProp(PROP_AUTH_TOKEN) ?: tokenPref)?.trim()?.ifEmpty { null }
        val token = if (authRequired) configured ?: generateToken() else configured
        return Resolved(
            Config(
                authRequired = authRequired,
                token = token,
                allowedIps = parseList(sysProp(PROP_ALLOWED_IPS) ?: allowedIpsPref),
                allowedHosts = parseList(sysProp(PROP_ALLOWED_HOSTS) ?: allowedHostsPref),
            ),
            generatedToken = authRequired && configured == null,
        )
    }
}
