package io.bitbytelab.raijin.transport

import burp.api.montoya.persistence.Preferences
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

    /** Whether the listeners bind a non-loopback address; recorded by [install]. */
    @Volatile
    var exposed: Boolean = false
        private set

    /** Installs [config] for the next request, for listeners whose bind is [exposed]. */
    fun install(config: Config, exposed: Boolean = this.exposed) {
        this.exposed = exposed
        current = config
    }

    /**
     * Resolves the settings from Burp [prefs] and `-D` properties, saves a freshly generated token
     * to [PREF_AUTH_TOKEN] (so it survives a reload) and installs the result for the next request.
     * Safe to call from any thread.
     */
    fun applyFromPreferences(
        prefs: Preferences,
        exposed: Boolean,
        sysProp: (String) -> String? = System::getProperty,
    ): Resolved = resolveFromPreferences(prefs, exposed, sysProp).also { install(it.config, exposed) }

    /** [applyFromPreferences] without the install: for a rebind, which installs once the listeners have moved. */
    fun resolveFromPreferences(
        prefs: Preferences,
        exposed: Boolean,
        sysProp: (String) -> String? = System::getProperty,
    ): Resolved {
        val resolved = resolve(
            exposed = exposed,
            requireAuthPref = runCatching { prefs.getBoolean(PREF_REQUIRE_AUTH) }.getOrNull(),
            tokenPref = runCatching { prefs.getString(PREF_AUTH_TOKEN) }.getOrNull(),
            allowedIpsPref = runCatching { prefs.getString(PREF_ALLOWED_IPS) }.getOrNull(),
            allowedHostsPref = runCatching { prefs.getString(PREF_ALLOWED_HOSTS) }.getOrNull(),
            sysProp = sysProp,
        )
        val token = resolved.config.token
        if (resolved.generatedToken && token != null) runCatching { prefs.setString(PREF_AUTH_TOKEN, token) }
        return resolved
    }

    /**
     * What the listeners enforce while they rebind from [previous] to [next]. A listener answers until it
     * has stopped, so a move to a bind that is not exposed keeps [previous] (its token, its allowlists)
     * while that requires a token: an exposed listener never answers without one. [next] is installed
     * once every listener has moved. A move to an exposed bind takes [next] at once, so the new
     * listeners never answer without their own token.
     */
    fun duringRebind(previous: Config, next: Config, nextExposed: Boolean): Config =
        if (!nextExposed && previous.authRequired) previous else next

    /** Re-applies the saved settings for the current exposure, e.g. after the Server tab changed them. */
    fun reapply(prefs: Preferences): Resolved = applyFromPreferences(prefs, exposed)

    /**
     * Operator-facing warnings about [config]: an exposed listener without a source allowlist, and
     * allowlist entries that cannot be used. Never mentions the token.
     */
    fun warnings(config: Config, exposed: Boolean): List<String> = buildList {
        if (exposed && config.allowedIps.isEmpty()) {
            add(
                "no source IP allowlist ($PREF_ALLOWED_IPS / -D$PROP_ALLOWED_IPS): any host that can reach the " +
                    "listeners may present the token. Restrict it to your client, e.g. 192.168.56.1 or 100.64.0.0/10."
            )
        }
        SourceAddressPolicy.invalidEntries(config.allowedIps).forEach {
            add("ignoring '$it' in $PREF_ALLOWED_IPS: not an IP address or CIDR range")
        }
        SecurityConfig.invalidHostEntries(config.allowedHosts).forEach {
            add("ignoring '$it' in $PREF_ALLOWED_HOSTS: not a host name, IP or host:port")
        }
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
