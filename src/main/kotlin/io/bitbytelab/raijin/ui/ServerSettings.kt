package io.bitbytelab.raijin.ui

import io.bitbytelab.raijin.core.RebindOutcome
import io.bitbytelab.raijin.safety.ScopeMode
import io.bitbytelab.raijin.transport.BindHostPolicy
import io.bitbytelab.raijin.transport.RemoteAccess
import io.bitbytelab.raijin.transport.SecurityConfig
import java.net.InetAddress

/**
 * The pure half of the Server tab: preference keys and values, bind-host classification that never
 * waits on DNS, address suggestions, allowlist checks and status texts. Free of Swing and Montoya so
 * it is unit-tested.
 */
internal object ServerSettings {
    const val PREF_SCOPE_MODE = "mcp_scope_mode"
    const val PREF_ALLOW_DESTRUCTIVE = "mcp_allow_destructive"
    const val PREF_BIND_HOST = "mcp_bind_host"
    const val PREF_ALLOW_REMOTE_BIND = "mcp_allow_remote_bind"

    /** Stored lower-case, the spelling ScopeGate's deny message gives; [ScopeMode.fromString] ignores case. */
    fun scopeModeValue(mode: ScopeMode): String = mode.name.lowercase()

    fun scopeModeHint(mode: ScopeMode): String = when (mode) {
        ScopeMode.OFF -> "No scope check on requests the agent sends."
        ScopeMode.WARN -> "Out-of-scope requests are sent and flagged in the tool result."
        ScopeMode.ENFORCE -> "Out-of-scope requests are refused."
    }

    // Dotted quad without leading zeros: the JDK rejects "010.0.0.1" as ambiguous, so leave that to classify().
    private val IPV4 = Regex("""(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})""")

    private fun ipv4Bytes(host: String): ByteArray? {
        val parts = IPV4.matchEntire(host)?.groupValues?.drop(1)?.map { it.toInt() } ?: return null
        if (parts.any { it > 255 }) return null
        return ByteArray(4) { parts[it].toByte() }
    }

    /** True when [InetAddress.getByName] parses [host] as an IPv6 literal, without a DNS lookup. */
    private fun ipv6Literal(host: String): InetAddress? {
        if (':' !in host || (host[0] != ':' && host[0].digitToIntOrNull(16) == null)) return null
        return try { InetAddress.getByName(host) } catch (_: Exception) { null }
    }

    private fun kindOf(address: InetAddress): BindHostPolicy.Kind = when {
        address.isAnyLocalAddress -> BindHostPolicy.Kind.WILDCARD
        address.isLoopbackAddress -> BindHostPolicy.Kind.LOOPBACK
        else -> BindHostPolicy.Kind.OTHER
    }

    /**
     * [BindHostPolicy.classify] for the hosts it can answer without DNS: IP literals, `localhost` and
     * malformed input. Null for a host name, which the caller classifies off the EDT.
     */
    fun quickKind(host: String): BindHostPolicy.Kind? {
        val h = host.trim().removePrefix("[").removeSuffix("]")
        if (h.isEmpty() || h.any { it.isWhitespace() }) return BindHostPolicy.Kind.INVALID
        if (h.equals("localhost", ignoreCase = true)) return BindHostPolicy.Kind.LOOPBACK
        ipv4Bytes(h)?.let { return kindOf(InetAddress.getByAddress(it)) }
        if (':' in h) return ipv6Literal(h)?.let(::kindOf) ?: BindHostPolicy.Kind.INVALID
        return null
    }

    /** A non-loopback bind always requires the bearer token ([RemoteAccess.resolve] forces it). */
    fun authForced(kind: BindHostPolicy.Kind?): Boolean =
        kind == BindHostPolicy.Kind.WILDCARD || kind == BindHostPolicy.Kind.OTHER

    /** Whether the listeners demand the token after a save: always when [authForced], else the -D property or the checkbox. */
    fun authRequired(kind: BindHostPolicy.Kind?, requireAuthChoice: Boolean, sysProp: (String) -> String?): Boolean =
        authForced(kind) || (sysProp(RemoteAccess.PROP_REQUIRE_AUTH)?.trim()?.toBooleanStrictOrNull() ?: requireAuthChoice)

    /**
     * Preference keys a `-Draijin.*` property overrides, as [RemoteAccess.resolve] reads them: the
     * require-auth property counts only when it parses as a boolean, the others whenever set.
     */
    fun overriddenPrefs(sysProp: (String) -> String?): Set<String> = buildSet {
        if (sysProp(RemoteAccess.PROP_REQUIRE_AUTH)?.trim()?.toBooleanStrictOrNull() != null) add(RemoteAccess.PREF_REQUIRE_AUTH)
        if (sysProp(RemoteAccess.PROP_AUTH_TOKEN) != null) add(RemoteAccess.PREF_AUTH_TOKEN)
        if (sysProp(RemoteAccess.PROP_ALLOWED_IPS) != null) add(RemoteAccess.PREF_ALLOWED_IPS)
        if (sysProp(RemoteAccess.PROP_ALLOWED_HOSTS) != null) add(RemoteAccess.PREF_ALLOWED_HOSTS)
    }

    // NetworkHosts strips the zone id, and a link-local address cannot be bound without it. Java
    // prints IPv6 in full ("0:0:0:0:0:0:0:1"), so the address is parsed rather than string-matched.
    private fun isReachable(literal: String): Boolean {
        val address = ipv4Bytes(literal)?.let { InetAddress.getByAddress(it) } ?: ipv6Literal(literal) ?: return false
        return !address.isLoopbackAddress && !address.isLinkLocalAddress && !address.isAnyLocalAddress
    }

    /** Addresses of this machine a remote client can reach: no loopback, wildcard or link-local; IPv4 first. */
    fun reachableAddresses(local: List<String>): List<String> =
        local.map { it.trim() }
            .filter(::isReachable)
            .distinct()
            .sortedBy { if (':' in it) 1 else 0 }

    /** Bind-host combo items: the current value, loopback, every interface, then this machine's addresses. */
    fun bindHostSuggestions(current: String, local: List<String>): List<String> =
        (listOf(current.trim(), BindHostPolicy.LOOPBACK, "0.0.0.0") + reachableAddresses(local))
            .filter { it.isNotEmpty() }
            .distinct()

    /**
     * Hosts a client can put in its URL for listeners bound to [bindHost], best first: the bound
     * address; for a wildcard bind this machine's reachable addresses, then loopback. [extraHosts]
     * (the Allowed Hosts setting: MagicDNS, `/etc/hosts` names) follow for a non-loopback bind.
     */
    fun clientHosts(bindHost: String, kind: BindHostPolicy.Kind?, local: List<String>, extraHosts: List<String>): List<String> {
        val bound = bindHost.trim().removePrefix("[").removeSuffix("]")
        val resolvedExtras = extraHosts.map {
            SecurityConfig.parseHostEntry(it)?.first?.removePrefix("[")?.removeSuffix("]") ?: it.trim()
        }
        val hosts = when (kind) {
            BindHostPolicy.Kind.WILDCARD -> reachableAddresses(local) + resolvedExtras + BindHostPolicy.LOOPBACK
            BindHostPolicy.Kind.OTHER -> listOf(bound) + resolvedExtras
            BindHostPolicy.Kind.LOOPBACK, BindHostPolicy.Kind.INVALID, null -> listOf(bound)
        }
        return hosts.map { it.trim() }.filter { it.isNotEmpty() }.distinct().ifEmpty { listOf(BindHostPolicy.LOOPBACK) }
    }

    /** Allowed IPs/CIDR entries that are neither an IP literal nor a CIDR range (`192.168.56.1`, `100.64.0.0/10`, `fd7a::/48`). */
    fun invalidIpEntries(entries: List<String>): List<String> = entries.filterNot(::isIpOrCidr)

    private fun isIpOrCidr(entry: String): Boolean {
        val address = entry.substringBefore('/').removePrefix("[").removeSuffix("]")
        val bits = when {
            ipv4Bytes(address) != null -> 32
            ipv6Literal(address) != null -> 128
            else -> return false
        }
        if ('/' !in entry) return true
        val prefix = entry.substringAfter('/').toIntOrNull() ?: return false
        return prefix in 0..bits
    }

    /**
     * Allowed Hosts entries that are invalid in the Server tab: a URL scheme, a path, credentials,
     * or something [SecurityConfig.parseHostEntry] rejects (`name`, `name:port`, `ip`, `[v6]:port`).
     */
    fun invalidHostEntries(entries: List<String>): List<String> = entries.filter { entry ->
        "://" in entry || '/' in entry || '@' in entry || SecurityConfig.parseHostEntry(entry) == null
    }

    /** [token] with all but its last four characters hidden, for on-screen display. */
    fun mask(token: String): String =
        if (token.length <= 4) "•".repeat(token.length) else "•".repeat(8) + token.takeLast(4)

    /** The remote-access fields as the operator left them; compared with the saved copy to flag unsaved edits. */
    data class RemoteForm(
        val bindHost: String,
        val allowRemoteBind: Boolean,
        val requireAuth: Boolean,
        val token: String,
        val allowedIps: List<String>,
        val allowedHosts: List<String>,
    ) {
        companion object {
            fun of(
                bindHost: String,
                allowRemoteBind: Boolean,
                requireAuth: Boolean,
                token: String,
                allowedIps: String,
                allowedHosts: String,
            ) = RemoteForm(
                bindHost.trim(), allowRemoteBind, requireAuth, token.trim(),
                RemoteAccess.parseList(allowedIps), RemoteAccess.parseList(allowedHosts),
            )
        }
    }

    enum class Tone { OK, WARN, ERROR, MUTED }

    data class Status(val text: String, val tone: Tone)

    /** One line on what the running listeners enforce ([config] = [RemoteAccess.current]). */
    fun effectiveStatus(config: RemoteAccess.Config, exposed: Boolean): Status {
        val ips = if (config.allowedIps.isEmpty()) "any source IP" else "source IPs ${config.allowedIps.joinToString(", ")}"
        val hosts = if (config.allowedHosts.isEmpty()) "" else " · extra hosts ${config.allowedHosts.joinToString(", ")}"
        val token = "bearer token ${config.token?.let(::mask).orEmpty()} required".replace("  ", " ")
        return when {
            exposed && !config.authRequired ->
                Status("Network-exposed with NO token: anyone who can reach the port can use the tools · $ips$hosts", Tone.ERROR)
            exposed && config.allowedIps.isEmpty() ->
                Status("Network-exposed · $token · any source IP (set Allowed IPs to restrict)$hosts", Tone.WARN)
            exposed -> Status("Network-exposed · $token · $ips$hosts", Tone.OK)
            config.authRequired -> Status("Loopback only · $token$hosts", Tone.OK)
            else -> Status("Loopback only · no token needed$hosts", Tone.MUTED)
        }
    }

    /** The confirmation shown before a non-loopback bind is saved. */
    fun exposureWarning(host: String, allowedIps: List<String>): String = buildString {
        append("Binding to \"$host\" makes Raijin's tools, the dashboard, and your captured proxy history\n")
        append("(requests, cookies, tokens) reachable from your network.\n\n")
        append("Clients must send the bearer token (Authorization: Bearer ...).\n")
        if (allowedIps.isEmpty()) {
            append("No Allowed IPs are set, so any machine that can reach the port may connect with the token.\n")
        } else {
            append("Only loopback and ${allowedIps.joinToString(", ")} may connect.\n")
        }
        append("\nRebind now and expose to the network?")
    }

    /** The report after a live rebind ([config] = [RemoteAccess.current] once the rebind re-resolved it). */
    fun rebindMessage(outcome: RebindOutcome, config: RemoteAccess.Config): String = buildString {
        append(
            if (outcome.boundOk) "Rebound live to ${outcome.effectiveHost} — no reload needed."
            else "Rebind attempted on ${outcome.effectiveHost} but it did NOT come up — check Extensions → Output."
        )
        if (outcome.downgraded) outcome.message?.let { append("\n\n").append(it) }
        if (outcome.exposed) {
            append("\n\nSECURITY: now reachable from your network.")
            append(
                if (config.authRequired) " Clients must send Authorization: Bearer <token>; Copy MCP Config includes it."
                else " No bearer token is enforced, so anyone who can reach the port can use the tools."
            )
            if (config.allowedIps.isEmpty()) append(" No source-IP allowlist is set.")
        } else if (config.authRequired) {
            append("\n\nClients must send Authorization: Bearer <token>; Copy MCP Config includes it.")
        }
    }
}
