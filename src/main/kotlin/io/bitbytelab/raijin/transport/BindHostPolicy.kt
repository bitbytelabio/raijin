package io.bitbytelab.raijin.transport

import java.net.InetAddress

/**
 * Security policy for the configurable server bind host (GitHub issue #4, contributed as PR #6
 * by @Spark0618 and re-implemented here with an operator gate).
 *
 * The embedded servers expose Burp-driving tools (SSRF-capable request engine, proxy history
 * containing captured credentials/cookies, scanner, collaborator) plus a dashboard API. On loopback
 * they need no token. Binding to a network-reachable interface is therefore a privileged action
 * that **requires an explicit operator opt-in** (Burp pref `mcp_allow_remote_bind` /
 * `-Draijin.allowRemoteBind`); absent that, any non-loopback request is refused and downgraded back
 * to `127.0.0.1`. An honored exposure ([Decision.exposed]) switches on the remote-access controls
 * ([RemoteAccess]: mandatory bearer token, optional source and host allowlists). This mirrors the
 * existing `mcp_allow_destructive` gate pattern.
 *
 * Kept pure (no Ktor, no I/O beyond a local `InetAddress` classification) so the gate is
 * deterministically unit-tested.
 */
object BindHostPolicy {
    const val LOOPBACK = "127.0.0.1"

    enum class Kind {
        /** 127.0.0.0/8 or ::1 or a name that resolves to loopback (e.g. "localhost"). */
        LOOPBACK,
        /** 0.0.0.0 / :: — binds to every interface (the broadest exposure). */
        WILDCARD,
        /** A concrete, network-reachable address/hostname. */
        OTHER,
        /** Empty, whitespace-bearing, or unresolvable — never bound. */
        INVALID
    }

    /**
     * @param effectiveHost the host the servers should ACTUALLY bind to (already gated).
     * @param exposed true when [effectiveHost] is network-reachable (operator opted in).
     * @param downgraded true when the request was refused/invalid and forced back to loopback.
     * @param message operator-facing reason, present when [exposed] or [downgraded].
     */
    data class Decision(
        val effectiveHost: String,
        val exposed: Boolean,
        val downgraded: Boolean,
        val message: String?
    )

    /** Classifies a requested bind host without ever binding. Whitespace/empty ⇒ [Kind.INVALID]. */
    fun classify(host: String): Kind {
        val h = host.trim().removePrefix("[").removeSuffix("]")
        if (h.isEmpty() || h.any { it.isWhitespace() }) return Kind.INVALID
        return try {
            val addr = InetAddress.getByName(h)
            when {
                addr.isAnyLocalAddress -> Kind.WILDCARD
                addr.isLoopbackAddress -> Kind.LOOPBACK
                else -> Kind.OTHER
            }
        } catch (_: Exception) {
            Kind.INVALID
        }
    }

    /** Applies the operator gate to a requested host, returning the host to actually bind to. */
    fun resolve(requested: String, allowRemoteBind: Boolean): Decision {
        val clean = requested.trim().removePrefix("[").removeSuffix("]")
        return when (classify(clean)) {
            Kind.LOOPBACK -> Decision(clean, exposed = false, downgraded = false, message = null)

            Kind.INVALID -> Decision(
                LOOPBACK, exposed = false, downgraded = true,
                message = "invalid bind host '$requested' — falling back to $LOOPBACK"
            )

            Kind.WILDCARD, Kind.OTHER ->
                if (allowRemoteBind) Decision(
                    clean, exposed = true, downgraded = false,
                    message = "binding to non-loopback interface '$clean' — remote security controls apply"
                ) else Decision(
                    LOOPBACK, exposed = false, downgraded = true,
                    message = "non-loopback bind '$clean' requires an operator opt-in " +
                        "(set Burp pref mcp_allow_remote_bind=true or -Draijin.allowRemoteBind=true) — " +
                        "falling back to $LOOPBACK"
                )
        }
    }

    /**
     * The address to PROBE for liveness. A server bound to a wildcard (`0.0.0.0`/`::`) is not
     * directly connectable at that address, so probe loopback instead — otherwise the bind
     * verification false-negatives and logs a false "NOT listening" error. Concrete addresses
     * are probed as-is (unbracketed for [java.net.InetSocketAddress]).
     */
    fun probeHost(bindHost: String): String {
        val clean = bindHost.trim().removePrefix("[").removeSuffix("]")
        return if (classify(clean) == Kind.WILDCARD) LOOPBACK else clean
    }
}
