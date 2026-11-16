package io.bitbytelab.raijin.transport

/**
 * Resolution and conflict diagnostics for the three listening ports.
 *
 * The ports used to be hardcoded, which made one failure mode unfixable and misdiagnosed:
 * **PortSwigger's own "MCP Server" extension also defaults to 9876**, so anyone running both
 * extensions has an unavoidable clash — and the only message they got blamed "a JAR built with
 * Java 22+", sending them down entirely the wrong path (the likely story behind GitHub issue #9).
 *
 * Ports are therefore operator-configurable on the same ladder as the bind host — JVM system
 * property (ops override), else a persisted Burp preference, else the default — and a bind onto an
 * occupied port now says what is actually wrong and how to fix it.
 */
object PortPolicy {

    const val DEFAULT_SSE = 9876
    const val DEFAULT_HTTP = 9877
    const val DEFAULT_DASHBOARD = 9878

    /** The port PortSwigger's official MCP Server extension listens on by default. */
    const val PORTSWIGGER_MCP_DEFAULT_PORT = 9876

    const val PREF_SSE_PORT = "mcp_sse_port"
    const val PREF_HTTP_PORT = "mcp_http_port"
    const val PREF_DASHBOARD_PORT = "mcp_dashboard_port"

    /**
     * Resolves a port from [systemProperty] (highest precedence), else [preference], else [default].
     *
     * Anything unparseable or outside 1..65535 is ignored in favour of the next source, so a typo
     * in a preference degrades to the default instead of failing the extension to start.
     */
    fun resolve(systemProperty: String?, preference: String?, default: Int): Int =
        parse(systemProperty) ?: parse(preference) ?: default

    private fun parse(raw: String?): Int? {
        val n = raw?.trim()?.toIntOrNull() ?: return null
        return if (n in 1..65535) n else null
    }

    /**
     * Detects duplicate listening port assignments across Primary SSE, Secondary SSE, and
     * Dashboard listeners so configuration clashes are surfaced explicitly rather than failing
     * silently on bind.
     */
    fun duplicatePortMessages(ssePort: Int, httpPort: Int, dashboardPort: Int): List<String> {
        val assignments = listOf(
            PREF_SSE_PORT to ssePort,
            PREF_HTTP_PORT to httpPort,
            PREF_DASHBOARD_PORT to dashboardPort
        )
        return assignments.groupBy { it.second }
            .filterValues { it.size > 1 }
            .map { (port, owners) ->
                "Raijin: conflicting port configuration — port $port is assigned to multiple listeners " +
                    "(${owners.joinToString(", ") { it.first }}). Assign distinct ports to each preference."
            }
    }

    /**
     * The three ports a session actually uses, plus one message per listener that had to move.
     *
     * @property messages operator-facing explanations; empty when the configuration had no clash.
     */
    data class Assignment(val ssePort: Int, val httpPort: Int, val dashboardPort: Int, val messages: List<String>)

    /**
     * Makes the three ports distinct so no listener is doomed to a bind failure against another
     * Raijin listener. Ports are claimed in the order primary, secondary, dashboard; a listener whose
     * port is already claimed moves to its own default when that is free, otherwise to the next free
     * port above its configured one. Every move is reported, naming the preference to fix.
     */
    fun resolveDistinct(ssePort: Int, httpPort: Int, dashboardPort: Int): Assignment {
        val claimed = mutableSetOf<Int>()
        val messages = mutableListOf<String>()
        fun claim(label: String, prefKey: String, configured: Int, default: Int): Int {
            if (claimed.add(configured)) return configured
            val moved = if (default !in claimed) default else nextFree(configured, claimed)
            claimed += moved
            messages += "Raijin: port $configured is configured for more than one listener; the $label " +
                "listener uses $moved for this session. Set distinct ports ('$prefKey') to silence this."
            return moved
        }
        val sse = claim("primary MCP", PREF_SSE_PORT, ssePort, DEFAULT_SSE)
        val http = claim("secondary MCP", PREF_HTTP_PORT, httpPort, DEFAULT_HTTP)
        val dashboard = claim("dashboard", PREF_DASHBOARD_PORT, dashboardPort, DEFAULT_DASHBOARD)
        return Assignment(sse, http, dashboard, messages)
    }

    private fun nextFree(from: Int, claimed: Set<Int>): Int {
        var p = from
        do {
            p = if (p >= 65535) 1024 else p + 1
        } while (p in claimed)
        return p
    }

    /**
     * The message logged when [port] is already taken, naming the causes an operator can actually
     * act on. [prefKey] is the preference that changes this particular port.
     */
    fun conflictMessage(label: String, host: String, port: Int, prefKey: String): String {
        val causes = mutableListOf<String>()
        if (port == PORTSWIGGER_MCP_DEFAULT_PORT) {
            causes += "PortSwigger's own \"MCP Server\" extension listens on $PORTSWIGGER_MCP_DEFAULT_PORT by default — " +
                "if it is installed, disable one of the two extensions or move this one to a free port"
        }
        causes += "a previous Raijin instance may still hold the socket — fully restart Burp (an extension reload is not always enough)"
        causes += "another application may own the port — check with: ss -ltnp | grep $port"

        return buildString {
            append("Raijin: $label cannot start — $host:$port is ALREADY IN USE. ")
            append("This is NOT the Java-version problem; the port is simply taken. Likely causes: ")
            causes.forEachIndexed { i, c -> append("(${i + 1}) $c. ") }
            append("Change the port with the '$prefKey' preference and reload the extension.")
        }
    }
}
