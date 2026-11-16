package io.bitbytelab.raijin.turbo

import io.bitbytelab.raijin.turbo.http3.GateConnection
import io.bitbytelab.raijin.turbo.http3.GateMode
import io.bitbytelab.raijin.turbo.http3.QpackGateLimits
import io.bitbytelab.raijin.turbo.http3.SdaBatch
import io.bitbytelab.raijin.turbo.http3.SdaOptions
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * The connection each gate of an HTTP/3 run holds for its batch: where it comes from, how the gate
 * will release on it, and how it is settled once the batch is over - handed back to the pool or
 * closed, exactly once, even when cancellation's bounded drain gives up on the batch first.
 */
internal class Http3GateConnections(
    private val pool: Http3ConnectionPool,
    private val runState: AtomicInteger,
    /** The dispatcher's drain count. A gate's connection counts as one job until it is settled. */
    private val activeJobs: AtomicInteger,
    private val requestsPerConnection: Int,
    private val gateMode: GateMode,
    private val options: SdaOptions,
) {
    /**
     * Membership is the exactly-once resource token for an active gate connection. The finisher
     * normally removes it after probing connectivity; cancellation removes anything whose probe
     * outlives the bounded drain and closes/releases it instead.
     */
    private val unsettledGateConnections = ConcurrentHashMap.newKeySet<GateConnection>()
    private val gateSettlementLock = Object()

    /**
     * Opens a gate's batch on an exclusive connection, deliberately outside any lock on the engine's
     * batches map. The open blocks on a connection slot that finishing a batch releases, and
     * finishing a batch has to reach the same map to do it — holding the map across the open
     * deadlocks the two against each other. Only the dispatcher thread creates batches, so a
     * get-then-put needs no atomicity beyond that.
     */
    fun openBatch(gateName: String): SdaBatch {
        var connection: GateConnection? = null
        var lease: Http3ConnectionPool.GateLease? = null
        var jobStarted = false
        return try {
            lease = pool.acquireGateConnection()
            activeJobs.incrementAndGet()
            jobStarted = true
            val gate = resolveGate(lease.session, gateName)
            connection = GateConnection(
                gateName,
                lease.session,
                lease.id,
                gate.mode,
                gate.qpackLimits,
                lease.requestsCarried,
                gate.releaseBudgetBytes,
            )
            check(unsettledGateConnections.add(connection)) {
                "Gate $gateName registered the same connection twice"
            }
            SdaBatch(gateName, connection)
        } catch (exception: Throwable) {
            if (connection == null && lease != null) {
                try {
                    pool.returnGateLeaseAfterSetupFailure(lease)
                } finally {
                    if (jobStarted) activeJobs.decrementAndGet()
                }
            }
            // Carrying the connection if it claimed one, so finishing the batch hands it back
            // rather than leaking the slot a half-opened gate was holding.
            SdaBatch(gateName, connection).also { it.fail(exception) }
        }
    }

    /**
     * How a gate will release, together with everything that decision was made from. A QPACK gate
     * has to carry the peer's exact limits away with it, because they bound what it may stage.
     */
    private data class ResolvedGate(
        val mode: GateMode,
        val qpackLimits: QpackGateLimits? = null,
        /**
         * What one release datagram carries on this gate's connection. Only a datagram gate is
         * bounded by it, so a QPACK gate leaves it unbounded.
         */
        val releaseBudgetBytes: Int = Int.MAX_VALUE,
    )

    /**
     * Settles how this gate will release, before a single request is staged.
     *
     * <p>It cannot be settled any later: the two modes put different bytes on the wire, so by the
     * time the batch is staged it is already committed to one of them.
     *
     * <p>A peer's SETTINGS arrive on a control stream it opens after the handshake, so a gate that
     * has just opened a connection may reach here before they land. Waiting is nearly always free
     * because a gate normally inherits a warm pooled connection whose SETTINGS arrived long ago.
     */
    private fun resolveGate(session: H3Session, gateName: String): ResolvedGate {
        if (gateMode == GateMode.SDA) {
            return ResolvedGate(GateMode.SDA, releaseBudgetBytes = releaseBudget(session))
        }
        if (gateMode == GateMode.QPACK) {
            val limits = session.awaitQpackGateLimits(SETTINGS_WAIT_MILLIS)
                ?: throw IllegalStateException(
                    "Gate $gateName asked for the QPACK blocked-stream gate, but this server did " +
                        "not advertise both QPACK_MAX_TABLE_CAPACITY and QPACK_BLOCKED_STREAMS, " +
                        "so a blocked field section would be a connection error rather than " +
                        "something it waits on. Use gateMode='auto' to fall back to the " +
                        "single-datagram gate.",
                )
            return ResolvedGate(GateMode.QPACK, limits)
        }
        // Auto prefers the QPACK gate wherever the peer allows it, because it is the only one
        // that cannot quietly fail to gate.
        //
        // The datagram gate holds only if the server actually reads the bytes it withheld. A
        // server that answers without reading the body — a redirect, a static handler, a 405 —
        // leaves the whole batch answered before the release, and the run reports a race as absent
        // when it was never tested. Measured across 100 hosts with a body: the datagram gate held
        // 243 of 294 runs and failed on every run against 16 of them, while the QPACK gate held
        // 291 of 291. The QPACK gate withholds the header decode, which no HTTP/3 server can skip.
        //
        // Nothing is traded for that. Across the 80 hosts where both gates held every run the two
        // were indistinguishable on how tightly responses clustered: 44 of 80 hosts and 127 of 240
        // paired rounds to the datagram gate, p around 0.4 either way. An earlier reading of eight
        // hosts had the datagram gate ahead and this preference reversed; it did not replicate.
        //
        // The QPACK gate's ceiling is also the peer's own SETTINGS_QPACK_BLOCKED_STREAMS rather
        // than a datagram, which is a number the peer states rather than one the engine has to
        // guess — and guessing is not available here anyway, since the dispatcher stages the first
        // gated request while the script is still queueing the rest.
        val limits = session.awaitQpackGateLimits(SETTINGS_WAIT_MILLIS)
        return if (limits != null) {
            ResolvedGate(GateMode.QPACK, limits)
        } else {
            ResolvedGate(GateMode.SDA, releaseBudgetBytes = releaseBudget(session))
        }
    }

    /**
     * What one release datagram carries on this connection, or unbounded where the session cannot
     * say. Read once per gate, because it depends on the path the connection settled on.
     */
    private fun releaseBudget(session: H3Session): Int =
        session.releaseDatagramBudget(options.maxDatagramSize)

    /**
     * Hands a gate's connection back, or closes it.
     *
     * Every question here is asked of that one connection: what it has carried, whether it is
     * still up, and whether its release got out.
     */
    fun finishConnection(batch: SdaBatch, connection: GateConnection) {
        val session = connection.session
        try {
            if (session == null) return
            // Hand the connection back rather than closing it, so a later gate inherits its warm
            // congestion window instead of paying for another handshake. Only a batch that
            // released cleanly, had every response answered and could finish every stream it
            // staged can be handed back: any other outcome leaves request streams dangling on the
            // connection, along with reader threads still waiting.
            val connectionId = connection.connectionId
            // A gate's requests count against its connection like any other. Without this the same
            // connection served every gate in a run however long it ran, and
            // requestsPerConnection never reached a gate.
            val carried = connection.requestsCarried + connection.staged().size
            val connected = runState.get() < 3 &&
                connectionId != null &&
                batch.releasedCleanly() &&
                carried < requestsPerConnection &&
                runCatching { session.isConnected() }.getOrDefault(false) &&
                // Last, because it writes: only a connection about to be handed back needs it.
                connection.staged().all { staged -> staged.exchange.finishStream() }
            synchronized(gateSettlementLock) {
                // Cancellation may have taken this token after its bounded drain while the probe
                // above was blocked. That path already closed the session and returned its slot.
                if (!unsettledGateConnections.remove(connection)) return
                // Publication and the dispatcher's final pool snapshot share the pool's lock, and
                // whether the pool is still open is deliberately asked after the probe: either the
                // returned session is swept, or this path closes it itself, exactly once.
                val reusable = connected && pool.returnGateConnection(session, connectionId!!, carried)
                if (reusable) {
                    pool.retireExcessOrdinaryConnections()
                    pool.wakeAllPoolWaiters()
                    return
                }
                pool.retireGateSession(session)
                pool.wakeAllPoolWaiters()
            }
        } finally {
            // Cancellation's drain must keep waiting until the session and slot have reached one
            // of the two settled states above. Decrementing before isConnected created a window
            // where completedLatch fired and this method then republished a live connection.
            activeJobs.decrementAndGet()
        }
    }

    /** Takes over gate resources whose finisher did not settle before the bounded drain expired. */
    fun forceCloseUnsettledGateConnections() {
        synchronized(gateSettlementLock) {
            unsettledGateConnections.toList().forEach { connection ->
                if (!unsettledGateConnections.remove(connection)) return@forEach
                pool.retireGateSession(connection.session)
            }
        }
        pool.wakeAllPoolWaiters()
    }

    private companion object {
        /**
         * How long a gate waits for the peer's SETTINGS before settling how it will release.
         * Only reached by a gate that opened its own connection; an inherited one has them already.
         */
        const val SETTINGS_WAIT_MILLIS = 1000L
    }
}
