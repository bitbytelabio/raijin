package io.bitbytelab.raijin.injection

/** Out-of-band interaction source for blind checks: Burp Collaborator in production. */
interface OobChannel {

    /** A host only one probe carries; [id] is how its interactions are reported. */
    data class Payload(val id: String, val host: String)

    /** One request the out-of-band server received; [type] is `dns`, `http` or `smtp`. */
    data class Interaction(
        val payloadId: String,
        val type: String,
        val clientIp: String = "",
        val timestamp: String = "",
        val detail: String = "",
    )

    /** A fresh payload for the probe described by [purpose], or null when none can be issued. */
    fun issue(purpose: String): Payload?

    /** Interactions received since the last call for payloads this channel issued. */
    fun collect(): List<Interaction>
}

/**
 * Shares one out-of-band client between probe runs. A poll made for one run can receive hits
 * that belong to another, including a run that has already returned, and a client hands an
 * interaction out once. The hub files every polled interaction under its payload: a run
 * collects its own through its [channel], and what arrives for a finished run is reported by
 * the next one through [late]. A client that returns an interaction again does not repeat it.
 *
 * @param generate issues a payload, or null when the client cannot (Collaborator disabled).
 * @param fetch polls the client for interactions.
 */
class OobHub(
    private val generate: () -> OobChannel.Payload?,
    private val fetch: () -> List<OobChannel.Interaction>,
) {
    /** An interaction that arrived after the run that sent [purpose] to [host] had ended. */
    data class Late(val purpose: String, val host: String, val interaction: OobChannel.Interaction)

    private class Issued(val purpose: String, val host: String, var owner: OobChannel?)

    private val issued = object : LinkedHashMap<String, Issued>() {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Issued>): Boolean = size > MAX_TRACKED
    }
    private val inbox = HashMap<String, MutableList<OobChannel.Interaction>>()
    private val seen = object : LinkedHashMap<OobChannel.Interaction, Unit>() {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<OobChannel.Interaction, Unit>): Boolean = size > MAX_SEEN
    }

    /** A channel for one probe run. Call [release] when the run ends. */
    fun channel(): OobChannel = object : OobChannel {
        override fun issue(purpose: String): OobChannel.Payload? = issueFor(this, purpose)
        override fun collect(): List<OobChannel.Interaction> = collectFor(this)
    }

    /** Ends [channel]'s run: interactions for its payloads count as [late] from now on. */
    @Synchronized
    fun release(channel: OobChannel) {
        for (entry in issued.values) if (entry.owner === channel) entry.owner = null
    }

    /** Polls once and returns what arrived for payloads of finished runs; each interaction is returned once. */
    @Synchronized
    fun late(): List<Late> {
        poll()
        val out = ArrayList<Late>()
        for (id in inbox.keys.filter { issued[it]?.owner == null }) {
            val interactions = inbox.remove(id) ?: continue
            val entry = issued[id] ?: continue
            for (interaction in interactions) out += Late(entry.purpose, entry.host, interaction)
        }
        return out
    }

    @Synchronized
    private fun issueFor(owner: OobChannel, purpose: String): OobChannel.Payload? {
        val payload = try { generate() } catch (_: Exception) { null } ?: return null
        issued[payload.id] = Issued(purpose, payload.host, owner)
        return payload
    }

    @Synchronized
    private fun collectFor(owner: OobChannel): List<OobChannel.Interaction> {
        poll()
        val out = ArrayList<OobChannel.Interaction>()
        for (id in inbox.keys.filter { issued[it]?.owner === owner }) inbox.remove(id)?.let { out += it }
        return out
    }

    private fun poll() {
        val interactions = try { fetch() } catch (_: Exception) { emptyList() }
        for (interaction in interactions) {
            if (interaction.payloadId !in issued || seen.put(interaction, Unit) != null) continue
            inbox.getOrPut(interaction.payloadId) { ArrayList() } += interaction
        }
    }

    private companion object {
        /** Payloads remembered for late interactions; older ones are forgotten. */
        const val MAX_TRACKED = 1000

        /** Interactions remembered to recognise one the client returns twice. */
        const val MAX_SEEN = 4000
    }
}
