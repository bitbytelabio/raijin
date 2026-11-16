package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.collaborator.CollaboratorClient
import burp.api.montoya.collaborator.CollaboratorPayload
import burp.api.montoya.collaborator.DnsDetails
import burp.api.montoya.collaborator.HttpDetails
import burp.api.montoya.collaborator.Interaction
import burp.api.montoya.collaborator.InteractionType
import burp.api.montoya.collaborator.PayloadOption
import burp.api.montoya.collaborator.SecretKey
import burp.api.montoya.collaborator.SmtpDetails
import io.bitbytelab.raijin.core.BodyText
import io.bitbytelab.raijin.core.EnumValidation
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.state.CollaboratorClientState
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.turbo.mcp.BurpCollaboratorProvider
import io.bitbytelab.raijin.turbo.mcp.CollaboratorBackend
import io.bitbytelab.raijin.turbo.mcp.CollaboratorDnsDetails
import io.bitbytelab.raijin.turbo.mcp.CollaboratorHttpDetails
import io.bitbytelab.raijin.turbo.mcp.CollaboratorPayloadInfo
import io.bitbytelab.raijin.turbo.mcp.CollaboratorRecord
import io.bitbytelab.raijin.turbo.mcp.CollaboratorSmtpDetails
import kotlinx.serialization.json.*
import java.time.Instant
import java.time.format.DateTimeFormatter
import java.util.HexFormat
import java.util.concurrent.ConcurrentHashMap

/**
 * Bridge wrapping the Montoya Collaborator API (Pro only).
 *
 * Provides methods to create and restore Collaborator clients, generate
 * payloads, and poll for out-of-band interactions (DNS, HTTP, SMTP).
 *
 * [StateManager.collaboratorClients] is the registry of live clients. Each client's secret key is
 * also saved in the Burp project, so the same client ids are back after an extension reload.
 *
 * Polling a client drains the Collaborator server: an interaction is handed out once. Every
 * fetched interaction therefore goes into the history of the shared [provider] (the one Turbo
 * uses too) and results are answered from that history, so a type or payload filter narrows what
 * is returned without discarding the rest.
 *
 * All methods guard against [UnsupportedOperationException] thrown when
 * running on Burp Suite Community Edition.
 */
class CollaboratorBridge(
    private val api: MontoyaApi,
    private val eventBus: EventBus,
    private val stateManager: StateManager,
    private val provider: BurpCollaboratorProvider = BurpCollaboratorProvider(),
) {

    /** Guards the client set: the [stateManager] registry together with the bookkeeping below. */
    private val clientsLock = Any()

    /** Clients saved in the Burp project, by id: the registered ones and any not restored yet. */
    private val saved = LinkedHashMap<String, SavedClient>()

    /** Saved clients Burp refused to restore, with the reason. They are retried when asked for. */
    private val restoreErrors = HashMap<String, String>()

    /** Clients brought back from a secret key, by project persistence or [restoreClient]. */
    private val restoredIds = HashSet<String>()

    /** Why the last write of [saved] to the project failed, if it did. */
    private var persistError: String? = null

    /** The client Turbo payloads are generated on. */
    @Volatile
    private var turboClientId: String? = null

    /** One lock per client, so two polls of it cannot interleave their batches. */
    private val pollLocks = ConcurrentHashMap<String, Any>()

    /** The Burp side of the shared provider: Turbo generates payloads and polls through here. */
    private val backend = object : CollaboratorBackend {
        override fun generatePayload(metadata: String): String {
            val state = turboClient()
            val payload = (state.client as CollaboratorClient).generatePayload()
            return remember(state.clientId, payload, metadata).payload
        }

        override fun sync(clientIds: Set<String>?) {
            val targets = stateManager.collaboratorClients.values.filter { clientIds == null || it.clientId in clientIds }
            var failed: Exception? = null
            var polled = 0
            for (state in targets) {
                try {
                    syncClient(state)
                    polled++
                } catch (e: Exception) {
                    failed = e
                }
            }
            if (failed != null && polled == 0) {
                throw IllegalStateException("Failed to poll Burp Collaborator: ${failed.message}", failed)
            }
        }
    }

    init {
        provider.attach(backend)
        synchronized(clientsLock) {
            loadSaved()
            restoreSaved()
            if (saved.isNotEmpty()) {
                runCatching {
                    api.logging().logToOutput(
                        "Raijin: restored ${saved.size - restoreErrors.size} of ${saved.size} Collaborator client(s) saved in this project"
                    )
                }
            }
        }
    }

    /**
     * Creates a new Collaborator client, stores it in the state manager and saves its secret key
     * in the Burp project.
     *
     * @return JSON object with client ID, server address, and creation timestamp.
     */
    fun createClient(): JsonObject {
        return try {
            synchronized(clientsLock) {
                clientJson(register(api.collaborator().createClient(), label = null, restored = false))
            }
        } catch (e: UnsupportedOperationException) {
            failure("Collaborator API is not available in Burp Suite Community Edition")
        } catch (e: Exception) {
            failure("Failed to create Collaborator client: ${e.message}")
        }
    }

    /**
     * Restores a previously created Collaborator client using its secret key.
     *
     * A key that already belongs to a registered client returns that client: a second client on
     * the same key would compete with the first for the interactions the server hands out once.
     *
     * @param secretKey Base64-encoded secret key from a previous client session.
     * @return JSON object with client ID, server address, and creation timestamp.
     */
    fun restoreClient(secretKey: String): JsonObject {
        val key = secretKey.trim()
        if (key.isEmpty()) return failure("Parameter 'secret_key' must not be blank")
        return try {
            synchronized(clientsLock) {
                val known = saved.values.firstOrNull { it.secretKey == key }
                if (known == null) {
                    val client = api.collaborator().restoreClient(SecretKey.secretKey(key))
                    clientJson(register(client, label = null, restored = true), restored = true)
                } else {
                    if (!stateManager.collaboratorClients.containsKey(known.clientId)) restoreSaved()
                    val state = stateManager.collaboratorClients[known.clientId]
                    if (state == null) {
                        failure("Failed to restore Collaborator client: ${restoreErrors[known.clientId] ?: "unknown error"}")
                    } else {
                        JsonObject(clientJson(state, restored = true) + ("already_registered" to JsonPrimitive(true)))
                    }
                }
            }
        } catch (e: UnsupportedOperationException) {
            failure("Collaborator API is not available in Burp Suite Community Edition")
        } catch (e: Exception) {
            failure("Failed to restore Collaborator client: ${e.message}")
        }
    }

    /**
     * Lists the registered clients with what Raijin recorded for each, plus any client saved in the
     * project that Burp could not restore. Does not contact the Collaborator server.
     */
    fun listClients(): JsonObject = synchronized(clientsLock) {
        if (restoreErrors.isNotEmpty()) restoreSaved()
        val clients = stateManager.collaboratorClients.values
            .sortedWith(compareBy<CollaboratorClientState>({ it.createdAt }, { it.clientId }))
        buildJsonObject {
            put("client_count", clients.size)
            putJsonArray("clients") {
                clients.forEach { state ->
                    val recorded = provider.history.summary(state.clientId)
                    addJsonObject {
                        put("client_id", state.clientId)
                        put("server", state.server)
                        put("created_at", state.createdAt)
                        put("restored", state.clientId in restoredIds)
                        put("persisted", isPersisted(state.clientId))
                        saved[state.clientId]?.label?.let { put("label", it) }
                        put("payloads_generated", provider.payloads.generatedBy(state.clientId))
                        put("interactions_recorded", recorded.retained)
                        recorded.lastTimestamp?.let { put("last_interaction_at", it) }
                        if (recorded.evicted > 0) put("interactions_dropped", recorded.evicted)
                    }
                }
            }
            if (restoreErrors.isNotEmpty()) {
                putJsonArray("unrestored") {
                    restoreErrors.forEach { (clientId, reason) ->
                        addJsonObject {
                            put("client_id", clientId)
                            saved[clientId]?.let {
                                put("server", it.server)
                                put("created_at", it.createdAt)
                            }
                            put("error", reason)
                        }
                    }
                }
            }
            persistError?.let { put("persistence_error", it) }
        }
    }

    /**
     * Generates a new Collaborator payload for the given client.
     *
     * @param clientId The Collaborator client identifier.
     * @param customData Optional custom data to embed in the payload.
     * @return JSON object with the generated payload string, its `payload_id` (the interaction id
     *   every interaction of this payload carries) and full interaction URL.
     */
    fun generatePayload(clientId: String, customData: String?): JsonObject {
        val clientState = findClient(clientId) ?: return missingClient(clientId)

        // Montoya's CollaboratorClient.generatePayload(customData) rejects any label
        // longer than 16 chars or containing non-alphanumerics with a raw
        // IllegalArgumentException ("Length of custom data must not exceed 16
        // alphanumeric characters"). Fit the label to that constraint up front so an
        // over-long/decorated label degrades gracefully instead of failing the call.
        val sanitized = customData?.let { sanitizeCustomData(it) }
        if (sanitized != null && sanitized.effective.isEmpty()) {
            return failure("custom_data must contain at least one alphanumeric character; Burp Collaborator allows up to $MAX_CUSTOM_DATA alphanumeric characters.")
        }
        val effectiveCustom = sanitized?.effective

        return try {
            val client = clientState.client as CollaboratorClient
            val payload: CollaboratorPayload = if (effectiveCustom != null) {
                client.generatePayload(effectiveCustom)
            } else {
                client.generatePayload()
            }

            // CollaboratorPayload.toString() already returns the full address
            // (subdomain + server), so it must NOT be concatenated with the
            // server address again.
            val info = remember(clientId, payload, metadata = null)

            buildJsonObject {
                put("client_id", clientId)
                put("payload", info.payload)
                put("payload_id", info.payloadId)
                put("interaction_url", "http://${info.payload}")
                if (effectiveCustom != null) {
                    put("custom_data", effectiveCustom)
                }
                if (sanitized?.adjusted == true) {
                    put("warning", sanitized.note)
                }
            }
        } catch (e: Exception) {
            failure("Failed to generate payload: ${e.message}")
        }
    }

    /**
     * Generates a payload using Burp's DEFAULT Collaborator payload generator.
     *
     * Unlike [generatePayload], these payloads are linked to Burp's native
     * Collaborator tab — any interactions appear in the Collaborator results
     * tab that was open when the payload was generated. The trade-off: the
     * default generator is generate-only, so these interactions CANNOT be
     * polled through the API ([pollInteractions] will not see them); they must
     * be read in the native Collaborator tab.
     *
     * @param withoutServerLocation when true, omit the server location from the payload.
     * @return JSON with the payload string, interaction URL/id, and (when present) server + custom data.
     */
    fun generateDefaultPayload(withoutServerLocation: Boolean): JsonObject {
        return try {
            val generator = api.collaborator().defaultPayloadGenerator()
            val payload = if (withoutServerLocation) {
                generator.generatePayload(PayloadOption.WITHOUT_SERVER_LOCATION)
            } else {
                generator.generatePayload()
            }

            val payloadStr = payload.toString()
            buildJsonObject {
                put("payload", payloadStr)
                put("interaction_url", "http://$payloadStr")
                put("interaction_id", payload.id().toString())
                payload.server().ifPresent { put("server", it.address()) }
                payload.customData().ifPresent { put("custom_data", it) }
                put(
                    "note",
                    "Linked to Burp's native Collaborator tab; interactions appear there and are NOT pollable via collaborator_poll."
                )
            }
        } catch (e: UnsupportedOperationException) {
            failure("Collaborator API is not available in Burp Suite Community Edition")
        } catch (e: IllegalStateException) {
            failure("Burp Collaborator is disabled: ${e.message}")
        } catch (e: Exception) {
            failure("Failed to generate default payload: ${e.message}")
        }
    }

    /**
     * Fetches the client's new interactions into the shared history, then returns the recorded
     * interactions that match. Nothing is removed by reading: the same call returns the same
     * interactions again, and [since] is what limits a later poll to newer ones.
     *
     * @param clientId The Collaborator client identifier.
     * @param type Optional interaction type filter: "dns", "http", "smtp".
     * @param payloadId Optional payload to filter by: its `payload_id`, or the payload host.
     * @param since Only interactions after this cursor (`next_since` of an earlier result).
     * @param limit Page size, 1..[MAX_POLL_LIMIT]; defaults to [DEFAULT_POLL_LIMIT].
     * @param maxBodyLength Cap on each rendered HTTP body and SMTP conversation; defaults to
     *   [BodyText.DEFAULT_MAX_LENGTH].
     * @return JSON object with a list of interactions.
     */
    fun pollInteractions(
        clientId: String,
        type: String?,
        payloadId: String?,
        since: Long? = null,
        limit: Int? = null,
        maxBodyLength: Int? = null,
    ): JsonObject {
        val wantedType = type?.trim()?.ifEmpty { null }
        EnumValidation.error(wantedType, INTERACTION_TYPES, "type")?.let { return it }
        if (since != null && since < 0) return failure("Parameter 'since' must be 0 or greater (got $since)")
        if (limit != null && limit !in 1..MAX_POLL_LIMIT) {
            return failure("Parameter 'limit' must be between 1 and $MAX_POLL_LIMIT (got $limit)")
        }
        if (maxBodyLength != null && maxBodyLength !in 1..MAX_BODY_LENGTH) {
            return failure("Parameter 'max_body_length' must be between 1 and $MAX_BODY_LENGTH (got $maxBodyLength)")
        }
        val clientState = findClient(clientId) ?: return missingClient(clientId)

        try {
            syncClient(clientState)
        } catch (e: Exception) {
            return failure("Failed to poll interactions: ${e.message}")
        }

        val page = provider.query(
            clientId = clientId,
            type = wantedType,
            payloads = payloadId?.trim()?.ifEmpty { null }?.let { listOf(it) },
            since = since ?: 0L,
            limit = limit ?: DEFAULT_POLL_LIMIT,
        )
        return buildJsonObject {
            put("client_id", clientId)
            put("interaction_count", page.records.size)
            put("next_since", page.nextSince)
            put("has_more", page.hasMore)
            if (page.filteredOut > 0) put("filtered_out", page.filteredOut)
            if (page.truncated) put("history_truncated", true)
            putJsonArray("interactions") {
                page.records.forEach { add(serializeInteraction(it, provider.payloads[it.payloadId], maxBodyLength)) }
            }
        }
    }

    /**
     * Returns the Collaborator server address for the given client.
     *
     * @param clientId The Collaborator client identifier.
     * @return JSON object with the server address.
     */
    fun getServerInfo(clientId: String): JsonObject {
        val clientState = findClient(clientId) ?: return missingClient(clientId)

        return try {
            val client = clientState.client as CollaboratorClient
            val serverAddress = client.server().address()

            buildJsonObject {
                put("client_id", clientId)
                put("server_address", serverAddress)
                put("created_at", clientState.createdAt)
            }
        } catch (e: Exception) {
            failure("Failed to get server info: ${e.message}")
        }
    }

    /**
     * Drops a Collaborator client from Raijin's own tracking: the registry, the project
     * persistence (so it does not come back on the next load) and its recorded interactions.
     * Montoya's Collaborator API has no server-side teardown for a client — it's just a
     * [SecretKey] handle, not a resource Burp needs told to close — so this is purely local
     * bookkeeping. The secret key is returned one last time (not just `client_id`) since that,
     * not the local id, is what `collaborator_restore_client` actually needs to bring the same
     * client back later.
     *
     * @param clientId The Collaborator client identifier.
     * @return JSON object confirming removal, with the secret key for later restoration.
     */
    fun removeClient(clientId: String): JsonObject {
        val (state, entry) = synchronized(clientsLock) {
            val removedState = stateManager.collaboratorClients.remove(clientId)
            val removedEntry = saved.remove(clientId)
            if (removedState == null && removedEntry == null) return failure("Client not found: $clientId")
            restoreErrors.remove(clientId)
            restoredIds.remove(clientId)
            if (turboClientId == clientId) turboClientId = null
            if (removedEntry != null) writeSaved()
            removedState to removedEntry
        }
        // Behind the client's poll lock, so a poll that was already running cannot re-add records.
        synchronized(pollLocks.computeIfAbsent(clientId) { Any() }) {
            provider.history.removeClient(clientId)
            provider.payloads.removeClient(clientId)
        }
        pollLocks.remove(clientId)

        val secretKey = entry?.secretKey ?: state?.let {
            runCatching { (it.client as CollaboratorClient).getSecretKey().toString() }.getOrNull()
        }

        return buildJsonObject {
            put("client_id", clientId)
            put("removed", true)
            if (secretKey != null) {
                put("secret_key", secretKey)
                put("note", "Removed from Raijin's tracking. Use collaborator_restore_client with this secret_key to bring it back later.")
            } else {
                put("note", "Removed from Raijin's tracking. The secret key could not be read, so this client cannot be restored later.")
            }
        }
    }

    /**
     * Returns the secret key for the given Collaborator client, base64-encoded.
     * This key can be used to restore the client in a future session.
     *
     * @param clientId The Collaborator client identifier.
     * @return JSON object with the secret key.
     */
    fun getSecret(clientId: String): JsonObject {
        val clientState = findClient(clientId) ?: return missingClient(clientId)

        return try {
            val client = clientState.client as CollaboratorClient
            val secretKey = client.getSecretKey().toString()

            buildJsonObject {
                put("client_id", clientId)
                put("secret_key", secretKey)
            }
        } catch (e: Exception) {
            failure("Failed to get secret key: ${e.message}")
        }
    }

    // ---------------------------------------------------------------
    // Client registry and project persistence
    // ---------------------------------------------------------------

    private fun failure(message: String): JsonObject = buildJsonObject { put("error", message) }

    /** The registered client, after one more restore attempt when it is a saved client Burp refused earlier. */
    private fun findClient(clientId: String): CollaboratorClientState? =
        stateManager.collaboratorClients[clientId] ?: synchronized(clientsLock) {
            if (clientId in restoreErrors) restoreSaved()
            stateManager.collaboratorClients[clientId]
        }

    private fun missingClient(clientId: String): JsonObject {
        val reason = synchronized(clientsLock) { restoreErrors[clientId] }
        return failure(
            if (reason == null) {
                "Client not found: $clientId"
            } else {
                "Client $clientId is saved in this project but Burp could not restore it: $reason. " +
                    "collaborator_remove_client drops it and returns its secret key."
            }
        )
    }

    /** JSON for a client that was just created or restored. Caller holds [clientsLock]. */
    private fun clientJson(state: CollaboratorClientState, restored: Boolean = false): JsonObject = buildJsonObject {
        put("client_id", state.clientId)
        put("server", state.server)
        if (restored) put("restored", true)
        put("created_at", state.createdAt)
        put("persisted", isPersisted(state.clientId))
    }

    private fun isPersisted(clientId: String): Boolean = persistError == null && clientId in saved

    /** Registers [client] under a new id and saves its secret key in the project. Caller holds [clientsLock]. */
    private fun register(client: CollaboratorClient, label: String?, restored: Boolean): CollaboratorClientState {
        val state = CollaboratorClientState(
            clientId = newClientId(),
            client = client,
            server = client.server().address(),
            createdAt = Instant.now().toString()
        )
        stateManager.collaboratorClients[state.clientId] = state
        if (restored) restoredIds += state.clientId
        runCatching { client.getSecretKey().toString() }.getOrNull()?.let { secretKey ->
            saved[state.clientId] = SavedClient(state.clientId, secretKey, state.server, state.createdAt, label)
            writeSaved()
        }
        return state
    }

    /**
     * A client id no registered or saved client uses. The id counter starts over on every load
     * while saved clients keep the ids they had, so a fresh id can collide with a restored one.
     */
    private fun newClientId(): String {
        while (true) {
            val id = stateManager.generateId("collab")
            if (!stateManager.collaboratorClients.containsKey(id) && id !in saved) return id
        }
    }

    private fun loadSaved() {
        val stored = try {
            api.persistence().extensionData().getString(PERSIST_KEY)
        } catch (_: Exception) {
            null
        }
        decodeSavedClients(stored).forEach { saved[it.clientId] = it }
    }

    private fun writeSaved() {
        persistError = try {
            api.persistence().extensionData().setString(PERSIST_KEY, encodeSavedClients(saved.values))
            null
        } catch (e: Exception) {
            e.message ?: e.javaClass.simpleName
        }
    }

    /**
     * Restores every saved client that is not registered, under the id it had. A client Burp
     * refuses (Collaborator disabled, Community Edition) stays saved and is noted in
     * [restoreErrors]. Caller holds [clientsLock].
     */
    private fun restoreSaved() {
        for (entry in saved.values) {
            if (stateManager.collaboratorClients.containsKey(entry.clientId)) continue
            try {
                val client = api.collaborator().restoreClient(SecretKey.secretKey(entry.secretKey))
                val server = runCatching { client.server().address() }.getOrNull() ?: entry.server
                stateManager.collaboratorClients[entry.clientId] =
                    CollaboratorClientState(entry.clientId, client, server, entry.createdAt)
                restoredIds += entry.clientId
                restoreErrors.remove(entry.clientId)
                if (entry.label == TURBO_LABEL && turboClientId == null) turboClientId = entry.clientId
            } catch (e: Exception) {
                restoreErrors[entry.clientId] = e.message ?: e.javaClass.simpleName
            }
        }
    }

    /** The client Turbo payloads are generated on, created and saved on first use. */
    private fun turboClient(): CollaboratorClientState = synchronized(clientsLock) {
        if (restoreErrors.isNotEmpty()) restoreSaved()
        turboClientId?.let { stateManager.collaboratorClients[it] } ?: try {
            register(api.collaborator().createClient(), label = TURBO_LABEL, restored = false)
                .also { turboClientId = it.clientId }
        } catch (e: Exception) {
            throw IllegalStateException("Burp Collaborator is not available: ${e.message}", e)
        }
    }

    /** Records a generated payload so its interactions can be traced back to it. */
    private fun remember(clientId: String, payload: CollaboratorPayload, metadata: String?): CollaboratorPayloadInfo {
        val info = CollaboratorPayloadInfo(
            payloadId = payload.id().toString(),
            payload = payload.toString(),
            clientId = clientId,
            customData = runCatching { payload.customData().orElse(null) }.getOrNull(),
            metadata = metadata,
            createdAt = Instant.now().toString()
        )
        provider.payloads.register(info)
        return info
    }

    // ---------------------------------------------------------------
    // Polling
    // ---------------------------------------------------------------

    /**
     * Fetches everything the server holds for the client into the history and announces each new
     * interaction on the event bus. Always all of it: a filtered fetch would throw the rest away.
     */
    private fun syncClient(state: CollaboratorClientState) {
        val client = state.client as CollaboratorClient
        val fresh = synchronized(pollLocks.computeIfAbsent(state.clientId) { Any() }) {
            if (stateManager.collaboratorClients[state.clientId] !== state) return // removed meanwhile
            val fetched = client.getAllInteractions().orEmpty()
            val ordered = runCatching { fetched.sortedBy { it.timeStamp().toInstant() } }.getOrDefault(fetched)
            ordered.map { interaction ->
                val record = provider.history.add(toRecord(state.clientId, interaction))
                // Turbo's Collaborator hits have always been copied to Organizer.
                if (record.type == CollaboratorRecord.HTTP && state.clientId == turboClientId) {
                    sendToOrganizer(interaction, record)
                }
                record
            }
        }
        fresh.forEach { record ->
            eventBus.emit(
                "collaborator.interaction",
                serializeInteraction(record, provider.payloads[record.payloadId], EVENT_TEXT_CHARS, full = false)
            )
        }
    }

    /**
     * Copies a Montoya interaction into a plain record. An interaction is gone from the server once
     * fetched, so an accessor that throws costs only its own field, never the record.
     */
    private fun toRecord(clientId: String, interaction: Interaction): CollaboratorRecord {
        val type = runCatching { interaction.type() }.getOrNull()
        var dns: CollaboratorDnsDetails? = null
        var http: CollaboratorHttpDetails? = null
        var smtp: CollaboratorSmtpDetails? = null
        var detailsError: String? = null
        try {
            when (type) {
                InteractionType.DNS -> dns = interaction.dnsDetails().orElse(null)?.let { dnsDetails(it) }
                InteractionType.HTTP -> http = interaction.httpDetails().orElse(null)?.let { httpDetails(it) }
                InteractionType.SMTP -> smtp = interaction.smtpDetails().orElse(null)?.let { smtpDetails(it) }
                null -> detailsError = "Interaction type could not be read"
            }
            if (type != null && dns == null && http == null && smtp == null) {
                detailsError = "${type.name} details not available"
            }
        } catch (e: Exception) {
            detailsError = "Could not read ${type?.name ?: "interaction"} details: ${e.message ?: e.javaClass.simpleName}"
        }
        return CollaboratorRecord(
            clientId = clientId,
            payloadId = runCatching { interaction.id().toString() }.getOrDefault(""),
            type = type?.name ?: "UNKNOWN",
            timestamp = runCatching { interaction.timeStamp().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME) }
                .getOrElse { Instant.now().toString() },
            clientIp = runCatching { interaction.clientIp().hostAddress }.getOrNull().orEmpty(),
            clientPort = runCatching { interaction.clientPort() }.getOrDefault(0),
            // The ≤16-char marker embedded via generatePayload(customData), echoed back by the hit.
            customData = runCatching { interaction.customData().orElse(null) }.getOrNull(),
            dns = dns,
            http = http,
            smtp = smtp,
            detailsError = detailsError
        )
    }

    private fun dnsDetails(details: DnsDetails): CollaboratorDnsDetails {
        // query() is the raw DNS request packet (ByteArray), not a hostname: decode the QNAME for
        // a readable value and keep the raw bytes as hex for forensics.
        val rawQuery = details.query().bytes
        val decoded = DnsQueryDecoder.decode(rawQuery)
        return CollaboratorDnsDetails(
            queryType = details.queryType().name,
            queryName = decoded.name,
            queryNameError = decoded.error,
            queryHex = HexFormat.of().formatHex(rawQuery)
        )
    }

    private fun httpDetails(details: HttpDetails): CollaboratorHttpDetails {
        val exchange = details.requestResponse()
        val request = exchange.request()
        val response = exchange.response()
        val rawRequest = request?.toString().orEmpty()
        val rawResponse = response?.toString()
        return CollaboratorHttpDetails(
            protocol = details.protocol().name,
            method = runCatching { request?.method() }.getOrNull().orEmpty(),
            url = BodyText.truncate(runCatching { request?.url() }.getOrNull().orEmpty(), MAX_HEADER_CHARS),
            status = runCatching { response?.statusCode()?.toInt() }.getOrNull(),
            request = BodyText.truncate(rawRequest, MAX_BODY_LENGTH),
            response = rawResponse?.let { BodyText.truncate(it, MAX_BODY_LENGTH) },
            responseMimeType = runCatching { response?.mimeType()?.name }.getOrNull(),
            requestLength = rawRequest.length,
            responseLength = rawResponse?.length ?: 0
        )
    }

    private fun smtpDetails(details: SmtpDetails): CollaboratorSmtpDetails {
        val conversation = details.conversation().orEmpty()
        return CollaboratorSmtpDetails(
            protocol = details.protocol().name,
            conversation = BodyText.truncate(conversation, MAX_BODY_LENGTH),
            conversationLength = conversation.length
        )
    }

    private fun sendToOrganizer(interaction: Interaction, record: CollaboratorRecord) {
        try {
            val exchange = interaction.httpDetails().orElse(null)?.requestResponse() ?: return
            val metadata = provider.payloads[record.payloadId]?.metadata
            val notes = buildString {
                append("[Collaborator]")
                if (metadata != null) append(" $metadata")
                append(" | ${record.timestamp} | ${record.clientIp}")
            }
            exchange.annotations().setNotes(notes)
            api.organizer().sendToOrganizer(exchange)
        } catch (_: Exception) {
            // The Organizer copy is a convenience; the interaction itself is already recorded.
        }
    }

    /**
     * One Collaborator client as saved in the Burp project.
     *
     * @property label what the client is kept for ([TURBO_LABEL]), null for one a caller created.
     */
    internal data class SavedClient(
        val clientId: String,
        val secretKey: String,
        val server: String,
        val createdAt: String,
        val label: String? = null,
    )

    /** A raw HTTP message split at its first blank line. */
    internal data class HttpMessage(val startLine: String, val headers: List<Pair<String, String>>, val body: String)

    /**
     * Pure, Montoya-independent helpers, kept `internal` so unit tests can
     * exercise the validation logic without a live Collaborator client (the
     * Montoya API is compileOnly and cannot be instantiated in tests).
     */
    internal companion object {
        /** Burp Collaborator custom-data limit: at most 16 ASCII-alphanumeric characters. */
        const val MAX_CUSTOM_DATA = 16

        /** Project persistence key holding the saved clients (see [encodeSavedClients]). */
        const val PERSIST_KEY = "raijin.collaborator.clients"

        /** [SavedClient.label] of the client Turbo payloads are generated on. */
        const val TURBO_LABEL = "turbo"

        /** Accepted values of the poll `type` filter. */
        val INTERACTION_TYPES = setOf("dns", "http", "smtp")

        const val DEFAULT_POLL_LIMIT = 100
        const val MAX_POLL_LIMIT = 1000

        /**
         * Most characters kept of a request, a response or an SMTP conversation, and so the highest
         * `max_body_length` worth asking for.
         */
        const val MAX_BODY_LENGTH = 1_000_000

        /** Cap on the header names and values emitted for one message, and on its URL and start line. */
        private const val MAX_HEADER_CHARS = 100_000

        /** Cap on the free text of an event, which is a summary and not the poll result. */
        private const val EVENT_TEXT_CHARS = 2_000

        /** Result of fitting a caller-supplied label to the Collaborator constraint. */
        data class CustomData(val effective: String, val adjusted: Boolean, val note: String?)

        /**
         * Fits arbitrary caller input to Montoya's `generatePayload(customData)`
         * constraint (≤16 ASCII-alphanumeric characters). Non-alphanumeric
         * characters are stripped and the result is truncated to 16 chars; the
         * returned [CustomData.note] explains any adjustment so the caller can
         * correlate on the value actually embedded. An all-non-alphanumeric input
         * yields an empty [CustomData.effective], which the caller rejects.
         */
        fun sanitizeCustomData(raw: String): CustomData {
            val alnum = raw.filter { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' }
            val effective = alnum.take(MAX_CUSTOM_DATA)
            val strippedNonAlnum = alnum.length != raw.length
            val truncated = alnum.length > MAX_CUSTOM_DATA
            val note = when {
                strippedNonAlnum && truncated ->
                    "custom_data had non-alphanumeric characters removed and was truncated to $MAX_CUSTOM_DATA chars; embedded '$effective'"
                strippedNonAlnum ->
                    "custom_data had non-alphanumeric characters removed (Collaborator allows alphanumeric only); embedded '$effective'"
                truncated ->
                    "custom_data was truncated to $MAX_CUSTOM_DATA chars (Collaborator limit); embedded '$effective'"
                else -> null
            }
            return CustomData(effective, note != null, note)
        }

        /** The JSON kept under [PERSIST_KEY]. */
        fun encodeSavedClients(clients: Collection<SavedClient>): String = buildJsonArray {
            clients.forEach { client ->
                addJsonObject {
                    put("client_id", client.clientId)
                    put("secret_key", client.secretKey)
                    put("server", client.server)
                    put("created_at", client.createdAt)
                    client.label?.let { put("label", it) }
                }
            }
        }.toString()

        /**
         * Reads what [encodeSavedClients] wrote. Entries without an id or a secret key, and repeats
         * of an id, are skipped; anything that is not such a list reads as no clients.
         */
        fun decodeSavedClients(stored: String?): List<SavedClient> {
            if (stored.isNullOrBlank()) return emptyList()
            val entries = runCatching { Json.parseToJsonElement(stored) as? JsonArray }.getOrNull() ?: return emptyList()
            val seen = HashSet<String>()
            return entries.mapNotNull { entry ->
                val fields = entry as? JsonObject ?: return@mapNotNull null
                fun text(key: String): String? = (fields[key] as? JsonPrimitive)?.takeIf { it.isString }?.content
                val clientId = text("client_id")?.takeIf { it.isNotBlank() } ?: return@mapNotNull null
                val secretKey = text("secret_key")?.takeIf { it.isNotBlank() } ?: return@mapNotNull null
                if (!seen.add(clientId)) return@mapNotNull null
                SavedClient(clientId, secretKey, text("server").orEmpty(), text("created_at").orEmpty(), text("label"))
            }
        }

        /**
         * Splits a raw request or response into start line, header lines and body. Nothing is
         * validated: a header line without a colon is kept as a name with an empty value, so odd
         * lines stay visible.
         */
        fun splitHttpMessage(raw: String): HttpMessage {
            val crlf = raw.indexOf("\r\n\r\n")
            val lf = raw.indexOf("\n\n")
            val (headEnd, bodyStart) = when {
                crlf >= 0 && (lf < 0 || crlf < lf) -> crlf to crlf + 4
                lf >= 0 -> lf to lf + 2
                else -> raw.length to raw.length
            }
            val lines = raw.substring(0, headEnd).split('\n').map { it.removeSuffix("\r") }
            val headers = lines.drop(1).filter { it.isNotEmpty() }.map { line ->
                val colon = line.indexOf(':', 1) // from 1: the colon that opens an HTTP/2 pseudo-header is part of its name
                if (colon < 0) line to "" else line.substring(0, colon) to line.substring(colon + 1).trimStart(' ', '\t')
            }
            return HttpMessage(lines.first(), headers, raw.substring(bodyStart))
        }

        /**
         * Serializes one recorded interaction with type-specific detail fields.
         *
         * `id` is the interaction id Montoya reports, which is the id of the payload: `payload_id`
         * names it for what it is, and `seq` is what tells two interactions of one payload apart.
         *
         * @param payload the payload that caused it, when it was generated through Raijin.
         * @param maxBodyLength cap on each HTTP body and SMTP conversation ([BodyText.render]).
         * @param full include the HTTP headers and bodies; false keeps an event-sized summary.
         */
        fun serializeInteraction(
            record: CollaboratorRecord,
            payload: CollaboratorPayloadInfo?,
            maxBodyLength: Int? = null,
            full: Boolean = true,
        ): JsonObject = buildJsonObject {
            put("seq", record.seq)
            put("type", record.type.lowercase())
            put("id", record.payloadId)
            put("payload_id", record.payloadId)
            payload?.let { put("payload", it.payload) }
            put("client_id", record.clientId)
            put("client_ip", record.clientIp)
            put("client_port", record.clientPort)
            put("timestamp", record.timestamp)
            record.customData?.let { put("custom_data", it) }
            payload?.metadata?.let { put("metadata", it) }
            when (record.type) {
                CollaboratorRecord.DNS -> put("dns_details", dnsJson(record))
                CollaboratorRecord.HTTP -> put("http_details", httpJson(record, maxBodyLength, full))
                CollaboratorRecord.SMTP -> put("smtp_details", smtpJson(record, maxBodyLength))
                else -> put("details_error", record.detailsError ?: "Unknown interaction type")
            }
        }

        private fun dnsJson(record: CollaboratorRecord): JsonObject = buildJsonObject {
            val dns = record.dns
            if (dns == null) {
                put("error", record.detailsError ?: "DNS details not available")
            } else {
                put("query_type", dns.queryType)
                dns.queryName?.let { put("query_name", it) }
                dns.queryNameError?.let { put("query_name_error", it) }
                put("query_hex", dns.queryHex)
            }
        }

        private fun httpJson(record: CollaboratorRecord, maxBodyLength: Int?, full: Boolean): JsonObject = buildJsonObject {
            val http = record.http
            if (http == null) {
                put("error", record.detailsError ?: "HTTP details not available")
            } else {
                val request = splitHttpMessage(http.request)
                val lineCap = if (full) MAX_HEADER_CHARS else EVENT_TEXT_CHARS
                put("protocol", http.protocol)
                put("request_method", fit(http.method, lineCap))
                put("request_url", fit(http.url, lineCap))
                put("response_status", http.status ?: 0)
                put("request_line", fit(request.startLine, lineCap))
                put("request_length", http.requestLength)
                if (http.response != null) put("response_length", http.responseLength)
                if (full) {
                    putHeaders("request_headers", request.headers)
                    putText(
                        "request_body", request.body, maxBodyLength, null, "request body",
                        cutAtCapture = http.requestLength > http.request.length
                    )
                    if (http.response != null) {
                        val response = splitHttpMessage(http.response)
                        putHeaders("response_headers", response.headers)
                        putText(
                            "response_body", response.body, maxBodyLength, http.responseMimeType, "response body",
                            cutAtCapture = http.responseLength > http.response.length
                        )
                    }
                }
            }
        }

        private fun smtpJson(record: CollaboratorRecord, maxBodyLength: Int?): JsonObject = buildJsonObject {
            val smtp = record.smtp
            if (smtp == null) {
                put("error", record.detailsError ?: "SMTP details not available")
            } else {
                put("protocol", smtp.protocol)
                putText(
                    "conversation", smtp.conversation, maxBodyLength, null, "SMTP conversation",
                    cutAtCapture = smtp.conversationLength > smtp.conversation.length
                )
                put("conversation_length", smtp.conversationLength)
            }
        }

        /** [text] through [BodyText.render], with `<key>_binary` / `<key>_truncated` flags where they apply. */
        private fun JsonObjectBuilder.putText(
            key: String,
            text: String,
            maxLength: Int?,
            mimeType: String?,
            label: String,
            cutAtCapture: Boolean,
        ) {
            val rendered = BodyText.render(text, maxLength, mimeType, label)
            put(key, rendered.text)
            if (rendered.binary) put("${key}_binary", true)
            if (rendered.truncated || cutAtCapture) put("${key}_truncated", true)
        }

        /** Header lines as `{name, value}` objects, up to [MAX_HEADER_CHARS] in total. */
        private fun JsonObjectBuilder.putHeaders(key: String, headers: List<Pair<String, String>>) {
            var room = MAX_HEADER_CHARS
            var cut = false
            putJsonArray(key) {
                for ((name, value) in headers) {
                    if (room <= 0) {
                        cut = true
                        break
                    }
                    val shownName = fit(name, room)
                    room -= shownName.length
                    val shownValue = if (room > 0) fit(value, room) else ""
                    room -= shownValue.length
                    if (shownName.length < name.length || shownValue.length < value.length) cut = true
                    addJsonObject {
                        put("name", shownName)
                        put("value", shownValue)
                    }
                }
            }
            if (cut) put("${key}_truncated", true)
        }

        /** [text] safe to encode and at most [room] characters ([room] must be positive). */
        private fun fit(text: String, room: Int): String = BodyText.truncate(BodyText.stripLoneSurrogates(text), room)
    }
}
