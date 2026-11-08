package io.bitbytelab.raijin.turbo.mcp

import io.bitbytelab.raijin.turbo.Utils
import burp.api.montoya.collaborator.CollaboratorClient
import burp.api.montoya.collaborator.Interaction
import burp.api.montoya.collaborator.InteractionFilter
import burp.api.montoya.collaborator.InteractionType
import java.time.format.DateTimeFormatter
import java.util.concurrent.ConcurrentHashMap

data class CollaboratorInteractionData(
    val payload: String,
    val metadata: String?,
    val type: String,
    val timestamp: String,
    val clientIp: String,
    val details: Map<String, Any>
)

interface CollaboratorProvider {
    fun generatePayload(metadata: String): String
    fun getInteractions(payloads: List<String>?): List<CollaboratorInteractionData>
}

class BurpCollaboratorProvider : CollaboratorProvider {
    // payloadDomain → metadata
    private val metadataRegistry = ConcurrentHashMap<String, String>()
    // interactionId → payloadDomain
    private val payloadIdRegistry = ConcurrentHashMap<String, String>()
    private var client: CollaboratorClient? = null

    private fun getOrCreateClient(): CollaboratorClient? {
        if (client == null) {
            client = Utils.montoyaApi?.collaborator()?.createClient()
        }
        return client
    }

    override fun generatePayload(metadata: String): String {
        val collaboratorClient = getOrCreateClient()
            ?: throw IllegalStateException("Burp Collaborator is not available")

        val payload = collaboratorClient.generatePayload()
        val payloadDomain = payload.toString()
        val interactionId = payload.id().toString()

        metadataRegistry[payloadDomain] = metadata
        payloadIdRegistry[interactionId] = payloadDomain
        return payloadDomain
    }

    override fun getInteractions(payloads: List<String>?): List<CollaboratorInteractionData> {
        val collaboratorClient = getOrCreateClient()
            ?: return emptyList()

        val interactions = if (payloads != null) {
            // Filter by specific payload domains
            payloads.flatMap { payloadDomain ->
                val filter = InteractionFilter.interactionPayloadFilter(payloadDomain)
                collaboratorClient.getInteractions(filter)
            }
        } else {
            collaboratorClient.getAllInteractions()
        }

        return interactions.map { interaction ->
            val interactionId = interaction.id().toString()
            val payloadDomain = payloadIdRegistry[interactionId] ?: interactionId
            val metadata = metadataRegistry[payloadDomain]
            val timestamp = interaction.timeStamp().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)
            val clientIp = interaction.clientIp().hostAddress

            // Send HTTP interactions to Burp Organizer
            if (interaction.type() == InteractionType.HTTP) {
                sendHttpInteractionToOrganizer(interaction, metadata, timestamp, clientIp)
            }

            CollaboratorInteractionData(
                payload = payloadDomain,
                metadata = metadata,
                type = interaction.type().name,
                timestamp = timestamp,
                clientIp = clientIp,
                details = extractDetails(interaction)
            )
        }
    }

    private fun sendHttpInteractionToOrganizer(
        interaction: Interaction,
        metadata: String?,
        timestamp: String,
        clientIp: String
    ) {
        interaction.httpDetails().ifPresent { http ->
            val organizer = Utils.montoyaApi?.organizer() ?: return@ifPresent
            val requestResponse = http.requestResponse()

            // Build notes with metadata
            val notes = buildString {
                append("[Collaborator]")
                if (metadata != null) {
                    append(" $metadata")
                }
                append(" | $timestamp | $clientIp")
            }

            // Set notes and send the full HttpRequestResponse to Organizer
            requestResponse.annotations().setNotes(notes)
            organizer.sendToOrganizer(requestResponse)
        }
    }

    private fun extractDetails(interaction: Interaction): Map<String, Any> {
        val details = mutableMapOf<String, Any>()

        when (interaction.type()) {
            InteractionType.DNS -> {
                interaction.dnsDetails().ifPresent { dns ->
                    details["query_type"] = dns.queryType().name
                }
            }
            InteractionType.HTTP -> {
                interaction.httpDetails().ifPresent { http ->
                    details["protocol"] = http.protocol().name
                    details["request"] = http.requestResponse().request().toString()
                    http.requestResponse().response()?.let {
                        details["response"] = it.toString()
                    }
                }
            }
            InteractionType.SMTP -> {
                interaction.smtpDetails().ifPresent { smtp ->
                    details["conversation"] = smtp.conversation()
                }
            }
        }

        return details
    }
}
