package io.bitbytelab.raijin.tools.collaborator

import io.bitbytelab.raijin.bridge.CollaboratorBridge
import io.bitbytelab.raijin.core.BodyText
import io.bitbytelab.raijin.core.asBooleanSafe
import io.bitbytelab.raijin.core.asBoundedInt
import io.bitbytelab.raijin.core.asLongSafe
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

/**
 * Registers the Collaborator MCP tools onto the given [Server].
 *
 * Each tool delegates to the [CollaboratorBridge] and catches exceptions so
 * that errors are returned as structured JSON inside a `CallToolResult`
 * rather than propagating unhandled.
 */
object CollaboratorTools {

    private const val CLIENT_ID = "Collaborator client id"

    /** A string argument; null when absent, JSON null or not a primitive. */
    private fun Map<String, JsonElement>.text(name: String): String? = (this[name] as? JsonPrimitive)?.contentOrNull

    fun register(server: Server, bridge: CollaboratorBridge, stateManager: StateManager) {

        // ---------------------------------------------------------------
        // collaborator_create_client
        // ---------------------------------------------------------------
        server.addTool(
            name = "collaborator_create_client",
            description = "Create a Burp Collaborator client for out-of-band (OOB) payloads; its secret key is saved in the " +
                "Burp project, so it survives an extension reload. Returns a client ID and the Collaborator server " +
                "address; collaborator_list_clients shows what is registered. Pro edition only.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { _ ->
            try {
                toolJsonResult(bridge.createClient())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // collaborator_restore_client
        // ---------------------------------------------------------------
        server.addTool(
            name = "collaborator_restore_client",
            description = "Restore a Collaborator client from its secret key (clients created in this Burp project come " +
                "back by themselves; this is for a key from elsewhere). That covers a client from another project " +
                "and one dropped with collaborator_remove_client. A key that is already registered returns its " +
                "existing client. Pro edition only.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("secret_key") { put("type", "string"); put("description", "Base64-encoded secret key") }
                },
                required = listOf("secret_key")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val secretKey = args.text("secret_key")?.takeIf { it.isNotBlank() }
                    ?: return@addTool toolError("Parameter 'secret_key' is required (base64-encoded secret key)")

                toolJsonResult(bridge.restoreClient(secretKey))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // collaborator_list_clients
        // ---------------------------------------------------------------
        server.addTool(
            name = "collaborator_list_clients",
            description = "List the Collaborator clients registered in this Burp project, including the ones restored " +
                "after an extension reload. Per client: client_id, server, created_at, restored, persisted (secret key " +
                "saved in the project), payloads_generated and interactions_recorded (what collaborator_poll has " +
                "fetched so far; this tool does not contact the Collaborator server). A saved client that Burp " +
                "could not restore is listed under 'unrestored' with the reason.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { _ ->
            try {
                toolJsonResult(bridge.listClients())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // collaborator_generate_payload
        // ---------------------------------------------------------------
        server.addTool(
            name = "collaborator_generate_payload",
            description = "Generate a unique Collaborator payload (subdomain) for OOB detection and return its " +
                "payload_id, the id carried by every interaction it causes. " +
                "Use this payload in injection points to detect blind vulnerabilities (SSRF, blind XSS, etc.), then " +
                "pass payload_id to collaborator_poll to see only this payload's interactions. " +
                "Optionally embed custom data in the payload for identification.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("client_id") { put("type", "string"); put("description", CLIENT_ID) }
                    putJsonObject("custom_data") {
                        put("type", "string")
                        put(
                            "description",
                            "Custom data to embed in the payload, echoed back by its interactions " +
                                "(up to ${CollaboratorBridge.MAX_CUSTOM_DATA} alphanumeric characters)"
                        )
                    }
                },
                required = listOf("client_id")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val clientId = args.text("client_id")?.takeIf { it.isNotBlank() }
                    ?: return@addTool toolError("Parameter 'client_id' is required")

                toolJsonResult(bridge.generatePayload(clientId, args.text("custom_data")))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // collaborator_poll
        // ---------------------------------------------------------------
        server.addTool(
            name = "collaborator_poll",
            description = "Poll for Collaborator interactions (DNS, HTTP with full request and response, SMTP); all are " +
                "kept in a history, so filters and repeated polls lose nothing. Results are read from that bounded " +
                "history: type and payload_id only narrow what is returned (filtered_out counts the interactions " +
                "they left out), and polling again returns the same interactions plus new ones. " +
                "Pass since=<next_since of the previous result> to get only newer ones. Each interaction has seq, " +
                "payload_id (as returned by collaborator_generate_payload), client address, timestamp and details: " +
                "the DNS query type, name and raw hex (query_name_error when the query does not decode), the " +
                "HTTP request and response (headers and bodies), or the SMTP conversation. has_more means limit cut " +
                "the page (continue from next_since); history_truncated means older interactions were dropped from " +
                "the history.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("client_id") { put("type", "string"); put("description", CLIENT_ID) }
                    putJsonObject("type") {
                        put("type", "string")
                        putJsonArray("enum") { CollaboratorBridge.INTERACTION_TYPES.forEach { add(it) } }
                        put("description", "Return only interactions of this type; the others stay in the history (filtered_out counts them)")
                    }
                    putJsonObject("payload_id") {
                        put("type", "string")
                        put(
                            "description",
                            "Return only interactions of this payload: the payload_id from collaborator_generate_payload, or the payload host"
                        )
                    }
                    putJsonObject("since") {
                        put("type", "integer"); put("minimum", 0)
                        put(
                            "description",
                            "Return only interactions after this cursor: the next_since of an earlier poll, or a seq. " +
                                "Without it a poll returns the whole history again"
                        )
                    }
                    putJsonObject("limit") {
                        put("type", "integer"); put("minimum", 1); put("maximum", CollaboratorBridge.MAX_POLL_LIMIT)
                        put(
                            "description",
                            "Maximum interactions to return, oldest first (default ${CollaboratorBridge.DEFAULT_POLL_LIMIT}); " +
                                "has_more means more follow, continue from next_since"
                        )
                    }
                    putJsonObject("max_body_length") {
                        put("type", "integer"); put("minimum", 1); put("maximum", CollaboratorBridge.MAX_BODY_LENGTH)
                        put(
                            "description",
                            "Truncate each HTTP body and SMTP conversation at N characters (default ${BodyText.DEFAULT_MAX_LENGTH})"
                        )
                    }
                },
                required = listOf("client_id")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val clientId = args.text("client_id")?.takeIf { it.isNotBlank() }
                    ?: return@addTool toolError("Parameter 'client_id' is required")
                val sinceArg = args["since"]
                val since = if (sinceArg == null || sinceArg is JsonNull) {
                    null
                } else {
                    sinceArg.asLongSafe()?.takeIf { it >= 0 }
                        ?: return@addTool toolError("Parameter 'since' must be a non-negative integer (got $sinceArg)")
                }
                val limit = args["limit"].asBoundedInt("limit", 1, CollaboratorBridge.MAX_POLL_LIMIT)
                    .getOrElse { return@addTool toolError(it.message ?: "Invalid limit") }
                val maxBodyLength = args["max_body_length"].asBoundedInt("max_body_length", 1, CollaboratorBridge.MAX_BODY_LENGTH)
                    .getOrElse { return@addTool toolError(it.message ?: "Invalid max_body_length") }

                toolJsonResult(
                    bridge.pollInteractions(clientId, args.text("type"), args.text("payload_id"), since, limit, maxBodyLength)
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // collaborator_server_info
        // ---------------------------------------------------------------
        server.addTool(
            name = "collaborator_server_info",
            description = "Get the Collaborator server address and metadata for a given client.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("client_id") { put("type", "string"); put("description", CLIENT_ID) }
                },
                required = listOf("client_id")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val clientId = args.text("client_id")?.takeIf { it.isNotBlank() }
                    ?: return@addTool toolError("Parameter 'client_id' is required")

                toolJsonResult(bridge.getServerInfo(clientId))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // collaborator_get_secret
        // ---------------------------------------------------------------
        server.addTool(
            name = "collaborator_get_secret",
            description = "Get the secret key for a Collaborator client. Within this Burp project the client is " +
                "restored automatically; keep the key to bring the client back elsewhere, or after " +
                "collaborator_remove_client, with collaborator_restore_client.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("client_id") { put("type", "string"); put("description", CLIENT_ID) }
                },
                required = listOf("client_id")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val clientId = args.text("client_id")?.takeIf { it.isNotBlank() }
                    ?: return@addTool toolError("Parameter 'client_id' is required")

                toolJsonResult(bridge.getSecret(clientId))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // collaborator_remove_client
        // ---------------------------------------------------------------
        server.addTool(
            name = "collaborator_remove_client",
            description = "Drop a Collaborator client from Raijin's tracking, with its saved secret key and its recorded " +
                "interactions, so it is not restored on the next load. Montoya's Collaborator API has no " +
                "server-side client teardown (a client is just a secret-key handle, not a resource Burp needs " +
                "told to close) — this is local bookkeeping only. Returns the secret_key one last time so the " +
                "client can still be brought back later with collaborator_restore_client if needed.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("client_id") { put("type", "string"); put("description", CLIENT_ID) }
                },
                required = listOf("client_id")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val clientId = args.text("client_id")?.takeIf { it.isNotBlank() }
                    ?: return@addTool toolError("Parameter 'client_id' is required")

                toolJsonResult(bridge.removeClient(clientId))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // ---------------------------------------------------------------
        // collaborator_default_payload
        // ---------------------------------------------------------------
        server.addTool(
            name = "collaborator_default_payload",
            description = "Generate a Collaborator payload using Burp's DEFAULT generator (no client_id needed). " +
                "Unlike collaborator_generate_payload, these payloads are linked to Burp's NATIVE Collaborator tab — " +
                "interactions show up there but CANNOT be polled via collaborator_poll. Use when you want hits visible " +
                "in Burp's own Collaborator UI rather than via API polling.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("without_server_location") {
                        put("type", "boolean")
                        put("description", "Omit the server location from the payload (default false)")
                    }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val withoutServerLocation = args["without_server_location"].asBooleanSafe() ?: false

                toolJsonResult(bridge.generateDefaultPayload(withoutServerLocation))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }
}
