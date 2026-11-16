package io.bitbytelab.raijin.tools.persistence

import io.bitbytelab.raijin.bridge.PersistenceBridge
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object PersistenceTools {

    fun register(server: Server, bridge: PersistenceBridge) {

        // 1. persistence_store
        server.addTool(
            name = "persistence_store",
            description = "Store a string value in Burp Suite's extension persistence store. " +
                "Data persists across Burp restarts within the same project. " +
                "Parameters: key (string, the storage key), value (string, the value to store).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("key") { put("type", "string"); put("description", "The storage key") }
                    putJsonObject("value") { put("type", "string"); put("description", "The value to store") }
                },
                required = listOf("key", "value")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val key = args["key"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: key")
                val value = args["value"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: value")
                toolJsonResult(bridge.store(key, value))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 2. persistence_get
        server.addTool(
            name = "persistence_get",
            description = "Retrieve a value from Burp Suite's extension persistence store by key. " +
                "Returns the value and a 'found' flag indicating whether the key exists. " +
                "Parameters: key (string, the storage key to look up).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("key") { put("type", "string"); put("description", "The storage key to look up") }
                },
                required = listOf("key")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val key = args["key"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: key")
                toolJsonResult(bridge.get(key))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 3. persistence_delete
        server.addTool(
            name = "persistence_delete",
            description = "Delete a key-value pair from Burp Suite's extension persistence store. " +
                "Returns whether the key existed before deletion. " +
                "Parameters: key (string, the storage key to delete).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("key") { put("type", "string"); put("description", "The storage key to delete") }
                },
                required = listOf("key")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val key = args["key"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: key")
                toolJsonResult(bridge.delete(key))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 4. persistence_list
        server.addTool(
            name = "persistence_list",
            description = "List all key-value pairs stored in Burp Suite's extension persistence store. " +
                "Returns the count and an array of all entries with their keys and values. " +
                "No parameters required.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { _ ->
            try {
                toolJsonResult(bridge.list())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 5. preference_store
        server.addTool(
            name = "preference_store",
            description = "Store a value in Burp Suite's user-level preferences. Unlike extension " +
                "persistence data, preferences survive across projects. " +
                "Parameters: key (string, the preference key), value (string, the value to store).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("key") { put("type", "string"); put("description", "The preference key") }
                    putJsonObject("value") { put("type", "string"); put("description", "The value to store") }
                },
                required = listOf("key", "value")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val key = args["key"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: key")
                val value = args["value"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: value")
                toolJsonResult(bridge.preferenceStore(key, value))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 6. preference_get
        server.addTool(
            name = "preference_get",
            description = "Retrieve a value from Burp Suite's user-level preferences by key. " +
                "Preferences are global across projects. " +
                "Parameters: key (string, the preference key to look up).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("key") { put("type", "string"); put("description", "The preference key to look up") }
                },
                required = listOf("key")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val key = args["key"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: key")
                toolJsonResult(bridge.preferenceGet(key))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 7. preference_delete
        server.addTool(
            name = "preference_delete",
            description = "Delete a key from Burp Suite's user-level preferences. Returns whether the key existed " +
                "before deletion. Parameters: key (string, the preference key to delete).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("key") { put("type", "string"); put("description", "The preference key to delete") }
                },
                required = listOf("key")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val key = args["key"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: key")
                toolJsonResult(bridge.preferenceDelete(key))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }
}
