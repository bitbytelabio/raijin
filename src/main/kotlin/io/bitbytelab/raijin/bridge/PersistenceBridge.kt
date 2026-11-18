package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.safety.ScopeGate
import kotlinx.serialization.json.*
import java.util.concurrent.ConcurrentHashMap

/**
 * Bridge wrapping the Montoya Persistence API.
 *
 * Since PersistedObject may not expose a listKeys() method, this bridge
 * maintains an internal shadow map of all keys stored through it. The key
 * list is itself persisted under the special key "_raijin_keys" so it
 * survives extension reloads.
 */
class PersistenceBridge(private val api: MontoyaApi, private val eventBus: EventBus) {

    companion object {
        private const val KEY_INDEX = "_raijin_keys"
        private const val KEY_SEPARATOR = "\u001F" // Unit separator
        private val SCOPE_MODES = setOf("off", "warn", "enforce")
        private const val DEFAULT_SCOPE_MODE = "warn (default)"
    }

    /** Shadow store mirroring what is in extensionData. */
    private val shadowStore = ConcurrentHashMap<String, String>()

    init {
        // Restore the key index from persistence on load
        try {
            val storedKeys = api.persistence().extensionData().getString(KEY_INDEX)
            if (storedKeys != null && storedKeys.isNotEmpty()) {
                storedKeys.split(KEY_SEPARATOR).filter { it.isNotEmpty() }.forEach { key ->
                    val value = api.persistence().extensionData().getString(key)
                    if (value != null) {
                        shadowStore[key] = value
                    }
                }
            }
        } catch (_: Exception) {
            // First load or corrupted index -- start fresh
        }
    }

    /**
     * Persists the current key index so it survives extension reloads.
     */
    private fun persistKeyIndex() {
        val keyList = shadowStore.keys().toList().joinToString(KEY_SEPARATOR)
        api.persistence().extensionData().setString(KEY_INDEX, keyList)
    }

    /**
     * Stores a string value under the given key.
     */
    fun store(key: String, value: String): JsonObject {
        api.persistence().extensionData().setString(key, value)
        shadowStore[key] = value
        persistKeyIndex()

        return buildJsonObject {
            put("status", "stored")
            put("key", key)
            put("value_length", value.length)
        }
    }

    /**
     * Retrieves a value by key.
     */
    fun get(key: String): JsonObject {
        val value = try {
            api.persistence().extensionData().getString(key)
        } catch (_: Exception) {
            null
        }

        return buildJsonObject {
            put("key", key)
            put("found", value != null)
            if (value != null) {
                put("value", value)
            }
        }
    }

    /**
     * Deletes a key from persistence.
     */
    fun delete(key: String): JsonObject {
        val existed = shadowStore.containsKey(key)
        api.persistence().extensionData().deleteString(key)
        shadowStore.remove(key)
        persistKeyIndex()

        return buildJsonObject {
            put("key", key)
            put("deleted", existed)
        }
    }

    /**
     * Lists all known keys and their values.
     */
    fun list(): JsonObject {
        val entries = buildJsonArray {
            for ((key, value) in shadowStore) {
                addJsonObject {
                    put("key", key)
                    put("value", value)
                }
            }
        }

        return buildJsonObject {
            put("count", shadowStore.size)
            put("entries", entries)
        }
    }

    /**
     * Stores a preference value (user-level, survives across projects).
     */
    fun preferenceStore(key: String, value: String): JsonObject {
        if (key == ScopeGate.PREF_SCOPE_MODE) return storeScopeMode(value)
        api.persistence().preferences().setString(key, value)

        return buildJsonObject {
            put("status", "stored")
            put("key", key)
            put("scope", "preferences")
            put("value_length", value.length)
        }
    }

    /**
     * `mcp_scope_mode` stays writable by an MCP client, but only as one of the three modes, and
     * every change is announced: a `scope.mode_changed` event and a line in Burp's output log.
     */
    private fun storeScopeMode(value: String): JsonObject {
        val normalized = value.trim().lowercase()
        if (normalized !in SCOPE_MODES) return buildJsonObject { put("error", "mcp_scope_mode must be off, warn or enforce") }
        val previous = try { api.persistence().preferences().getString(ScopeGate.PREF_SCOPE_MODE) } catch (_: Exception) { null }
        api.persistence().preferences().setString(ScopeGate.PREF_SCOPE_MODE, normalized)
        val from = previous ?: DEFAULT_SCOPE_MODE
        announceScopeMode(from, normalized)
        return buildJsonObject {
            put("status", "stored")
            put("key", ScopeGate.PREF_SCOPE_MODE)
            put("scope", "preferences")
            put("value", normalized)
            put("previous_value", previous)
            put("note", "scope mode changed from $from to $normalized")
        }
    }

    private fun announceScopeMode(from: String, to: String) {
        eventBus.emit("scope.mode_changed", buildJsonObject {
            put("from", from)
            put("to", to)
            put("source", "preference_store")
        })
        try {
            api.logging().logToOutput("[Raijin] mcp_scope_mode changed by an MCP client: $from -> $to")
        } catch (_: Exception) {
        }
    }

    /**
     * Retrieves a preference value.
     */
    fun preferenceGet(key: String): JsonObject {
        val value = try {
            api.persistence().preferences().getString(key)
        } catch (_: Exception) {
            null
        }

        return buildJsonObject {
            put("key", key)
            put("scope", "preferences")
            put("found", value != null)
            if (value != null) {
                put("value", value)
            }
        }
    }

    /**
     * Deletes a preference key (user-level). Unlike [delete]'s extensionData, no shadow index
     * is needed here — Montoya's `Preferences` already exposes `deleteString` directly.
     */
    fun preferenceDelete(key: String): JsonObject {
        val previous = try { api.persistence().preferences().getString(key) } catch (_: Exception) { null }
        api.persistence().preferences().deleteString(key)
        val scopeMode = key == ScopeGate.PREF_SCOPE_MODE && previous != null
        if (scopeMode) announceScopeMode(previous, DEFAULT_SCOPE_MODE)
        return buildJsonObject {
            put("key", key)
            put("scope", "preferences")
            put("deleted", previous != null)
            if (scopeMode) put("note", "scope mode changed from $previous to $DEFAULT_SCOPE_MODE")
        }
    }
}
