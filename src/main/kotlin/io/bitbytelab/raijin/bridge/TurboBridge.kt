package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.turbo.TurboModule
import io.bitbytelab.raijin.turbo.TurboSettings
import io.bitbytelab.raijin.turbo.mcp.BurpCollaboratorProvider
import io.bitbytelab.raijin.turbo.mcp.BurpOrganizerProvider
import io.bitbytelab.raijin.turbo.mcp.McpResourceHandlers
import io.bitbytelab.raijin.turbo.mcp.McpToolHandlers
import io.bitbytelab.raijin.turbo.mcp.RunManager
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Bridge between the MCP tools and the Turbo engine. Shares [TurboModule.runManager] with the
 * GUI, so a run started by an agent is visible in the Turbo tab and vice versa.
 */
class TurboBridge(val manager: RunManager = TurboModule.runManager) {
    private val organizer = BurpOrganizerProvider()
    val tools = McpToolHandlers(manager, organizer, BurpCollaboratorProvider())
    val resources = McpResourceHandlers(manager, organizer) { TurboSettings.desyncAgent }

    /** Starting a run executes Python inside Burp's JVM, so it is opt-in. */
    fun runsAllowed(): Boolean = TurboSettings.allowMcpRuns

    companion object {
        const val RUNS_DISABLED_MESSAGE =
            "Script runs from MCP clients are disabled. A run executes Python inside Burp's JVM, so it is " +
                "off by default. The user can enable it in Burp > Settings > Extensions > Raijin Turbo > " +
                "\"Allow MCP clients to run Turbo scripts\"."

        /** Converts the handler result maps (String/Number/Boolean/List/Map/null) to JSON. */
        fun toJson(value: Any?): JsonElement = when (value) {
            null -> JsonNull
            is JsonElement -> value
            is String -> JsonPrimitive(value)
            is Boolean -> JsonPrimitive(value)
            is Number -> JsonPrimitive(value)
            is Map<*, *> -> JsonObject(value.entries.associate { it.key.toString() to toJson(it.value) })
            is Iterable<*> -> JsonArray(value.map { toJson(it) })
            is Array<*> -> JsonArray(value.map { toJson(it) })
            else -> JsonPrimitive(value.toString())
        }
    }
}
