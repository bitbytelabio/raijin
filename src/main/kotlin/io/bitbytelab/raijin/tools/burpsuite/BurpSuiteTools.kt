package io.bitbytelab.raijin.tools.burpsuite

import io.bitbytelab.raijin.bridge.BurpSuiteBridge
import io.bitbytelab.raijin.core.EnumValidation
import io.bitbytelab.raijin.core.asBooleanSafe
import io.bitbytelab.raijin.core.asStringList
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object BurpSuiteTools {

    fun register(server: Server, bridge: BurpSuiteBridge) {

        // 1. burp_version
        server.addTool(
            name = "burp_version",
            description = "Get Burp Suite version information including product name, " +
                "version number, build number, and edition (Professional/Community).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {},
                required = emptyList()
            )
        ) { _ ->
            try {
                toolJsonResult(bridge.getVersion())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 2. burp_export_project_config
        server.addTool(
            name = "burp_export_project_config",
            description = "Export Burp Suite project-level configuration as JSON. " +
                "Parameters: paths (optional string array of configuration paths to " +
                "export, e.g. [\"proxy\", \"scanner\"]. If omitted, exports all " +
                "project options).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("paths") {
                        put("type", "array")
                        put("description", "Configuration paths to export (optional)")
                        putJsonObject("items") { put("type", "string") }
                    }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val paths = args["paths"].asStringList() ?: emptyList()

                val configJson = bridge.exportProjectConfig(paths)
                CallToolResult(content = listOf(TextContent(configJson)))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 3. burp_export_user_config
        server.addTool(
            name = "burp_export_user_config",
            description = "Export Burp Suite user-level configuration as JSON. " +
                "Parameters: paths (optional string array of configuration paths to " +
                "export. If omitted, exports all user options).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("paths") {
                        put("type", "array")
                        put("description", "Configuration paths to export (optional)")
                        putJsonObject("items") { put("type", "string") }
                    }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val paths = args["paths"].asStringList() ?: emptyList()

                val configJson = bridge.exportUserConfig(paths)
                CallToolResult(content = listOf(TextContent(configJson)))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 4. burp_import_project_config
        server.addTool(
            name = "burp_import_project_config",
            description = "Import project-level configuration into Burp Suite from a " +
                "JSON string. Parameters: config_json (required, the JSON configuration " +
                "string to import).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("config_json") { put("type", "string"); put("description", "Project config JSON to import") }
                },
                required = listOf("config_json")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val configJson = args["config_json"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: config_json")

                destructiveBlocked("burp_import_project_config", bridge.destructiveAllowed())?.let { return@addTool it }
                toolJsonResult(bridge.importProjectConfig(configJson))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 5. burp_import_user_config
        server.addTool(
            name = "burp_import_user_config",
            description = "Import user-level configuration into Burp Suite from a " +
                "JSON string. Parameters: config_json (required, the JSON configuration " +
                "string to import).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("config_json") { put("type", "string"); put("description", "User config JSON to import") }
                },
                required = listOf("config_json")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val configJson = args["config_json"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: config_json")

                destructiveBlocked("burp_import_user_config", bridge.destructiveAllowed())?.let { return@addTool it }
                toolJsonResult(bridge.importUserConfig(configJson))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 6. burp_task_engine_state
        server.addTool(
            name = "burp_task_engine_state",
            description = "Get the current state of Burp Suite's task execution engine " +
                "(running or paused). The task engine controls whether background tasks " +
                "like scanning and crawling are actively executing.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {},
                required = emptyList()
            )
        ) { _ ->
            try {
                toolJsonResult(bridge.getTaskEngineState())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 7. burp_task_engine_set
        server.addTool(
            name = "burp_task_engine_set",
            description = "Set the state of Burp Suite's task execution engine. " +
                "Parameters: state (required, must be 'running' or 'paused'). " +
                "Pausing the engine suspends all background tasks (scans, crawls).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("state") {
                        put("type", "string")
                        putJsonArray("enum") { TASK_ENGINE_STATES.forEach { add(it) } }
                        put("description", "Engine state")
                    }
                },
                required = listOf("state")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val state = args["state"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: state")
                EnumValidation.error(state, TASK_ENGINE_STATES.toSet(), "state")?.let { return@addTool toolJsonResult(it) }

                toolJsonResult(bridge.setTaskEngineState(state))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 8. burp_command_line_args
        server.addTool(
            name = "burp_command_line_args",
            description = "Get the command line arguments that were used to launch " +
                "Burp Suite. Returns the arguments as a list of strings.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {},
                required = emptyList()
            )
        ) { _ ->
            try {
                toolJsonResult(bridge.getCommandLineArgs())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 9. burp_shutdown
        server.addTool(
            name = "burp_shutdown",
            description = "Initiate a Burp Suite shutdown. Parameters: prompt_user " +
                "(optional boolean, default false. If true, prompts the user with a " +
                "confirmation dialog before shutting down).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("prompt_user") { put("type", "boolean"); put("description", "Prompt user with confirmation dialog (default false)") }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val promptUser = args["prompt_user"].asBooleanSafe() ?: false

                destructiveBlocked("burp_shutdown", bridge.destructiveAllowed())?.let { return@addTool it }
                toolJsonResult(bridge.shutdown(promptUser))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }

    /**
     * Server-side gate for destructive tools. Returns a blocked [CallToolResult]
     * (caller should return it) when the operator has not enabled
     * `mcp_allow_destructive`; null when the tool may proceed.
     */
    private fun destructiveBlocked(toolName: String, allowed: Boolean): CallToolResult? {
        if (io.bitbytelab.raijin.safety.ActionPolicy.isAllowed(toolName, allowed)) return null
        return toolJsonResult(buildJsonObject {
            put("error", "Blocked: '$toolName' is a destructive action disabled by policy. " +
                "An operator must enable it by setting Burp preference mcp_allow_destructive=true.")
            put("blocked_by", "mcp_allow_destructive")
        })
    }

    private val TASK_ENGINE_STATES = listOf("running", "paused")
}
