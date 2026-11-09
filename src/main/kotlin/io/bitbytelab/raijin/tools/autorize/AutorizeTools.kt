package io.bitbytelab.raijin.tools.autorize

import io.bitbytelab.raijin.bridge.AutorizeBridge
import io.bitbytelab.raijin.core.asJsonObjectList
import io.bitbytelab.raijin.core.asStringList
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/**
 * Registers the live Autorize-style tap tools: configure/list/remove rules that clone and
 * replay matching proxy traffic under a second identity in the background, and list/clear the
 * flagged mismatches. The actual tap runs in [io.bitbytelab.raijin.bridge.ProxyBridge]; this is
 * just CRUD against [io.bitbytelab.raijin.state.StateManager] via [AutorizeBridge].
 */
object AutorizeTools {
    fun register(server: Server, bridge: AutorizeBridge) {
        server.addTool(
            name = "autorize_set_rule",
            description = "Start (or update) a live broken-access-control tap: every proxied request matching the " +
                "filters is cloned and replayed under each of 'identities' in the background, then diffed against " +
                "the already-captured response (same engine as auth_diff/access_control_sweep). A critical/high " +
                "mismatch is recorded here AND pushed to findings(action=add). Browse the app as normal after " +
                "setting the rule — no need to resend anything yourself.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("rule_id") { put("type", "string"); put("description", "Omit to create a new rule; pass an existing id to update it") }
                    putJsonObject("identities") { put("type", "array"); putJsonObject("items") { put("type", "object") }; put("description", "At least 2, required when creating a rule: [{\"name\":\"none\"}] to test unauthenticated, or [{\"name\":\"low_priv\",\"header_name\":\"Cookie\",\"header_value\":\"session=...\"}] for a second session. Omit on an update to keep the rule's existing identities.") }
                    putJsonObject("in_scope_only") { put("type", "boolean"); put("description", "Only tap requests Burp's scope considers in scope (default true on create; omit on an update to keep the existing value)") }
                    putJsonObject("include_host_pattern") { put("type", "string"); put("description", "Optional hostname glob, e.g. '*.example.com'; omit to tap every host (or, on an update, to keep the existing value)") }
                    putJsonObject("exclude_url_regex") { put("type", "string"); put("description", "Optional URL regex; matching requests are skipped (omit on an update to keep the existing value)") }
                    putJsonObject("methods") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "Optional HTTP methods to tap; omit to tap every method (or, on an update, to keep the existing filter)") }
                    putJsonObject("ignore_static_assets") { put("type", "boolean"); put("description", "Skip responses that look like a static asset (default true on create; omit on an update to keep the existing value)") }
                    putJsonObject("similarity_threshold") { put("type", "number"); put("description", "Body-similarity percent (0-100) controlling match strictness (default 90 on create; omit on an update to keep the existing value)") }
                    putJsonObject("enabled") { put("type", "boolean"); put("description", "Whether the rule taps traffic (default true on create; omit on an update to keep the existing value — it does NOT re-enable a disabled rule)") }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val a = request.params.arguments ?: emptyMap()
                // Every optional field is passed through AS-IS (null when omitted) rather than
                // defaulted here — AutorizeBridge.setRule treats null as "keep the existing rule's
                // value" on an update, and only falls back to a hardcoded default when creating a
                // brand-new rule. Defaulting here instead would silently wipe out any field the
                // caller didn't resend on every update (e.g. updating just similarity_threshold
                // would otherwise clear 'methods' back to "all methods").
                val result = bridge.setRule(
                    ruleId = a["rule_id"]?.jsonPrimitive?.contentOrNull,
                    identities = a["identities"].asJsonObjectList(),
                    inScopeOnly = a["in_scope_only"]?.jsonPrimitive?.booleanOrNull,
                    includeHostPattern = a["include_host_pattern"]?.jsonPrimitive?.contentOrNull,
                    excludeUrlRegex = a["exclude_url_regex"]?.jsonPrimitive?.contentOrNull,
                    methods = a["methods"].asStringList(),
                    ignoreStaticAssets = a["ignore_static_assets"]?.jsonPrimitive?.booleanOrNull,
                    similarityThreshold = a["similarity_threshold"]?.jsonPrimitive?.doubleOrNull,
                    enabled = a["enabled"]?.jsonPrimitive?.booleanOrNull,
                )
                CallToolResult(content = listOf(TextContent(result.toString())), isError = result["error"] != null)
            } catch (e: Exception) { err(e.message) }
        }

        server.addTool(
            name = "autorize_list_rules",
            description = "List configured live Autorize-style tap rules.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { _ ->
            try {
                CallToolResult(content = listOf(TextContent(bridge.listRules().toString())))
            } catch (e: Exception) { err(e.message) }
        }

        server.addTool(
            name = "autorize_remove_rule",
            description = "Stop and remove a live Autorize-style tap rule by id.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("rule_id") { put("type", "string"); put("description", "Rule id from autorize_set_rule/autorize_list_rules") }
                },
                required = listOf("rule_id")
            )
        ) { request ->
            try {
                val a = request.params.arguments ?: emptyMap()
                val ruleId = a["rule_id"]?.jsonPrimitive?.contentOrNull ?: return@addTool err("Parameter 'rule_id' is required")
                val result = bridge.removeRule(ruleId)
                CallToolResult(content = listOf(TextContent(result.toString())), isError = result["error"] != null)
            } catch (e: Exception) { err(e.message) }
        }

        server.addTool(
            name = "autorize_list_matches",
            description = "List flagged mismatches recorded by live Autorize-style taps, newest first. Each one is " +
                "also in findings(action=list) if it was critical/high severity.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("rule_id") { put("type", "string"); put("description", "Optional: limit to one rule") }
                    putJsonObject("min_severity") { put("type", "string"); put("description", "Optional: critical|high|info") }
                    putJsonObject("start_index") { put("type", "integer"); put("description", "Zero-based offset (default 0)") }
                    putJsonObject("count") { put("type", "integer"); put("description", "Max results (default 50, max 500)") }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val a = request.params.arguments ?: emptyMap()
                val result = bridge.listMatches(
                    ruleId = a["rule_id"]?.jsonPrimitive?.contentOrNull,
                    minSeverity = a["min_severity"]?.jsonPrimitive?.contentOrNull,
                    startIndex = a["start_index"]?.jsonPrimitive?.intOrNull ?: 0,
                    count = a["count"]?.jsonPrimitive?.intOrNull ?: 50,
                )
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) { err(e.message) }
        }

        server.addTool(
            name = "autorize_clear_matches",
            description = "Clear recorded Autorize-style matches (optionally scoped to one rule), and optionally " +
                "reset the dedup guard so already-tested endpoints get retested.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("rule_id") { put("type", "string"); put("description", "Optional: limit to one rule; omit to clear all") }
                    putJsonObject("reset_seen") { put("type", "boolean"); put("description", "Also forget which endpoints were already tested (default false)") }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val a = request.params.arguments ?: emptyMap()
                val result = bridge.clearMatches(
                    ruleId = a["rule_id"]?.jsonPrimitive?.contentOrNull,
                    resetSeen = a["reset_seen"]?.jsonPrimitive?.booleanOrNull ?: false,
                )
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) { err(e.message) }
        }
    }

    private fun err(msg: String?): CallToolResult =
        CallToolResult(content = listOf(TextContent(buildJsonObject { put("error", msg ?: "Unknown error") }.toString())), isError = true)
}
