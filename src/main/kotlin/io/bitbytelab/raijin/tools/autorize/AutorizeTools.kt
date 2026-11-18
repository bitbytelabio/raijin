package io.bitbytelab.raijin.tools.autorize

import io.bitbytelab.raijin.bridge.AutorizeBridge
import io.bitbytelab.raijin.core.EnumValidation
import io.bitbytelab.raijin.core.asJsonObjectList
import io.bitbytelab.raijin.core.asLongSafe
import io.bitbytelab.raijin.core.asStringList
import io.bitbytelab.raijin.safety.ScopeGate
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/**
 * Registers the live Autorize-style tap tools: configure/list/remove rules that clone and
 * replay matching proxy traffic under other identities in the background, and list/clear the
 * flagged mismatches. The tap itself is [io.bitbytelab.raijin.bridge.AutorizeTap] (run by
 * [io.bitbytelab.raijin.bridge.ProxyBridge]); this is just CRUD against
 * [io.bitbytelab.raijin.state.StateManager] via [AutorizeBridge].
 */
object AutorizeTools {

    private val SEVERITIES = listOf("critical", "high", "info")

    fun register(server: Server, bridge: AutorizeBridge) {
        server.addTool(
            name = "autorize_set_rule",
            description = "Start (or update) a live broken-access-control tap: every proxied request matching the " +
                "filters is cloned and replayed under each of 'identities' in the background, then diffed against " +
                "the already-captured response (same engine as auth_diff/access_control_sweep). A critical/high " +
                "mismatch is recorded here AND pushed to findings(action=add). Browse the app as normal after " +
                "setting the rule — no need to resend anything yourself. State-changing methods (POST, PUT, DELETE, " +
                "PATCH) are not replayed unless include_mutating=true, and originals that were not authenticated " +
                "(no credentials, or answered 401) or answered 404 are skipped. Matches persist per Burp project and " +
                "are emitted as 'autorize.match' events. Setting a rule (new or updated) re-tests endpoints it already replayed. " +
                ScopeGate.TOOL_NOTE + " Each replay is checked: the rule's skipped_out_of_scope and sent_out_of_scope counters show the outcome.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("rule_id") { put("type", "string"); put("description", "Omit to create a new rule; pass an existing id to update it") }
                    putJsonObject("identities") { put("type", "array"); putJsonObject("items") { put("type", "object") }; put("description", "Required when creating a rule: at least one identity that changes the request. Each is {name, header_name?, header_value?, headers?, remove_headers?} as in auth_diff: every header it names replaces the captured request's header of that name, remove_headers drops headers, and a name of none/unauth/anonymous strips every credential header. The captured response is the authenticated reference, e.g. [{\"name\":\"low_priv\",\"header_name\":\"Cookie\",\"header_value\":\"session=...\"},{\"name\":\"none\"}]. An identity that would resend the request unchanged is not replayed; header names and values are written as given. Omit on an update to keep the rule's existing identities.") }
                    putJsonObject("in_scope_only") { put("type", "boolean"); put("description", "Only tap requests Burp's scope considers in scope (default true on create; omit on an update to keep the existing value)") }
                    putJsonObject("include_host_pattern") { put("type", "string"); put("description", "Optional host glob ('*.example.com') or regex; omit to tap every host (or, on an update, to keep the existing value)") }
                    putJsonObject("exclude_url_regex") { put("type", "string"); put("description", "Optional URL regex; matching requests are skipped (omit on an update to keep the existing value)") }
                    putJsonObject("methods") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "Optional HTTP methods to tap; omit to tap every method include_mutating allows (or, on an update, to keep the existing filter)") }
                    putJsonObject("include_mutating") { put("type", "boolean"); put("description", "Also replay POST, PUT, DELETE and PATCH requests: each replay repeats the action once per identity (default false on create, also when 'methods' names them; omit on an update to keep the existing value)") }
                    putJsonObject("ignore_static_assets") { put("type", "boolean"); put("description", "Skip responses that look like a static asset (default true on create; omit on an update to keep the existing value)") }
                    putJsonObject("similarity_threshold") { put("type", "number"); put("minimum", 0); put("maximum", 100); put("description", "Body-similarity percent (0-100) controlling match strictness (default 90 on create; omit on an update to keep the existing value)") }
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
                    ruleId = a.string("rule_id"),
                    identities = a["identities"].asJsonObjectList(),
                    inScopeOnly = a.bool("in_scope_only"),
                    includeHostPattern = a.string("include_host_pattern"),
                    excludeUrlRegex = a.string("exclude_url_regex"),
                    methods = a["methods"].asStringList(),
                    ignoreStaticAssets = a.bool("ignore_static_assets"),
                    similarityThreshold = a.number("similarity_threshold"),
                    enabled = a.bool("enabled"),
                    includeMutating = a.bool("include_mutating"),
                )
                toolJsonResult(result)
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "autorize_list_rules",
            description = "List configured live Autorize-style tap rules.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { _ ->
            try {
                toolJsonResult(bridge.listRules())
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
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
                val ruleId = a.string("rule_id") ?: return@addTool toolError("Parameter 'rule_id' is required")
                toolJsonResult(bridge.removeRule(ruleId))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "autorize_list_matches",
            description = "List flagged mismatches recorded by live Autorize-style taps, newest first, with the original " +
                "exchange and what each identity received when replayed (match_id shows one in full). A critical/high one is " +
                "also in findings(action=list); a soft denial (soft_denial: true) is one the denial-wording heuristic turned " +
                "informational, kept for review. Matches persist across reloads, per Burp project.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("rule_id") { put("type", "string"); put("description", "Optional: limit to one rule") }
                    putJsonObject("min_severity") {
                        put("type", "string")
                        putJsonArray("enum") { SEVERITIES.forEach { add(it) } }
                        put("description", "Optional: only matches with a finding at least this severe")
                    }
                    putJsonObject("start_index") { put("type", "integer"); put("minimum", 0); put("description", "Zero-based offset (default 0)") }
                    putJsonObject("count") { put("type", "integer"); put("minimum", 1); put("description", "Max results (default 50; above ${AutorizeBridge.MAX_MATCH_PAGE} is served as ${AutorizeBridge.MAX_MATCH_PAGE} with a note)") }
                    putJsonObject("match_id") { put("type", "integer"); put("description", "Return only this match, with the original and every identity's replayed request and response at length") }
                    putJsonObject("include_replays") { put("type", "boolean"); put("description", "Include each identity's replayed request and response in the list (default false: identity, status and response length only)") }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val a = request.params.arguments ?: emptyMap()
                val minSeverity = a.string("min_severity")
                EnumValidation.error(minSeverity, SEVERITIES.toSet(), "min_severity")?.let { return@addTool toolJsonResult(it) }
                val result = bridge.listMatches(
                    ruleId = a.string("rule_id"),
                    minSeverity = minSeverity?.trim(),
                    startIndex = a.integer("start_index") ?: 0,
                    count = a.integer("count") ?: 50,
                    matchId = a.long("match_id"),
                    includeReplays = a.bool("include_replays") ?: false,
                )
                toolJsonResult(result)
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
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
                    ruleId = a.string("rule_id"),
                    resetSeen = a.bool("reset_seen") ?: false,
                )
                toolJsonResult(result)
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }

    private fun Map<String, JsonElement>.string(name: String): String? = (this[name] as? JsonPrimitive)?.contentOrNull

    private fun Map<String, JsonElement>.bool(name: String): Boolean? = (this[name] as? JsonPrimitive)?.booleanOrNull

    /** Optional number argument; a value that is present but not a number throws, reported as a tool error. */
    private fun Map<String, JsonElement>.number(name: String): Double? {
        val element = this[name]
        if (element == null || element is JsonNull) return null
        return (element as? JsonPrimitive)?.doubleOrNull
            ?: throw IllegalArgumentException("Parameter '$name' must be a number")
    }

    /** Optional integer argument as a Long; a non-integer throws, reported as a tool error. */
    private fun Map<String, JsonElement>.long(name: String): Long? {
        val element = this[name]
        if (element == null || element is JsonNull) return null
        return element.asLongSafe() ?: throw IllegalArgumentException("Parameter '$name' must be an integer")
    }

    /**
     * Optional integer argument without a range: the bridge serves an out-of-range value at the
     * nearest bound and says so in `notes`. A non-integer throws, reported as a tool error.
     */
    private fun Map<String, JsonElement>.integer(name: String): Int? =
        long(name)?.coerceIn(Int.MIN_VALUE.toLong(), Int.MAX_VALUE.toLong())?.toInt()
}
