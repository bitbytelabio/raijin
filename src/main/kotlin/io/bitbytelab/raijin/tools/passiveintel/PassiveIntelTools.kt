package io.bitbytelab.raijin.tools.passiveintel

import io.bitbytelab.raijin.bridge.PassiveIntelBridge
import io.bitbytelab.raijin.core.asLongSafe
import io.bitbytelab.raijin.core.asStringList
import io.bitbytelab.raijin.recon.SecretPatterns
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object PassiveIntelTools {
    private val HISTORY_ITEMS = 1..100_000

    fun register(server: Server, bridge: PassiveIntelBridge) {
        server.addTool(
            name = "passive_intel",
            description = """Scan proxy history for sensitive data: cloud and API keys (AWS, Google, GitHub including fine-grained github_pat_, GitLab glpat-, OpenAI sk-proj-, Anthropic sk-ant-, Slack, Stripe), JWTs, private keys, internal IPs and URLs, S3/Azure/GCS buckets, source-map URLs, stack traces, SQL errors, server versions and sensitive paths. Zero-effort intelligence gathering from traffic already captured: no request is sent. Binary bodies are skipped and each body is scanned up to ${PassiveIntelBridge.MAX_BODY_CHARS} characters. A finding is one distinct value of a category: where it was first seen (url, request or response), how many such places carry it ("occurrences") and up to ${PassiveIntelBridge.MAX_PLACES_PER_VALUE - 1} more of them ("also_seen"). At most ${PassiveIntelBridge.MAX_PER_CATEGORY} distinct values per category, so a token sent on every page takes one slot; further values are counted in "omitted".

Parameters: max_items (int, default 1000), in_scope_only (bool, default false), categories (optional array of pattern names; a partial name such as "aws" selects every pattern containing it), host_filter (optional regex).

Available categories: ${SecretPatterns.ALL.keys.joinToString(", ")}. ${SecretPatterns.OPT_IN.joinToString(" and ")} match too much to be useful by default and run only when named in categories.""",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("max_items") {
                        put("type", "integer")
                        put("minimum", HISTORY_ITEMS.first)
                        put("maximum", HISTORY_ITEMS.last)
                        put("description", "Maximum proxy history items to scan (the most recent ones), default 1000")
                    }
                    putJsonObject("in_scope_only") { put("type", "boolean"); put("description", "Only scan in-scope items, default false") }
                    putJsonObject("categories") {
                        put("type", "array")
                        put("description", "Optional array of pattern names to check; a partial name selects every pattern containing it (\"aws\" selects aws_access_key and aws_secret_key). The available names are listed in the tool description.")
                        putJsonObject("items") { put("type", "string") }
                    }
                    putJsonObject("host_filter") { put("type", "string"); put("description", "Optional regex to filter by host") }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments.orEmpty()
                val maxItems = args["max_items"]?.takeUnless { it is JsonNull }?.let { element ->
                    val value = element.asLongSafe() ?: return@addTool toolError("Parameter 'max_items' must be an integer")
                    if (value < HISTORY_ITEMS.first || value > HISTORY_ITEMS.last) {
                        return@addTool toolError("Parameter 'max_items' must be between ${HISTORY_ITEMS.first} and ${HISTORY_ITEMS.last} (got $value)")
                    }
                    value.toInt()
                } ?: 1000
                val inScopeOnly = (args["in_scope_only"] as? JsonPrimitive)?.booleanOrNull ?: false
                val categories = args["categories"].asStringList()
                val hostFilter = (args["host_filter"] as? JsonPrimitive)?.contentOrNull

                toolJsonResult(bridge.extractIntel(maxItems, inScopeOnly, categories, hostFilter))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }
}
