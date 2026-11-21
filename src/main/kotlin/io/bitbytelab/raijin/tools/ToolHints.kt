package io.bitbytelab.raijin.tools

import io.modelcontextprotocol.kotlin.sdk.types.ToolAnnotations

/**
 * MCP [ToolAnnotations] of every published tool. A grouped tool is classified by its most
 * consequential action: `scope` is destructive because `scope(action=remove)` is, even though
 * `scope(action=check)` only reads.
 */
internal object ToolHints {

    /** Never change Burp state or send traffic. */
    val READ_ONLY: Set<String> = setOf(
        "proxy_history", "proxy_history_search", "bambda_templates", "turbo_docs", "util", "analyze",
        "search_skills", "load_skill",
    )

    /** At least one action removes, overwrites or shuts down something. */
    val DESTRUCTIVE: Set<String> = setOf(
        "burp", "config", "scope", "persistence", "custom_check", "scanner", "scanner_task", "proxy_rule",
        "proxy_intercept", "http_rule", "http_state", "findings", "events", "websocket", "collaborator",
        "turbo_run", "autorize", "jwt_keys",
    )

    /** May send traffic to targets outside Burp. */
    val OPEN_WORLD: Set<String> = setOf(
        "http_send_request", "http_send_requests_parallel", "http_send_request_chain", "http_send_raw_bytes",
        "http_send_pipeline", "http_fuzz", "http_race", "http_rule", "probe", "recon", "auth_diff", "autorize",
        "scanner", "scanner_task", "websocket", "turbo_run", "collaborator", "ai", "api_import_openapi",
    )

    fun of(name: String): ToolAnnotations = ToolAnnotations(
        title = null,
        readOnlyHint = name in READ_ONLY,
        destructiveHint = name in DESTRUCTIVE,
        idempotentHint = if (name in READ_ONLY) true else null,
        openWorldHint = name in OPEN_WORLD,
    )
}
