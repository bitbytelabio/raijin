package io.bitbytelab.raijin.tools

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray

/**
 * Hand-picked `example` calls for argument errors and `guide`: read-only, with real values, every
 * required parameter set. Keyed by `tool` or `tool.action`; the arguments leave out `action`.
 * A tool or action without an entry gets [ToolArgs.example]'s placeholders. An entry that does not
 * fit the published schema is not used ([ToolArgs.fits]); `ToolExamplesTest` keeps every entry fitting.
 */
internal object ToolExamples {

    val EXAMPLES: Map<String, JsonObject> = mapOf(
        "http_send_request" to buildJsonObject { put("url", "https://example.com/") },
        "http_send_raw_bytes" to buildJsonObject {
            put("host", "example.com"); put("raw_request", "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        },
        "proxy_history" to buildJsonObject { put("count", 20) },
        "proxy_history_search" to buildJsonObject { put("pattern", "(?i)password"); put("max_results", 20) },
        "proxy_annotate" to buildJsonObject { put("id", 1); put("comment", "checked") },
        "bambda_templates" to JsonObject(emptyMap()),
        "sitemap.query" to buildJsonObject { put("url_prefix", "https://example.com/"); put("max_results", 20) },
        "sitemap.get_issues" to buildJsonObject { put("url_prefix", "https://example.com/") },
        "scope.check" to buildJsonObject { put("url", "https://example.com/") },
        "scope.list" to JsonObject(emptyMap()),
        "scope.get_config" to JsonObject(emptyMap()),
        "burp.version" to JsonObject(emptyMap()),
        "burp.project_info" to JsonObject(emptyMap()),
        "burp.task_engine_state" to JsonObject(emptyMap()),
        "util.hash" to buildJsonObject { put("data", "hello"); put("algorithm", "SHA_256") },
        "util.url_encode" to buildJsonObject { put("data", "a b&c") },
        "util.url_decode" to buildJsonObject { put("data", "a%20b%26c") },
        "util.base64_encode" to buildJsonObject { put("data", "hello") },
        "util.base64_decode" to buildJsonObject { put("data", "aGVsbG8=") },
        "util.html_encode" to buildJsonObject { put("data", "<b>") },
        "util.random_string" to buildJsonObject { put("length", 16); put("charset", "alphanumeric") },
        "util.random_bytes" to buildJsonObject { put("length", 16) },
        "util.decode_smart" to buildJsonObject { put("data", "JTNDYiUzRQ==") },
        "turbo_docs.get_docs" to buildJsonObject { put("topic", "api-quickstart") },
        "turbo_docs.list_examples" to JsonObject(emptyMap()),
        "turbo_docs.get_example" to buildJsonObject { put("name", "basic") },
        "turbo_run.list" to JsonObject(emptyMap()),
        "turbo_run.status" to buildJsonObject { put("run_id", "<run_id from turbo_run.list>") },
        "collaborator.list_clients" to JsonObject(emptyMap()),
        "collaborator.default_payload" to JsonObject(emptyMap()),
        "findings.list" to JsonObject(emptyMap()),
        "analyze.request" to buildJsonObject { put("request", "GET /?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n") },
        "analyze.extract_params" to buildJsonObject { put("request", "GET /?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n") },
        "analyze.response_body_search" to buildJsonObject { put("pattern", "(?i)api[_-]?key"); put("max_results", 20) },
        "analyze.passive_intel" to buildJsonObject { put("max_items", 200) },
        "scanner.get_all_issues" to JsonObject(emptyMap()),
        "scanner_task.list" to JsonObject(emptyMap()),
        "events.get" to JsonObject(emptyMap()),
        "persistence.list" to JsonObject(emptyMap()),
        "config.proxy_listeners_list" to JsonObject(emptyMap()),
        "websocket.list" to JsonObject(emptyMap()),
        "proxy_rule.list" to JsonObject(emptyMap()),
        "proxy_intercept.status" to JsonObject(emptyMap()),
        "http_rule.traffic_rule_list" to JsonObject(emptyMap()),
        "http_state.cookie_jar_get" to JsonObject(emptyMap()),
        "autorize.list_rules" to JsonObject(emptyMap()),
        "custom_check.bcheck_list" to JsonObject(emptyMap()),
        "organizer.get_items" to JsonObject(emptyMap()),
        "recon.fingerprint" to buildJsonObject { put("url", "https://example.com/") },
        "send_to_tool.repeater" to buildJsonObject {
            put("request", "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"); put("host", "example.com"); put("port", 443); put("use_tls", true)
        },
        "log.message" to buildJsonObject { put("message", "checked login") },
        "ai.status" to JsonObject(emptyMap()),
        "auth_diff" to buildJsonObject {
            put("request", "GET /api/me HTTP/1.1\r\nHost: example.com\r\n\r\n"); put("host", "example.com")
            putJsonArray("auth_levels") {
                addJsonObject { put("name", "user"); put("header_name", "Authorization"); put("header_value", "Bearer <token>") }
                addJsonObject { put("name", "anonymous") }
            }
        },
    )

    /** The hand-picked arguments for [tool] with [action] (null for an ungrouped tool), or null. */
    fun of(tool: String, action: String?): JsonObject? = EXAMPLES[if (action == null) tool else "$tool.$action"]
}
