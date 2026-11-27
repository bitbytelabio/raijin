package io.bitbytelab.raijin.tools

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray

/**
 * Hand-picked `example` calls for argument errors and `guide`: real values, every required
 * parameter set except ids that come from another call ([ID_SOURCES]). Most only read; a few write
 * (proxy_annotate, log.message, send_to_tool.repeater, scope.include, findings.add,
 * persistence.store) or send traffic (http_send_request, http_send_raw_bytes, recon.fingerprint,
 * probe.*, turbo_run.start) to example.com. None removes or stops anything (ToolExamplesTest).
 * Keyed by `tool` or `tool.action`; the arguments leave out `action`. A tool or action without an
 * entry gets [ToolArgs.example]'s placeholders; an entry that does not fit the published schema is
 * not used ([ToolArgs.fits]).
 */
internal object ToolExamples {

    private const val REQUEST = "GET /search?q=test HTTP/1.1\r\nHost: example.com\r\n\r\n"
    private const val RESPONSE = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<p>test</p>"
    private const val RESPONSE_404 =
        "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<p>missing</p>"
    private const val JWT = "eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opsbCGfG_HACGpVUMN_a9IV7pAx_Zmeo"
    private const val TURBO_SCRIPT =
        "def queueRequests(target, wordlists):\n" +
            "    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, engine=Engine.THREADED)\n" +
            "    engine.queue(target.req, 'test')\n\n" +
            "def handleResponse(req, interesting):\n" +
            "    table.add(req)\n"

    /**
     * Tool -> (parameter -> the call that lists its values): ids an example cannot hold a real
     * value for. Examples leave these out, and errors about them point at the list call (`see`).
     */
    val ID_SOURCES: Map<String, Map<String, String>> =
        mapOf(
            "turbo_run" to mapOf("run_id" to "turbo_run.list"),
            "collaborator" to mapOf("client_id" to "collaborator.list_clients"),
            "scanner_task" to mapOf("task_id" to "scanner_task.list"),
            "findings" to mapOf("id" to "findings.list"),
            "websocket" to
                mapOf(
                    "connection_id" to "websocket.list",
                    "rule_id" to "websocket.list_intercept_rules",
                ),
            "events" to mapOf("subscription_id" to "events.subscribe"),
            "autorize" to mapOf("rule_id" to "autorize.list_rules"),
            "proxy_rule" to mapOf("rule_id" to "proxy_rule.list"),
            "http_rule" to
                mapOf(
                    "rule_id" to "http_rule.traffic_rule_list",
                    "rule_name" to "http_rule.token_rule_list",
                    "name" to "http_rule.macro_list",
                ),
            "custom_check" to mapOf("id" to "custom_check.bcheck_list"),
            "persistence" to mapOf("key" to "persistence.list"),
            "proxy_annotate" to mapOf("id" to "proxy_history"),
        )

    /**
     * `{"do": "<list call>"}` for [param] of [tool] when it is an id from another call, else null.
     */
    fun idSource(tool: String, param: String): JsonObject? =
        ID_SOURCES[tool]?.get(param)?.let { call -> buildJsonObject { put("do", call) } }

    private val EMPTY = JsonObject(emptyMap())

    val EXAMPLES: Map<String, JsonObject> =
        mapOf(
            "http_send_request" to buildJsonObject { put("url", "https://example.com/") },
            "http_send_raw_bytes" to
                buildJsonObject {
                    put("host", "example.com")
                    put("raw_request", "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                },
            "http_send_request_chain" to
                buildJsonObject {
                    putJsonArray("steps") {
                        addJsonObject { put("url", "https://example.com/login") }
                        addJsonObject { put("url", "https://example.com/account") }
                    }
                },
            "http_send_requests_parallel" to
                buildJsonObject {
                    putJsonArray("requests") {
                        addJsonObject { put("url", "https://example.com/a") }
                        addJsonObject { put("url", "https://example.com/b") }
                    }
                },
            "proxy_history" to buildJsonObject { put("count", 20) },
            "proxy_history_search" to
                buildJsonObject {
                    put("pattern", "(?i)password")
                    put("max_results", 20)
                },
            "proxy_annotate" to
                buildJsonObject {
                    put("id", 1)
                    put("comment", "checked")
                },
            "bambda_templates" to EMPTY,
            "sitemap.query" to
                buildJsonObject {
                    put("url_prefix", "https://example.com/")
                    put("max_results", 20)
                },
            "sitemap.get_issues" to buildJsonObject { put("url_prefix", "https://example.com/") },
            "sitemap.annotate" to
                buildJsonObject {
                    put("url", "https://example.com/")
                    put("notes", "login page")
                },
            "scope.check" to buildJsonObject { put("url", "https://example.com/") },
            "scope.list" to EMPTY,
            "scope.get_config" to EMPTY,
            "scope.include" to buildJsonObject { put("url", "https://example.com") },
            "scope.exclude" to buildJsonObject { put("url", "https://example.com/logout") },
            "burp.version" to EMPTY,
            "burp.project_info" to EMPTY,
            "burp.task_engine_state" to EMPTY,
            "util.hash" to
                buildJsonObject {
                    put("data", "hello")
                    put("algorithm", "SHA_256")
                },
            "util.url_encode" to buildJsonObject { put("data", "a b&c") },
            "util.url_decode" to buildJsonObject { put("data", "a%20b%26c") },
            "util.base64_encode" to buildJsonObject { put("data", "hello") },
            "util.base64_decode" to buildJsonObject { put("data", "aGVsbG8=") },
            "util.html_encode" to buildJsonObject { put("data", "<b>") },
            "util.random_string" to
                buildJsonObject {
                    put("length", 16)
                    put("charset", "alphanumeric")
                },
            "util.random_bytes" to buildJsonObject { put("length", 16) },
            "util.decode_smart" to buildJsonObject { put("data", "JTNDYiUzRQ==") },
            "util.jwt_decode" to buildJsonObject { put("token", JWT) },
            "util.compress" to
                buildJsonObject {
                    put("data", "aGVsbG8=")
                    put("algorithm", "GZIP")
                },
            "util.decompress" to
                buildJsonObject {
                    put("data", "H4sIAAAAAAAA/8tIzcnJBwCGphA2BQAAAA==")
                    put("algorithm", "GZIP")
                },
            "turbo_docs.get_docs" to buildJsonObject { put("topic", "api-quickstart") },
            "turbo_docs.list_examples" to EMPTY,
            "turbo_docs.get_example" to buildJsonObject { put("name", "basic") },
            "turbo_run.list" to EMPTY,
            "turbo_run.status" to EMPTY,
            "turbo_run.results" to EMPTY,
            "turbo_run.script" to EMPTY,
            "turbo_run.result" to buildJsonObject { put("id", 1) },
            "turbo_run.search_responses" to buildJsonObject { put("query", "200") },
            "turbo_run.start" to
                buildJsonObject {
                    put("script", TURBO_SCRIPT)
                    put("base_request", "GET /?q=%s HTTP/1.1\r\nHost: example.com\r\n\r\n")
                    put("endpoint", "https://example.com:443")
                },
            "turbo_run.start_async" to
                buildJsonObject {
                    put("script", TURBO_SCRIPT)
                    put("base_request", "GET /?q=%s HTTP/1.1\r\nHost: example.com\r\n\r\n")
                    put("endpoint", "https://example.com:443")
                },
            "collaborator.list_clients" to EMPTY,
            "collaborator.default_payload" to EMPTY,
            "collaborator.get_secret" to EMPTY,
            "collaborator.generate_payload" to EMPTY,
            "collaborator.poll" to EMPTY,
            "collaborator.server_info" to EMPTY,
            "findings.list" to EMPTY,
            "findings.add" to
                buildJsonObject {
                    put("type", "xss")
                    put("url", "https://example.com/search?q=test")
                    put("severity", "medium")
                },
            "analyze.request" to
                buildJsonObject {
                    put("request", "GET /?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
                },
            "analyze.extract_params" to
                buildJsonObject {
                    put("request", "GET /?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
                },
            "analyze.response_body_search" to
                buildJsonObject {
                    put("pattern", "(?i)api[_-]?key")
                    put("max_results", 20)
                },
            "analyze.passive_intel" to buildJsonObject { put("max_items", 200) },
            "analyze.response" to buildJsonObject { put("response", RESPONSE) },
            "analyze.find_reflected" to
                buildJsonObject {
                    put("request", REQUEST)
                    put("response", RESPONSE)
                },
            "analyze.insertion_points" to
                buildJsonObject {
                    put("request", REQUEST)
                    put("host", "example.com")
                    put("port", 443)
                },
            "analyze.diff" to
                buildJsonObject {
                    put("item1", RESPONSE)
                    put("item2", RESPONSE_404)
                    put("type", "response")
                },
            "analyze.http_keywords" to
                buildJsonObject {
                    put("response", RESPONSE)
                    putJsonArray("keywords") { add("test") }
                },
            "analyze.http_variations" to
                buildJsonObject {
                    putJsonArray("responses") {
                        add(RESPONSE)
                        add(RESPONSE_404)
                    }
                },
            "scanner.get_all_issues" to EMPTY,
            "scanner_task.list" to EMPTY,
            "scanner_task.status" to EMPTY,
            "scanner_task.issues" to EMPTY,
            "events.get" to buildJsonObject { put("max_events", 20) },
            "events.get_by_type" to
                buildJsonObject {
                    putJsonArray("types") { add("proxy.request") }
                    put("max_events", 20)
                },
            "persistence.list" to EMPTY,
            "persistence.store" to
                buildJsonObject {
                    put("key", "notes")
                    put("value", "login uses /api/auth")
                },
            "persistence.get" to EMPTY,
            "persistence.preference_store" to
                buildJsonObject {
                    put("key", "notes")
                    put("value", "x")
                },
            "persistence.preference_get" to buildJsonObject { put("key", "notes") },
            "config.proxy_listeners_list" to EMPTY,
            "websocket.list" to EMPTY,
            "websocket.history_search" to buildJsonObject { put("pattern", "token") },
            "websocket.get_messages" to EMPTY,
            "proxy_rule.list" to EMPTY,
            "proxy_intercept.status" to EMPTY,
            "http_rule.traffic_rule_list" to EMPTY,
            "http_state.cookie_jar_get" to EMPTY,
            "autorize.list_rules" to EMPTY,
            "custom_check.bcheck_list" to EMPTY,
            "organizer.get_items" to EMPTY,
            "recon.fingerprint" to buildJsonObject { put("url", "https://example.com/") },
            "recon.content_discovery" to
                buildJsonObject {
                    put("base_url", "https://example.com")
                    putJsonArray("paths") {
                        add("admin")
                        add("robots.txt")
                    }
                },
            "recon.param_mine" to buildJsonObject { put("url", "https://example.com/search") },
            "probe.cors" to buildJsonObject { put("url", "https://example.com/") },
            "probe.cache" to buildJsonObject { put("url", "https://example.com/") },
            "probe.graphql" to buildJsonObject { put("url", "https://example.com/graphql") },
            "probe.injection" to
                buildJsonObject {
                    put("request", "GET /search?q=FUZZ HTTP/1.1\r\nHost: example.com\r\n\r\n")
                    put("host", "example.com")
                },
            "probe.access_control" to
                buildJsonObject {
                    putJsonArray("requests") {
                        addJsonObject {
                            put("raw_request", REQUEST)
                            put("host", "example.com")
                        }
                    }
                    putJsonArray("identities") {
                        addJsonObject {
                            put("name", "admin")
                            put("header_name", "Authorization")
                            put("header_value", "Bearer admin-token")
                        }
                        addJsonObject { put("name", "none") }
                    }
                },
            "probe.idor" to
                buildJsonObject {
                    put("request", "GET /api/orders/1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
                    put("host", "example.com")
                    putJsonArray("identities") {
                        addJsonObject {
                            put("name", "alice")
                            put("header_name", "Authorization")
                            put("header_value", "Bearer alice-token")
                        }
                        addJsonObject {
                            put("name", "bob")
                            put("header_name", "Authorization")
                            put("header_value", "Bearer bob-token")
                        }
                    }
                },
            "probe.jwt" to buildJsonObject { put("token", JWT) },
            "send_to_tool.repeater" to
                buildJsonObject {
                    put("request", "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                    put("host", "example.com")
                    put("port", 443)
                    put("use_tls", true)
                },
            "log.message" to buildJsonObject { put("message", "checked login") },
            "log.event" to buildJsonObject { put("message", "checkpoint reached") },
            "ai.status" to EMPTY,
            "auth_diff" to
                buildJsonObject {
                    put("request", "GET /api/me HTTP/1.1\r\nHost: example.com\r\n\r\n")
                    put("host", "example.com")
                    putJsonArray("auth_levels") {
                        addJsonObject {
                            put("name", "user")
                            put("header_name", "Authorization")
                            put("header_value", "Bearer <token>")
                        }
                        addJsonObject { put("name", "anonymous") }
                    }
                },
        )

    /** The hand-picked arguments for [tool] with [action] (null for an ungrouped tool), or null. */
    fun of(tool: String, action: String?): JsonObject? =
        EXAMPLES[if (action == null) tool else "$tool.$action"]
}
