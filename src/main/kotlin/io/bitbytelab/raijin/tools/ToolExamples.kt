package io.bitbytelab.raijin.tools

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray

/**
 * Hand-picked `example` calls for argument errors and `guide`: real values, every required
 * parameter set except ids that come from another call ([ID_SOURCES]). Most only read; some write
 * (proxy_annotate, log.message, send_to_tool.*, scope.include, findings.add, persistence.store,
 * config.*_add/_set/_register, custom_check.*_create*, http_rule.*_create/_set,
 * http_state.cookie_jar_set, organizer.send, sitemap.add_*, scanner.create_issue,
 * scanner.register_check, scanner_task.add_request, turbo_run.save_to_organizer, bambda_import,
 * api_import_openapi, proxy_auto_auth) or send traffic (http_send_request, http_send_raw_bytes,
 * http_send_pipeline, http_fuzz, http_race, recon.fingerprint, probe.*, turbo_run.start,
 * scanner.start_crawl, websocket.*) to example.com. None removes or stops anything
 * (ToolExamplesTest). Keyed by `tool` or `tool.action`; the arguments leave out `action`. A tool or
 * action without an entry gets [ToolArgs.example]'s placeholders; an entry that does not fit the
 * published schema is not used ([ToolArgs.fits]).
 */
internal object ToolExamples {

    private const val REQUEST = "GET /search?q=test HTTP/1.1\r\nHost: example.com\r\n\r\n"
    private const val ROOT_REQUEST = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    private const val DEBUG_HEADER_DETAIL = "The response carries an X-Debug header."
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
            "collaborator" to
                mapOf(
                    "client_id" to "collaborator.list_clients",
                    "secret_key" to "collaborator.get_secret",
                ),
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

    /** Actions where a param that is an id elsewhere in the tool names something new. */
    private val NEW_NAMES: Map<String, Set<String>> =
        mapOf(
            "http_rule.macro_set" to setOf("name"),
            "http_rule.token_rule_create" to setOf("rule_name"),
        )

    /** Param -> list call of [tool] with [action]: [ID_SOURCES] without [NEW_NAMES]. */
    fun ids(tool: String, action: String?): Map<String, String> =
        ID_SOURCES[tool].orEmpty() - NEW_NAMES[ToolArgs.callName(tool, action)].orEmpty()

    /**
     * `{"do": "<list call>"}` for [param] of [tool] with [action] when it is an id from another
     * call, else null.
     */
    fun idSource(tool: String, action: String?, param: String): JsonObject? =
        ids(tool, action)[param]?.let { call -> buildJsonObject { put("do", call) } }

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
            "ai.prompt" to
                buildJsonObject {
                    putJsonArray("messages") { add("Summarise the login flow in one sentence.") }
                },
            "collaborator.restore_client" to EMPTY,
            "config.proxy_listener_add" to buildJsonObject { put("interface", "127.0.0.1:8081") },
            "config.match_replace_add" to
                buildJsonObject {
                    put("type", "request_header")
                    put("match", "^User-Agent.*$")
                    put("replace", "User-Agent: raijin-test")
                    put("comment", "example")
                },
            "config.upstream_proxy_set" to
                buildJsonObject {
                    put("host", "127.0.0.1")
                    put("port", 8080)
                },
            "config.intruder_payload_processor_register" to
                buildJsonObject {
                    put("name", "base64-encode")
                    put("transform_type", "encode_base64")
                },
            "custom_check.bcheck_create" to
                buildJsonObject {
                    put("name", "Debug header")
                    put("description", "Response exposes an X-Debug header")
                    put("type", "passive_response")
                    put("match_pattern", "X-Debug:")
                    put("match_location", "response_headers")
                    put("match_condition", "contains")
                    put("severity", "low")
                    put("confidence", "firm")
                },
            "custom_check.scancheck_create_passive" to
                buildJsonObject {
                    put("name", "Debug header")
                    put("description", "Response exposes an X-Debug header")
                    putJsonArray("conditions") {
                        addJsonObject {
                            put("location", "response_headers")
                            put("pattern", "X-Debug")
                            put("condition_type", "contains")
                        }
                    }
                    put("severity", "low")
                    put("confidence", "firm")
                    put("issue_detail", DEBUG_HEADER_DETAIL)
                },
            "custom_check.scancheck_create_active" to
                buildJsonObject {
                    put("name", "Reflected marker")
                    put("description", "The payload is reflected unencoded")
                    putJsonArray("steps") {
                        addJsonObject {
                            put("payload", "raijin-probe-1")
                            putJsonArray("response_conditions") {
                                addJsonObject {
                                    put("location", "response_body")
                                    put("pattern", "raijin-probe-1")
                                    put("condition_type", "contains")
                                }
                            }
                        }
                    }
                    put("severity", "low")
                    put("confidence", "tentative")
                    put("issue_detail", "The injected marker came back in the response body.")
                },
            "http_rule.token_rule_create" to
                buildJsonObject {
                    put("rule_name", "bearer-from-login")
                    put("scope", "all")
                    put("extract_from", "body")
                    put("extract_json_path", "$.token")
                    put("inject_into", "header")
                    put("inject_name", "Authorization")
                    put("inject_value_template", "Bearer {value}")
                },
            "http_rule.macro_set" to
                buildJsonObject {
                    put("name", "login")
                    putJsonArray("steps") {
                        addJsonObject {
                            put("url", "https://example.com/login")
                            put("method", "POST")
                            put("body", "user=test&pass=test")
                        }
                    }
                    put("scope", "all")
                },
            "http_state.cookie_jar_set" to
                buildJsonObject {
                    put("name", "session")
                    put("value", "test")
                    put("domain", "example.com")
                },
            "organizer.send" to target(ROOT_REQUEST),
            "send_to_tool.intruder" to target(ROOT_REQUEST),
            "sitemap.add_request" to target(ROOT_REQUEST) { put("response", RESPONSE) },
            "send_to_tool.intruder_positions" to
                target(REQUEST) {
                    // Offsets of `test` in REQUEST.
                    putJsonArray("positions") {
                        add(
                            buildJsonArray {
                                add(14)
                                add(18)
                            },
                        )
                    }
                },
            "send_to_tool.comparer" to
                buildJsonObject {
                    putJsonArray("data") {
                        add(RESPONSE)
                        add(RESPONSE_404)
                    }
                },
            "send_to_tool.decoder" to buildJsonObject { putJsonArray("data") { add("aGVsbG8=") } },
            "scanner.start_crawl" to
                buildJsonObject { putJsonArray("urls") { add("https://example.com/") } },
            "scanner.generate_report" to
                buildJsonObject {
                    put("output_path", "raijin-report.html")
                    put("format", "HTML")
                },
            "scanner.create_issue" to
                buildJsonObject {
                    put("name", "Debug header exposed")
                    put("url", "https://example.com/")
                    put("detail", DEBUG_HEADER_DETAIL)
                    put("severity", "low")
                    put("confidence", "firm")
                },
            "scanner.register_check" to
                buildJsonObject {
                    put("check_name", "debug-header")
                    put("issue_name", "Debug header exposed")
                    put("passive_header_match", "X-Debug:")
                },
            // The request is ROOT_REQUEST in base64.
            "scanner_task.add_request" to
                target("R0VUIC8gSFRUUC8xLjENCkhvc3Q6IGV4YW1wbGUuY29tDQoNCg=="),
            "sitemap.add_issue" to
                buildJsonObject {
                    put("name", "Debug header exposed")
                    put("detail", DEBUG_HEADER_DETAIL)
                    put("severity", "LOW")
                    put("confidence", "FIRM")
                    put("url", "https://example.com/")
                },
            "turbo_run.save_to_organizer" to
                buildJsonObject { put("items", "[{\"request_id\":1,\"notes\":\"interesting\"}]") },
            "websocket.create" to buildJsonObject { put("url", "wss://example.com/ws") },
            "websocket.send_text" to buildJsonObject { put("message", "ping") },
            "websocket.send_binary" to buildJsonObject { put("data", "aGVsbG8=") },
            "api_import_openapi" to
                buildJsonObject {
                    put(
                        "spec_json",
                        "{\"openapi\":\"3.0.0\",\"info\":{\"title\":\"Example\",\"version\":\"1\"}," +
                            "\"servers\":[{\"url\":\"https://example.com\"}],\"paths\":{\"/health\":" +
                            "{\"get\":{\"responses\":{\"200\":{\"description\":\"ok\"}}}}}}",
                    )
                },
            "bambda_import" to
                buildJsonObject {
                    put("script", "return requestResponse.request().url().contains(\"/api/\");")
                    put("name", "API requests")
                },
            "http_fuzz" to
                buildJsonObject {
                    put("request", "GET /search?q=FUZZ HTTP/1.1\r\nHost: example.com\r\n\r\n")
                    put("host", "example.com")
                    putJsonArray("payloads") {
                        add("test")
                        add("'")
                    }
                },
            "http_race" to
                buildJsonObject {
                    put(
                        "request",
                        "POST /api/redeem HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
                    )
                    put("host", "example.com")
                    put("count", 10)
                },
            "http_send_pipeline" to
                buildJsonObject {
                    put("host", "example.com")
                    putJsonArray("requests") {
                        addJsonObject {
                            put("raw_request", "GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n")
                        }
                        addJsonObject {
                            put(
                                "raw_request",
                                "GET /b HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
                            )
                        }
                    }
                },
            "proxy_auto_auth" to
                buildJsonObject {
                    put("header_value", "Bearer test-token")
                    put("host_pattern", "example.com")
                },
        )

    /** [request] to example.com:443 over TLS, plus [extra]. */
    private fun target(request: String, extra: JsonObjectBuilder.() -> Unit = {}): JsonObject =
        buildJsonObject {
            put("request", request)
            put("host", "example.com")
            put("port", 443)
            put("use_tls", true)
            extra()
        }

    /** The hand-picked arguments for [tool] with [action] (null for an ungrouped tool), or null. */
    fun of(tool: String, action: String?): JsonObject? =
        EXAMPLES[if (action == null) tool else "$tool.$action"]
}
