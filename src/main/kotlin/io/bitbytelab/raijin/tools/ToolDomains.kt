package io.bitbytelab.raijin.tools

import io.modelcontextprotocol.kotlin.sdk.types.Tool
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

/**
 * Raijin's published tools grouped by what an agent wants to do, for the `raijin mcp` gateway
 * (`discover`). Shipped in the jar as `catalog/tools.json` ([catalogJson]), so the CLI can describe
 * every tool while Burp is down. `ToolCatalogTest` keeps the domains, the published tools and the
 * committed file in step.
 */
object ToolDomains {

    data class Domain(val name: String, val description: String, val notes: String, val skill: String, val tools: List<String>)

    /** Published tools the gateway replaces with its own `skill` tool. */
    val EXCLUDED: Set<String> = setOf("search_skills", "load_skill")

    val DOMAINS: List<Domain> = listOf(
        Domain(
            "http",
            "Build and send HTTP requests: single, parallel, chained, raw bytes, pipelined, raced, fuzzed; outgoing traffic rules and cookie jar.",
            "Not for reading captured traffic (proxy) or offline .burp files (history).",
            "http-testing",
            listOf(
                "http_send_request", "http_send_requests_parallel", "http_send_request_chain", "http_send_raw_bytes",
                "http_send_pipeline", "http_race", "http_fuzz", "http_rule", "http_state",
            ),
        ),
        Domain(
            "proxy",
            "Live traffic of a running Burp: proxy history and search, annotations, intercept, proxy rules, site map, Organizer, send to Repeater/Intruder/Comparer/Decoder, WebSockets.",
            "Needs a running Burp; yesterday's .burp files are history.",
            "proxy-traffic",
            listOf(
                "proxy_history", "proxy_history_search", "proxy_annotate", "proxy_auto_auth", "proxy_intercept", "proxy_rule",
                "sitemap", "organizer", "send_to_tool", "websocket",
            ),
        ),
        Domain(
            "scanner",
            "Burp Scanner crawls and audits, scan tasks and issues, custom checks (BChecks, scan checks) and Bambdas.",
            "One targeted vulnerability class is recon (probe), not a full audit.",
            "scanner-audit",
            listOf("scanner", "scanner_task", "custom_check", "bambda_import", "bambda_templates"),
        ),
        Domain(
            "recon",
            "Recon (JS endpoints, content discovery, parameter mining, fingerprinting), guided probes (CORS, cache poisoning/deception, GraphQL, injection, access control, IDOR, JWT) and OpenAPI import.",
            "Comparing one request across privilege levels is authz.",
            "recon-probes",
            listOf("recon", "probe", "api_import_openapi"),
        ),
        Domain(
            "authz",
            "Authorization testing: auth-level diffing, live Autorize replay under lower-privilege identities, JWK key ring.",
            "JWT probing itself is recon (probe action=jwt); keys live here.",
            "recon-probes",
            listOf("auth_diff", "autorize", "jwt_keys"),
        ),
        Domain(
            "oob",
            "Burp Collaborator: payloads, clients and polling for out-of-band detection.",
            "Payloads only resolve while Burp runs.",
            "collaborator-oob",
            listOf("collaborator"),
        ),
        Domain(
            "turbo",
            "Turbo Python scripts on the Turbo request engine (high volume, custom timing, HTTP/2, HTTP/3) and their docs.",
            "Read turbo_docs before turbo_run; a plain payload list is http_fuzz (http).",
            "turbo-scripting",
            listOf("turbo_run", "turbo_docs"),
        ),
        Domain(
            "analysis",
            "Offline analysis of requests, responses and traffic (no new traffic is sent unless stated), plus encode/decode/hash/compress helpers.",
            ".burp files without Burp are history.",
            "http-testing",
            listOf("analyze", "util"),
        ),
        Domain(
            "findings",
            "Findings you record, the event feed and the Raijin log.",
            "Scanner-found issues are scanner.",
            "findings-reporting",
            listOf("findings", "events", "log"),
        ),
        Domain(
            "settings",
            "Burp itself (version, project, config, tasks), target scope, proxy listeners and match/replace, persistence, Burp AI.",
            "Check scope here before sending traffic.",
            "overview",
            listOf("burp", "config", "scope", "persistence", "ai"),
        ),
    )

    private val domainOf: Map<String, String> = DOMAINS.flatMap { d -> d.tools.map { it to d.name } }.toMap()

    /**
     * `catalog/tools.json`: the domains, every published tool's schema and annotations (tools sorted
     * by name), and `aliases`: each grouped member name mapped to its `{tool, action}`.
     */
    fun catalogJson(tools: Collection<Tool>): JsonObject = buildJsonObject {
        put("schema_version", 1)
        putJsonArray("excluded") { EXCLUDED.sorted().forEach { add(it) } }
        putJsonArray("domains") {
            DOMAINS.forEach { d ->
                addJsonObject {
                    put("name", d.name)
                    put("description", d.description)
                    put("notes", d.notes)
                    put("skill", d.skill)
                    putJsonArray("tools") { d.tools.forEach { add(it) } }
                }
            }
        }
        putJsonArray("tools") {
            tools.sortedBy { it.name }.forEach { tool ->
                addJsonObject {
                    put("name", tool.name)
                    put("description", tool.description)
                    putJsonObject("inputSchema") {
                        put("type", "object")
                        put("properties", tool.inputSchema.properties ?: JsonObject(emptyMap()))
                        putJsonArray("required") { tool.inputSchema.required.orEmpty().forEach { add(it) } }
                    }
                    put("domain", domainOf[tool.name])
                    tool.annotations?.let { a ->
                        putJsonObject("annotations") {
                            a.readOnlyHint?.let { put("readOnlyHint", it) }
                            a.destructiveHint?.let { put("destructiveHint", it) }
                            a.idempotentHint?.let { put("idempotentHint", it) }
                            a.openWorldHint?.let { put("openWorldHint", it) }
                        }
                    }
                }
            }
        }
        putJsonObject("aliases") {
            ToolConsolidation.GROUPS
                .flatMap { g -> g.actions.map { (action, member) -> Triple(member, g.tool, action) } }
                .filter { it.first != it.second }
                .sortedBy { it.first }
                .forEach { (member, tool, action) ->
                    putJsonObject(member) { put("tool", tool); put("action", action) }
                }
        }
    }
}
