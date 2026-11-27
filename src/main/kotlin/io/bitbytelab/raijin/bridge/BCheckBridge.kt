package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.core.EnumValidation
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.state.StateManager
import java.time.Instant
import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.serialization.json.*

data class DeployedBCheck(
    val id: String,
    val name: String,
    val type: String,
    val script: String,
    val deployedAt: String,
)

/**
 * A `bcheck_create` definition with every default and fallback resolved, so the script emitter and
 * the dry run act on the same decisions.
 */
internal sealed interface BCheckSpec {

    /**
     * One comparison in the generated script.
     *
     * @property location which part of a message, named as [CheckCondition.location] names it.
     * @property regex true for `matches`, false for `is`.
     * @property value the regex or the exact text.
     */
    class Match(val location: String, val regex: Boolean, val value: String) {
        /** The same comparison for the dry run. BCheck comparisons are case-sensitive. */
        fun condition(): CheckCondition =
            CheckCondition(location, value, if (regex) "matches" else "equals", ignoreCase = false)
    }

    class Passive(val onRequest: Boolean, val match: Match) : BCheckSpec

    class InsertionPoint(val payloads: List<String>, val match: Match) : BCheckSpec

    class Host(val path: String, val match: Match) : BCheckSpec

    class Path(val suffixes: List<String>, val match: Match?) : BCheckSpec

    class Collaborator(val header: String, val valueTemplate: String, val interaction: String) :
        BCheckSpec
}

/**
 * A BCheck dry run: it is shown history items, then says what the check would have done with them.
 *
 * @property parts the message parts it looks at; nothing else has to be read from the history.
 */
internal class BCheckDryRun(
    val parts: Set<String>,
    val visit: (HistoryItem) -> Unit,
    val result: () -> JsonObject,
    val note: String,
)

class BCheckBridge(
    private val api: MontoyaApi,
    private val stateManager: StateManager,
) {
    private val deployedChecks = CopyOnWriteArrayList<DeployedBCheck>()

    /**
     * Generate a BCheck script from high-level parameters and import it. This is the KEY method —
     * the AI agent describes WHAT to check, this generates the HOW.
     */
    fun create(
        name: String,
        description: String,
        author: String?,
        tags: String?,
        type: String, // passive_response, passive_request, insertion_point, host_level, path_level,
        // collaborator
        // Match conditions (for passive checks)
        matchPattern: String?, // Regex pattern to match
        matchLocation:
            String?, // response_body, response_headers, request_body, request_headers, status_code
        matchCondition: String?, // "matches", "contains", or "is"
        // Active check params
        payloads: List<String>?, // Payloads to inject (for insertion_point type)
        responseMatchPattern: String?, // What to look for in the response after injection
        // Collaborator params
        collaboratorPayloadType: String?, // dns, http
        // Issue reporting
        severity: String, // high, medium, low, information
        confidence: String, // certain, firm, tentative
        issueDetail: String?,
        issueRemediation: String?,
        path: String? = null, // Path a host_level check requests (default "/")
    ): JsonObject {
        // Validate all closed-set parameters BEFORE emitting or importing any DSL.
        // A bad enum here must return a clean structured error, never a deployed check.
        validateInputs(type, severity, confidence, matchCondition)?.let {
            return it
        }
        if (name.isBlank()) return errorJson("name must not be blank")
        // What the type needs: a non-empty pattern (an empty one matches every message), a valid
        // regex, payloads to send. Rejected here rather than by Burp's importer, or not at all.
        definitionError(
                type,
                matchPattern,
                matchLocation,
                matchCondition,
                payloads,
                responseMatchPattern,
                collaboratorPayloadType,
                path,
            )
            ?.let {
                return errorJson(it)
            }

        val script =
            emitScript(
                name,
                description,
                author ?: "Raijin AI Agent",
                tags ?: "ai-generated",
                type,
                matchPattern,
                matchLocation,
                matchCondition,
                payloads,
                responseMatchPattern,
                collaboratorPayloadType,
                severity,
                confidence,
                issueDetail,
                issueRemediation,
                path,
            )

        // Import into Burp
        return importScript(script, name, type.trim().lowercase())
    }

    /**
     * Shows what a `bcheck_create` definition would do with the proxy history Burp has already
     * recorded. Nothing is imported and nothing is sent.
     *
     * A passive check is evaluated in full: which recorded messages it would report. A check that
     * sends requests cannot be, so the result says how much it would send and what the history
     * already shows: responses that carry the pattern before any payload (insertion_point), or
     * recorded responses for the very paths the check would request (host_level, path_level).
     *
     * The parameters up to [path] are those of [create]. [urlPattern], [inScopeOnly] and [maxItems]
     * choose the history items read (the newest [maxItems] that match); [maxMatches] is how many
     * matches are listed in full.
     */
    fun dryRun(
        type: String,
        matchPattern: String?,
        matchLocation: String?,
        matchCondition: String?,
        payloads: List<String>?,
        responseMatchPattern: String?,
        collaboratorPayloadType: String?,
        path: String?,
        urlPattern: String?,
        inScopeOnly: Boolean,
        maxItems: Int?,
        maxMatches: Int?,
    ): JsonObject {
        validateInputs(type, DRY_RUN_SEVERITY, DRY_RUN_CONFIDENCE, matchCondition)?.let {
            return it
        }
        return try {
            val spec =
                resolve(
                    type,
                    matchPattern,
                    matchLocation,
                    matchCondition,
                    payloads,
                    responseMatchPattern,
                    collaboratorPayloadType,
                    path,
                )
            val filter = HistoryFilter.of(urlPattern, inScopeOnly, maxItems)
            val run = dryRunOf(spec, HistoryFilter.matchLimit(maxMatches))
            val script =
                emitScript(
                    "Dry run",
                    "Dry run of a bcheck_create definition",
                    "Raijin",
                    "dry-run",
                    type,
                    matchPattern,
                    matchLocation,
                    matchCondition,
                    payloads,
                    responseMatchPattern,
                    collaboratorPayloadType,
                    DRY_RUN_SEVERITY,
                    DRY_RUN_CONFIDENCE,
                    null,
                    null,
                    path,
                )
            val historySize = HistorySampler(api).forEach(filter, run.parts, run.visit)
            val report =
                dryRunReport(type.trim().lowercase(), historySize, filter, run.result(), run.note)
            JsonObject(report + ("script" to JsonPrimitive(script)))
        } catch (e: IllegalArgumentException) {
            errorJson(e.message ?: "Invalid BCheck definition")
        } catch (e: InvalidCheckException) {
            errorJson(e.message ?: "Invalid dry run parameters")
        } catch (e: Exception) {
            errorJson("Dry run failed: ${e.message}")
        }
    }

    /** Import a raw BCheck script string directly. */
    fun importRaw(script: String): JsonObject {
        // Extract name from the script metadata
        val nameMatch = BCHECK_NAME.find(script.take(4096))
        val name = nameMatch?.groupValues?.get(1) ?: "unnamed-bcheck"
        val typeGuess =
            when {
                script.contains("given insertion point") -> "insertion_point"
                script.contains("given host") -> "host_level"
                script.contains("given path") -> "path_level"
                script.contains("collaborator") -> "collaborator"
                script.contains("given response") -> "passive_response"
                script.contains("given request") -> "passive_request"
                else -> "unknown"
            }

        return importScript(script, name, typeGuess)
    }

    private fun importScript(script: String, name: String, type: String): JsonObject {
        return try {
            val result = api.scanner().bChecks().importBCheck(script)

            // Burp returns a status even when the script is syntactically parseable
            // but semantically invalid. Only treat LOADED_WITHOUT_ERRORS as success;
            // otherwise the BCheck is NOT active and must not be recorded as deployed.
            if (
                result.status() !=
                    burp.api.montoya.scanner.bchecks.BCheckImportResult.Status.LOADED_WITHOUT_ERRORS
            ) {
                return buildJsonObject {
                    put("status", "error")
                    put("imported", false)
                    put("name", name)
                    put("type", type)
                    put("errors", buildJsonArray { result.importErrors().forEach { add(it) } })
                    put("script", script)
                    put(
                        "hint",
                        "Check the BCheck syntax. Common issues: missing metadata, wrong scope keyword, invalid regex.",
                    )
                }
            }

            val id = stateManager.generateId("bcheck")
            deployedChecks.add(
                DeployedBCheck(
                    id = id,
                    name = name,
                    type = type,
                    script = script,
                    deployedAt = Instant.now().toString(),
                ),
            )

            buildJsonObject {
                put("id", id)
                put("name", name)
                put("type", type)
                put("status", "deployed")
                put("deployed_at", Instant.now().toString())
                put("script", script)
                putJsonArray("notes") {
                    add(
                        "BCheck is now active. It will run on all future scans and can also check existing proxy history.",
                    )
                }
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to import BCheck: ${e.message}")
                put("script", script)
                put(
                    "hint",
                    "Check the BCheck syntax. Common issues: missing metadata, wrong scope keyword, invalid regex.",
                )
            }
        }
    }

    /** List all BChecks deployed via MCP. */
    fun list(): JsonObject {
        return buildJsonObject {
            put("count", deployedChecks.size)
            put(
                "checks",
                buildJsonArray {
                    deployedChecks.forEach { check ->
                        add(
                            buildJsonObject {
                                put("id", check.id)
                                put("name", check.name)
                                put("type", check.type)
                                put("deployed_at", check.deployedAt)
                                put("script_preview", check.script.take(200))
                            },
                        )
                    }
                },
            )
        }
    }

    /**
     * Remove a deployed BCheck by ID. Note: The Montoya API may not support removing individual
     * BChecks. We track removal in our state but Burp may need manual removal.
     */
    fun remove(id: String): JsonObject {
        val check =
            deployedChecks.find { it.id == id }
                ?: return buildJsonObject { put("error", "BCheck not found: $id") }

        deployedChecks.removeIf { it.id == id }

        return buildJsonObject {
            put("id", id)
            put("name", check.name)
            // Montoya cannot unload a BCheck: only the MCP list forgets it, and it keeps running.
            put("still_active_in_burp", true)
            putJsonArray("notes") {
                add(
                    "delete it in Extensions > Custom scan checks ('${check.name}'); until then it runs on every scan",
                )
            }
        }
    }

    /** Clears MCP tracking list on extension unload. */
    fun shutdown() {
        deployedChecks.clear()
    }

    /** Get BCheck script by ID (full script content). */
    fun getScript(id: String): JsonObject {
        val check =
            deployedChecks.find { it.id == id }
                ?: return buildJsonObject { put("error", "BCheck not found: $id") }

        return buildJsonObject {
            put("id", check.id)
            put("name", check.name)
            put("type", check.type)
            put("script", check.script)
        }
    }

    /**
     * Return all BCheck templates with descriptions and example code. This teaches the AI agent the
     * BCheck DSL patterns.
     */
    fun getTemplates(): JsonObject {
        return buildJsonObject {
            put("template_count", 7)
            put("bcheck_dsl_version", "v2-beta")
            put(
                "templates",
                buildJsonArray {

                    // Template 1: Passive Response Check
                    add(
                        buildJsonObject {
                            put("type", "passive_response")
                            put("name", "Response-level passive check")
                            put(
                                "description",
                                "Matches patterns in HTTP responses. Runs on every response during passive scanning.",
                            )
                            put(
                                "use_cases",
                                "Detect leaked API keys, exposed stack traces, sensitive data in responses, security header misconfigurations",
                            )
                            put(
                                "example",
                                """
                                metadata:
                                    language: v2-beta
                                    name: "Leaked AWS Access Key"
                                    description: "Detects AWS Access Key IDs in HTTP responses"
                                    author: "Raijin"
                                    tags: "aws", "secrets", "passive"

                                given response then
                                    if {latest.response.body} matches "AKIA[0-9A-Z]{16}" then
                                        report issue:
                                            severity: high
                                            confidence: firm
                                            detail: `AWS Access Key ID found in response body.`
                                            remediation: `Remove all hardcoded AWS credentials from application responses. Use environment variables or AWS Secrets Manager instead.`
                                    end if
                                """
                                    .trimIndent(),
                            )
                        },
                    )

                    // Template 2: Passive Request Check
                    add(
                        buildJsonObject {
                            put("type", "passive_request")
                            put("name", "Request-level passive check")
                            put(
                                "description",
                                "Matches patterns in HTTP requests. Useful for detecting insecure client-side patterns.",
                            )
                            put(
                                "use_cases",
                                "Detect credentials in URLs, insecure auth patterns, sensitive data in query strings",
                            )
                            put(
                                "example",
                                """
                                metadata:
                                    language: v2-beta
                                    name: "Password in URL"
                                    description: "Detects passwords being sent in URL query parameters"
                                    author: "Raijin"
                                    tags: "credentials", "passive"

                                given request then
                                    if {base.request.url} matches "(?i)(password|passwd|pwd|secret)=[^&]+" then
                                        report issue:
                                            severity: high
                                            confidence: certain
                                            detail: `Password or secret value detected in URL query parameters. This is logged in server access logs, browser history, and proxy logs.`
                                            remediation: `Send sensitive values in the request body (POST) instead of query parameters (GET). Use HTTPS for all authentication endpoints.`
                                    end if
                                """
                                    .trimIndent(),
                            )
                        },
                    )

                    // Template 3: Insertion Point (Active)
                    add(
                        buildJsonObject {
                            put("type", "insertion_point")
                            put("name", "Insertion-point-level active check")
                            put(
                                "description",
                                "Injects payloads at each parameter and analyzes the response. The core of active scanning.",
                            )
                            put(
                                "use_cases",
                                "Custom injection detection, input transformation detection, technology fingerprinting via error messages",
                            )
                            put(
                                "example",
                                """
                                metadata:
                                    language: v2-beta
                                    name: "Server-side template injection (basic)"
                                    description: "Detects basic SSTI by injecting a math expression"
                                    author: "Raijin"
                                    tags: "ssti", "injection", "active"

                                define:
                                    probe = "${'$'}{1337*1337}"
                                    answer = "1787569"

                                given insertion point then
                                    # the answer must not already be in the response to the unmodified request
                                    if not({answer} in {base.response.body}) then
                                        send payload called check_ssti:
                                            replacing: {probe}

                                        if {answer} in {check_ssti.response.body} then
                                            report issue:
                                                severity: high
                                                confidence: firm
                                                detail: `Server-side template injection detected. The expression {probe} was evaluated: the response contains {answer}, which the unmodified response does not.`
                                                remediation: `Never pass user input directly into template engines. Use template engines in sandboxed mode. Validate and sanitize all user input before template processing.`
                                        end if
                                    end if
                                """
                                    .trimIndent(),
                            )
                        },
                    )

                    // Template 4: Host Level
                    add(
                        buildJsonObject {
                            put("type", "host_level")
                            put("name", "Host-level check")
                            put(
                                "description",
                                "Runs once per unique host. Good for infrastructure checks.",
                            )
                            put(
                                "use_cases",
                                "Exposed git directories, admin panels, backup files, directory listings, server version detection",
                            )
                            put(
                                "example",
                                """
                                metadata:
                                    language: v2-beta
                                    name: "Exposed .git directory"
                                    description: "Checks if .git directory is publicly accessible"
                                    author: "Raijin"
                                    tags: "git", "exposure", "host"

                                given host then
                                    send request called git_check:
                                        method: "GET"
                                        path: "/.git/config"

                                    if {git_check.response.status_code} is "200" and
                                        {git_check.response.body} matches "\[core\]" then
                                        report issue:
                                            severity: high
                                            confidence: certain
                                            detail: `The .git directory is publicly accessible. An attacker can download the entire source code repository, including commit history, branches, and potentially sensitive configuration files.`
                                            remediation: "Block access to .git directories in your web server configuration."
                                    end if
                                """
                                    .trimIndent(),
                            )
                        },
                    )

                    // Template 5: Path Level
                    add(
                        buildJsonObject {
                            put("type", "path_level")
                            put("name", "Path-level check")
                            put(
                                "description",
                                "Runs once per unique path. Good for testing backup/alternate extensions.",
                            )
                            put(
                                "use_cases",
                                "Backup file detection (.bak, .old, ~), alternate file extensions, source code exposure",
                            )
                            put(
                                "example",
                                """
                                metadata:
                                    language: v2-beta
                                    name: "Backup file detection"
                                    description: "Checks for common backup file extensions"
                                    author: "Raijin"
                                    tags: "backup", "exposure", "path"

                                run for each:
                                    extension = ".bak", ".old", ".orig", ".save", ".swp", "~", ".tmp"

                                given path then
                                    send request called backup_check:
                                        method: "GET"
                                        replacing path: `{base.request.url.path}{extension}`

                                    if {backup_check.response.status_code} is "200" then
                                        # a site that answers 200 to anything is not serving a backup file
                                        send request called garbage_check:
                                            method: "GET"
                                            replacing path: `{base.request.url.path}.{random_str(10)}`

                                        if {garbage_check} differs from {backup_check} then
                                            report issue and continue:
                                                severity: medium
                                                confidence: tentative
                                                detail: `A backup file was found at {backup_check.request.url}. Backup files may contain source code, configuration details, or other sensitive information.`
                                                remediation: `Remove all backup files from production servers. Configure your deployment process to exclude backup files.`
                                        end if
                                    end if
                                """
                                    .trimIndent(),
                            )
                        },
                    )

                    // Template 6: Collaborator (OOB)
                    add(
                        buildJsonObject {
                            put("type", "collaborator")
                            put("name", "Request-level collaborator check")
                            put(
                                "description",
                                "Uses Burp Collaborator for out-of-band (OOB) testing. Injects collaborator payloads and monitors for DNS/HTTP callbacks.",
                            )
                            put(
                                "use_cases",
                                "Blind SSRF detection, blind XXE, blind command injection, DNS exfiltration",
                            )
                            put(
                                "example",
                                """
                                metadata:
                                    language: v2-beta
                                    name: "Blind SSRF via Referer header"
                                    description: "Tests for blind SSRF by injecting a collaborator URL in the Referer header"
                                    author: "Raijin"
                                    tags: "ssrf", "blind", "oob", "collaborator"

                                given request then
                                    send request called ssrf_test:
                                        replacing headers:
                                            "Referer": `https://{generate_collaborator_address()}/ssrf-test`

                                    if dns interactions then
                                        report issue:
                                            severity: high
                                            confidence: firm
                                            detail: `Blind SSRF detected via Referer header. The server made a DNS lookup to the collaborator address injected in the Referer header, indicating it processes and follows URLs from this header.`
                                            remediation: `Validate and sanitize all URLs derived from user input. Implement allowlists for permitted external domains. Block outbound requests to internal network ranges.`
                                    end if
                                """
                                    .trimIndent(),
                            )
                        },
                    )

                    // Template 7: Multi-step with define block
                    add(
                        buildJsonObject {
                            put("type", "multi_step")
                            put("name", "Multi-step with variables")
                            put(
                                "description",
                                "A check with a variable, a modified request and two conditions that must both hold. Use define for a single value and run for each (before given) to repeat the check per value.",
                            )
                            put(
                                "use_cases",
                                "Complex vulnerability detection requiring multiple requests, IDOR verification, authentication bypass chains",
                            )
                            put(
                                "example",
                                """
                                metadata:
                                    language: v2-beta
                                    name: "CORS misconfiguration"
                                    description: "Tests for permissive CORS configurations"
                                    author: "Raijin"
                                    tags: "cors", "misconfiguration"

                                define:
                                    evil_origin = "https://evil.example"

                                given request then
                                    send request called cors_test:
                                        replacing headers:
                                            "Origin": {evil_origin}

                                    if {cors_test.response.headers} matches "(?i)access-control-allow-origin:\s*https://evil\.example" and
                                        {cors_test.response.headers} matches "(?i)access-control-allow-credentials:\s*true" then
                                        report issue:
                                            severity: high
                                            confidence: firm
                                            detail: `CORS misconfiguration detected. The server reflects the Origin header {evil_origin} in Access-Control-Allow-Origin while also setting Access-Control-Allow-Credentials: true. This allows an attacker-controlled domain to read authenticated responses cross-origin.`
                                            remediation: `Implement a strict allowlist of permitted origins. Never reflect arbitrary Origin values when Access-Control-Allow-Credentials is true.`
                                    end if
                                """
                                    .trimIndent(),
                            )
                        },
                    )
                },
            )

            put(
                "dsl_reference",
                buildJsonObject {
                    put(
                        "metadata_fields",
                        buildJsonArray {
                            add("language: v2-beta (required)")
                            add("name: \"Check name\" (required)")
                            add("description: \"What it does\" (required)")
                            add("author: \"Author name\"")
                            add("tags: \"tag1\", \"tag2\"")
                        },
                    )
                    put(
                        "scope_keywords",
                        buildJsonArray {
                            add("given response then - passive, runs on every response")
                            add("given request then - runs once per request; may send requests")
                            add(
                                "given insertion point then - active, runs at each insertion point (any | query | header | body | cookie insertion point)",
                            )
                            add("given host then - once per unique host")
                            add("given path then - once per unique path")
                        },
                    )
                    put(
                        "variables_and_loops",
                        buildJsonArray {
                            add(
                                "define: name = \"value\" - a variable; placed after metadata, before given",
                            )
                            add(
                                "run for each: name = \"a\", \"b\" - placed before given; the check runs once per value",
                            )
                        },
                    )
                    put(
                        "request_operations",
                        buildJsonArray {
                            add("send request called <name>: method: \"GET\" path: \"/test\"")
                            add(
                                "send payload called <name>: replacing: \"payload\" (or appending:) - insertion point checks only",
                            )
                            add(
                                "replacing headers: \"Name\": \"value\", \"Other\": {variable} - under send request; also appending headers, removing headers",
                            )
                            add(
                                "replacing path / appending path / replacing queries / replacing body - under send request",
                            )
                        },
                    )
                    put(
                        "conditions",
                        buildJsonArray {
                            add(
                                "{var.response.body} matches \"regex\" - Java regex found in the text",
                            )
                            add("{var.response.status_code} is \"200\"")
                            add("\"text\" in {var.response.body} - substring test")
                            add("{a} differs from {b} - two responses differ")
                            add(
                                "dns interactions | http interactions | smtp interactions | any interactions - Collaborator callbacks",
                            )
                            add("not(...) - negate a condition")
                            add("... and ... - combine conditions")
                            add("... or ... - alternative conditions; use brackets to group")
                        },
                    )
                    put(
                        "strings",
                        buildJsonArray {
                            add(
                                "\"literal\" - taken as written: { and \\ are plain characters, \\\" is a quote. A regex after matches must be a literal",
                            )
                            add(
                                "`interpolated` - {variable} is replaced. Write \\{ for a brace, \\\\ for a backslash, \\` for a backtick; \\n \\r \\t \\s are line feed, carriage return, tab, space",
                            )
                        },
                    )
                    put(
                        "variables",
                        buildJsonArray {
                            add("{base.request.url} - original request URL")
                            add("{base.request.url.path} - original request path")
                            add("{base.request.method} - original request method")
                            add("{base.request.body} - original request body")
                            add(
                                "{base.response.body} - response to the original request (the baseline)",
                            )
                            add("{latest.response.body} - most recent response body")
                            add("{latest.response.status_code} - most recent status code")
                            add("{latest.response.headers} - most recent response headers")
                            add("{generate_collaborator_address()} - generate OOB payload")
                            add("{random_str(10)} - random string of that length")
                        },
                    )
                    put(
                        "reporting",
                        buildJsonArray {
                            add(
                                "report issue: - reports and ends the check; report issue and continue: - reports and goes on",
                            )
                            add("severity: info | low | medium | high")
                            add("confidence: certain | firm | tentative")
                            add("detail: `Issue description with {variables}`")
                            add("remediation: `How to fix`")
                        },
                    )
                },
            )
        }
    }

    fun getDeployedChecks(): List<DeployedBCheck> = deployedChecks.toList()

    private fun errorJson(message: String): JsonObject = buildJsonObject { put("error", message) }

    companion object {
        // Closed sets accepted by the v2-beta BCheck DSL. Anything outside these
        // sets must be rejected up front — an unknown value silently emitted into
        // the generated DSL either fails to import or (worse, for `type`) produces
        // a degenerate `matches ""` check that fires on every response.
        internal val ALLOWED_SEVERITIES = setOf("high", "medium", "low", "information")
        internal val ALLOWED_CONFIDENCES = setOf("certain", "firm", "tentative")
        internal val ALLOWED_TYPES =
            setOf(
                "passive_response",
                "passive_request",
                "insertion_point",
                "host_level",
                "path_level",
                "collaborator",
            )
        // The grammar only supports `matches` and `is`. `contains` is advertised by
        // the tool schema as a convenience and is translated to an escaped-substring
        // `matches` regex — see [normalizeCondition].
        internal val ALLOWED_CONDITIONS = setOf("matches", "is", "contains")
        internal val ALLOWED_INTERACTIONS = setOf("dns", "http")

        /**
         * `match_location` values of a passive_response check, as [CheckCondition.location] names.
         */
        private val RESPONSE_LOCATIONS =
            mapOf(
                "response_body" to "response_body",
                "body" to "response_body",
                "response_headers" to "response_headers",
                "headers" to "response_headers",
                "status_code" to "status_code",
            )

        /** `match_location` values of a passive_request check. */
        private val REQUEST_LOCATIONS =
            mapOf(
                "request_url" to "request_url",
                "url" to "request_url",
                "request_headers" to "request_headers",
                "headers" to "request_headers",
                "request_body" to "request_body",
                "body" to "request_body",
            )

        private val DEFAULT_SUFFIXES = listOf(".bak", ".old", ".orig", ".swp", "~")
        private const val COLLABORATOR_ADDRESS = "{generate_collaborator_address()}"
        private const val DRY_RUN_SEVERITY = "information"
        private const val DRY_RUN_CONFIDENCE = "tentative"

        /**
         * Validate every closed-set parameter that feeds the DSL emitter. Returns a clean
         * `{"error": ...}` object on the first bad value, or null when all pass. Kept pure/static
         * so it can be unit-tested without a live Burp instance.
         */
        fun validateInputs(
            type: String,
            severity: String,
            confidence: String,
            matchCondition: String?,
        ): JsonObject? {
            EnumValidation.error(type, ALLOWED_TYPES, "type", required = true)?.let {
                return it
            }
            EnumValidation.error(severity, ALLOWED_SEVERITIES, "severity", required = true)?.let {
                return it
            }
            EnumValidation.error(confidence, ALLOWED_CONFIDENCES, "confidence", required = true)
                ?.let {
                    return it
                }
            // matchCondition is optional (defaults to "matches"); only validate when supplied.
            EnumValidation.error(
                    matchCondition,
                    ALLOWED_CONDITIONS,
                    "match_condition",
                    required = false,
                )
                ?.let {
                    return it
                }
            return null
        }

        /**
         * What is wrong with a definition beyond its enums, or null when a script can be emitted
         * for it: a missing or empty pattern, an invalid regex, a location the type does not have,
         * no payload to send.
         */
        internal fun definitionError(
            type: String,
            matchPattern: String?,
            matchLocation: String?,
            matchCondition: String?,
            payloads: List<String>?,
            responseMatchPattern: String?,
            collaboratorPayloadType: String?,
            path: String?,
        ): String? =
            try {
                resolve(
                    type,
                    matchPattern,
                    matchLocation,
                    matchCondition,
                    payloads,
                    responseMatchPattern,
                    collaboratorPayloadType,
                    path,
                )
                null
            } catch (e: IllegalArgumentException) {
                e.message ?: "Invalid BCheck definition"
            }

        /**
         * Resolves a definition's defaults and fallbacks into a [BCheckSpec].
         *
         * @throws IllegalArgumentException naming what is missing or invalid. An unsupported [type]
         *   is rejected here, never turned into a check that matches everything.
         */
        internal fun resolve(
            type: String,
            matchPattern: String?,
            matchLocation: String?,
            matchCondition: String?,
            payloads: List<String>?,
            responseMatchPattern: String?,
            collaboratorPayloadType: String?,
            path: String?,
        ): BCheckSpec {
            val kind = type.trim().lowercase()

            fun match(location: String, param: String, pattern: String?): BCheckSpec.Match {
                require(!pattern.isNullOrEmpty()) {
                    "$kind checks need a non-empty $param: an empty pattern matches every message"
                }
                val (operator, operand) = normalizeCondition(matchCondition, pattern)
                if (operator == "matches") {
                    regexError(operand)?.let {
                        throw IllegalArgumentException("Invalid $param regex: $it")
                    }
                }
                return BCheckSpec.Match(location, regex = operator == "matches", value = operand)
            }

            fun location(known: Map<String, String>, default: String): String {
                val given =
                    matchLocation?.trim()?.lowercase().takeUnless { it.isNullOrEmpty() }
                        ?: return default
                return known[given]
                    ?: throw IllegalArgumentException(
                        "match_location '$matchLocation' is not available for $kind checks. " +
                            "Allowed: ${known.keys.joinToString(", ")}",
                    )
            }

            return when (kind) {
                "passive_response" ->
                    BCheckSpec.Passive(
                        onRequest = false,
                        match =
                            match(
                                location(RESPONSE_LOCATIONS, "response_body"),
                                "match_pattern",
                                matchPattern,
                            ),
                    )

                "passive_request" ->
                    BCheckSpec.Passive(
                        onRequest = true,
                        match =
                            match(
                                location(REQUEST_LOCATIONS, "request_url"),
                                "match_pattern",
                                matchPattern,
                            ),
                    )

                "insertion_point" -> {
                    val response =
                        match(
                            "response_body",
                            "response_match_pattern",
                            responseMatchPattern ?: matchPattern,
                        )
                    // Without 'payloads', match_pattern is the payload when response_match_pattern
                    // says what to look for: the shape this tool had before it took a payload list.
                    val sent =
                        payloads
                            .orEmpty()
                            .filter { it.isNotEmpty() }
                            .ifEmpty {
                                listOfNotNull(
                                    matchPattern?.takeIf {
                                        it.isNotEmpty() && responseMatchPattern != null
                                    },
                                )
                            }
                    require(sent.isNotEmpty()) {
                        "insertion_point checks need 'payloads' to inject"
                    }
                    BCheckSpec.InsertionPoint(sent, response)
                }

                "host_level" -> {
                    // Before 'path' existed, match_pattern was the path whenever it looked like
                    // one.
                    val pathFromPattern = matchPattern?.takeIf {
                        path == null && it.startsWith("/")
                    }
                    val probe = path ?: pathFromPattern ?: "/"
                    require(probe.isNotBlank()) { "host_level checks need a non-blank path" }
                    val body =
                        responseMatchPattern ?: matchPattern.takeIf { pathFromPattern == null }
                    BCheckSpec.Host(probe, match("response_body", "response_match_pattern", body))
                }

                "path_level" ->
                    BCheckSpec.Path(
                        suffixes =
                            payloads
                                .orEmpty()
                                .filter { it.isNotEmpty() }
                                .ifEmpty { DEFAULT_SUFFIXES },
                        match =
                            responseMatchPattern
                                ?.takeIf { it.isNotEmpty() }
                                ?.let { match("response_body", "response_match_pattern", it) },
                    )

                "collaborator" -> {
                    val header = matchLocation ?: "Referer"
                    require(header.isNotBlank()) {
                        "collaborator checks need a header name in match_location"
                    }
                    val template = matchPattern ?: "https://$COLLABORATOR_ADDRESS"
                    require(COLLABORATOR_ADDRESS in template) {
                        "For a collaborator check, match_pattern is the header value to inject and must contain " +
                            "$COLLABORATOR_ADDRESS; without it nothing can call back"
                    }
                    val interaction =
                        collaboratorPayloadType?.trim()?.lowercase().takeUnless {
                            it.isNullOrEmpty()
                        } ?: "dns"
                    require(interaction in ALLOWED_INTERACTIONS) {
                        "Parameter 'collaborator_payload_type' has invalid value '$collaboratorPayloadType'. " +
                            "Allowed: ${ALLOWED_INTERACTIONS.joinToString(", ")}"
                    }
                    BCheckSpec.Collaborator(header, template, interaction)
                }

                else ->
                    throw IllegalArgumentException(
                        "Unsupported BCheck type '$type'. Allowed: ${ALLOWED_TYPES.sorted().joinToString(", ")}",
                    )
            }
        }

        /**
         * Pure BCheck v2-beta DSL emitter. No Burp/Montoya dependency, so it can be unit-tested
         * directly.
         *
         * Every caller-supplied string is written through [stringToken], [regexToken],
         * [metadataToken] or [interpolatedBody], so whatever it contains (quotes, backslashes,
         * backticks, braces, line breaks) it stays inside its string and is taken as text.
         *
         * @throws IllegalArgumentException for a definition [resolve] rejects, or a severity or
         *   confidence outside the grammar.
         */
        internal fun emitScript(
            name: String,
            description: String,
            author: String,
            tags: String,
            type: String,
            matchPattern: String?,
            matchLocation: String?,
            matchCondition: String?,
            payloads: List<String>?,
            responseMatchPattern: String?,
            collaboratorPayloadType: String?,
            severity: String,
            confidence: String,
            issueDetail: String?,
            issueRemediation: String?,
            path: String? = null,
        ): String {
            val spec =
                resolve(
                    type,
                    matchPattern,
                    matchLocation,
                    matchCondition,
                    payloads,
                    responseMatchPattern,
                    collaboratorPayloadType,
                    path,
                )

            // QA #32 (live-verified): Burp's BCheck v2-beta parser rejects `severity: information`
            // ("Unexpected token information") — it expects `info`. Callers still pass
            // "information"
            // (matching AuditIssueSeverity + the tool schema); we emit the token Burp accepts.
            val emitSeverity =
                when (val given = severity.trim().lowercase()) {
                    "information",
                    "info" -> "info"
                    "high",
                    "medium",
                    "low" -> given
                    else -> throw IllegalArgumentException("Unsupported severity '$severity'")
                }
            val emitConfidence = confidence.trim().lowercase()
            require(emitConfidence in ALLOWED_CONFIDENCES) {
                "Unsupported confidence '$confidence'"
            }

            val detail = issueDetail ?: "$name was detected."
            val remediation = issueRemediation ?: "Review and fix the identified issue."
            val sb = StringBuilder()

            fun report(indent: String, detailToken: String, action: String = "report issue") {
                sb.appendLine("$indent$action:")
                sb.appendLine("$indent    severity: $emitSeverity")
                sb.appendLine("$indent    confidence: $emitConfidence")
                sb.appendLine("$indent    detail: $detailToken")
                sb.appendLine("$indent    remediation: `${interpolatedBody(remediation)}`")
            }

            // Metadata
            sb.appendLine("metadata:")
            sb.appendLine("    language: v2-beta")
            sb.appendLine("    name: ${metadataToken(name)}")
            sb.appendLine("    description: ${metadataToken(description)}")
            sb.appendLine("    author: ${metadataToken(author)}")
            val tagList = tags.split(",").map { it.trim() }.filter { it.isNotEmpty() }
            if (tagList.isNotEmpty())
                sb.appendLine("    tags: ${tagList.joinToString(", ") { metadataToken(it) }}")
            sb.appendLine()

            when (spec) {
                is BCheckSpec.Passive -> {
                    sb.appendLine(
                        if (spec.onRequest) "given request then" else "given response then",
                    )
                    sb.appendLine(
                        "    if ${comparison(if (spec.onRequest) "base" else "latest", spec.match)} then",
                    )
                    report("        ", "`${interpolatedBody(detail)}`")
                    sb.appendLine("    end if")
                }

                is BCheckSpec.InsertionPoint -> {
                    // v2-beta does NOT support `run for each` over a define list under
                    // `given insertion point then` with `send payload`. Emit one distinct
                    // `send payload called p{n}` per payload, each with its own detection block.
                    //
                    // The outer `if` is the baseline guard: what the payloads are meant to provoke
                    // must not already be in the response to the unmodified request, or every
                    // insertion point of such a page would be reported.
                    sb.appendLine("given insertion point then")
                    sb.appendLine("    if not(${comparison("base", spec.match)}) then")
                    spec.payloads.forEachIndexed { index, payload ->
                        val pair = "p${index + 1}"
                        sb.appendLine("        send payload called $pair:")
                        sb.appendLine("            replacing: ${stringToken(payload)}")
                        sb.appendLine()
                        sb.appendLine("        if ${comparison(pair, spec.match)} then")
                        report(
                            "            ",
                            "`${interpolatedBody(detail)} Payload: ${interpolatedBody(payload)}`",
                        )
                        sb.appendLine("        end if")
                        if (index < spec.payloads.lastIndex) sb.appendLine()
                    }
                    sb.appendLine("    end if")
                }

                is BCheckSpec.Host -> {
                    sb.appendLine("given host then")
                    sb.appendLine("    send request called host_check:")
                    sb.appendLine("        method: \"GET\"")
                    sb.appendLine("        path: ${stringToken(spec.path)}")
                    sb.appendLine()
                    sb.appendLine("    if {host_check.response.status_code} is \"200\" and")
                    sb.appendLine("        ${comparison("host_check", spec.match)} then")
                    report("        ", "`${interpolatedBody(detail)}`")
                    sb.appendLine("    end if")
                }

                is BCheckSpec.Path -> {
                    // `run for each` declares the list and goes before `given`; the check then runs
                    // once per suffix. The second request asks for a path that cannot exist: a site
                    // that answers it the same way answers 200 to anything and has no backup file.
                    sb.appendLine("run for each:")
                    sb.appendLine(
                        "    extension = ${spec.suffixes.joinToString(", ") { stringToken(it) }}",
                    )
                    sb.appendLine()
                    sb.appendLine("given path then")
                    sb.appendLine("    send request called path_check:")
                    sb.appendLine("        method: \"GET\"")
                    sb.appendLine("        replacing path: `{base.request.url.path}{extension}`")
                    sb.appendLine()
                    if (spec.match == null) {
                        sb.appendLine("    if {path_check.response.status_code} is \"200\" then")
                    } else {
                        sb.appendLine("    if {path_check.response.status_code} is \"200\" and")
                        sb.appendLine("        ${comparison("path_check", spec.match)} then")
                    }
                    sb.appendLine("        send request called garbage_check:")
                    sb.appendLine("            method: \"GET\"")
                    sb.appendLine(
                        "            replacing path: `{base.request.url.path}.{random_str(10)}`",
                    )
                    sb.appendLine()
                    sb.appendLine("        if {garbage_check} differs from {path_check} then")
                    report(
                        "            ",
                        "`${interpolatedBody(detail)} Found at: {path_check.request.url}`",
                        action = "report issue and continue",
                    )
                    sb.appendLine("        end if")
                    sb.appendLine("    end if")
                }

                is BCheckSpec.Collaborator -> {
                    val value =
                        spec.valueTemplate.split(COLLABORATOR_ADDRESS).joinToString(
                            COLLABORATOR_ADDRESS,
                        ) {
                            interpolatedBody(it)
                        }
                    sb.appendLine("given request then")
                    sb.appendLine("    send request called collab_test:")
                    sb.appendLine("        replacing headers:")
                    sb.appendLine("            ${stringToken(spec.header)}: `$value`")
                    sb.appendLine()
                    sb.appendLine("    if ${spec.interaction} interactions then")
                    report("        ", "`${interpolatedBody(detail)}`")
                    sb.appendLine("    end if")
                }
            }

            return sb.toString()
        }

        /**
         * `{pair...} matches "regex"` or `{pair...} is "text"` for [match] on the request/response
         * pair [pair].
         */
        private fun comparison(pair: String, match: BCheckSpec.Match): String {
            val variable =
                when (match.location) {
                    "response_headers" -> "{$pair.response.headers}"
                    "status_code" -> "{$pair.response.status_code}"
                    "request_url" -> "{$pair.request.url}"
                    "request_headers" -> "{$pair.request.headers}"
                    "request_body" -> "{$pair.request.body}"
                    else -> "{$pair.response.body}"
                }
            return if (match.regex) "$variable matches ${regexToken(match.value)}"
            else "$variable is ${stringToken(match.value)}"
        }

        // BCheck has two kinds of string. A "literal" is taken as written: the only escape is \"
        // and a backslash is an ordinary character, so a literal cannot end in one (the backslash
        // would pair with the closing quote). An `interpolated` string substitutes {variables}
        // and reads \ as an escape character. A line break inside either is re-wrapped by Burp
        // (line endings replaced, each line trimmed), so none is ever emitted raw.

        /** [text] for inside a `"literal"`. */
        internal fun literalBody(text: String): String = text.replace("\"", "\\\"")

        /**
         * [text] for inside an `` `interpolated` `` string, so that it comes out as exactly [text].
         */
        internal fun interpolatedBody(text: String): String =
            buildString(text.length + 8) {
                for (c in text) {
                    when (c) {
                        '\\' -> append("\\\\")
                        '`' -> append("\\`")
                        '{' -> append("\\{")
                        '\r' -> append("\\r")
                        '\n' -> append("\\n")
                        else -> append(c)
                    }
                }
            }

        /**
         * One string token whose value is exactly [text]: a literal where a literal can hold it, an
         * escaped interpolated string for a trailing backslash or a line break.
         */
        internal fun stringToken(text: String): String =
            if (text.endsWith('\\') || text.any { it == '\r' || it == '\n' })
                "`${interpolatedBody(text)}`"
            else "\"${literalBody(text)}\""

        /**
         * [pattern] as the operand of `matches`, which has to be a literal. A line break becomes
         * its regex escape. A pattern ending in an escaped backslash gets an empty group appended,
         * which matches nothing extra and keeps the backslash off the closing quote.
         */
        internal fun regexToken(pattern: String): String {
            val oneLine =
                buildString(pattern.length + 8) {
                    var escaped = false
                    for (c in pattern) {
                        when (c) {
                            // After an escaping backslash the pair already means "this character".
                            '\n' -> append(if (escaped) "n" else "\\n")
                            '\r' -> append(if (escaped) "r" else "\\r")
                            else -> append(c)
                        }
                        escaped = !escaped && c == '\\'
                    }
                }
            return "\"" +
                literalBody(if (oneLine.endsWith('\\')) "$oneLine(?:)" else oneLine) +
                "\""
        }

        /**
         * [text] as a metadata literal: one line, as Burp's UI shows it, and never ending in a
         * backslash.
         */
        internal fun metadataToken(text: String): String {
            val oneLine = text.replace(LINE_BREAKS, " ").trim()
            return "\"" + literalBody(if (oneLine.endsWith('\\')) "$oneLine " else oneLine) + "\""
        }

        private val LINE_BREAKS = Regex("[\\r\\n]+")

        /** Why [pattern] cannot be the regex of a `matches`, or null. */
        private fun regexError(pattern: String): String? {
            SafeRegex.validate(pattern)?.let {
                return it
            }
            // Java accepts a lone trailing backslash inside an unterminated \Q quote; a literal
            // cannot end in one.
            val trailing = pattern.length - pattern.trimEnd('\\').length
            return if (trailing % 2 == 1) "the pattern ends in a backslash that escapes nothing"
            else null
        }

        /**
         * The v2-beta grammar only supports the operators `matches` (regex) and `is` (exact string
         * equality). The tool schema also advertises `contains`, which the grammar has no direct
         * operator for — translate it to a `matches` over the regex-escaped substring so the
         * emitted DSL is always valid.
         *
         * Returns the operator to emit and the (already regex-safe) pattern to compare against.
         * `matches`/`is` pass the pattern through unchanged; `contains` escapes every regex
         * metacharacter in the pattern so it is treated as a literal.
         */
        internal fun normalizeCondition(condition: String?, pattern: String): Pair<String, String> {
            return when (condition?.trim()?.lowercase()) {
                "is" -> "is" to pattern
                "contains" -> "matches" to regexEscapeLiteral(pattern)
                else -> "matches" to pattern // default and explicit "matches"
            }
        }

        /**
         * Escape every regex metacharacter so [literal] is matched verbatim inside a `matches`
         * regex. Used to implement the `contains` convenience operator.
         */
        internal fun regexEscapeLiteral(literal: String): String {
            val sb = StringBuilder(literal.length + 8)
            for (c in literal) {
                if (c in "\\.^$|?*+()[]{}") sb.append('\\')
                sb.append(c)
            }
            return sb.toString()
        }

        /**
         * The dry run of [spec]: what to count over the history, and how to read the counts.
         *
         * @param maxMatches how many matches to list in full.
         */
        internal fun dryRunOf(spec: BCheckSpec, maxMatches: Int): BCheckDryRun =
            when (spec) {
                is BCheckSpec.Passive -> {
                    val run =
                        PassiveDryRun(listOf(spec.match.condition()), MatchMode.ALL, maxMatches)
                    BCheckDryRun(
                        run.parts,
                        run::visit,
                        run::toJson,
                        "would_report counts the recorded messages the BCheck flags; Burp consolidates them per path.",
                    )
                }

                is BCheckSpec.InsertionPoint -> {
                    val guard =
                        ActiveStep(spec.payloads.joinToString(", "), listOf(spec.match.condition()))
                    val run = BaselineDryRun(listOf(guard), maxMatches)
                    BCheckDryRun(
                        run.parts,
                        run::visit,
                        run::toJson,
                        "No payload was sent. baseline_matches counts recorded responses that already show the response " +
                            "pattern: the generated BCheck skips those requests, and a high count means the pattern is too broad.",
                    )
                }

                is BCheckSpec.Host -> {
                    val conditions = listOf(STATUS_200, spec.match.condition())
                    val run = ProbeDryRun({ it == spec.path }, conditions, maxMatches)
                    BCheckDryRun(
                        run.parts,
                        run::visit,
                        {
                            JsonObject(
                                run.toJson() +
                                    mapOf(
                                        "hosts" to JsonPrimitive(run.hostCount),
                                        "probe_requests" to JsonPrimitive(run.hostCount),
                                    ),
                            )
                        },
                        "A scan would send one GET ${spec.path} to each of the hosts. recorded_hits are recorded responses " +
                            "for that path that already meet the check's conditions; none recorded does not mean none exists.",
                    )
                }

                is BCheckSpec.Path -> {
                    val conditions = listOfNotNull(STATUS_200, spec.match?.condition())
                    val run =
                        ProbeDryRun(
                            { path -> spec.suffixes.any { path.endsWith(it) } },
                            conditions,
                            maxMatches,
                        )
                    BCheckDryRun(
                        run.parts,
                        run::visit,
                        {
                            JsonObject(
                                run.toJson() +
                                    mapOf(
                                        "distinct_paths" to JsonPrimitive(run.pathCount),
                                        "probe_requests" to
                                            JsonPrimitive(run.pathCount * spec.suffixes.size),
                                    ),
                            )
                        },
                        "A scan would request every recorded path with each suffix (probe_requests, plus one comparison " +
                            "request per 200 answer). recorded_hits are recorded 200 responses whose path already ends in a suffix.",
                    )
                }

                is BCheckSpec.Collaborator -> {
                    val run = ProbeDryRun({ false }, emptyList(), maxMatches)
                    BCheckDryRun(
                        run.parts,
                        run::visit,
                        {
                            JsonObject(
                                mapOf(
                                    "items_evaluated" to JsonPrimitive(run.itemCount),
                                    "probe_requests" to JsonPrimitive(run.itemCount),
                                ),
                            )
                        },
                        "A scan would resend each audited request once with the ${spec.header} header replaced. Whether a " +
                            "${spec.interaction} interaction follows can only be seen by running it.",
                    )
                }
            }

        private val STATUS_200 = CheckCondition("status_code", "200", "equals", ignoreCase = false)
        private val BCHECK_NAME = Regex("""name:\s*"([^"]+)"""")
    }
}
